import json

from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from secure_messenger.identity import DeviceStatus, Permission, state_hash
from secure_messenger.identity.errors import EncodingError, ReplayError, SignatureError

from .helpers import Scenario, reject, resign


@given(position=st.integers(min_value=0, max_value=63), bit=st.integers(min_value=0, max_value=7))
@settings(max_examples=80, deadline=None)
def test_every_sampled_signature_bit_flip_rejects_atomically(position, bit):
    s = Scenario()
    t, _ = s.addition()
    signature = bytearray.fromhex(t.author_signature)
    signature[position] ^= 1 << bit
    reject(s.machine, t.model_copy(update={"author_signature": signature.hex()}), SignatureError)


@given(
    permissions=st.sampled_from(
        [
            [],
            ["device_management"],
            ["identity_recovery"],
            ["device_management", "messaging"],
        ]
    )
)
@settings(max_examples=10, deadline=None)
def test_unsigned_permission_tampering_is_atomic(permissions):
    s = Scenario()
    t, _ = s.addition()
    data = t.model_dump(mode="json")
    data["action"]["device"]["permissions"] = permissions
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii")
    reject(s.machine, raw, SignatureError)


@given(raw=st.binary(max_size=500))
@settings(max_examples=100, deadline=None)
def test_arbitrary_wire_input_never_partially_commits(raw):
    s = Scenario()
    reject(s.machine, raw, EncodingError)


class Lifecycle(RuleBasedStateMachine):
    """Independent membership/role model; random valid and invalid operation sequences."""

    def __init__(self):
        super().__init__()
        self.s = Scenario()
        self.keys = [self.s.manager]
        self.expected = {
            self.s.manager.device.device_id: (
                DeviceStatus.ACTIVE,
                (Permission.DEVICE_MANAGEMENT, Permission.MESSAGING),
            ),
        }
        self.successful = 0
        self.accepted = []
        self.stale_siblings = []

    @rule()
    def add_messaging_device(self):
        transition, device = self.s.addition()
        sibling, _ = self.s.addition()
        self.s.commit(transition)
        self.keys.append(device)
        self.expected[device.device.device_id] = (DeviceStatus.ACTIVE, (Permission.MESSAGING,))
        self.successful += 1
        self.accepted.append(transition)
        self.stale_siblings.append(sibling)

    @rule(index=st.integers(min_value=0, max_value=100))
    def revoke_noninitial_device(self, index):
        options = [
            d for d in self.keys[1:] if self.expected[d.device.device_id][0] == DeviceStatus.ACTIVE
        ]
        if not options:
            return
        device = options[index % len(options)]
        transition = self.s.revocation(device)
        self.s.commit(transition)
        self.expected[device.device.device_id] = (DeviceStatus.REVOKED, ())
        self.successful += 1
        self.accepted.append(transition)

    @rule(index=st.integers(min_value=0, max_value=100))
    def change_explicit_manager_role(self, index):
        options = [
            d for d in self.keys[1:] if self.expected[d.device.device_id][0] == DeviceStatus.ACTIVE
        ]
        if not options:
            return
        device = options[index % len(options)]
        prior = self.expected[device.device.device_id][1]
        permissions = (
            (Permission.MESSAGING,)
            if Permission.DEVICE_MANAGEMENT in prior
            else (Permission.DEVICE_MANAGEMENT, Permission.MESSAGING)
        )
        transition = self.s.permission_change(device, permissions, root=True)
        self.s.commit(transition)
        self.expected[device.device.device_id] = (DeviceStatus.ACTIVE, permissions)
        self.successful += 1
        self.accepted.append(transition)

    @rule(index=st.integers(min_value=0, max_value=100))
    def replay_does_not_mutate_anything(self, index):
        if self.accepted:
            reject(self.s.machine, self.accepted[index % len(self.accepted)], ReplayError)

    @rule(index=st.integers(min_value=0, max_value=100))
    def authenticated_stale_branch_never_merges(self, index):
        if self.stale_siblings:
            from secure_messenger.identity.errors import ForkError

            reject(self.s.machine, self.stale_siblings[index % len(self.stale_siblings)], ForkError)

    @rule()
    def rejected_permissions_do_not_consume_action_id(self):
        transition, new = self.s.addition()
        forged = transition.model_copy(update={"author_signature": "00" * 64})
        reject(self.s.machine, forged, SignatureError)
        self.s.commit(transition)
        self.keys.append(new)
        self.expected[new.device.device_id] = (DeviceStatus.ACTIVE, (Permission.MESSAGING,))
        self.successful += 1
        self.accepted.append(transition)

    @rule()
    def fresh_generation_with_used_action_id_is_still_replay(self):
        transition, new = self.s.addition()
        action_id = (
            self.accepted[-1].action.action_id
            if self.accepted
            else self.s.machine.history.genesis.genesis.action_id
        )
        forged = resign(transition, self.s.manager.auth, new.auth, action_id=action_id)
        reject(self.s.machine, forged, ReplayError)

    @invariant()
    def membership_and_history_match_independent_model(self):
        state = self.s.machine.state
        actual = {d.device_id: (d.status, d.permissions) for d in state.devices}
        assert actual == self.expected
        assert state.generation == self.successful
        assert len(self.s.machine.history.transitions) == self.successful
        assert len(self.s.machine.history.states) == self.successful + 1
        assert len({s.last_action_id for s in self.s.machine.history.states}) == self.successful + 1
        assert Permission.IDENTITY_RECOVERY not in {p for d in state.devices for p in d.permissions}
        if self.successful:
            assert state.previous_state_hash == state_hash(self.s.machine.history.states[-2])


TestLifecycle = Lifecycle.TestCase
TestLifecycle.settings = settings(max_examples=40, stateful_step_count=25, deadline=None)


@given(lifetime=st.integers(min_value=1, max_value=300), overrun=st.integers(0, 100))
@settings(max_examples=40, deadline=None)
def test_expiry_at_commit_boundary_preserves_the_entire_snapshot(lifetime, overrun):
    from secure_messenger.identity import FreshnessPolicy
    from secure_messenger.identity.errors import ExpiredFreshness

    s = Scenario(
        policy=FreshnessPolicy(challenge_max_age_seconds=300, confirmation_max_age_seconds=300)
    )
    s.witness.lifetime = lifetime
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    reads = 0

    def advancing_wall_clock():
        nonlocal reads
        reads += 1
        if reads == 2:
            s.clock.monotonic += lifetime + overrun
        return s.clock.wall

    s.machine._wall_clock = advancing_wall_clock
    reject(s.machine, t, ExpiredFreshness, challenge=challenge, evidence=evidence)


@given(data=st.data(), replacement=st.integers(min_value=0, max_value=255))
@settings(max_examples=60, deadline=None)
def test_near_valid_wire_corruption_never_partially_commits(data, replacement):
    from secure_messenger.identity.errors import IdentityError

    s = Scenario()
    t, _ = s.addition()
    from secure_messenger.identity.codec import canonical

    original = canonical(t)
    challenge, evidence = s.proof(t)
    raw = bytearray(original)
    position = data.draw(st.integers(min_value=0, max_value=len(raw) - 1))
    raw[position] = replacement
    if bytes(raw) == original:
        assert s.machine.apply(bytes(raw), challenge=challenge, evidence=evidence).generation == 1
    else:
        reject(s.machine, bytes(raw), IdentityError, challenge=challenge, evidence=evidence)
