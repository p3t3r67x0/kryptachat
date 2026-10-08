"""Adversarial reproductions for the 2026-10-08 review; no production witness."""

import pytest

from secure_messenger.identity.errors import ExpiredFreshness, VersionConflict

from .helpers import Scenario, reject


def test_confirmation_expiring_during_final_wall_clock_check_never_commits():
    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    reads = 0

    def wall_clock():
        nonlocal reads
        reads += 1
        if reads == 2:  # The final authorization check after verifier and monotonic check.
            s.clock.monotonic += s.witness.lifetime
        return s.clock.wall

    s.machine._wall_clock = wall_clock
    reject(s.machine, t, ExpiredFreshness, challenge=challenge, evidence=evidence)


def test_wall_clock_reentry_cannot_commit_inside_a_rejected_outer_operation():
    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    entered = False

    def wall_clock():
        nonlocal entered
        if not entered:
            entered = True
            s.machine.apply(t, challenge=challenge, evidence=evidence)
            raise RuntimeError("outer clock failed after nested commit")
        return s.clock.wall

    s.machine._wall_clock = wall_clock
    reject(s.machine, t, VersionConflict, challenge=challenge, evidence=evidence)


def test_expired_challenge_capacity_can_be_reused_without_resetting_identity():
    s = Scenario()
    t, _ = s.addition()
    for _ in range(128):
        s.machine.begin_freshness_check(t)
    s.clock.monotonic += 30
    # A relay can repeatedly supply one valid action; expiry must release local capacity.
    challenge, evidence = s.proof(t)
    assert s.machine.apply(t, challenge=challenge, evidence=evidence).generation == 1


def test_ill_typed_verifier_result_is_a_typed_atomic_rejection():
    from secure_messenger.identity import FreshnessChallenge
    from secure_messenger.identity.errors import FreshnessError

    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    s.witness.verify = lambda data, requested: FreshnessChallenge.model_validate(requested)
    reject(s.machine, t, FreshnessError, challenge=challenge, evidence=evidence)


def test_history_allocation_failure_and_guard_reset_are_atomic(monkeypatch):
    from secure_messenger.identity.history import History

    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    original = History.appended

    def fail(*args):
        raise MemoryError("simulated allocation failure")

    monkeypatch.setattr(History, "appended", fail)
    reject(s.machine, t, MemoryError, challenge=challenge, evidence=evidence)
    monkeypatch.setattr(History, "appended", original)
    assert s.machine.apply(t, challenge=challenge, evidence=evidence).generation == 1


def test_expiry_during_history_allocation_never_commits(monkeypatch):
    from secure_messenger.identity.history import History

    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    original = History.appended

    def slow_append(history, state, transition):
        s.clock.monotonic += s.witness.lifetime
        return original(history, state, transition)

    monkeypatch.setattr(History, "appended", slow_append)
    reject(s.machine, t, ExpiredFreshness, challenge=challenge, evidence=evidence)


def test_pruning_failure_does_not_replace_snapshot_and_valid_clock_can_retry():
    from secure_messenger.identity.errors import FreshnessError

    s = Scenario()
    t, _ = s.addition()
    s.machine.begin_freshness_check(t)
    before = s.machine._snapshot
    s.clock.monotonic -= 1
    with pytest.raises(FreshnessError):
        s.machine.begin_freshness_check(t)
    assert s.machine._snapshot is before
    s.clock.monotonic += 31
    challenge, evidence = s.proof(t)
    s.machine.apply(t, challenge=challenge, evidence=evidence)


def test_all_signing_context_pairs_reject_reused_signature():
    from itertools import permutations

    from secure_messenger.identity.errors import SignatureError
    from secure_messenger.identity.signatures import (
        ADD_POSSESSION_DOMAIN,
        AUTHOR_DOMAIN,
        GENESIS_DEVICE_DOMAIN,
        GENESIS_ROOT_DOMAIN,
        MANAGER_POSSESSION_DOMAIN,
        SigningKey,
        verify,
    )

    key = SigningKey.generate()
    payload = b"same key, same payload, different protocol purpose"
    domains = (
        ADD_POSSESSION_DOMAIN,
        AUTHOR_DOMAIN,
        GENESIS_DEVICE_DOMAIN,
        GENESIS_ROOT_DOMAIN,
        MANAGER_POSSESSION_DOMAIN,
    )
    assert len(set(domains)) == len(domains)
    for signed_domain, verified_domain in permutations(domains, 2):
        signature = key.sign(signed_domain, payload)
        with pytest.raises(SignatureError):
            verify(key.public_key, signature, verified_domain, payload)


def test_noncanonical_ed25519_signature_scalar_is_rejected_by_both_backends():
    from nacl.bindings import crypto_sign_open
    from nacl.exceptions import BadSignatureError

    from secure_messenger.identity.errors import SignatureError
    from secure_messenger.identity.signatures import AUTHOR_DOMAIN, verify

    s = Scenario()
    t, _ = s.addition()
    from secure_messenger.identity.codec import canonical

    payload = canonical(t.action)
    signature = bytes.fromhex(t.author_signature)
    # RFC 8032 section 5.1.7 requires 0 <= S < L. Test an equivalent S+L encoding.
    order = 2**252 + 27742317777372353535851937790883648493
    alternate = signature[:32] + (int.from_bytes(signature[32:], "little") + order).to_bytes(
        32, "little"
    )
    with pytest.raises(SignatureError):
        verify(s.manager.auth.public_key, alternate.hex(), AUTHOR_DOMAIN, payload)
    with pytest.raises(BadSignatureError):
        crypto_sign_open(
            alternate + AUTHOR_DOMAIN + payload, bytes.fromhex(s.manager.auth.public_key)
        )


def test_previously_confirmed_fork_is_still_accepted_on_an_unaware_offline_copy():
    """Executable known design limitation: signed observations are not atomic head leases."""
    import copy

    s = Scenario()
    offline = copy.copy(s.machine)
    a, _ = s.addition()
    b, _ = s.addition()
    # Honest observations of candidate heads at different instants, same local parent.
    a_challenge, a_evidence = s.proof(a, offline)
    b_challenge, b_evidence = s.proof(b)
    s.machine.apply(b, challenge=b_challenge, evidence=b_evidence)
    offline.apply(a, challenge=a_challenge, evidence=a_evidence)
    assert offline.state.generation == s.machine.state.generation == 1
    from secure_messenger.identity import state_hash

    assert state_hash(offline.state) != state_hash(s.machine.state)
    from secure_messenger.identity.errors import ForkError

    reject(offline, b, ForkError)


def test_compromised_manager_can_add_messaging_and_revoke_another_manager_within_policy():
    """Accepted authority power; mitigation requires an explicit quorum policy decision."""
    from secure_messenger.identity import Permission
    from secure_messenger.identity.errors import AuthorizationError

    s = Scenario()
    t, compromised = s.addition()
    s.commit(t)
    s.commit(s.permission_change(compromised, (Permission.DEVICE_MANAGEMENT,), root=True))
    injected, device = s.addition(author=compromised)
    s.commit(injected)
    unauthorized = s.permission_change(device, (Permission.DEVICE_MANAGEMENT,), author=compromised)
    reject(s.machine, unauthorized, AuthorizationError)
    s.commit(s.revocation(s.manager, author=compromised))
    assert s.machine.state.generation == 4


@pytest.mark.parametrize(
    "encoded",
    ["f6" + "ff" * 30 + "7f", "f5" + "ff" * 30 + "7f", "95" + "99" * 31],
)
def test_upstream_noncanonical_and_non_subgroup_public_points_fail_closed(encoded):
    from nacl.bindings import crypto_core_ed25519_is_valid_point

    from secure_messenger.identity.errors import SignatureError
    from secure_messenger.identity.signatures import AUTHOR_DOMAIN, verify

    # Upstream libsodium test/default/core_ed25519.c point-validation vectors.
    assert not crypto_core_ed25519_is_valid_point(bytes.fromhex(encoded))
    with pytest.raises(SignatureError):
        verify(encoded, "00" * 64, AUTHOR_DOMAIN, b"test")


def test_authorization_expiring_inside_verifier_cannot_commit():
    from secure_messenger.identity.errors import TransitionError

    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    original = s.witness.verify

    def slow_verifier(data, requested):
        result = original(data, requested)
        s.clock.wall = t.action.expires_at
        return result

    s.witness.verify = slow_verifier
    reject(s.machine, t, TransitionError, challenge=challenge, evidence=evidence)


def test_bootstrap_result_allocation_failure_never_initializes_partial_identity(monkeypatch):
    import secure_messenger.identity.state_machine as module
    from secure_messenger.identity import IdentityStateMachine

    machine = IdentityStateMachine()
    original = module.BootstrapKeys

    def fail(*args):
        raise MemoryError("simulated bootstrap result allocation failure")

    monkeypatch.setattr(module, "BootstrapKeys", fail)
    with pytest.raises(MemoryError):
        machine.initialize()
    assert machine._snapshot is None
    monkeypatch.setattr(module, "BootstrapKeys", original)
    keys = machine.initialize()
    assert machine.state.root_public_key == keys.root.public_key
