import secrets
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from pydantic import ValidationError

from secure_messenger.identity import (
    Actor,
    AddDevice,
    DeviceKeys,
    DeviceStatus,
    IdentityStateMachine,
    IdentityStatus,
    Permission,
    SignerKind,
    sign_transition,
    state_hash,
)
from secure_messenger.identity.codec import canonical, parse
from secure_messenger.identity.errors import (
    AlreadyInitialized,
    AuthorizationError,
    EncodingError,
    ForkError,
    IdentityError,
    ReplayError,
    RollbackError,
    SignatureError,
    UnknownSigner,
    VersionConflict,
)
from secure_messenger.identity.models import SignedGenesis
from secure_messenger.identity.signatures import (
    ADD_POSSESSION_DOMAIN,
    AUTHOR_DOMAIN,
    GENESIS_ROOT_DOMAIN,
    identity_id,
    verify,
    verify_author,
    verify_genesis,
)

from .helpers import Scenario, flip_signature, reject, resign


def test_genesis_has_independent_keys_signed_identity_and_no_import():
    s = Scenario()
    state = s.machine.state
    assert state.generation == 0
    assert state.previous_state_hash is None
    assert state.identity_id == identity_id(s.bootstrap.root.public_key)
    keys = {
        state.root_public_key,
        state.devices[0].auth_public_key,
        state.devices[0].session_public_key,
    }
    assert len(keys) == 3
    verify_genesis(s.machine.history.genesis)
    assert parse(canonical(s.machine.history.genesis), SignedGenesis) == s.machine.history.genesis
    before = s.machine.history
    with pytest.raises(AlreadyInitialized):
        s.machine.initialize()
    assert s.machine.history is before
    other = IdentityStateMachine()
    other.initialize()
    assert other.state.identity_id != state.identity_id
    with pytest.raises(TypeError):
        IdentityStateMachine(root=s.bootstrap.root)


def test_add_change_permissions_revoke_and_history_chain():
    s = Scenario()
    transition, device = s.addition()
    before = s.machine.state
    candidate = s.machine.validate_transition(transition)
    assert s.machine.state is before  # local validation never commits
    state = s.commit(transition)
    assert state == candidate
    assert state.previous_state_hash == state_hash(before)
    s.commit(s.permission_change(device, ()))
    s.commit(s.revocation(device))
    stored = next(d for d in s.machine.state.devices if d.device_id == device.device.device_id)
    assert stored.status == DeviceStatus.REVOKED
    assert stored.permissions == ()
    assert len(s.machine.history.states) == 4
    assert len(s.machine.history.transitions) == 3
    for previous, current in zip(
        s.machine.history.states[:-1], s.machine.history.states[1:], strict=True
    ):
        assert current.generation == previous.generation + 1
        assert current.previous_state_hash == state_hash(previous)


def test_invalid_signature_is_atomic():
    s = Scenario()
    t, _ = s.addition()
    reject(
        s.machine,
        t.model_copy(update={"author_signature": flip_signature(t.author_signature)}),
        SignatureError,
    )


@pytest.mark.parametrize("public_key", [bytes(32), bytes([1]) + bytes(31)])
def test_degenerate_ed25519_public_key_and_forged_possession_are_rejected(public_key):
    s = Scenario()
    t, _ = s.addition()
    forged_signature = public_key + bytes(32)
    with pytest.raises(SignatureError):
        verify(public_key.hex(), forged_signature.hex(), ADD_POSSESSION_DOMAIN, b"any context")
    invalid_device = t.action.device.model_copy(update={"auth_public_key": public_key.hex()})
    action = t.action.model_copy(update={"device": invalid_device})
    signed = sign_transition(action, s.manager.auth)
    signed = signed.model_copy(update={"possession_signature": forged_signature.hex()})
    reject(s.machine, signed, SignatureError)


def test_unsigned_transition_is_atomic():
    s = Scenario()
    t, _ = s.addition()
    reject(s.machine, t.model_copy(update={"author_signature": None}), EncodingError)


def test_valid_signature_does_not_grant_authority():
    s = Scenario()
    t, device = s.addition()
    s.commit(t)
    unauthorized, _ = s.addition(author=device)
    verify_author(unauthorized, s.machine.state)  # crypto passes separately
    reject(s.machine, unauthorized, AuthorizationError)


def test_unknown_signer_is_not_trusted_from_message():
    s = Scenario()
    t, _ = s.addition(author=DeviceKeys.generate())
    reject(s.machine, t, UnknownSigner)


def test_replay_and_action_id_reuse_are_atomic():
    s = Scenario()
    t, _ = s.addition()
    s.commit(t)
    reject(s.machine, t, ReplayError)
    next_t, new = s.addition()
    reused = resign(next_t, s.manager.auth, new.auth, action_id=t.action.action_id)
    reject(s.machine, reused, ReplayError)


def test_manipulated_parent_and_generation_jump():
    s = Scenario()
    t, new = s.addition()
    reject(
        s.machine,
        resign(t, s.manager.auth, new.auth, previous_state_hash="00" * 32),
        VersionConflict,
    )
    reject(
        s.machine,
        resign(t, s.manager.auth, new.auth, generation=t.action.generation + 1),
        VersionConflict,
    )


def test_known_rollback_and_authenticated_fork():
    s = Scenario()
    old = s.machine.state
    a, _ = s.addition()
    b, _ = s.addition()
    s.commit(a)
    history = s.machine.history
    with pytest.raises(RollbackError):
        s.machine.check_known_state(old)
    assert s.machine.history is history
    reject(s.machine, b, ForkError)
    corrupt = b.model_copy(update={"author_signature": flip_signature(b.author_signature)})
    reject(s.machine, corrupt, SignatureError)  # invalid input is not an authenticated fork


def test_untrusted_state_claim_cannot_advance_or_authenticate_fork():
    s = Scenario()
    t, _ = s.addition()
    candidate = s.machine.validate_transition(t)
    before = s.machine.history
    with pytest.raises(VersionConflict):
        s.machine.check_known_state(candidate)
    assert s.machine.history is before
    s.machine.check_known_state(s.machine.state)


def test_permissions_cannot_be_changed_after_signing():
    s = Scenario()
    t, _ = s.addition()
    device = t.action.device.model_copy(update={"permissions": (Permission.DEVICE_MANAGEMENT,)})
    altered = t.model_copy(update={"action": t.action.model_copy(update={"device": device})})
    reject(s.machine, altered, SignatureError)


@pytest.mark.parametrize(
    "permissions",
    [
        (Permission.DEVICE_MANAGEMENT,),
        (Permission.IDENTITY_RECOVERY,),
        (Permission.DEVICE_MANAGEMENT, Permission.MESSAGING),
        (),
    ],
)
def test_manager_cannot_grant_privilege_or_recovery_at_add(permissions):
    s = Scenario()
    t, _ = s.addition(DeviceKeys.generate(permissions))
    reject(s.machine, t, AuthorizationError)


def test_manager_grant_needs_root_and_existing_device_fresh_possession():
    s = Scenario()
    t, device = s.addition()
    s.commit(t)
    permissions = (Permission.DEVICE_MANAGEMENT, Permission.MESSAGING)
    reject(s.machine, s.permission_change(device, permissions), AuthorizationError)
    reject(
        s.machine,
        s.permission_change(device, permissions, root=True, possession=False),
        SignatureError,
    )
    grant = s.permission_change(device, permissions, root=True)
    old_payload_proof = device.auth.sign(GENESIS_ROOT_DOMAIN, canonical(grant.action))
    reject(
        s.machine,
        grant.model_copy(update={"possession_signature": old_payload_proof}),
        SignatureError,
    )
    s.commit(grant)
    new, _ = s.addition(author=device)
    s.commit(new)
    reject(
        s.machine,
        s.permission_change(DeviceKeys.generate(), permissions, root=True),
        AuthorizationError,
    )


def test_root_alone_cannot_add_or_take_manager_shortcut():
    s = Scenario()
    new = DeviceKeys.generate()
    action = AddDevice(**s.common(Actor(kind=SignerKind.ROOT)), device=new.device)
    reject(s.machine, sign_transition(action, s.bootstrap.root, new.auth), AuthorizationError)
    reject(
        s.machine, s.permission_change(s.manager, (), root=True, possession=False), SignatureError
    )


def test_roles_do_not_implicitly_include_messaging():
    s = Scenario()
    s.commit(s.permission_change(s.manager, (Permission.DEVICE_MANAGEMENT,)))
    assert s.machine.state.devices[0].permissions == (Permission.DEVICE_MANAGEMENT,)
    t, _ = s.addition()
    s.commit(t)
    # A separate role still allows management, without granting messaging back.
    manager = next(d for d in s.machine.state.devices if d.device_id == s.manager.device.device_id)
    assert Permission.MESSAGING not in manager.permissions


def test_revoked_signer_and_id_reactivation_are_blocked():
    s = Scenario()
    t, device = s.addition()
    s.commit(t)
    s.commit(s.permission_change(device, (Permission.DEVICE_MANAGEMENT,), root=True))
    s.commit(s.revocation(device))
    forged, _ = s.addition(author=device)
    reject(s.machine, forged, AuthorizationError)
    reused, _ = s.addition(device)
    reject(s.machine, reused, AuthorizationError)
    reject(
        s.machine,
        s.permission_change(device, (Permission.DEVICE_MANAGEMENT,), root=True),
        AuthorizationError,
    )


def test_last_revocation_is_terminal_no_recovery_even_with_root():
    s = Scenario()
    s.commit(s.revocation(s.manager))
    assert s.machine.state.status == IdentityStatus.RETIRED
    action = AddDevice(**s.common(Actor(kind=SignerKind.ROOT)), device=DeviceKeys.generate().device)
    reject(s.machine, sign_transition(action, s.bootstrap.root), AuthorizationError)
    reject(
        s.machine,
        s.permission_change(s.manager, (Permission.DEVICE_MANAGEMENT,), root=True),
        AuthorizationError,
    )
    fresh = IdentityStateMachine()
    fresh.initialize()
    assert fresh.state.identity_id != s.machine.state.identity_id


def test_key_reuse_even_across_revoked_records_is_rejected():
    s = Scenario()
    t, device = s.addition()
    s.commit(t)
    s.commit(s.revocation(device))
    recycled = DeviceKeys(
        device.device.model_copy(update={"device_id": secrets.token_hex(16)}),
        device.auth,
        device._session,
    )
    t, _ = s.addition(recycled)
    reject(s.machine, t, IdentityError)


def test_signature_domain_and_identity_reuse_are_rejected():
    s = Scenario()
    t, _ = s.addition()
    wrong = s.manager.auth.sign(GENESIS_ROOT_DOMAIN, canonical(t.action))
    reject(s.machine, t.model_copy(update={"author_signature": wrong}), SignatureError)
    other = Scenario()
    reject(other.machine, t, VersionConflict)
    assert s.manager.auth.sign(AUTHOR_DOMAIN, canonical(t.action)) != wrong


def test_possession_proof_cannot_be_reused_for_another_action():
    s = Scenario()
    t, device = s.addition()
    second, _ = s.addition(device)
    reject(
        s.machine,
        second.model_copy(update={"possession_signature": t.possession_signature}),
        SignatureError,
    )


def test_immutable_state_and_model_copy_bypass_are_checked():
    s = Scenario()
    with pytest.raises(ValidationError):
        s.machine.state.generation = 10
    t, _ = s.addition()
    reject(
        s.machine,
        t.model_copy(update={"action": t.action.model_copy(update={"generation": True})}),
        EncodingError,
    )


def test_simultaneous_authorized_changes_commit_exactly_once():
    s = Scenario()
    a, _ = s.addition()
    b, _ = s.addition()
    a_challenge, a_evidence = s.proof(a)
    b_challenge, b_evidence = s.proof(b)
    barrier = Barrier(2)

    def attempt(transition, challenge, evidence):
        barrier.wait(timeout=10)
        try:
            s.machine.apply(transition, challenge=challenge, evidence=evidence)
            return "committed"
        except ForkError:
            return "fork"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(attempt, a, a_challenge, a_evidence),
            pool.submit(attempt, b, b_challenge, b_evidence),
        ]
        outcomes = [f.result(timeout=10) for f in futures]
    assert sorted(outcomes) == ["committed", "fork"]
    assert s.machine.state.generation == 1
    assert len(s.machine.history.transitions) == 1
