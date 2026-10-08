import copy

import pytest

from secure_messenger.identity import ExternalConfirmation, FreshnessPolicy, Permission
from secure_messenger.identity.codec import canonical
from secure_messenger.identity.errors import (
    AuthorizationError,
    ExpiredFreshness,
    ForkError,
    FreshnessError,
    MissingFreshness,
    TransitionError,
    VersionConflict,
)

from .helpers import TEST_WITNESS_DOMAIN, Scenario, reject


def test_default_no_verifier_fails_closed_even_with_valid_test_evidence():
    s = Scenario(verifier=False)
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    reject(s.machine, t, MissingFreshness, challenge=challenge, evidence=evidence)


def test_missing_proof_and_unrequested_proof_fail_closed():
    s = Scenario()
    t, _ = s.addition()
    reject(s.machine, t, MissingFreshness)
    challenge, evidence = s.proof(t)
    reject(s.machine, t, MissingFreshness, challenge=challenge)
    forged = challenge.model_copy(update={"nonce": "00" * 32})
    reject(s.machine, t, MissingFreshness, challenge=forged, evidence=evidence)


@pytest.mark.parametrize("elapsed", [20, 21, 300])
def test_expired_external_confirmation_is_atomic(elapsed):
    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    s.clock.monotonic += elapsed
    reject(s.machine, t, ExpiredFreshness, challenge=challenge, evidence=evidence)


def test_configurable_challenge_deadline_is_separate_from_signed_action_expiry():
    s = Scenario(policy=FreshnessPolicy(challenge_max_age_seconds=5))
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    s.clock.monotonic += 5
    assert s.clock.wall < t.action.expires_at
    reject(s.machine, t, ExpiredFreshness, challenge=challenge, evidence=evidence)


@pytest.mark.parametrize(
    "field,value",
    [
        ("identity_id", "00" * 32),
        ("state_hash", "00" * 32),
        ("generation", 9),
        ("nonce", "00" * 32),
    ],
)
def test_authentic_confirmation_with_wrong_binding_is_rejected(field, value):
    s = Scenario()
    t, _ = s.addition()
    challenge, _ = s.proof(t)
    wrong = ExternalConfirmation(
        challenge=challenge.model_copy(update={field: value}),
        valid_for_seconds=20,
    )
    raw = canonical(wrong)
    evidence = bytes.fromhex(s.witness.key.sign(TEST_WITNESS_DOMAIN, raw)) + raw
    reject(s.machine, t, FreshnessError, challenge=challenge, evidence=evidence)


def test_invalid_external_signature_and_overlong_lifetime_are_rejected():
    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    altered = bytes([evidence[0] ^ 1]) + evidence[1:]
    reject(s.machine, t, FreshnessError, challenge=challenge, evidence=altered)
    s.witness.lifetime = 31
    reject(
        s.machine, t, FreshnessError, challenge=challenge, evidence=s.witness.evidence(challenge)
    )


@pytest.mark.parametrize("clock", [float("nan"), float("inf"), 99])
def test_invalid_monotonic_clock_fails_closed(clock):
    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    s.clock.monotonic = clock
    reject(s.machine, t, FreshnessError, challenge=challenge, evidence=evidence)


@pytest.mark.parametrize("wall", [999, 1120, float("nan"), float("inf")])
def test_authorization_window_is_bounded_but_not_a_freshness_proof(wall):
    s = Scenario()
    t, _ = s.addition()
    s.clock.wall = wall
    reject(s.machine, t, TransitionError)


def test_verifier_failure_does_not_consume_a_valid_pending_challenge():
    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    reject(s.machine, t, FreshnessError, challenge=challenge, evidence=b"broken")
    s.machine.apply(t, challenge=challenge, evidence=evidence)
    assert s.machine.state.generation == 1


def test_invalid_policy_is_rejected():
    for invalid in (0, 301, True, 1.5):
        with pytest.raises(ValueError):
            FreshnessPolicy(challenge_max_age_seconds=invalid)


def test_offline_unknown_addition_cannot_be_safely_inferred_locally():
    s = Scenario()
    offline = copy.copy(s.machine)  # trusted in-memory snapshot; no public restore API
    addition, _ = s.addition()
    s.commit(addition)
    stale, _ = s.addition(machine=offline)
    # Local checks are deliberately unable to discover a withheld update.
    assert offline.validate_transition(stale).generation == 1
    challenge = offline.begin_freshness_check(stale)
    with pytest.raises(FreshnessError):
        s.witness.evidence(challenge)
    reject(offline, stale, MissingFreshness, challenge=challenge)
    # Upon reconnect, the omitted signed event must be processed, not a raw state jump.
    before = offline.history
    with pytest.raises(VersionConflict):
        offline.check_known_state(s.machine.state)
    assert offline.history is before
    s.commit(addition, offline)
    reject(offline, stale, ForkError)


def test_delayed_revocation_stale_manager_cannot_obtain_current_head_confirmation():
    s = Scenario()
    t, device = s.addition()
    s.commit(t)
    s.commit(s.permission_change(device, (Permission.DEVICE_MANAGEMENT,), root=True))
    offline = copy.copy(s.machine)
    revocation = s.revocation(device)
    s.commit(revocation)
    stale, _ = s.addition(author=device, machine=offline)
    assert offline.validate_transition(stale).generation == offline.state.generation + 1
    challenge = offline.begin_freshness_check(stale)
    with pytest.raises(FreshnessError):
        s.witness.evidence(challenge)
    reject(offline, stale, MissingFreshness, challenge=challenge)
    s.commit(revocation, offline)
    current_bad, _ = s.addition(author=device, machine=offline)
    reject(offline, current_bad, AuthorizationError)


def test_long_offline_reconnection_rejects_expired_authorization_without_skipping_history():
    s = Scenario()
    offline = copy.copy(s.machine)
    t, _ = s.addition()
    s.commit(t)
    s.clock.wall += 7 * 24 * 60 * 60
    reject(offline, t, TransitionError)
    # Historical catch-up and checkpoint persistence are explicitly out of prototype scope.
    assert offline.state.generation == 0


def test_reentrant_adapter_cannot_overwrite_a_changed_snapshot():
    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)
    original = s.witness.verify

    def reentrant(data, requested):
        s.machine.begin_freshness_check(t)
        return original(data, requested)

    s.witness.verify = reentrant
    reject(s.machine, t, FreshnessError, challenge=challenge, evidence=evidence)


def test_reentrant_commit_is_rejected_before_any_nested_state_change():
    s = Scenario()
    t, _ = s.addition()
    challenge, evidence = s.proof(t)

    def nested_commit(data, requested):
        s.machine.apply(t, challenge=challenge, evidence=evidence)
        raise AssertionError("nested mutation must have been blocked")

    s.witness.verify = nested_commit
    reject(s.machine, t, FreshnessError, challenge=challenge, evidence=evidence)
