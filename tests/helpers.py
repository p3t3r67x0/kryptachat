"""TEST ONLY: a pinned signing witness, NOT a transparency service or freshness design."""

import secrets
from dataclasses import dataclass

import pytest

from secure_messenger.identity import (
    Actor,
    AddDevice,
    ChangePermissions,
    DeviceKeys,
    ExternalConfirmation,
    FreshnessPolicy,
    IdentityStateMachine,
    RevokeDevice,
    SignedTransition,
    SignerKind,
    SigningKey,
    sign_transition,
    state_hash,
)
from secure_messenger.identity.codec import canonical, parse
from secure_messenger.identity.errors import FreshnessError, IdentityError
from secure_messenger.identity.signatures import verify

TEST_WITNESS_DOMAIN = b"KRYPTA/TEST-ONLY/WITNESS/V1\x00"


@dataclass
class Clock:
    wall: float = 1_000
    monotonic: float = 100


class TestWitness:
    __test__ = False

    def __init__(self):
        self.key = SigningKey.generate()
        self.current_head: tuple[str, str, int] | None = None
        self.lifetime = 20

    def evidence(self, challenge):
        if self.current_head != (
            challenge.identity_id,
            challenge.state_hash,
            challenge.generation,
        ):
            raise FreshnessError("test witness refuses a withheld or competing head")
        confirmation = ExternalConfirmation(
            challenge=challenge,
            valid_for_seconds=self.lifetime,
        )
        raw = canonical(confirmation)
        return bytes.fromhex(self.key.sign(TEST_WITNESS_DOMAIN, raw)) + raw

    def verify(self, evidence, challenge):
        if len(evidence) <= 64:
            raise FreshnessError("test evidence truncated")
        signature, raw = evidence[:64], evidence[64:]
        verify(self.key.public_key, signature.hex(), TEST_WITNESS_DOMAIN, raw)
        return parse(raw, ExternalConfirmation)


class Scenario:
    def __init__(self, *, policy=None, verifier=True):
        self.clock = Clock()
        self.witness = TestWitness()
        self.machine = IdentityStateMachine(
            freshness_verifier=self.witness if verifier else None,
            freshness_policy=policy or FreshnessPolicy(),
            wall_clock=lambda: self.clock.wall,
            monotonic_clock=lambda: self.clock.monotonic,
        )
        self.bootstrap = self.machine.initialize()
        self.manager = self.bootstrap.first_device

    def common(self, actor=None, machine=None):
        state = (machine or self.machine).state
        return dict(
            identity_id=state.identity_id,
            action_id=secrets.token_hex(16),
            generation=state.generation + 1,
            previous_state_hash=state_hash(state),
            issued_at=int(self.clock.wall),
            expires_at=int(self.clock.wall) + 120,
            actor=actor or Actor(kind=SignerKind.DEVICE, device_id=self.manager.device.device_id),
        )

    def addition(self, new=None, *, author=None, machine=None):
        new = new or DeviceKeys.generate()
        author = author or self.manager
        actor = Actor(kind=SignerKind.DEVICE, device_id=author.device.device_id)
        action = AddDevice(**self.common(actor, machine), device=new.device)
        return sign_transition(action, author.auth, new.auth), new

    def permission_change(self, target, permissions, *, root=False, possession=True, author=None):
        actor = (
            Actor(kind=SignerKind.ROOT)
            if root
            else Actor(kind=SignerKind.DEVICE, device_id=(author or self.manager).device.device_id)
        )
        action = ChangePermissions(
            **self.common(actor),
            target_device_id=target.device.device_id,
            permissions=tuple(sorted(permissions)),
        )
        return sign_transition(
            action,
            self.bootstrap.root if root else (author or self.manager).auth,
            target.auth if root and possession else None,
        )

    def revocation(self, target, *, author=None, machine=None):
        author = author or self.manager
        action = RevokeDevice(
            **self.common(
                Actor(kind=SignerKind.DEVICE, device_id=author.device.device_id),
                machine,
            ),
            target_device_id=target.device.device_id,
        )
        return sign_transition(action, author.auth)

    def proof(self, transition, machine=None):
        machine = machine or self.machine
        candidate = machine.validate_transition(transition)
        self.witness.current_head = (
            candidate.identity_id,
            state_hash(candidate),
            candidate.generation,
        )
        challenge = machine.begin_freshness_check(transition)
        return challenge, self.witness.evidence(challenge)

    def commit(self, transition, machine=None):
        machine = machine or self.machine
        challenge, evidence = self.proof(transition, machine)
        return machine.apply(transition, challenge=challenge, evidence=evidence)


def reject(machine, transition, error=IdentityError, **kwargs):
    state, history = machine.state, machine.history
    snapshot = machine._snapshot
    with pytest.raises(error):
        machine.apply(transition, **kwargs)
    assert machine.state is state
    assert machine.history is history
    assert machine._snapshot is snapshot  # Includes pending challenges, not just device history.


def resign(transition: SignedTransition, signer: SigningKey, possession=None, **changes):
    return sign_transition(transition.action.model_copy(update=changes), signer, possession)


def flip_signature(signature):
    return bytes([int(signature[:2], 16) ^ 1]).hex() + signature[2:]
