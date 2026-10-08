"""Isolated in-memory state machine. Every post-genesis commit requires external evidence."""

import math
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from .authority import authorize
from .codec import canonical, checked, parse
from .consistency import check_known_state, require_next, require_unseen_action
from .errors import (
    AlreadyInitialized,
    FreshnessError,
    MissingFreshness,
    SignatureError,
    TransitionError,
    VersionConflict,
)
from .freshness import (
    FreshnessPolicy,
    FreshnessVerifier,
    PendingChallenge,
    verify_freshness,
)
from .history import History
from .models import (
    AddDevice,
    FreshnessChallenge,
    Genesis,
    IdentityState,
    IdentityStatus,
    Permission,
    SignedGenesis,
    SignedTransition,
)
from .signatures import (
    ADD_POSSESSION_DOMAIN,
    GENESIS_DEVICE_DOMAIN,
    GENESIS_ROOT_DOMAIN,
    MANAGER_POSSESSION_DOMAIN,
    DeviceKeys,
    SigningKey,
    action_hash,
    identity_id,
    state_hash,
    verify,
    verify_author,
    verify_genesis,
)
from .transitions import project


@dataclass(frozen=True, repr=False)
class BootstrapKeys:
    root: SigningKey = field(repr=False)
    first_device: DeviceKeys = field(repr=False)


@dataclass(frozen=True)
class _Snapshot:
    history: History
    pending: tuple[PendingChallenge, ...] = ()


class IdentityStateMachine:
    def __init__(
        self,
        *,
        freshness_policy: FreshnessPolicy | None = None,
        freshness_verifier: FreshnessVerifier | None = None,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = freshness_policy or FreshnessPolicy()
        self._verifier = freshness_verifier
        self._wall_clock = wall_clock
        self._monotonic = monotonic_clock
        self._lock = threading.RLock()
        self._snapshot: _Snapshot | None = None
        self._operating = False

    @contextmanager
    def _operation(self) -> Iterator[None]:
        """Serialize operations and prevent callbacks from recursively changing this identity."""
        with self._lock:
            if self._operating:
                raise VersionConflict("callbacks must not reenter state machine operations")
            self._operating = True
            try:
                yield
            finally:
                self._operating = False

    def _initialized(self) -> _Snapshot:
        if self._snapshot is None:
            raise TransitionError("identity has not been initialized")
        return self._snapshot

    @property
    def state(self) -> IdentityState:
        with self._lock:
            return self._initialized().history.current

    @property
    def history(self) -> History:
        with self._lock:
            return self._initialized().history

    def initialize(self) -> BootstrapKeys:
        """Always generates a NEW root. No root import, restore, recovery or genesis replay API."""
        with self._operation():
            if self._snapshot is not None:
                raise AlreadyInitialized("identity is already initialized")
            root = SigningKey.generate()
            first = DeviceKeys.generate((Permission.DEVICE_MANAGEMENT, Permission.MESSAGING))
            genesis = Genesis(
                identity_id=identity_id(root.public_key),
                root_public_key=root.public_key,
                action_id=secrets.token_hex(16),
                device=first.device,
            )
            payload = canonical(genesis)
            signed = SignedGenesis(
                genesis=genesis,
                root_signature=root.sign(GENESIS_ROOT_DOMAIN, payload),
                device_signature=first.auth.sign(GENESIS_DEVICE_DOMAIN, payload),
            )
            verify_genesis(signed)
            state = IdentityState(
                identity_id=genesis.identity_id,
                root_public_key=root.public_key,
                generation=0,
                previous_state_hash=None,
                last_action_id=genesis.action_id,
                action_hash=action_hash(genesis),
                devices=(first.device,),
                status=IdentityStatus.ACTIVE,
            )
            keys = BootstrapKeys(root, first)
            self._snapshot = _Snapshot(History(signed, (state,)))
            return keys

    def _validity(self, transition: SignedTransition) -> None:
        now = self._wall_clock()
        action = transition.action
        if not math.isfinite(now) or not action.issued_at <= now < action.expires_at:
            raise TransitionError("authorization validity window is not satisfied")

    def _validate(
        self,
        value: SignedTransition | bytes,
        snapshot: _Snapshot,
    ) -> tuple[SignedTransition, IdentityState]:
        transition = parse(value, SignedTransition) if isinstance(value, bytes) else checked(value)
        action = transition.action
        history = snapshot.history
        if action.identity_id != history.current.identity_id:
            raise VersionConflict("action belongs to another identity")
        require_unseen_action(history, transition)
        parent = history.find(action.previous_state_hash)
        if parent is None:
            raise VersionConflict("referenced previous state is not in the verified local history")
        if action.generation != parent.generation + 1:
            raise VersionConflict("generation must increment the referenced parent by exactly one")
        verify_author(transition, parent)
        possession_device = authorize(transition, parent)
        if possession_device is not None:
            if transition.possession_signature is None:
                raise SignatureError("fresh target-device possession proof is required")
            domain = (
                ADD_POSSESSION_DOMAIN
                if isinstance(action, AddDevice)
                else MANAGER_POSSESSION_DOMAIN
            )
            verify(
                possession_device.auth_public_key,
                transition.possession_signature,
                domain,
                canonical(action),
            )
        elif transition.possession_signature is not None:
            raise SignatureError("unexpected possession proof")
        candidate = project(parent, action)
        require_next(history, parent, candidate)
        self._validity(transition)
        return transition, candidate

    def validate_transition(self, transition: SignedTransition | bytes) -> IdentityState:
        """Local signature/authority/consistency checks only. Does NOT establish freshness."""
        with self._operation():
            return self._validate(transition, self._initialized())[1]

    def check_known_state(self, state: IdentityState) -> None:
        with self._operation():
            check_known_state(self._initialized().history, checked(state))

    def begin_freshness_check(self, transition: SignedTransition | bytes) -> FreshnessChallenge:
        """Bind a nonce to the exact prospective successor; no network IO takes place."""
        with self._operation():
            snapshot = self._initialized()
            parsed, candidate = self._validate(transition, snapshot)
            started_at = self._monotonic()
            if not math.isfinite(started_at):
                raise FreshnessError("invalid local monotonic clock")
            live_pending = []
            for request in snapshot.pending:
                elapsed = started_at - request.started_at
                if not math.isfinite(elapsed) or elapsed < 0:
                    raise FreshnessError("invalid local monotonic clock")
                if elapsed < self._policy.challenge_max_age_seconds:
                    live_pending.append(request)
            if len(live_pending) >= 128:
                raise FreshnessError("too many outstanding freshness requests")
            challenge = FreshnessChallenge(
                identity_id=candidate.identity_id,
                generation=candidate.generation,
                state_hash=state_hash(candidate),
                nonce=secrets.token_hex(32),
            )
            pending = PendingChallenge(
                challenge,
                parsed.action.action_id,
                state_hash(snapshot.history.current),
                started_at,
            )
            self._snapshot = _Snapshot(snapshot.history, (*live_pending, pending))
            return challenge

    def apply(
        self,
        transition: SignedTransition | bytes,
        *,
        challenge: FreshnessChallenge | None = None,
        evidence: bytes | None = None,
    ) -> IdentityState:
        with self._operation():
            snapshot = self._initialized()
            parsed, candidate = self._validate(transition, snapshot)
            if challenge is None:
                raise MissingFreshness("a requested external freshness challenge is required")
            challenge = checked(challenge)
            pending = next((p for p in snapshot.pending if p.challenge == challenge), None)
            if pending is not None and (
                pending.action_id != parsed.action.action_id
                or pending.parent_hash != state_hash(snapshot.history.current)
                or pending.challenge.state_hash != state_hash(candidate)
            ):
                raise FreshnessError("challenge does not match this transition and current parent")
            deadline = verify_freshness(
                pending, evidence, self._verifier, self._policy, self._monotonic
            )
            # Prepare allocations before the last expiry checks; exceptions never commit.
            updated = _Snapshot(snapshot.history.appended(candidate, parsed))
            self._validity(parsed)
            deadline.require_live(self._monotonic())
            if self._snapshot is not snapshot:
                raise VersionConflict("state changed during external verification")
            # Single commit point: history and pending requests change together, after ALL checks.
            self._snapshot = updated
            return candidate
