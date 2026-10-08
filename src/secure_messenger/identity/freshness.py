"""Fail-closed adapter boundary. Local clocks never attest to a globally current head."""

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .codec import checked
from .errors import ExpiredFreshness, FreshnessError, MissingFreshness
from .models import ExternalConfirmation, FreshnessChallenge


class FreshnessVerifier(Protocol):
    def verify(
        self,
        evidence: bytes,
        challenge: FreshnessChallenge,
    ) -> ExternalConfirmation:
        """Authenticate an external current-head claim; adapter and authority are trusted."""
        ...


@dataclass(frozen=True)
class FreshnessPolicy:
    challenge_max_age_seconds: int = 30
    confirmation_max_age_seconds: int = 30

    def __post_init__(self) -> None:
        for value in (self.challenge_max_age_seconds, self.confirmation_max_age_seconds):
            if type(value) is not int or not 1 <= value <= 300:
                raise ValueError("freshness lifetime must be an integer from 1 to 300 seconds")


@dataclass(frozen=True)
class PendingChallenge:
    challenge: FreshnessChallenge
    action_id: str
    parent_hash: str
    started_at: float


def verify_freshness(
    pending: PendingChallenge | None,
    evidence: bytes | None,
    verifier: FreshnessVerifier | None,
    policy: FreshnessPolicy,
    monotonic: Callable[[], float],
) -> None:
    if pending is None or evidence is None or verifier is None:
        raise MissingFreshness("external verifier, challenge and evidence are required")
    if type(evidence) is not bytes or not 0 < len(evidence) <= 65_536:
        raise FreshnessError("invalid external evidence size or type")
    try:
        confirmation = checked(verifier.verify(evidence, pending.challenge))
    except Exception as exc:
        # Untrusted evidence must not escape the adapter as a successful confirmation.
        raise FreshnessError("external evidence verification failed") from exc
    if confirmation.challenge != pending.challenge:
        raise FreshnessError("confirmation is not bound to the requested candidate and nonce")
    if confirmation.valid_for_seconds > policy.confirmation_max_age_seconds:
        raise FreshnessError("external confirmation lifetime exceeds policy")
    elapsed = monotonic() - pending.started_at
    if not math.isfinite(elapsed) or elapsed < 0:
        raise FreshnessError("local monotonic clock is invalid")
    if elapsed >= min(policy.challenge_max_age_seconds, confirmation.valid_for_seconds):
        raise ExpiredFreshness("external confirmation or challenge expired")
