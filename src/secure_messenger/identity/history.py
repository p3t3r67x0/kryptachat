"""Immutable in-memory authenticated history; no persistence or snapshot import."""

from dataclasses import dataclass

from .models import IdentityState, SignedGenesis, SignedTransition
from .signatures import state_hash


@dataclass(frozen=True)
class History:
    genesis: SignedGenesis
    states: tuple[IdentityState, ...]
    transitions: tuple[SignedTransition, ...] = ()

    @property
    def current(self) -> IdentityState:
        return self.states[-1]

    def find(self, digest: str) -> IdentityState | None:
        return next((s for s in self.states if state_hash(s) == digest), None)

    def contains_action(self, action_id: str) -> bool:
        return any(s.last_action_id == action_id for s in self.states)

    def appended(self, state: IdentityState, transition: SignedTransition) -> "History":
        return History(self.genesis, (*self.states, state), (*self.transitions, transition))
