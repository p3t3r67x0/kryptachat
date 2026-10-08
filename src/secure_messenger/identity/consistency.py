"""Local consistency only. Hash chains do not prevent undisclosed global split views."""

from .errors import ForkError, ReplayError, RollbackError, VersionConflict
from .history import History
from .models import IdentityState, SignedTransition
from .signatures import state_hash


def require_next(history: History, parent: IdentityState, candidate: IdentityState) -> None:
    if state_hash(parent) != state_hash(history.current):
        # Caller has already verified both signature and authorization at this parent.
        if any(state_hash(candidate) == state_hash(s) for s in history.states):
            raise RollbackError("previously committed state cannot become current again")
        raise ForkError("authenticated alternative successor of a known historical state")


def require_unseen_action(history: History, transition: SignedTransition) -> None:
    if history.contains_action(transition.action.action_id):
        raise ReplayError("action id has already been committed")


def check_known_state(history: History, state: IdentityState) -> None:
    """A raw state claim can be compared but cannot authenticate a fork or advance history."""
    if state.identity_id != history.current.identity_id:
        raise VersionConflict("state belongs to another identity")
    digest = state_hash(state)
    if digest == state_hash(history.current):
        return
    if history.find(digest) is not None:
        raise RollbackError("known older state presented")
    raise VersionConflict("untrusted state claim; complete signed history is required")
