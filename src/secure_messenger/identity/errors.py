"""Typed, non-secret-bearing rejection reasons. Rejection never commits a state."""


class IdentityError(Exception):
    """Base class for expected protocol rejections."""


class EncodingError(IdentityError):
    pass


class UnsupportedVersion(EncodingError):
    pass


class SignatureError(IdentityError):
    pass


class UnknownSigner(SignatureError):
    pass


class AuthorizationError(IdentityError):
    pass


class TransitionError(IdentityError):
    pass


class AlreadyInitialized(TransitionError):
    pass


class ReplayError(TransitionError):
    pass


class VersionConflict(TransitionError):
    pass


class RollbackError(VersionConflict):
    pass


class ForkError(VersionConflict):
    """Authenticated competing branch observed; host must quarantine this identity."""


class FreshnessError(IdentityError):
    pass


class MissingFreshness(FreshnessError):
    pass


class ExpiredFreshness(FreshnessError):
    pass
