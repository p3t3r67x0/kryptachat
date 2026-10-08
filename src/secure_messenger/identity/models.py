"""Immutable, closed-schema models for the prototype's restricted JSON format."""

from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .errors import UnsupportedVersion

Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)]
Identifier = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$", min_length=32, max_length=32)]
Signature = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$", min_length=128, max_length=128)]
Counter = Annotated[int, Field(ge=0, le=2**53 - 1)]
Timestamp = Counter
PROTOCOL_VERSION = 1
POLICY_VERSION = 1
SUITE: Final = "KRYPTA-IDENTITY-PROTOTYPE-ED25519-SHA256-V1"


class FrozenModel(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
        revalidate_instances="always",
        hide_input_in_errors=True,
    )


class Versioned(FrozenModel):
    protocol_version: int = PROTOCOL_VERSION
    policy_version: int = POLICY_VERSION
    suite: Literal["KRYPTA-IDENTITY-PROTOTYPE-ED25519-SHA256-V1"] = SUITE

    @model_validator(mode="after")
    def supported(self) -> Self:
        if self.protocol_version != PROTOCOL_VERSION or self.policy_version != POLICY_VERSION:
            raise UnsupportedVersion("unsupported protocol or policy version")
        return self


class Permission(StrEnum):
    MESSAGING = "messaging"
    DEVICE_MANAGEMENT = "device_management"
    IDENTITY_RECOVERY = "identity_recovery"


Permissions = Annotated[tuple[Permission, ...], Field(max_length=3)]


def check_permissions(permissions: tuple[Permission, ...]) -> None:
    if permissions != tuple(sorted(set(permissions))):
        raise ValueError("permissions must be sorted and unique")


class DeviceStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class Device(FrozenModel):
    device_id: Identifier
    auth_public_key: Hex32
    session_public_key: Hex32
    permissions: Permissions
    status: DeviceStatus = DeviceStatus.ACTIVE

    @model_validator(mode="after")
    def valid_device(self) -> Self:
        check_permissions(self.permissions)
        if self.auth_public_key == self.session_public_key:
            raise ValueError("authentication and session keys must differ")
        if self.status == DeviceStatus.REVOKED and self.permissions:
            raise ValueError("revoked devices have no permissions")
        return self


class IdentityStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"


class IdentityState(Versioned):
    identity_id: Hex32
    root_public_key: Hex32
    generation: Counter
    previous_state_hash: Hex32 | None
    last_action_id: Identifier
    action_hash: Hex32
    devices: Annotated[tuple[Device, ...], Field(min_length=1, max_length=64)]
    status: IdentityStatus
    recovery_policy: Literal["NO_RECOVERY"] = "NO_RECOVERY"

    @model_validator(mode="after")
    def valid_state(self) -> Self:
        if (self.generation == 0) != (self.previous_state_hash is None):
            raise ValueError("only genesis has no previous state")
        ids = tuple(d.device_id for d in self.devices)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("devices must be sorted and unique")
        keys = [self.root_public_key]
        for device in self.devices:
            keys.extend((device.auth_public_key, device.session_public_key))
            if Permission.IDENTITY_RECOVERY in device.permissions:
                raise ValueError("NO_RECOVERY prohibits recovery permissions")
        if len(set(keys)) != len(keys):
            raise ValueError("key reuse is prohibited, including revoked devices")
        active = any(d.status == DeviceStatus.ACTIVE for d in self.devices)
        if active != (self.status == IdentityStatus.ACTIVE):
            raise ValueError("identity status contradicts device status")
        return self


class SignerKind(StrEnum):
    ROOT = "root"
    DEVICE = "device"


class Actor(FrozenModel):
    kind: SignerKind
    device_id: Identifier | None = None

    @model_validator(mode="after")
    def valid_actor(self) -> Self:
        if (self.kind == SignerKind.DEVICE) != (self.device_id is not None):
            raise ValueError("only device actors have a device id")
        return self


class ActionBase(Versioned):
    identity_id: Hex32
    action_id: Identifier
    generation: Counter
    previous_state_hash: Hex32
    actor: Actor
    issued_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if self.expires_at <= self.issued_at or self.expires_at - self.issued_at > 300:
            raise ValueError("authorization window must be positive and at most 300 seconds")
        return self


class AddDevice(ActionBase):
    kind: Literal["add_device"] = "add_device"
    device: Device


class ChangePermissions(ActionBase):
    kind: Literal["change_permissions"] = "change_permissions"
    target_device_id: Identifier
    permissions: Permissions

    @model_validator(mode="after")
    def valid_permissions(self) -> Self:
        check_permissions(self.permissions)
        return self


class RevokeDevice(ActionBase):
    kind: Literal["revoke_device"] = "revoke_device"
    target_device_id: Identifier


type Action = Annotated[AddDevice | ChangePermissions | RevokeDevice, Field(discriminator="kind")]


class SignedTransition(FrozenModel):
    action: Action
    author_signature: Signature
    possession_signature: Signature | None = None


class Genesis(Versioned):
    identity_id: Hex32
    root_public_key: Hex32
    action_id: Identifier
    device: Device


class SignedGenesis(FrozenModel):
    genesis: Genesis
    root_signature: Signature
    device_signature: Signature


class FreshnessChallenge(FrozenModel):
    identity_id: Hex32
    state_hash: Hex32
    generation: Counter
    nonce: Hex32


class ExternalConfirmation(FrozenModel):
    challenge: FreshnessChallenge
    valid_for_seconds: Annotated[int, Field(ge=1, le=300)]
