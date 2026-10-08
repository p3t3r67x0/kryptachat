"""Pure role authorization. A valid signature does not imply permission."""

from .errors import AuthorizationError
from .models import (
    AddDevice,
    ChangePermissions,
    Device,
    DeviceStatus,
    IdentityState,
    IdentityStatus,
    Permission,
    SignedTransition,
    SignerKind,
)


def active_device(state: IdentityState, device_id: str | None) -> Device:
    device = next((d for d in state.devices if d.device_id == device_id), None)
    if device is None or device.status != DeviceStatus.ACTIVE:
        raise AuthorizationError("device is unknown or revoked")
    return device


def require_manager(state: IdentityState, transition: SignedTransition) -> None:
    actor = transition.action.actor
    if actor.kind != SignerKind.DEVICE:
        raise AuthorizationError("this operation requires an active device manager")
    device = active_device(state, actor.device_id)
    if Permission.DEVICE_MANAGEMENT not in device.permissions:
        raise AuthorizationError("device_management permission is required")


def authorize(transition: SignedTransition, parent: IdentityState) -> Device | None:
    """Return the device whose fresh possession proof is required, if any."""
    if parent.status != IdentityStatus.ACTIVE:
        raise AuthorizationError("retired identity is terminal; NO_RECOVERY")
    action = transition.action
    if isinstance(action, AddDevice):
        require_manager(parent, transition)
        if action.device.status != DeviceStatus.ACTIVE:
            raise AuthorizationError("new device must be active")
        if action.device.permissions != (Permission.MESSAGING,):
            raise AuthorizationError("new devices may receive only messaging permission")
        if any(d.device_id == action.device.device_id for d in parent.devices):
            raise AuthorizationError("device ids cannot be reused, including revoked ids")
        return action.device
    target = active_device(parent, action.target_device_id)
    if isinstance(action, ChangePermissions):
        if Permission.IDENTITY_RECOVERY in action.permissions:
            raise AuthorizationError("identity_recovery is disabled by NO_RECOVERY")
        if action.permissions == target.permissions:
            raise AuthorizationError("no-op permission change")
        manager_change = (Permission.DEVICE_MANAGEMENT in action.permissions) != (
            Permission.DEVICE_MANAGEMENT in target.permissions
        )
        if manager_change:
            if action.actor.kind != SignerKind.ROOT:
                raise AuthorizationError("only the root may change the manager role")
            return target
        require_manager(parent, transition)
        return None
    require_manager(parent, transition)
    return None
