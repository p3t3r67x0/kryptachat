"""Pure projection into a candidate state, never an in-place update."""

from pydantic import ValidationError

from .errors import TransitionError
from .models import (
    Action,
    AddDevice,
    ChangePermissions,
    Device,
    DeviceStatus,
    IdentityState,
    IdentityStatus,
)
from .revocation import revoked
from .signatures import action_hash, state_hash


def project(parent: IdentityState, action: Action) -> IdentityState:
    devices = list(parent.devices)
    if isinstance(action, AddDevice):
        devices.append(action.device)
    else:
        devices = [
            (
                Device(
                    device_id=d.device_id,
                    auth_public_key=d.auth_public_key,
                    session_public_key=d.session_public_key,
                    permissions=action.permissions,
                    status=d.status,
                )
                if isinstance(action, ChangePermissions)
                else revoked(d)
            )
            if d.device_id == action.target_device_id
            else d
            for d in devices
        ]
    active = any(d.status == DeviceStatus.ACTIVE for d in devices)
    try:
        return IdentityState(
            identity_id=parent.identity_id,
            root_public_key=parent.root_public_key,
            generation=action.generation,
            previous_state_hash=state_hash(parent),
            last_action_id=action.action_id,
            action_hash=action_hash(action),
            devices=tuple(sorted(devices, key=lambda d: d.device_id)),
            status=IdentityStatus.ACTIVE if active else IdentityStatus.RETIRED,
        )
    except ValidationError as exc:
        raise TransitionError("candidate violates state invariants") from exc
