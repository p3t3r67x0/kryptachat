"""Irreversible local tombstones. This does not remotely erase any data."""

from .models import Device, DeviceStatus


def revoked(device: Device) -> Device:
    return Device(
        device_id=device.device_id,
        auth_public_key=device.auth_public_key,
        session_public_key=device.session_public_key,
        permissions=(),
        status=DeviceStatus.REVOKED,
    )
