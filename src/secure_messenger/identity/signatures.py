"""Native Ed25519 signatures; distinct domains for every signature and hash purpose."""

import hashlib
import secrets
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from nacl.bindings import crypto_core_ed25519_is_valid_point

from .codec import canonical, checked
from .errors import SignatureError, UnknownSigner
from .models import (
    Action,
    AddDevice,
    Device,
    Genesis,
    IdentityState,
    Permission,
    SignedGenesis,
    SignedTransition,
    SignerKind,
)

PREFIX = b"KRYPTA/IDENTITY/PROTOTYPE/V1/"
AUTHOR_DOMAIN = PREFIX + b"TRANSITION-AUTHOR\x00"
ADD_POSSESSION_DOMAIN = PREFIX + b"ADD-DEVICE-POSSESSION\x00"
MANAGER_POSSESSION_DOMAIN = PREFIX + b"EXISTING-DEVICE-POSSESSION\x00"
GENESIS_ROOT_DOMAIN = PREFIX + b"GENESIS-ROOT\x00"
GENESIS_DEVICE_DOMAIN = PREFIX + b"GENESIS-DEVICE\x00"


def identity_id(root_public_key: str) -> str:
    return hashlib.sha256(PREFIX + b"IDENTITY-ID\x00" + bytes.fromhex(root_public_key)).hexdigest()


def state_hash(state: IdentityState) -> str:
    return hashlib.sha256(PREFIX + b"STATE-HASH\x00" + canonical(state)).hexdigest()


def action_hash(action: Action | Genesis) -> str:
    return hashlib.sha256(PREFIX + b"ACTION-HASH\x00" + canonical(action)).hexdigest()


@dataclass(frozen=True, repr=False)
class SigningKey:
    _native: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> str:
        return self._native.public_key().public_bytes_raw().hex()

    def sign(self, domain: bytes, payload: bytes) -> str:
        return self._native.sign(domain + payload).hex()


@dataclass(frozen=True, repr=False)
class DeviceKeys:
    device: Device
    auth: SigningKey = field(repr=False)
    _session: X25519PrivateKey = field(repr=False)

    @classmethod
    def generate(
        cls,
        permissions: tuple[Permission, ...] = (Permission.MESSAGING,),
    ) -> "DeviceKeys":
        auth = SigningKey.generate()
        session = X25519PrivateKey.generate()
        return cls(
            Device(
                device_id=secrets.token_hex(16),
                auth_public_key=auth.public_key,
                session_public_key=session.public_key().public_bytes_raw().hex(),
                permissions=permissions,
            ),
            auth,
            session,
        )


def verify(public_key: str, signature: str, domain: bytes, payload: bytes) -> None:
    try:
        encoded_key = bytes.fromhex(public_key)
        if not crypto_core_ed25519_is_valid_point(encoded_key):
            raise SignatureError("noncanonical or invalid Ed25519 public point")
        Ed25519PublicKey.from_public_bytes(encoded_key).verify(
            bytes.fromhex(signature),
            domain + payload,
        )
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("signature verification failed") from exc


def sign_transition(
    action: Action,
    author: SigningKey,
    possession: SigningKey | None = None,
) -> SignedTransition:
    action = checked(action)
    payload = canonical(action)
    domain = ADD_POSSESSION_DOMAIN if isinstance(action, AddDevice) else MANAGER_POSSESSION_DOMAIN
    return SignedTransition(
        action=action,
        author_signature=author.sign(AUTHOR_DOMAIN, payload),
        possession_signature=None if possession is None else possession.sign(domain, payload),
    )


def verify_author(transition: SignedTransition, parent: IdentityState) -> None:
    """Only cryptographic verification and pinned key lookup; no role authorization."""
    actor = transition.action.actor
    if actor.kind == SignerKind.ROOT:
        public_key = parent.root_public_key
    else:
        found = next((d for d in parent.devices if d.device_id == actor.device_id), None)
        if found is None:
            raise UnknownSigner("author device is not known in the referenced state")
        public_key = found.auth_public_key
    verify(public_key, transition.author_signature, AUTHOR_DOMAIN, canonical(transition.action))


def verify_genesis(signed: SignedGenesis) -> None:
    genesis = checked(signed).genesis
    if genesis.identity_id != identity_id(genesis.root_public_key):
        raise SignatureError("genesis identity is not bound to the root")
    payload = canonical(genesis)
    verify(genesis.root_public_key, signed.root_signature, GENESIS_ROOT_DOMAIN, payload)
    verify(genesis.device.auth_public_key, signed.device_signature, GENESIS_DEVICE_DOMAIN, payload)
