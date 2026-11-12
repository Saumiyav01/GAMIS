"""Key interfaces, Ed25519 software signer, trust store and rotation.

Boundary: everything that needs a private key depends only on the ``Signer`` protocol. The software
implementation here is for development and tests. A hardware-backed signer (HSM / TPM / KMS) is a future
implementation of the same protocol and is NOT provided in P1.
"""
from __future__ import annotations

import base64
import hashlib
import threading
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Protocol, Self, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, StringConstraints, model_validator

from gamis.schemas.common import Identifier, Principal, PrincipalType, StrictModel, UtcDatetime, require_unique
from gamis.schemas.signature import SignatureAlgorithm, SignedObjectType

# Which kind of principal may sign which object type. Enforced when a key is trusted and on verification.
REQUIRED_SIGNER_TYPE: dict[SignedObjectType, PrincipalType] = {
    SignedObjectType.MISSION_GRANT: PrincipalType.MISSION_ISSUER,
    SignedObjectType.AGENT_ASSIGNMENT: PrincipalType.AUTHORITY_SERVICE,
    SignedObjectType.TOOL_RECEIPT: PrincipalType.TOOL_GATEWAY,
    SignedObjectType.TOOL_REGISTRY: PrincipalType.REGISTRY_ADMIN,
    SignedObjectType.EVIDENCE_BUNDLE: PrincipalType.WORKER,
    SignedObjectType.AUDIT_CHECKPOINT: PrincipalType.AUDIT_SERVICE,
}


class KeyManagementError(Exception):
    pass


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url_encode(data) != text:
        raise ValueError("non-canonical base64url encoding")
    return data


def compute_key_id(public_key_raw: bytes) -> str:
    """Key identifier derived from the public key, so an id can never point at a different key."""
    return "gk-" + hashlib.sha256(b"GAMIS-KEY-ID-V1\x00" + public_key_raw).hexdigest()[:32]


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@runtime_checkable
class Signer(Protocol):
    """The only capability signing code may depend on. Never exposes private key material."""

    @property
    def key_id(self) -> str: ...
    @property
    def key_name(self) -> str: ...
    @property
    def key_version(self) -> int: ...
    @property
    def principal(self) -> Principal: ...
    def public_key_raw(self) -> bytes: ...
    def sign(self, message: bytes) -> bytes: ...


class Ed25519Signer:
    """Software Ed25519 signer (development / test). Holds the key in process memory."""

    __slots__ = ("__private", "_public_raw", "_key_name", "_key_version", "_principal")

    def __init__(self, private_key: Ed25519PrivateKey, *, key_name: str, key_version: int, principal: Principal):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise KeyManagementError("an Ed25519 private key is required")
        self.__private = private_key
        self._public_raw = _raw_public(private_key.public_key())
        self._key_name, self._key_version, self._principal = key_name, key_version, principal

    key_id = property(lambda self: compute_key_id(self._public_raw))
    key_name = property(lambda self: self._key_name)
    key_version = property(lambda self: self._key_version)
    principal = property(lambda self: self._principal)

    def public_key_raw(self) -> bytes:
        return self._public_raw

    def sign(self, message: bytes) -> bytes:
        return self.__private.sign(message)

    def __repr__(self) -> str:
        return f"Ed25519Signer(key_id={self.key_id!r}, key_name={self._key_name!r}, version={self._key_version})"

    def __reduce__(self):  # never pickle key material
        raise KeyManagementError("signers cannot be serialized")


def verify_ed25519(public_key_raw: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


class KeyStatus(StrEnum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"   # rotated out: verifies only signatures made before not_after
    REVOKED = "REVOKED"   # compromised: verifies nothing


class TrustedKey(StrictModel):
    """Public record of a verification key. Contains no secret material."""

    key_id: Identifier
    key_name: Identifier
    key_version: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]
    algorithm: SignatureAlgorithm
    public_key: Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_\-]{43}$")]
    principal: Principal
    allowed_object_types: Annotated[tuple[SignedObjectType, ...], Field(min_length=1)]
    status: KeyStatus
    not_before: UtcDatetime
    not_after: UtcDatetime | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.allowed_object_types, "allowed object type")
        if compute_key_id(self.public_key_raw()) != self.key_id:
            raise ValueError("key_id does not match the public key")
        for object_type in self.allowed_object_types:
            required = REQUIRED_SIGNER_TYPE[object_type]
            if self.principal.principal_type is not required:
                raise ValueError(f"a {self.principal.principal_type.value} principal may not sign "
                                 f"{object_type.value}; {required.value} is required")
        if self.status is KeyStatus.RETIRED and self.not_after is None:
            raise ValueError("a RETIRED key requires not_after")
        if self.not_after is not None and self.not_after < self.not_before:
            raise ValueError("not_after must not be before not_before")
        return self

    def public_key_raw(self) -> bytes:
        return b64url_decode(self.public_key)


class TrustStore:
    """Set of verification keys a verifier accepts. Holds public material only."""

    def __init__(self, keys: tuple[TrustedKey, ...] = ()):
        self._keys: dict[str, TrustedKey] = {}
        self._lock = threading.Lock()
        for key in keys:
            self.add(key)

    def add(self, key: TrustedKey) -> None:
        key = key.revalidate()
        with self._lock:
            if key.key_id in self._keys:
                raise KeyManagementError(f"key {key.key_id} is already trusted")
            if any(k.key_name == key.key_name and k.key_version == key.key_version for k in self._keys.values()):
                raise KeyManagementError(f"{key.key_name} version {key.key_version} already exists")
            self._keys[key.key_id] = key

    def get(self, key_id: str) -> TrustedKey | None:
        return self._keys.get(key_id)

    def versions(self, key_name: str) -> tuple[TrustedKey, ...]:
        return tuple(sorted((k for k in self._keys.values() if k.key_name == key_name),
                            key=lambda k: k.key_version))

    def all(self) -> tuple[TrustedKey, ...]:
        return tuple(sorted(self._keys.values(), key=lambda k: (k.key_name, k.key_version)))

    def _replace(self, key_id: str, **changes: object) -> TrustedKey:
        with self._lock:
            current = self._keys.get(key_id)
            if current is None:
                raise KeyManagementError(f"unknown key {key_id}")
            updated = TrustedKey.model_validate({**current.model_dump(mode="json"), **changes})
            self._keys[key_id] = updated
            return updated

    def retire(self, key_id: str, at: datetime) -> TrustedKey:
        current = self.get(key_id)
        if current is not None and current.status is KeyStatus.REVOKED:
            raise KeyManagementError("a revoked key cannot be retired")
        return self._replace(key_id, status=KeyStatus.RETIRED, not_after=at)

    def revoke(self, key_id: str) -> TrustedKey:
        return self._replace(key_id, status=KeyStatus.REVOKED)


def trusted_key_for(signer: Signer, allowed_object_types: tuple[SignedObjectType, ...],
                    not_before: datetime) -> TrustedKey:
    return TrustedKey(key_id=signer.key_id, key_name=signer.key_name, key_version=signer.key_version,
                      algorithm=SignatureAlgorithm.ED25519, public_key=b64url_encode(signer.public_key_raw()),
                      principal=signer.principal, allowed_object_types=allowed_object_types,
                      status=KeyStatus.ACTIVE, not_before=not_before)


@runtime_checkable
class KeyRotator(Protocol):
    """Rotation interface every key backend (software now, hardware later) must provide."""

    def current(self, key_name: str) -> Signer: ...
    def rotate(self, key_name: str, now: datetime) -> Signer: ...


class SoftwareKeyManager:
    """In-memory Ed25519 key manager with versioning and rotation. Development / test only."""

    def __init__(self, trust_store: TrustStore | None = None):
        self.trust_store = trust_store if trust_store is not None else TrustStore()
        self._signers: dict[str, Ed25519Signer] = {}
        self._lock = threading.Lock()

    def create_key(self, key_name: str, principal: Principal, allowed_object_types: tuple[SignedObjectType, ...],
                   now: datetime, *, private_key: Ed25519PrivateKey | None = None) -> Ed25519Signer:
        with self._lock:
            if key_name in self._signers:
                raise KeyManagementError(f"key {key_name} already exists; use rotate()")
            return self._install(key_name, 1, principal, allowed_object_types, now, private_key)

    def current(self, key_name: str) -> Ed25519Signer:
        try:
            return self._signers[key_name]
        except KeyError:
            raise KeyManagementError(f"no key named {key_name}") from None

    def rotate(self, key_name: str, now: datetime, *, private_key: Ed25519PrivateKey | None = None) -> Ed25519Signer:
        """Create version N+1 and retire version N. Old signatures stay verifiable; new ones need N+1."""
        with self._lock:
            old = self.current(key_name)
            record = self.trust_store.get(old.key_id)
            new = self._install(key_name, old.key_version + 1, old.principal, record.allowed_object_types, now,
                                private_key)
            self._record_changed(self.trust_store.retire(old.key_id, now))
            return new

    def _install(self, key_name, version, principal, allowed, now, private_key) -> Ed25519Signer:
        private_key = private_key or Ed25519PrivateKey.generate()
        signer = Ed25519Signer(private_key, key_name=key_name, key_version=version, principal=principal)
        record = trusted_key_for(signer, allowed, now)
        self.trust_store.add(record)
        self._signers[key_name] = signer
        self._key_created(record, private_key)
        return signer

    # persistence hooks for subclasses
    def _key_created(self, record: TrustedKey, private_key: Ed25519PrivateKey) -> None:
        pass

    def _record_changed(self, record: TrustedKey) -> None:
        pass
