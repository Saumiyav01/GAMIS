"""Ed25519 signing and verification of GAMIS objects with domain separation.

What is signed, exactly:

    payload_digest = SHA-256( "GAMIS-DIGEST-V1" 0x00 <object_type> 0x00 JCS(signed_payload) )
    signing_input  = "GAMIS-SIGNATURE-V1" 0x00 <object_type> 0x00 JCS(protected_header)

``signed_payload`` is every field of the object except ``signature_metadata``; ``protected_header`` is
every field of SignatureMetadata except ``signature`` and includes ``payload_digest``. The object type is
bound three times (digest prefix, signature prefix, header), and the verifier takes the expected type from
the Python class being verified - never from the untrusted metadata.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from gamis.schemas.signature import (ProtectedHeader, SignableModel, SignatureAlgorithm, SignatureMetadata,
                                     SignedObjectType)
from gamis.security.canonical import canonicalize
from gamis.security.digest import domain_digest
from gamis.security.keys import (REQUIRED_SIGNER_TYPE, KeyStatus, Signer, TrustedKey, TrustStore, b64url_decode,
                                 b64url_encode, verify_ed25519)

SIGNATURE_PREFIX = b"GAMIS-SIGNATURE-V1\x00"
DEFAULT_CLOCK_SKEW = timedelta(seconds=30)


class SignatureVerificationError(Exception):
    """Base class: the object must be treated as unauthenticated."""


class MissingSignatureError(SignatureVerificationError): ...
class DomainMismatchError(SignatureVerificationError): ...
class UnknownKeyError(SignatureVerificationError): ...
class KeyVersionMismatchError(SignatureVerificationError): ...
class KeyNotAuthorizedError(SignatureVerificationError): ...
class KeyRevokedError(SignatureVerificationError): ...
class KeyValidityError(SignatureVerificationError): ...
class SignerMismatchError(SignatureVerificationError): ...
class PayloadTamperedError(SignatureVerificationError): ...
class InvalidSignatureError(SignatureVerificationError): ...
class MalformedSignedObjectError(SignatureVerificationError): ...


@dataclass(frozen=True)
class VerifiedSignature:
    object_type: SignedObjectType
    key: TrustedKey
    metadata: SignatureMetadata


def payload_digest(object_type: SignedObjectType, payload: Mapping[str, Any]) -> str:
    return domain_digest(object_type.value, payload)


def signing_input(object_type: SignedObjectType, protected_header: Mapping[str, Any]) -> bytes:
    return SIGNATURE_PREFIX + object_type.value.encode("ascii") + b"\x00" + canonicalize(protected_header)


def sign_object(obj: SignableModel, signer: Signer, *, now: datetime) -> SignatureMetadata:
    """Produce signature metadata for ``obj``. Does not attach it; use ``obj.with_signature``."""
    object_type = type(obj).OBJECT_TYPE
    required = REQUIRED_SIGNER_TYPE[object_type]
    if signer.principal.principal_type is not required:
        raise KeyNotAuthorizedError(f"{signer.principal.principal_type.value} may not sign {object_type.value}")
    obj = obj.revalidate()
    header = ProtectedHeader(signature_version=1, algorithm=SignatureAlgorithm.ED25519, canonicalization="RFC8785",
                             object_type=object_type, key_id=signer.key_id, key_version=signer.key_version,
                             signer_identity=signer.principal, signed_at=now,
                             payload_digest=payload_digest(object_type, obj.signed_payload()))
    signature = signer.sign(signing_input(object_type, header.model_dump(mode="json")))
    return SignatureMetadata(**{name: getattr(header, name) for name in ProtectedHeader.model_fields},
                             signature=b64url_encode(signature))


def verify_object(obj: SignableModel, trust_store: TrustStore, *, now: datetime,
                  max_clock_skew: timedelta = DEFAULT_CLOCK_SKEW) -> VerifiedSignature:
    """Verify ``obj`` against ``trust_store``. Raises a SignatureVerificationError subclass on any failure."""
    if not isinstance(obj, SignableModel):
        raise MalformedSignedObjectError("not a signable object")
    object_type = type(obj).OBJECT_TYPE
    meta = obj.signature_metadata
    if meta is None:
        raise MissingSignatureError(f"{object_type.value} is not signed")
    try:  # defend against objects assembled without validation
        meta = SignatureMetadata.model_validate(meta.model_dump(mode="json", warnings=False))
        payload = obj.revalidate().signed_payload()
    except Exception as exc:
        raise MalformedSignedObjectError(f"signed object failed validation: {exc}") from exc
    if meta.object_type is not object_type:
        raise DomainMismatchError(f"signature is for {meta.object_type.value}, not {object_type.value}")
    key = trust_store.get(meta.key_id)
    if key is None:
        raise UnknownKeyError(f"key {meta.key_id} is not trusted")
    if key.key_version != meta.key_version:
        raise KeyVersionMismatchError(f"key {meta.key_id} is version {key.key_version}, "
                                      f"metadata claims {meta.key_version}")
    if key.algorithm is not meta.algorithm:
        raise KeyNotAuthorizedError("algorithm mismatch")
    if object_type not in key.allowed_object_types:
        raise KeyNotAuthorizedError(f"key {key.key_name} is not authorized to sign {object_type.value}")
    if key.principal.principal_type is not REQUIRED_SIGNER_TYPE[object_type]:
        raise KeyNotAuthorizedError(f"{key.principal.principal_type.value} may not sign {object_type.value}")
    if key.principal != meta.signer_identity:
        raise SignerMismatchError("signer_identity does not match the key owner")
    if key.status is KeyStatus.REVOKED:
        raise KeyRevokedError(f"key {key.key_id} is revoked")
    if meta.signed_at < key.not_before:
        raise KeyValidityError("signature predates the key's validity")
    if key.not_after is not None and meta.signed_at > key.not_after:
        raise KeyValidityError("signature was made after the key was retired")
    if meta.signed_at > now + max_clock_skew:
        raise KeyValidityError("signature timestamp is in the future")
    if not hmac.compare_digest(payload_digest(object_type, payload), meta.payload_digest):
        raise PayloadTamperedError(f"{object_type.value} content does not match the signed digest")
    try:
        signature = b64url_decode(meta.signature)
    except ValueError as exc:
        raise InvalidSignatureError(str(exc)) from exc
    if not verify_ed25519(key.public_key_raw(), signature, signing_input(object_type, meta.protected_header())):
        raise InvalidSignatureError("Ed25519 signature verification failed")
    return VerifiedSignature(object_type=object_type, key=key, metadata=meta)
