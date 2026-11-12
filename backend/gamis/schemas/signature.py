"""Signature metadata and the base class for signable objects.

Signed content of a signable object = every field except ``signature_metadata``.
Mutable runtime state never lives on a signable object (see ``MissionStatus``).
"""
from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import Field, StringConstraints

from gamis.schemas.common import Identifier, Principal, Sha256Hex, StrictModel, UtcDatetime


class SignedObjectType(StrEnum):
    """Domain-separation tag. Each signable object type has exactly one."""

    MISSION_GRANT = "gamis.mission_grant.v1"
    AGENT_ASSIGNMENT = "gamis.agent_assignment.v1"
    TOOL_RECEIPT = "gamis.tool_receipt.v1"
    TOOL_REGISTRY = "gamis.tool_registry.v1"
    EVIDENCE_BUNDLE = "gamis.evidence_bundle.v1"
    AUDIT_CHECKPOINT = "gamis.audit_checkpoint.v1"


class SignatureAlgorithm(StrEnum):
    ED25519 = "Ed25519"


Ed25519SignatureB64 = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_\-]{86}$")]


class ProtectedHeader(StrictModel):
    """Everything bound by the signature besides the payload itself (which is bound via its digest)."""

    signature_version: Annotated[int, Field(strict=True, ge=1, le=1)]
    algorithm: SignatureAlgorithm
    canonicalization: Literal["RFC8785"]
    object_type: SignedObjectType
    key_id: Identifier
    key_version: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]
    signer_identity: Principal
    signed_at: UtcDatetime
    payload_digest: Sha256Hex


class SignatureMetadata(ProtectedHeader):
    signature: Ed25519SignatureB64

    def protected_header(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"}, warnings=False)


class SignableModel(StrictModel):
    OBJECT_TYPE: ClassVar[SignedObjectType]
    UNSIGNED_FIELDS: ClassVar[frozenset[str]] = frozenset({"signature_metadata"})

    signature_metadata: SignatureMetadata | None = None

    @classmethod
    def signed_field_names(cls) -> tuple[str, ...]:
        return tuple(sorted(set(cls.model_fields) - cls.UNSIGNED_FIELDS))

    def signed_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude=set(self.UNSIGNED_FIELDS), warnings=False)

    @property
    def is_signed(self) -> bool:
        return self.signature_metadata is not None

    def with_signature(self, metadata: SignatureMetadata) -> Self:
        return self.model_copy(update={"signature_metadata": metadata})

    def without_signature(self) -> Self:
        return self.model_copy(update={"signature_metadata": None})
