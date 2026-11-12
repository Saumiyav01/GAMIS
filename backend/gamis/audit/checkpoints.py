"""Signed audit checkpoints (P2), signed with the P1 Ed25519 primitives under domain gamis.audit_checkpoint.v1.

A checkpoint commits to (ledger_id, genesis_hash, sequence_number, head_event_hash) at one moment. Kept
OUTSIDE the database (exported JSON, another system, paper), it is the anchor that detects whole-history
rewrites and truncation, which the hash chain alone cannot detect.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, ClassVar

from pydantic import Field

from gamis.schemas.common import Identifier, Sha256Hex, UtcDatetime
from gamis.schemas.signature import SignableModel, SignedObjectType
from gamis.security.keys import TrustStore
from gamis.security.signing import (DEFAULT_CLOCK_SKEW, MalformedSignedObjectError, SignatureVerificationError,
                                    VerifiedSignature, verify_object)


class AuditCheckpoint(SignableModel):
    OBJECT_TYPE: ClassVar[SignedObjectType] = SignedObjectType.AUDIT_CHECKPOINT

    checkpoint_id: Identifier
    ledger_id: Identifier
    genesis_hash: Sha256Hex
    sequence_number: Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]
    head_event_hash: Sha256Hex
    created_at: UtcDatetime
    signing_key_id: Identifier
    signing_key_version: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]


def verify_checkpoint_signature(checkpoint: AuditCheckpoint, trust_store: TrustStore, *, now: datetime,
                                max_clock_skew: timedelta = DEFAULT_CLOCK_SKEW) -> VerifiedSignature:
    """P1 signature verification plus binding of the signed key fields to the signature metadata."""
    verified = verify_object(checkpoint, trust_store, now=now, max_clock_skew=max_clock_skew)
    meta = verified.metadata
    if (meta.key_id, meta.key_version) != (checkpoint.signing_key_id, checkpoint.signing_key_version):
        raise MalformedSignedObjectError("signing_key_id/version do not match the signature metadata")
    return verified


def save_checkpoint(checkpoint: AuditCheckpoint, path: str | Path) -> None:
    """Export for external retention. Contains public data only."""
    Path(path).write_text(checkpoint.model_dump_json(indent=2) + "\n", encoding="utf-8")


def load_checkpoint(path: str | Path) -> AuditCheckpoint:
    return AuditCheckpoint.model_validate_json(Path(path).read_text(encoding="utf-8"))


__all__ = ["AuditCheckpoint", "SignatureVerificationError", "load_checkpoint", "save_checkpoint",
           "verify_checkpoint_signature"]
