"""Typed outputs for P6 evidence intelligence."""
from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import Field

from gamis.schemas.common import Confidence, Identifier, LongText, ShortText, StrictModel
from gamis.schemas.evidence import ProvenanceRecord


class VerificationStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNVERIFIED = "UNVERIFIED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ContradictionType(StrEnum):
    DIRECT_CONTRADICTION = "DIRECT_CONTRADICTION"
    TEMPORAL_INCONSISTENCY = "TEMPORAL_INCONSISTENCY"
    SOURCE_DISAGREEMENT = "SOURCE_DISAGREEMENT"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"


class EvidenceCorrelation(StrictModel):
    correlation_id: Identifier
    content_digest: str
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=2, max_length=4096)]
    source_record_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    worker_ids: Annotated[tuple[Identifier, ...], Field(max_length=256)]
    receipt_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    timestamps: Annotated[tuple[str, ...], Field(max_length=4096)]
    explanation: ShortText


class EvidenceContradiction(StrictModel):
    contradiction_id: Identifier
    contradiction_type: ContradictionType
    description: LongText
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=4096)]
    claim_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)] = ()
    preserved_as_unresolved: bool = True


class ConfidenceAssessment(StrictModel):
    evidence_strength: Confidence
    model_confidence: Confidence
    relevance: Confidence
    reliability: Confidence
    independent_corroboration: Confidence
    contradiction_factor: Confidence
    completeness: Confidence
    rationale: LongText


class VerifiedClaim(StrictModel):
    claim_id: Identifier
    description: LongText
    supporting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)]
    contradicting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)]
    verification_status: VerificationStatus
    confidence: Confidence
    confidence_assessment: ConfidenceAssessment
    provenance: Annotated[tuple[ProvenanceRecord, ...], Field(max_length=4096)]
    worker_ids: Annotated[tuple[Identifier, ...], Field(max_length=256)]
    explanation: LongText


class EvidenceIntelligenceReport(StrictModel):
    evidence_count: Annotated[int, Field(strict=True, ge=0)]
    receipt_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    evidence_correlations: Annotated[tuple[EvidenceCorrelation, ...], Field(max_length=4096)]
    contradictions: Annotated[tuple[EvidenceContradiction, ...], Field(max_length=4096)]
    verified_claims: Annotated[tuple[VerifiedClaim, ...], Field(max_length=4096)]
    evidence_gaps: Annotated[tuple[ShortText, ...], Field(max_length=1024)]
    supporting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    contradicting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    limitations: Annotated[tuple[ShortText, ...], Field(max_length=1024)]
