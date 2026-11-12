"""Evidence models: provenance, evidence items, claims and the worker's EvidenceBundle."""
from __future__ import annotations

from typing import Annotated, ClassVar, Self

from pydantic import Field, model_validator

from gamis.schemas.common import (CompletionStatus, Confidence, Count, ExecutionStatus, Flag, FrozenJson, Identifier,
                                  LongText, Sha256Hex, ShortText, SourceType, StrictModel, UtcDatetime,
                                  require_unique)
from gamis.schemas.signature import SignableModel, SignedObjectType
from gamis.security.digest import canonical_digest


class ProvenanceRecord(StrictModel):
    provenance_id: Identifier
    origin: ShortText
    source_type: SourceType
    collected_by: Identifier
    collected_at: UtcDatetime
    method: ShortText
    receipt_id: Identifier | None = None
    derived_from: Annotated[tuple[Identifier, ...], Field(max_length=256)] = ()
    transformation: ShortText | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.derived_from, "derived_from reference")
        if self.source_type is SourceType.TOOL_RESULT and self.receipt_id is None:
            raise ValueError("TOOL_RESULT provenance requires receipt_id")
        if self.source_type is SourceType.DERIVED and not self.derived_from:
            raise ValueError("DERIVED provenance requires derived_from")
        return self


class EvidenceItem(StrictModel):
    evidence_id: Identifier
    source: ShortText
    source_type: SourceType
    source_record_id: Identifier | None = None
    content: FrozenJson = None
    content_reference: ShortText | None = None  # protected reference when content is not inlined
    integrity_digest: Sha256Hex
    timestamp: UtcDatetime
    provenance: ProvenanceRecord
    receipt_id: Identifier | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.content is None and self.content_reference is None:
            raise ValueError("evidence requires content or content_reference")
        if self.content is not None and canonical_digest(self.content) != self.integrity_digest:
            raise ValueError("integrity_digest does not match the canonical digest of content")
        if self.provenance.source_type is not self.source_type:
            raise ValueError("provenance.source_type must match source_type")
        if self.source_type is SourceType.TOOL_RESULT and self.receipt_id is None:
            raise ValueError("TOOL_RESULT evidence requires receipt_id")
        if self.receipt_id != self.provenance.receipt_id:
            raise ValueError("receipt_id must match provenance.receipt_id")
        return self


class Claim(StrictModel):
    claim_id: Identifier
    statement: LongText
    supporting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)]
    contradicting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)]
    confidence: Confidence
    rationale: LongText
    disputed: Flag = False

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.supporting_evidence_ids, "supporting evidence reference")
        require_unique(self.contradicting_evidence_ids, "contradicting evidence reference")
        if set(self.supporting_evidence_ids) & set(self.contradicting_evidence_ids):
            raise ValueError("an evidence item cannot both support and contradict the same claim")
        return self


class ToolCallRecord(StrictModel):
    sequence_number: Count
    request_id: Identifier
    receipt_id: Identifier | None
    tool_id: Identifier
    operation_id: Identifier
    execution_status: ExecutionStatus
    requested_at: UtcDatetime


class EvidenceBundle(SignableModel):
    OBJECT_TYPE: ClassVar[SignedObjectType] = SignedObjectType.EVIDENCE_BUNDLE

    evidence_bundle_id: Identifier
    mission_id: Identifier
    assignment_id: Identifier
    worker_id: Identifier
    claims: Annotated[tuple[Claim, ...], Field(max_length=1024)]
    evidence_items: Annotated[tuple[EvidenceItem, ...], Field(max_length=4096)]
    supporting_evidence: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    contradicting_evidence: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    assumptions: Annotated[tuple[ShortText, ...], Field(max_length=256)]
    confidence: Confidence
    provenance: ProvenanceRecord
    referenced_tool_receipts: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    tool_call_history: Annotated[tuple[ToolCallRecord, ...], Field(max_length=4096)]
    completion_status: CompletionStatus
    limitations: Annotated[tuple[ShortText, ...], Field(max_length=256)]
    generated_at: UtcDatetime

    @model_validator(mode="after")
    def _check(self) -> Self:
        require_unique(self.claims, "claim", key=lambda c: c.claim_id)
        require_unique(self.evidence_items, "evidence item", key=lambda e: e.evidence_id)
        require_unique(self.supporting_evidence, "supporting evidence reference")
        require_unique(self.contradicting_evidence, "contradicting evidence reference")
        require_unique(self.referenced_tool_receipts, "tool receipt reference")
        require_unique(self.tool_call_history, "tool call request", key=lambda r: r.request_id)
        evidence_ids = {e.evidence_id for e in self.evidence_items}
        receipts = set(self.referenced_tool_receipts)
        for claim in self.claims:
            unknown = (set(claim.supporting_evidence_ids) | set(claim.contradicting_evidence_ids)) - evidence_ids
            if unknown:
                raise ValueError(f"claim {claim.claim_id} references unknown evidence: {sorted(unknown)}")
            if not set(claim.supporting_evidence_ids) <= set(self.supporting_evidence):
                raise ValueError(f"claim {claim.claim_id} supporting evidence missing from supporting_evidence")
            if not set(claim.contradicting_evidence_ids) <= set(self.contradicting_evidence):
                raise ValueError(f"claim {claim.claim_id} contradicting evidence missing from contradicting_evidence")
            if self.completion_status is CompletionStatus.COMPLETE and not claim.supporting_evidence_ids:
                raise ValueError(f"claim {claim.claim_id} has no supporting evidence in a complete bundle")
        unknown = (set(self.supporting_evidence) | set(self.contradicting_evidence)) - evidence_ids
        if unknown:
            raise ValueError(f"bundle references unknown evidence: {sorted(unknown)}")
        for item in self.evidence_items:
            if item.receipt_id is not None and item.receipt_id not in receipts:
                raise ValueError(f"evidence {item.evidence_id} cites a receipt not in referenced_tool_receipts")
        history_receipts = {r.receipt_id for r in self.tool_call_history if r.receipt_id is not None}
        if history_receipts != receipts:
            raise ValueError("referenced_tool_receipts must equal the receipts in tool_call_history")
        sequence = [r.sequence_number for r in self.tool_call_history]
        if sequence != sorted(set(sequence)):
            raise ValueError("tool_call_history sequence numbers must be strictly increasing")
        if self.provenance.source_type is not SourceType.WORKER_ANALYSIS:
            raise ValueError("bundle provenance must have source_type WORKER_ANALYSIS")
        if self.provenance.collected_by != self.worker_id:
            raise ValueError("bundle provenance.collected_by must be the bundle's worker")
        return self
