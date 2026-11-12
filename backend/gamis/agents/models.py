"""Strict structured inputs and outputs used at the Supervisor/Worker LLM boundary."""
from __future__ import annotations

from typing import Annotated

from pydantic import Field, model_validator

from gamis.agents.intelligence_models import EvidenceIntelligenceReport
from gamis.schemas.common import Confidence, Identifier, LongText, ShortText, StrictModel, require_unique


class MissionTask(StrictModel):
    task_id: Identifier
    worker_role: Identifier
    objective: ShortText
    success_criteria: Annotated[tuple[ShortText, ...], Field(min_length=1, max_length=16)]
    depends_on: Annotated[tuple[Identifier, ...], Field(max_length=32)] = ()


class MissionPlan(StrictModel):
    tasks: Annotated[tuple[MissionTask, ...], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def validate_dependencies(self) -> "MissionPlan":
        ids = tuple(task.task_id for task in self.tasks)
        require_unique(ids, "task")
        known: set[str] = set()
        for task in self.tasks:
            require_unique(task.depends_on, "dependency")
            if task.task_id in task.depends_on or not set(task.depends_on) <= known:
                raise ValueError(f"{task.task_id}: dependencies must refer to earlier tasks")
            known.add(task.task_id)
        return self


class LLMClaim(StrictModel):
    statement: LongText
    confidence: Confidence
    supporting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)] = ()
    contradicting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)] = ()
    rationale: LongText = "Evidence-linked assessment."

    @model_validator(mode="after")
    def validate_evidence_references(self) -> "LLMClaim":
        require_unique(self.supporting_evidence_ids, "supporting evidence reference")
        require_unique(self.contradicting_evidence_ids, "contradicting evidence reference")
        if set(self.supporting_evidence_ids) & set(self.contradicting_evidence_ids):
            raise ValueError("evidence cannot both support and contradict one claim")
        return self


class LLMGeneratedClaim(StrictModel):
    statement: LongText
    confidence: Confidence
    supporting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)]
    contradicting_evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=1024)]
    rationale: LongText

    @model_validator(mode="after")
    def validate_evidence_references(self) -> "LLMGeneratedClaim":
        require_unique(self.supporting_evidence_ids, "supporting evidence reference")
        require_unique(self.contradicting_evidence_ids, "contradicting evidence reference")
        if not self.supporting_evidence_ids and not self.contradicting_evidence_ids:
            raise ValueError("generated claims must cite supporting or contradicting evidence")
        if set(self.supporting_evidence_ids) & set(self.contradicting_evidence_ids):
            raise ValueError("evidence cannot both support and contradict one claim")
        return self


class LLMWorkerOutput(StrictModel):
    summary: LongText
    claims: Annotated[tuple[LLMGeneratedClaim, ...], Field(min_length=1, max_length=32)]
    limitations: Annotated[tuple[ShortText, ...], Field(max_length=32)] = ()
    missing_information: Annotated[tuple[ShortText, ...], Field(max_length=32)] = ()


class LLMFinalAssessment(StrictModel):
    executive_summary: LongText
    conclusion: LongText
    claims: Annotated[tuple[LLMGeneratedClaim, ...], Field(min_length=1, max_length=32)]
    missing_information: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()
    limitations: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()
    confidence: Confidence


class WorkerReport(StrictModel):
    task_id: Identifier
    worker_id: Identifier
    worker_role: Identifier
    evidence_bundle_id: Identifier
    summary: LongText
    claims: Annotated[tuple[LLMClaim, ...], Field(min_length=1, max_length=32)]
    evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=2048)]
    source_record_ids: Annotated[tuple[Identifier, ...], Field(max_length=2048)]
    receipt_ids: Annotated[tuple[Identifier, ...], Field(max_length=256)]
    limitations: Annotated[tuple[ShortText, ...], Field(max_length=64)]
    confidence: Confidence
    missing_information: Annotated[tuple[ShortText, ...], Field(max_length=32)] = ()


class InvestigationReport(StrictModel):
    mission_id: Identifier
    grant_id: Identifier
    objective: LongText
    status: str
    conclusion: LongText
    worker_reports: Annotated[tuple[WorkerReport, ...], Field(max_length=16)]
    evidence_count: Annotated[int, Field(strict=True, ge=0)]
    receipt_count: Annotated[int, Field(strict=True, ge=0)]
    limitations: Annotated[tuple[ShortText, ...], Field(max_length=128)]
    confidence: Confidence
    executive_summary: LongText | None = None
    claims: Annotated[tuple[LLMClaim, ...], Field(max_length=32)] = ()
    missing_information: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()
    receipt_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)] = ()
    active_provider: Identifier | None = None
    supervisor_model: Identifier | None = None
    worker_model: Identifier | None = None
    worker_models: dict[str, Identifier] | None = None
    evidence_intelligence: EvidenceIntelligenceReport | None = None
