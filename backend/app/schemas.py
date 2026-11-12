from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MissionSubmission(APIModel):
    objective: Annotated[str, Field(min_length=8, max_length=4000)]
    provider: Literal["ollama", "mock"] | None = None
    supervisor_model: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    research_model: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    analysis_model: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    verification_model: Annotated[str, Field(min_length=1, max_length=128)] | None = None


class MissionAccepted(APIModel):
    mission_id: str
    grant_id: str
    status: str
    provider: str
    models: dict[str, str]
    accepted_at: str


class MissionSummary(APIModel):
    mission_id: str
    grant_id: str
    objective: str
    status: str
    created_at: str
    updated_at: str
    provider: str | None = None
    task_count: int
    completed_tasks: int
    progress: float
    evidence_count: int
    receipt_count: int
    budgets: dict[str, Any]


class MissionListResponse(APIModel):
    missions: list[MissionSummary]


class MissionDetail(APIModel):
    mission_id: str
    grant_id: str
    objective: str
    status: str
    failure: str | None = None
    created_at: str
    updated_at: str
    provider: str | None = None
    models: dict[str, Any] | None = None
    progress: float
    task_count: int
    completed_tasks: int
    evidence_count: int
    receipt_count: int
    budgets: dict[str, Any]
    recovery: dict[str, Any]
    report_ready: bool


class TaskListResponse(APIModel):
    mission_id: str
    tasks: list[dict[str, Any]]


class ModelCatalog(APIModel):
    provider: str
    endpoint: str | None = None
    available_models: list[str]
    configured_models: dict[str, str]


class AgentListResponse(APIModel):
    agents: list[dict[str, Any]]


class EvidenceListResponse(APIModel):
    evidence: list[dict[str, Any]]


class ReceiptListResponse(APIModel):
    mission_id: str
    receipts: list[dict[str, Any]]


class LedgerResponse(APIModel):
    ledger_id: str
    start: int
    limit: int
    events: list[dict[str, Any]]


class GatewayActivity(APIModel):
    mission_id: str
    decisions: list[dict[str, Any]]
    requests: list[dict[str, Any]]
    executions: list[dict[str, Any]]
    receipts: list[dict[str, Any]]
    uncertain_actions: list[dict[str, Any]]


class ErrorBody(APIModel):
    code: str
    message: str


class ErrorResponse(APIModel):
    error: ErrorBody


class OperationResponse(APIModel):
    mission_id: str
    status: str
    message: str


class JobStatus(APIModel):
    mission_id: str
    status: str
    provider: str
    error: str | None = None


class ReportResponse(APIModel):
    mission_id: str
    report: dict[str, Any]
