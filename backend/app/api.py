from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status

from gamis.llm.provider import LLMConfiguration, LLMError, create_provider
from gamis.runtime import ROLE_TO_WORKER, WORKER_NAMES, LocalRuntime

from .schemas import (AgentListResponse, GatewayActivity, JobStatus, LedgerResponse, MissionAccepted,
                      MissionDetail, MissionListResponse, MissionSubmission, ModelCatalog, OperationResponse,
                      ReceiptListResponse, ReportResponse, TaskListResponse)


@dataclass
class MissionJob:
    mission_id: str
    provider: str
    status: str
    future: Future[Any] | None = None
    error: str | None = None


class APIContext:
    def __init__(self, runtime: LocalRuntime):
        self.runtime = runtime
        self.executor = ThreadPoolExecutor(max_workers=runtime.concurrency, thread_name_prefix="gamis-api-mission")
        self._job_slots = threading.BoundedSemaphore(runtime.concurrency * 2)
        self.jobs: dict[str, MissionJob] = {}
        self.lock = threading.RLock()
        self._closed = False

    def submit(self, grant: Any, objective: str, host: str, indicator: str,
               configuration: LLMConfiguration, provider: Any) -> MissionJob:
        if not self._job_slots.acquire(blocking=False):
            raise RuntimeError("mission submission queue is full; retry after active work finishes")
        job = MissionJob(grant.mission_id, configuration.provider, "QUEUED")

        def run() -> Any:
            try:
                with self.lock:
                    job.status = "RUNNING"
                report = self.runtime.execute_grant(
                    grant, objective, host=host, indicator=indicator,
                    configuration=configuration, provider_instance=provider)
                with self.lock:
                    job.status = report.status.upper()
                return report
            except Exception as exc:
                with self.lock:
                    job.status, job.error = "FAILED", f"{type(exc).__name__}: {exc}"[:1000]
                raise
            finally:
                self._job_slots.release()

        try:
            with self.lock:
                if self._closed:
                    raise RuntimeError("GAMIS API is shutting down")
                self.jobs[job.mission_id] = job
            job.future = self.executor.submit(run)
        except Exception:
            with self.lock:
                self.jobs.pop(job.mission_id, None)
            self._job_slots.release()
            raise
        return job

    def resume(self, mission_id: str, configuration: LLMConfiguration, provider: Any) -> MissionJob:
        if not self._job_slots.acquire(blocking=False):
            raise RuntimeError("mission submission queue is full; retry after active work finishes")
        job = MissionJob(mission_id, configuration.provider, "QUEUED")

        def run() -> Any:
            try:
                with self.lock:
                    job.status = "RUNNING"
                report = self.runtime.resume(mission_id, configuration=configuration, provider_instance=provider)
                with self.lock:
                    job.status = report.status.upper()
                return report
            except Exception as exc:
                with self.lock:
                    job.status, job.error = "FAILED", f"{type(exc).__name__}: {exc}"[:1000]
                raise
            finally:
                self._job_slots.release()

        try:
            with self.lock:
                if self._closed:
                    raise RuntimeError("GAMIS API is shutting down")
                existing = self.jobs.get(mission_id)
                if existing is not None and existing.status in {"QUEUED", "RUNNING"}:
                    raise RuntimeError("mission already has an active API job")
                self.jobs[mission_id] = job
            job.future = self.executor.submit(run)
        except Exception:
            with self.lock:
                self.jobs.pop(mission_id, None)
            self._job_slots.release()
            raise
        return job

    def close(self) -> None:
        with self.lock:
            if self._closed:
                return
            self._closed = True
        self.executor.shutdown(wait=True)
        self.runtime.close()


router = APIRouter()


def context(request: Request) -> APIContext:
    return request.app.state.gamis


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _mission(ctx: APIContext, mission_id: str) -> dict[str, Any]:
    try:
        return ctx.runtime.mission_store.mission(mission_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"code": "MISSION_NOT_FOUND", "message": str(exc)}) from exc


def _report_dict(mission: dict[str, Any]) -> dict[str, Any]:
    report = mission["report"]
    return {} if report is None else report.model_dump(mode="json")


def _budget_summary(ctx: APIContext, mission: dict[str, Any]) -> dict[str, Any]:
    grant = ctx.runtime.mission_store.grant(mission["mission_id"])
    gateway_state = ctx.runtime.gateway_store.checkpoint_state(mission["mission_id"])
    calls = gateway_state["tool_usage"]
    evidence_usage = gateway_state["evidence_usage"]
    return {
        **ctx.runtime.mission_store.budget(mission["mission_id"]),
        "tokens_limit": grant.global_resource_limits.max_tokens,
        "tool_calls_used": sum(row["calls"] for row in calls),
        "tool_calls_limit": grant.global_resource_limits.max_tool_calls,
        "evidence_bytes_used": sum(row["byte_count"] for row in evidence_usage),
        "evidence_bytes_limit": grant.global_resource_limits.max_evidence_bytes,
    }


def _mission_counts(ctx: APIContext, mission: dict[str, Any]) -> dict[str, Any]:
    tasks = ctx.runtime.mission_store.tasks(mission["mission_id"])
    receipts = [receipt for receipt in ctx.runtime.gateway_store.list_receipts()
                if receipt.mission_id == mission["mission_id"]]
    evidence_ids = ctx.runtime.evidence.list_evidence_ids(mission_id=mission["mission_id"])
    done = sum(task["status"] in {"COMPLETE", "COMPLETED", "SUCCEEDED"} for task in tasks)
    return {"task_count": len(tasks), "completed_tasks": done,
            "progress": 0.0 if not tasks else round(done / len(tasks), 4),
            "evidence_count": len(evidence_ids), "receipt_count": len(receipts)}


def _summary(ctx: APIContext, mission: dict[str, Any]) -> dict[str, Any]:
    report = _report_dict(mission)
    return {
        "mission_id": mission["mission_id"], "grant_id": mission["grant_id"],
        "objective": mission["objective"], "status": mission["status"],
        "created_at": mission["created_at"], "updated_at": mission["updated_at"],
        "provider": report.get("active_provider"), **_mission_counts(ctx, mission),
        "budgets": _budget_summary(ctx, mission),
    }


def _recovery(ctx: APIContext, mission: dict[str, Any]) -> dict[str, Any]:
    mission_id = mission["mission_id"]
    grant = ctx.runtime.mission_store.grant(mission_id)
    status_record = ctx.runtime.grant_status.get(grant.grant_id)
    cancelled, cancel_reason = ctx.runtime.mission_store.cancel_requested(mission_id)
    try:
        checkpoint = ctx.runtime.mission_store.checkpoint_summary(mission_id)
        checkpoints_verified = True
    except ValueError:
        checkpoint = {"count": None, "latest": None}
        checkpoints_verified = False
    grant_active = status_record is not None and status_record.state.value == "ACTIVE"
    latest = checkpoint["latest"]
    gateway_state = ctx.runtime.gateway_store.checkpoint_state(mission_id)
    with ctx.lock:
        job = ctx.jobs.get(mission_id)
        job_is_running = job is not None and job.status in {"QUEUED", "RUNNING"}
    eligible = (mission["status"] in {"RUNNING", "PARTIAL", "INTERRUPTED"}
                and grant_active and grant.expires_at > ctx.runtime.clock()
                and not cancelled and not job_is_running
                and checkpoints_verified and checkpoint["latest"] is not None)
    return {
        "mission_id": mission_id, "resume_supported": True, "resume_eligible": eligible,
        "cancel_requested": cancelled, "cancel_reason": cancel_reason,
        "grant_state": None if status_record is None else status_record.state.value,
        "grant_expires_at": grant.expires_at.isoformat(),
        "checkpoint_count": checkpoint["count"],
        "latest_checkpoint": None if latest is None else {
            "checkpoint_id": latest["checkpoint_id"], "sequence": latest["sequence"],
            "digest": latest["digest"], "created_at": latest["created_at"],
        },
        "checkpoints_verified": checkpoints_verified,
        "job_is_running": job_is_running,
        "uncertain_actions": [row for row in gateway_state["actions"] if row["state"] == "UNCERTAIN"],
        "reconciliations": gateway_state["reconciliations"],
    }


def _configuration(ctx: APIContext, payload: MissionSubmission) -> tuple[LLMConfiguration, Any]:
    base = ctx.runtime.configuration
    provider_name = payload.provider or base.provider
    if provider_name not in {"ollama", "mock"}:
        raise HTTPException(status_code=422, detail={"code": "PROVIDER_UNSUPPORTED",
                                                     "message": "provider must be 'ollama' or 'mock'"})
    from dataclasses import replace

    configuration = replace(
        base, provider=provider_name,
        supervisor_model=payload.supervisor_model or base.supervisor_model,
        research_model=payload.research_model if payload.research_model is not None else base.research_model,
        analysis_model=payload.analysis_model if payload.analysis_model is not None else base.analysis_model,
        verification_model=(payload.verification_model if payload.verification_model is not None
                            else base.verification_model))
    provider = create_provider(configuration)
    try:
        ctx.runtime.validate_provider(configuration, provider)
    except (LLMError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail={"code": "PROVIDER_UNAVAILABLE", "message": str(exc)}) from exc
    return configuration, provider


@router.get("/health")
def health(request: Request) -> dict[str, Any]:
    ctx = context(request)
    head = ctx.runtime.ledger.get_ledger_head()
    return {
        "status": "ok", "service": "GAMIS", "provider": ctx.runtime.configuration.provider,
        "provider_endpoint": ctx.runtime.configuration.endpoint,
        "ledger_id": head.ledger_id, "ledger_sequence": head.sequence_number,
        "timestamp": ctx.runtime.clock().isoformat(),
    }


@router.get("/api/models", response_model=ModelCatalog)
def models(request: Request, provider: str | None = Query(default=None, pattern="^(ollama|mock)$")):
    ctx = context(request)
    base = ctx.runtime.configuration
    config = base
    if provider is not None:
        from dataclasses import replace

        config = replace(base, provider=provider)
    selected_provider = create_provider(config)
    try:
        available = selected_provider.list_models()
    except LLMError as exc:
        raise HTTPException(status_code=503, detail={"code": "PROVIDER_UNAVAILABLE", "message": str(exc)}) from exc
    selected = {
        "supervisor": config.supervisor_model if config.provider == "ollama" else "gamis-deterministic-mock",
        "research": config.model_for_role("evidence-reader") if config.provider == "ollama" else
        "gamis-deterministic-mock",
        "analysis": config.model_for_role("intel-analyst") if config.provider == "ollama" else
        "gamis-deterministic-mock",
        "verification": config.model_for_role("responder") if config.provider == "ollama" else
        "gamis-deterministic-mock",
    }
    return ModelCatalog(provider=config.provider, endpoint=config.endpoint if config.provider == "ollama" else None,
                       available_models=list(available), configured_models=selected)


@router.get("/api/missions", response_model=MissionListResponse)
def list_missions(request: Request):
    ctx = context(request)
    return {"missions": [_summary(ctx, _mission(ctx, row["mission_id"]))
                         for row in ctx.runtime.mission_store.list_missions()]}


@router.post("/api/missions", response_model=MissionAccepted, status_code=status.HTTP_202_ACCEPTED)
def create_mission(payload: MissionSubmission, request: Request):
    ctx = context(request)
    configuration, provider = _configuration(ctx, payload)
    try:
        grant = ctx.runtime.create_grant(payload.objective, "web-01", "203.0.113.50")
        ctx.runtime.mission_store.create(grant, payload.objective, ctx.runtime.clock())
        ctx.runtime.mission_store.save_execution_config(grant.mission_id, asdict(configuration))
        job = ctx.submit(grant, payload.objective, "web-01", "203.0.113.50", configuration, provider)
    except (RuntimeError, ValueError) as exc:
        if "grant" in locals():
            ctx.runtime.mission_store.fail(grant.mission_id, ctx.runtime.clock(),
                                           f"mission submission failed: {type(exc).__name__}")
            status_record = ctx.runtime.grant_status.get(grant.grant_id)
            if status_record is not None and status_record.state.value == "ACTIVE":
                ctx.runtime.grant_status.suspend(grant.grant_id, ctx.runtime.clock(),
                                                  "mission submission could not be queued")
        raise HTTPException(status_code=503, detail={"code": "MISSION_SUBMISSION_FAILED",
                                                     "message": str(exc)}) from exc
    models_used = {
        "supervisor": configuration.supervisor_model if configuration.provider == "ollama" else
        "gamis-deterministic-mock",
        "research": configuration.model_for_role("evidence-reader") if configuration.provider == "ollama" else
        "gamis-deterministic-mock",
        "analysis": configuration.model_for_role("intel-analyst") if configuration.provider == "ollama" else
        "gamis-deterministic-mock",
        "verification": configuration.model_for_role("responder") if configuration.provider == "ollama" else
        "gamis-deterministic-mock",
    }
    return MissionAccepted(mission_id=grant.mission_id, grant_id=grant.grant_id, status=job.status,
                           provider=configuration.provider, models=models_used,
                           accepted_at=ctx.runtime.clock().isoformat())


@router.get("/api/missions/{mission_id}", response_model=MissionDetail)
def get_mission(mission_id: str, request: Request):
    ctx = context(request)
    mission = _mission(ctx, mission_id)
    counts = _mission_counts(ctx, mission)
    report = _report_dict(mission)
    recovery = _recovery(ctx, mission)
    return MissionDetail(
        mission_id=mission["mission_id"], grant_id=mission["grant_id"], objective=mission["objective"],
        status=mission["status"], failure=mission["failure"], created_at=mission["created_at"],
        updated_at=mission["updated_at"], provider=report.get("active_provider"),
        models=None if not report else {
            "supervisor": report.get("supervisor_model"), "workers": report.get("worker_models"),
        }, progress=counts["progress"], task_count=counts["task_count"],
        completed_tasks=counts["completed_tasks"], evidence_count=counts["evidence_count"],
        receipt_count=counts["receipt_count"], budgets=_budget_summary(ctx, mission), recovery=recovery,
        report_ready=bool(report.get("evidence_intelligence")))


@router.get("/api/missions/{mission_id}/job", response_model=JobStatus)
def get_job(mission_id: str, request: Request):
    ctx = context(request)
    _mission(ctx, mission_id)
    with ctx.lock:
        job = ctx.jobs.get(mission_id)
        if job is None:
            mission = _mission(ctx, mission_id)
            return JobStatus(mission_id=mission_id, status=mission["status"], provider="unknown")
        return JobStatus(mission_id=mission_id, status=job.status, provider=job.provider, error=job.error)


@router.get("/api/missions/{mission_id}/report", response_model=ReportResponse)
def get_report(mission_id: str, request: Request):
    ctx = context(request)
    mission = _mission(ctx, mission_id)
    report = _report_dict(mission)
    if not report or report.get("evidence_intelligence") is None:
        raise HTTPException(status_code=409, detail={"code": "REPORT_NOT_READY",
                                                    "message": f"mission is {mission['status']}; final evidence "
                                                               "intelligence report is not ready"})
    return {"mission_id": mission_id, "report": report}


@router.get("/api/missions/{mission_id}/tasks", response_model=TaskListResponse)
def get_tasks(mission_id: str, request: Request):
    ctx = context(request)
    _mission(ctx, mission_id)
    items = []
    for row in ctx.runtime.mission_store.tasks(mission_id):
        assignment = row["assignment"]
        report = row["report"]
        items.append({
            "task_id": row["task_id"], "worker_role": row["worker_role"], "status": row["status"],
            "error": row["error"], "assignment": None if assignment is None else {
                "assignment_id": assignment.assignment_id, "worker_id": assignment.worker_id,
                "expires_at": assignment.expires_at.isoformat(), "scope": _jsonable(assignment.authorized_scope),
                "tools": list(assignment.permitted_tools),
                "operations": _jsonable(assignment.permitted_operations),
            },
            "report": None if report is None else _jsonable(report),
        })
    return {"mission_id": mission_id, "tasks": items}


@router.post("/api/missions/{mission_id}/resume", response_model=OperationResponse,
             status_code=status.HTTP_202_ACCEPTED)
def resume_mission(mission_id: str, request: Request):
    ctx = context(request)
    mission = _mission(ctx, mission_id)
    recovery = _recovery(ctx, mission)
    if not recovery["resume_eligible"]:
        raise HTTPException(status_code=409, detail={"code": "RESUME_NOT_ALLOWED",
                                                     "message": "mission does not meet the runtime's resume checks"})
    persisted = ctx.runtime.mission_store.execution_config(mission_id)
    configuration = ctx.runtime.configuration if persisted is None else LLMConfiguration(**persisted)
    provider = create_provider(configuration)
    try:
        ctx.runtime.validate_provider(configuration, provider)
    except (LLMError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail={"code": "RESUME_PROVIDER_UNAVAILABLE",
                                                     "message": str(exc)}) from exc
    try:
        job = ctx.resume(mission_id, configuration, provider)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail={"code": "RESUME_NOT_ALLOWED", "message": str(exc)}) from exc
    return OperationResponse(mission_id=mission_id, status=job.status, message="Resume queued for runtime validation.")


@router.post("/api/missions/{mission_id}/cancel", response_model=OperationResponse)
def cancel_mission(mission_id: str, request: Request):
    ctx = context(request)
    _mission(ctx, mission_id)
    try:
        ctx.runtime.cancel(mission_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail={"code": "CANCEL_NOT_ALLOWED", "message": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail={"code": "CANCEL_NOT_ALLOWED", "message": str(exc)}) from exc
    return OperationResponse(mission_id=mission_id, status="CANCEL_REQUESTED",
                             message="Cancellation recorded; in-flight work will stop at its next safe boundary.")


@router.get("/api/missions/{mission_id}/recovery")
def mission_recovery(mission_id: str, request: Request):
    ctx = context(request)
    return _recovery(ctx, _mission(ctx, mission_id))


@router.get("/api/agents", response_model=AgentListResponse)
def list_agents(request: Request):
    ctx = context(request)
    latest: dict[str, tuple[str, str, str]] = {}
    for mission_row in ctx.runtime.mission_store.list_missions():
        mission_id = mission_row["mission_id"]
        for task in ctx.runtime.mission_store.tasks(mission_id):
            assignment = task["assignment"]
            if assignment is not None:
                previous = latest.get(assignment.worker_id)
                updated_at = task.get("updated_at") or mission_row["updated_at"]
                if previous is None or updated_at >= previous[0]:
                    latest[assignment.worker_id] = (updated_at, mission_id, task["status"])
    agents = []
    for role, worker_id in ROLE_TO_WORKER.items():
        identity = ctx.runtime.worker_directory.get(worker_id)
        if identity is None:
            continue
        latest_task = latest.get(worker_id)
        agents.append({
            "worker_id": identity.worker_id, "name": WORKER_NAMES[role], "role": role,
            "enabled": identity.enabled, "status": "IDLE" if latest_task is None else latest_task[2],
            "mission_id": None if latest_task is None else latest_task[1],
            "registered_at": identity.registered_at.isoformat(),
        })
    return {"agents": agents}


@router.get("/api/evidence")
def list_evidence(request: Request, mission_id: str | None = None,
                  limit: int = Query(default=200, ge=1, le=1000)):
    ctx = context(request)
    missions = ([mission_id] if mission_id is not None else
                [row["mission_id"] for row in ctx.runtime.mission_store.list_missions()])
    records = []
    for current_mission in missions:
        if mission_id is not None:
            _mission(ctx, current_mission)
        for evidence_id in ctx.runtime.evidence.list_evidence_ids(mission_id=current_mission):
            if len(records) >= limit:
                return {"evidence": records}
            item = ctx.runtime.evidence.get_evidence(evidence_id)
            view = None
            from gamis.evidence.store import EvidenceNotFoundError

            try:
                view = ctx.runtime.evidence.get_sanitized_view(evidence_id).model_dump(mode="json")
            except EvidenceNotFoundError:
                pass
            records.append({
                "mission_id": current_mission, "item": item.model_dump(mode="json"),
                "sanitized_view": view,
                "links": [list(link) for link in ctx.runtime.evidence.evidence_links(evidence_id)],
                "claim_relations": [list(relation) for relation in
                                    ctx.runtime.evidence.claims_for_evidence(evidence_id)],
                "integrity": {"status": "VERIFIED"},
            })
    return {"evidence": records}


@router.get("/api/missions/{mission_id}/evidence")
def mission_evidence(mission_id: str, request: Request, limit: int = Query(default=200, ge=1, le=1000)):
    return list_evidence(request, mission_id=mission_id, limit=limit)


@router.get("/api/missions/{mission_id}/receipts", response_model=ReceiptListResponse)
def mission_receipts(mission_id: str, request: Request):
    ctx = context(request)
    _mission(ctx, mission_id)
    receipts = [receipt.model_dump(mode="json") for receipt in ctx.runtime.gateway_store.list_receipts()
                if receipt.mission_id == mission_id]
    return {"mission_id": mission_id, "receipts": receipts}


@router.get("/api/missions/{mission_id}/gateway", response_model=GatewayActivity)
def mission_gateway(mission_id: str, request: Request):
    ctx = context(request)
    _mission(ctx, mission_id)
    events = ctx.runtime.ledger.get_events(mission_id=mission_id, start=1, limit=10000)
    by_type = {
        event_type: [_jsonable(event) for event in events if event.event_type.value == event_type]
        for event_type in ("AUTHORIZATION_DECISION", "TOOL_REQUEST_RECEIVED", "TOOL_EXECUTION_COMPLETED")
    }
    state = ctx.runtime.gateway_store.checkpoint_state(mission_id)
    receipts = [receipt.model_dump(mode="json") for receipt in ctx.runtime.gateway_store.list_receipts()
                if receipt.mission_id == mission_id]
    return GatewayActivity(
        mission_id=mission_id, decisions=by_type["AUTHORIZATION_DECISION"],
        requests=by_type["TOOL_REQUEST_RECEIVED"], executions=by_type["TOOL_EXECUTION_COMPLETED"],
        receipts=receipts, uncertain_actions=[row for row in state["actions"] if row["state"] == "UNCERTAIN"])


@router.get("/api/ledger", response_model=LedgerResponse)
def list_ledger(request: Request, start: int = Query(default=1, ge=1),
                limit: int = Query(default=100, ge=1, le=1000), mission_id: str | None = None):
    ledger = context(request).runtime.ledger
    events = ledger.get_events(start=start, mission_id=mission_id, limit=limit)
    head = ledger.get_ledger_head()
    return LedgerResponse(ledger_id=head.ledger_id, start=start, limit=limit,
                          events=[_jsonable(event) for event in events])


@router.get("/api/ledger/verify")
def verify_ledger(request: Request):
    ctx = context(request)
    return ctx.runtime.ledger.get_verification_report(
        trust_store=ctx.runtime.keys.trust_store, now=ctx.runtime.clock()).to_dict()


@router.get("/api/approvals")
def approvals_unavailable():
    raise HTTPException(status_code=501, detail={"code": "APPROVALS_UNAVAILABLE",
                                                 "message": "This runtime has no persistent human approval queue."})


@router.post("/api/approvals/{approval_id}/decision")
def approval_decision_unavailable(approval_id: str):
    raise HTTPException(status_code=501, detail={"code": "APPROVALS_UNAVAILABLE",
                                                 "message": f"No approval decision service is configured for "
                                                            f"{approval_id}."})


@router.post("/api/gateway/requests")
def gateway_request_unavailable():
    raise HTTPException(status_code=501, detail={
        "code": "DIRECT_GATEWAY_REQUEST_UNAVAILABLE",
        "message": "Dashboard clients cannot submit tool requests. Workers must use signed assignments and "
                   "worker credentials through the runtime-owned Gateway.",
    })


@router.get("/api/evaluation/scenarios")
def evaluation_scenarios():
    from gamis.evaluation.harness import build_scenarios

    return {"scenarios": [{"scenario_id": row.id, "scenario_type": row.kind,
                           "description": row.request, "runnable": False}
                          for row in build_scenarios()]}
