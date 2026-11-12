"""Local synthetic-only GAMIS runtime composition."""
from __future__ import annotations

import os
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from gamis.agents.orchestrator import MissionOrchestrator, MissionStore
from gamis.agents.intelligence import EvidenceIntelligence
from gamis.agents.supervisor import Supervisor
from gamis.agents.workers import WorkerAgent
from gamis.audit.events import AuditEventType
from gamis.audit.ledger import SQLiteAuditLedger
from gamis.audit.recorder import AuditRecorder
from gamis.authority.directory import InMemoryGrantStatusStore, InMemoryIssuanceLedger, InMemoryWorkerDirectory
from gamis.authority.grants import issue_mission_grant
from gamis.authority.service import AuthorityService
from gamis.authority.verification import AssignmentVerifier
from gamis.evaluation.loader import load_all
from gamis.evidence.store import EvidenceStore
from gamis.gateway import GatewayStore, GrantStatusStore, SecureToolGateway
from gamis.llm.provider import LLMConfiguration, LLMError, LLMProvider, create_provider
from gamis.schemas.assignment import WorkerIdentity
from gamis.schemas.common import Principal, PrincipalType
from gamis.schemas.mission import MissionGrant, ScopeEntry
from gamis.schemas.policy import PolicyVersion
from gamis.schemas.signature import SignedObjectType
from gamis.security.dev_keys import DevKeyStore
from gamis.security.keys import KeyManagementError
from gamis.security.signing import SignatureVerificationError, verify_object
from gamis.security.trust_io import save_trust_store
from gamis.tools.mock_tools import MockCaseAction, MockIntelLookup, MockLogSearch
from gamis.tools.sample_registry import build_sample_registry

DEFAULT_OBJECTIVE = (
    "Investigate suspicious network events and determine whether the available evidence supports a security incident."
)
POLICY = PolicyVersion(policy_id="gamis-sample-policy", version="1.0.0")
ROLE_TO_WORKER = {"evidence-reader": "worker-reader-1", "intel-analyst": "worker-intel-1",
                  "responder": "worker-responder-1"}
WORKER_NAMES = {"evidence-reader": "Research Worker", "intel-analyst": "Analysis Worker",
                "responder": "Verification Worker"}


class LocalRuntime:
    """Owns the trust world and adapters; neither workers nor Supervisor receive adapter handles."""

    def __init__(self, state_dir: Path, *, configuration: LLMConfiguration | None = None,
                 provider: LLMProvider | None = None, concurrency: int | None = None):
        self.state_dir = state_dir.expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.clock = lambda: datetime.now(timezone.utc)
        self.configuration = configuration or LLMConfiguration.from_environment()
        self.provider = provider or create_provider(self.configuration)
        audit_path = self.state_dir / "audit.db"
        self.ledger = (SQLiteAuditLedger.open(audit_path, clock=self.clock) if audit_path.exists() else
                       SQLiteAuditLedger.create(audit_path, ledger_id="gamis-local-audit",
                                                actor=Principal(principal_id="audit-local",
                                                                principal_type=PrincipalType.AUDIT_SERVICE),
                                                clock=self.clock))
        self.recorder = AuditRecorder(self.ledger)
        key_dir = Path(os.getenv("GAMIS_DEV_KEY_DIR", str(self.state_dir / "dev-keys")))
        environment = os.getenv("GAMIS_ENV", "development")
        self.keys = DevKeyStore(key_dir, environ={"GAMIS_ENV": environment, "GAMIS_DEV_KEY_DIR": str(key_dir)})
        start = self.clock()
        self.issuer_signer = self._signer(
            "mission-issuer", Principal(principal_id="issuer-local", principal_type=PrincipalType.MISSION_ISSUER),
            SignedObjectType.MISSION_GRANT, start)
        self.authority_signer = self._signer(
            "authority", Principal(principal_id="authority-local", principal_type=PrincipalType.AUTHORITY_SERVICE),
            SignedObjectType.AGENT_ASSIGNMENT, start)
        self.gateway_signer = self._signer(
            "gateway", Principal(principal_id="gateway-local", principal_type=PrincipalType.TOOL_GATEWAY),
            SignedObjectType.TOOL_RECEIPT, start)
        registry_signer = self._signer(
            "registry", Principal(principal_id="registry-local", principal_type=PrincipalType.REGISTRY_ADMIN),
            SignedObjectType.TOOL_REGISTRY, start)
        self.worker_signers = {}
        self.worker_directory = InMemoryWorkerDirectory(tuple(
            WorkerIdentity(worker_id=worker_id, worker_role=role, display_name=WORKER_NAMES[role], enabled=True,
                           registered_at=start)
            for role, worker_id in ROLE_TO_WORKER.items()))
        for role, worker_id in ROLE_TO_WORKER.items():
            self.worker_signers[role] = self._signer(
                f"worker-{role}", Principal(principal_id=worker_id, principal_type=PrincipalType.WORKER),
                SignedObjectType.EVIDENCE_BUNDLE, start)
        self.audit_signer = self._signer(
            "audit-checkpoint", Principal(principal_id="audit-local", principal_type=PrincipalType.AUDIT_SERVICE),
            SignedObjectType.AUDIT_CHECKPOINT, start)
        save_trust_store(self.keys.trust_store, self.state_dir / "trust.json")

        self.registry = build_sample_registry(POLICY, Principal(principal_id="registry-local",
                                                               principal_type=PrincipalType.REGISTRY_ADMIN),
                                              recorder=self.recorder)
        self.registry.seal(registry_signer, start)
        self.memory_status = InMemoryGrantStatusStore()
        self.authority = AuthorityService(
            signer=self.authority_signer, trust_store=self.keys.trust_store, registry=self.registry.read_only(),
            workers=self.worker_directory, grant_status=self.memory_status, active_policy=POLICY,
            clock=self.clock, ledger=InMemoryIssuanceLedger(), recorder=self.recorder)
        self.verifier = AssignmentVerifier(self.keys.trust_store, self.clock)

        self.gateway_store = GatewayStore(self.state_dir / "gateway.db", recorder=self.recorder,
                                          actor=self.gateway_signer.principal)
        self.grant_status = GrantStatusStore(self.state_dir / "gateway.db", recorder=self.recorder,
                                             actor=self.issuer_signer.principal)
        self.evidence = EvidenceStore.open(self.state_dir / "evidence.db", self.state_dir / "evidence-objects",
                                           clock=self.clock, audit=self.ledger, trust_store=self.keys.trust_store)
        seeds = load_all()
        self.log_adapter = MockLogSearch(seeds["logs"])
        self.intel_adapter = MockIntelLookup(seeds["intel"])
        self.action_adapter = MockCaseAction(enabled=False)
        self.gateway = SecureToolGateway(
            verifier=self.verifier, trust_store=self.keys.trust_store, registry=self.registry.read_only(),
            grant_status=self.grant_status, signer=self.gateway_signer, clock=self.clock,
            workers=self.worker_directory,
            adapters={("log_search", "search"): self.log_adapter, ("intel_lookup", "lookup"): self.intel_adapter,
                      ("case_action", "execute"): self.action_adapter},
            worker_public_keys={ROLE_TO_WORKER[role]: signer.public_key_raw()
                                for role, signer in self.worker_signers.items()},
            store=self.gateway_store, scope_validator=self._scope_check, recorder=self.recorder,
            evidence_store=self.evidence)
        self.mission_store = MissionStore(self.state_dir / "missions.db")
        self.concurrency = concurrency if concurrency is not None else int(os.getenv("GAMIS_WORKER_CONCURRENCY", "3"))
        if self.concurrency < 1 or self.concurrency > 32:
            raise ValueError("GAMIS_WORKER_CONCURRENCY must be between 1 and 32")
        self._closed = False

    @staticmethod
    def _scope_check(request, assignment, grant) -> bool:
        scope = {item.resource_type: item.selector for item in assignment.authorized_scope}
        if scope.get("dataset") != "synthetic-seeds":
            return False
        if request.tool_id == "log_search":
            return request.arguments.get("host") == scope.get("host")
        if request.tool_id == "intel_lookup":
            return request.arguments.get("indicator") == scope.get("indicator")
        return False

    def create_grant(self, objective: str, host: str, indicator: str) -> MissionGrant:
        now = self.clock()
        mission_id = f"MIS-{uuid.uuid4().hex[:12]}"
        grant_id = f"GRANT-{uuid.uuid4().hex[:12]}"
        raw = {
            "mission_id": mission_id, "grant_id": grant_id, "mission_objective": objective,
            "authorized_scope": [
                ScopeEntry(resource_type="dataset", selector="synthetic-seeds").model_dump(mode="json"),
                ScopeEntry(resource_type="host", selector=host).model_dump(mode="json"),
                ScopeEntry(resource_type="indicator", selector=indicator).model_dump(mode="json")],
            "permitted_roles": tuple(ROLE_TO_WORKER), "permitted_tools": ("log_search", "intel_lookup"),
            "permitted_operations": ({"tool_id": "log_search", "operation_id": "search", "permission_class": "READ"},
                                     {"tool_id": "intel_lookup", "operation_id": "lookup",
                                      "permission_class": "READ"}),
            "permitted_permission_classes": ("READ",), "maximum_worker_count": 3,
            "global_resource_limits": {"max_tool_calls": 100, "max_wall_clock_seconds": 3600,
                                       "max_tokens": 100_000, "max_cost_units": 1000,
                                       "max_evidence_bytes": 1_000_000},
            "approval_requirements": (), "evidence_requirements": [{
                "requirement_id": "tool-receipts", "description": "All tool-derived evidence links a signed receipt",
                "minimum_items": 1, "require_tool_receipts": True, "accepted_source_types": ["TOOL_RESULT"],
                "applies_to_roles": ()}],
            "policy_version": POLICY.model_dump(mode="json"), "issued_at": now,
            "expires_at": now + timedelta(days=30), "issuer_identity": self.issuer_signer.principal,
            "revocation_reference": f"REV-{uuid.uuid4().hex[:12]}",
        }
        grant = MissionGrant.model_validate(raw)
        grant = issue_mission_grant(grant, self.issuer_signer, now=now, recorder=self.recorder)
        self.memory_status.activate(grant, now)
        self.grant_status.activate(grant, now)
        return grant

    def submit(self, objective: str = DEFAULT_OBJECTIVE, *, host: str = "web-01",
               indicator: str = "203.0.113.50") -> Any:
        self.validate_provider(self.configuration, self.provider)
        grant = self.create_grant(objective, host, indicator)
        return self.execute_grant(grant, objective, host=host, indicator=indicator,
                                  configuration=self.configuration, provider_instance=self.provider)

    @staticmethod
    def validate_provider(configuration: LLMConfiguration, provider: LLMProvider) -> tuple[str, ...]:
        if configuration.provider != "ollama":
            return ()
        try:
            available_models = set(provider.list_models())
        except LLMError as exc:
            raise RuntimeError(
                f"Cannot reach Ollama at {configuration.endpoint}. Start Ollama or run "
                f"`ollama serve`, then retry. Details: {exc}") from exc
        models = {configuration.supervisor_model,
                  *(configuration.model_for_role(role) for role in ROLE_TO_WORKER)}
        missing = sorted(model for model in models if model not in available_models)
        if missing:
            raise RuntimeError(
                f"Ollama model(s) {', '.join(repr(model) for model in missing)} are not installed. "
                f"Run `ollama pull {missing[0]}` or configure GAMIS_SUPERVISOR_MODEL / GAMIS_WORKER_MODEL.")
        return tuple(sorted(available_models))

    def execute_grant(self, grant: MissionGrant, objective: str, *, host: str = "web-01",
                      indicator: str = "203.0.113.50", configuration: LLMConfiguration | None = None,
                      provider_instance: LLMProvider | None = None) -> Any:
        configuration = configuration or self.configuration
        provider_instance = provider_instance or (
            self.provider if configuration == self.configuration else create_provider(configuration))
        try:
            self.validate_provider(configuration, provider_instance)
            report = self._orchestrator(grant, configuration=configuration,
                                        provider_instance=provider_instance).run(
                                            grant, objective, host=host, indicator=indicator)
            report = self._add_evidence_intelligence(report)
        except Exception as exc:
            self.grant_status.suspend(grant.grant_id, self.clock(),
                                      f"mission execution failed: {type(exc).__name__}"[:250])
            raise
        if report.status == "complete":
            self.grant_status.complete(grant.grant_id, self.clock())
        return report

    def resume(self, mission_id: str, *, configuration: LLMConfiguration | None = None,
               provider_instance: LLMProvider | None = None) -> Any:
        configuration = configuration or self.configuration
        provider_instance = provider_instance or (
            self.provider if configuration == self.configuration else create_provider(configuration))
        mission = self.mission_store.mission(mission_id)
        grant = self.mission_store.grant(mission_id)
        status = self.grant_status.get(grant.grant_id)
        if status is None or status.state.value != "ACTIVE":
            raise RuntimeError("mission cannot resume: its durable grant is not ACTIVE")
        if mission["status"] not in {"RUNNING", "PARTIAL", "INTERRUPTED"}:
            raise RuntimeError(f"mission cannot resume from status {mission['status']}")
        if grant.expires_at <= self.clock():
            raise RuntimeError("mission cannot resume: the signed grant has expired")
        try:
            verify_object(grant, self.keys.trust_store, now=self.clock())
        except SignatureVerificationError as exc:
            raise RuntimeError(f"mission cannot resume: signed grant verification failed: {exc}") from exc
        self.validate_provider(configuration, provider_instance)
        self.memory_status.activate(grant, self.clock())
        checkpoint = self.mission_store.verify_checkpoints(mission_id)
        if checkpoint is None:
            raise RuntimeError("mission cannot resume: no integrity-verified checkpoint exists")
        self._verify_checkpoint_audit(mission_id, checkpoint)
        assignments = tuple(task["assignment"] for task in self.mission_store.tasks(mission_id)
                            if task["assignment"] is not None)
        self.authority._restore_assignments(grant, assignments)
        self._verify_checkpoint_progress(mission_id, checkpoint)
        try:
            report = self._orchestrator(grant, configuration=configuration,
                                        provider_instance=provider_instance).resume(
                                            mission_id, host="web-01", indicator="203.0.113.50")
            report = self._add_evidence_intelligence(report)
        except Exception as exc:
            self.grant_status.suspend(grant.grant_id, self.clock(),
                                      f"mission recovery failed: {type(exc).__name__}"[:250])
            raise
        if report.status == "complete":
            self.grant_status.complete(grant.grant_id, self.clock())
        return report

    def cancel(self, mission_id: str, reason: str = "Operator requested cancellation.") -> None:
        self.mission_store.mission(mission_id)
        grant = self.mission_store.grant(mission_id)
        requested, _ = self.mission_store.cancel_requested(mission_id)
        if requested:
            return
        status = self.grant_status.get(grant.grant_id)
        if status is None or status.state.value != "ACTIVE":
            raise RuntimeError("mission cannot be cancelled because its durable grant is not ACTIVE")
        self.grant_status.suspend(grant.grant_id, self.clock(), reason[:250])
        self.mission_store.request_cancel(mission_id, reason)
        self._checkpoint_callback(grant, self.mission_store.create_checkpoint(
            mission_id, self.clock(), external_state=self._checkpoint_context(grant)))
        self.recorder.recovery_event(
            AuditEventType.MISSION_CANCELLED, Principal(principal_id="supervisor-local",
                                                        principal_type=PrincipalType.SUPERVISOR),
            mission_id=mission_id, grant_id=grant.grant_id, correlation_id=mission_id,
            state="CANCEL_REQUESTED", reason=reason)

    def _orchestrator(self, grant: MissionGrant, *, configuration: LLMConfiguration | None = None,
                      provider_instance: LLMProvider | None = None) -> MissionOrchestrator:
        configuration = configuration or self.configuration
        provider_instance = provider_instance or self.provider
        supervisor_model = (configuration.supervisor_model if configuration.provider == "ollama"
                            else "gamis-deterministic-mock")
        worker_models = {role: configuration.model_for_role(role)
                         if configuration.provider == "ollama" else "gamis-deterministic-mock"
                         for role in ROLE_TO_WORKER}
        worker_model = configuration.worker_model if configuration.provider == "ollama" else \
            "gamis-deterministic-mock"
        supervisor = Supervisor(provider=provider_instance, model=supervisor_model,
                                authority=self.authority, worker_by_role=ROLE_TO_WORKER, clock=self.clock,
                                provider_name=configuration.provider, worker_model=worker_model,
                                worker_models=worker_models)
        workers = {
            role: WorkerAgent(worker_id=worker_id, role=role, signer=self.worker_signers[role],
                              gateway=self.gateway, provider=provider_instance, model=worker_models[role],
                              clock=self.clock, evidence_store=self.evidence,
                              token_budget=lambda assignment, count, g=grant:
                              self.mission_store.reserve_tokens(g.mission_id, assignment, count, g))
            for role, worker_id in ROLE_TO_WORKER.items()
        }
        return MissionOrchestrator(
            supervisor=supervisor, workers=workers, store=self.mission_store, clock=self.clock,
            concurrency=self.concurrency,
            task_timeout_seconds=configuration.timeout_seconds + 30,
            mission_timeout_seconds=max(600, (configuration.timeout_seconds + 30) * 3),
            checkpoint_context=self._checkpoint_context, checkpoint_callback=self._checkpoint_callback,
            recovery_callback=self._recovery_callback)

    def _add_evidence_intelligence(self, report):
        intelligence = EvidenceIntelligence(self.evidence).analyze(
            report.mission_id, report.worker_reports, report.claims)
        enriched = type(report).model_validate({
            **report.model_dump(mode="python"), "evidence_intelligence": intelligence.model_dump(mode="python"),
            "evidence_count": intelligence.evidence_count, "receipt_count": len(intelligence.receipt_ids),
            "receipt_ids": intelligence.receipt_ids,
        })
        self.mission_store.finish(enriched, self.clock())
        return enriched

    def _checkpoint_context(self, grant: MissionGrant) -> dict[str, Any]:
        status = self.grant_status.get(grant.grant_id)
        receipts = tuple(sorted(receipt.receipt_id for receipt in self.gateway_store.list_receipts()
                                if receipt.mission_id == grant.mission_id))
        return {
            "durable_grant_state": None if status is None else status.state.value,
            "gateway": self.gateway_store.checkpoint_state(grant.mission_id),
            "evidence_ids": self.evidence.list_evidence_ids(mission_id=grant.mission_id),
            "receipt_ids": receipts,
        }

    def _checkpoint_callback(self, grant: MissionGrant, checkpoint: Mapping[str, Any]) -> None:
        self.recorder.recovery_event(
            AuditEventType.MISSION_CHECKPOINT_CREATED,
            Principal(principal_id="supervisor-local", principal_type=PrincipalType.SUPERVISOR),
            mission_id=grant.mission_id, grant_id=grant.grant_id,
            correlation_id=checkpoint["checkpoint_id"], checkpoint_id=checkpoint["checkpoint_id"],
            checkpoint_digest=checkpoint["digest"], state="PERSISTED")

    def _recovery_callback(self, event_name: str, grant: MissionGrant, **fields: Any) -> None:
        self.recorder.recovery_event(
            AuditEventType[event_name],
            Principal(principal_id="supervisor-local", principal_type=PrincipalType.SUPERVISOR),
            mission_id=grant.mission_id, grant_id=grant.grant_id,
            correlation_id=fields.get("task_id", fields.get("checkpoint_id", grant.mission_id)),
            **fields)

    def _verify_checkpoint_audit(self, mission_id: str, checkpoint: Mapping[str, Any]) -> None:
        for event in self.ledger.iter_events():
            if (event.event_type is AuditEventType.MISSION_CHECKPOINT_CREATED
                    and event.mission_id == mission_id
                    and event.event_payload.get("checkpoint_id") == checkpoint["checkpoint_id"]
                    and event.event_payload.get("checkpoint_digest") == checkpoint["digest"]):
                return
        raise RuntimeError("latest mission checkpoint does not match the append-only audit ledger")

    def _verify_checkpoint_progress(self, mission_id: str, checkpoint: Mapping[str, Any]) -> None:
        expected = checkpoint["state"]["external_state"]
        gateway_expected = expected.get("gateway", {})
        gateway_current = self.gateway_store.checkpoint_state(mission_id)
        for key in ("tool_usage", "evidence_usage"):
            current_by_key = {
                tuple(sorted((name, value) for name, value in row.items() if name not in {"calls", "byte_count"})):
                row.get("calls", row.get("byte_count", 0))
                for row in gateway_current.get(key, ())
            }
            for row in gateway_expected.get(key, ()):
                identity = tuple(sorted((name, value) for name, value in row.items()
                                        if name not in {"calls", "byte_count"}))
                expected_count = row.get("calls", row.get("byte_count", 0))
                if current_by_key.get(identity, 0) < expected_count:
                    raise RuntimeError(f"mission cannot resume: persistent {key} budget usage moved backwards")
        current_actions = {row["idempotency_key"]: row for row in gateway_current.get("actions", ())}
        for row in gateway_expected.get("actions", ()):
            current = current_actions.get(row["idempotency_key"])
            allowed = {
                "RESERVED": {"RESERVED", "DISPATCHED", "COMMITTED", "VERIFIED", "UNCERTAIN"},
                "DISPATCHED": {"DISPATCHED", "COMMITTED", "VERIFIED", "UNCERTAIN"},
                "COMMITTED": {"COMMITTED", "VERIFIED", "UNCERTAIN"},
                "VERIFIED": {"VERIFIED"},
                "UNCERTAIN": {"UNCERTAIN", "VERIFIED"},
            }
            if current is None or current["state"] not in allowed.get(row["state"], set()):
                raise RuntimeError("mission cannot resume: persisted action state moved backwards or disappeared")
        expected_ids = set(expected.get("evidence_ids", ()))
        if not expected_ids <= set(self.evidence.list_evidence_ids(mission_id=mission_id)):
            raise RuntimeError("mission cannot resume: persisted evidence inventory moved backwards")
        expected_receipts = set(expected.get("receipt_ids", ()))
        current_receipts = {receipt.receipt_id for receipt in self.gateway_store.list_receipts()
                            if receipt.mission_id == mission_id}
        if not expected_receipts <= current_receipts:
            raise RuntimeError("mission cannot resume: persisted receipt inventory moved backwards")

    def close(self) -> None:
        if self._closed:
            return
        self.mission_store.close()
        self.evidence.close()
        self.gateway_store.close()
        self.grant_status.close()
        self.ledger.close()
        self._closed = True

    def _signer(self, name: str, principal: Principal, object_type: SignedObjectType, now: datetime):
        try:
            signer = self.keys.current(name)
        except KeyManagementError:
            return self.keys.create_key(name, principal, (object_type,), now)
        record = self.keys.trust_store.get(signer.key_id)
        if signer.principal != principal or record is None or object_type not in record.allowed_object_types:
            raise KeyManagementError(f"persisted development key {name!r} has an unexpected identity or purpose")
        return signer

    def __enter__(self) -> "LocalRuntime":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def default_state_dir() -> Path:
    return Path(os.getenv("GAMIS_HOME", str(Path.home() / ".gamis")))


def with_provider(configuration: LLMConfiguration, provider: str | None) -> LLMConfiguration:
    return configuration if provider is None else replace(configuration, provider=provider)


def open_runtime(*, provider: str | None = None, concurrency: int | None = None,
                 state_dir: Path | None = None) -> LocalRuntime:
    config = with_provider(LLMConfiguration.from_environment(), provider)
    return LocalRuntime(state_dir or default_state_dir(), configuration=config, concurrency=concurrency)
