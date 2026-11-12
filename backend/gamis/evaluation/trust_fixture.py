"""A complete, self-consistent P1 trust setup over the P0 sample tools, for tests and verification scripts.

Keys are generated fresh in memory on every call; no key material exists in the repository.
Nothing here is a production configuration.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from gamis.authority.grants import issue_mission_grant
from gamis.authority.directory import InMemoryGrantStatusStore, InMemoryIssuanceLedger, InMemoryWorkerDirectory
from gamis.authority.service import AuthorityService
from gamis.authority.verification import AssignmentVerifier
from gamis.schemas import (AgentAssignment, MissionGrant, PolicyVersion, Principal, PrincipalType, SignedObjectType,
                           WorkerIdentity)
from gamis.security.keys import Ed25519Signer, SoftwareKeyManager
from gamis.security.signing import sign_object
from gamis.tools.registry import ToolRegistry
from gamis.tools.sample_registry import build_sample_registry

if TYPE_CHECKING:
    from gamis.audit.recorder import AuditRecorder

NOW = datetime(2026, 1, 10, 9, 0, 0, tzinfo=timezone.utc)
POLICY = PolicyVersion(policy_id="gamis-sample-policy", version="1.0.0")
ISSUER = Principal(principal_id="mission-issuer-1", principal_type=PrincipalType.MISSION_ISSUER)
AUTHORITY = Principal(principal_id="authority-service-1", principal_type=PrincipalType.AUTHORITY_SERVICE)
GATEWAY = Principal(principal_id="tool-gateway-1", principal_type=PrincipalType.TOOL_GATEWAY)
REGISTRY_ADMIN = Principal(principal_id="registry-admin-1", principal_type=PrincipalType.REGISTRY_ADMIN)
SUPERVISOR = Principal(principal_id="supervisor-1", principal_type=PrincipalType.SUPERVISOR)
AUDITOR = Principal(principal_id="audit-service-1", principal_type=PrincipalType.AUDIT_SERVICE)

READ_OPS = [{"tool_id": "log_search", "operation_id": "search", "permission_class": "READ"},
            {"tool_id": "intel_lookup", "operation_id": "lookup", "permission_class": "READ"}]
ACTION_OP = {"tool_id": "case_action", "operation_id": "execute", "permission_class": "ACTION"}
EVIDENCE_REQUIREMENT = {"requirement_id": "ev-receipts", "description": "Tool evidence must cite receipts",
                        "minimum_items": 1, "require_tool_receipts": True,
                        "accepted_source_types": ["TOOL_RESULT"], "applies_to_roles": []}


class MutableClock:
    def __init__(self, now: datetime):
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **delta: float) -> None:
        self.now += timedelta(**delta)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def grant_dict(now: datetime = NOW, **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "mission_id": "MIS-001", "grant_id": "GRANT-001",
        "mission_objective": "Investigate the reported activity and report evidence-backed findings.",
        "authorized_scope": [{"resource_type": "dataset", "selector": "synthetic-seeds"}],
        "permitted_roles": ["evidence-reader", "intel-analyst", "responder"],
        "permitted_tools": ["log_search", "intel_lookup", "case_action"],
        "permitted_operations": [*READ_OPS, ACTION_OP],
        "permitted_permission_classes": ["READ", "ACTION"],
        "maximum_worker_count": 3,
        "global_resource_limits": {"max_tool_calls": 100, "max_wall_clock_seconds": 3600, "max_tokens": 100_000,
                                   "max_cost_units": 1000, "max_evidence_bytes": 1_000_000},
        "approval_requirements": [{"requirement_id": "action-approval", "approval_type": "HUMAN_APPROVAL",
                                   "applies_to": "ACTION", "approver_roles": ["mission-owner"],
                                   "minimum_approvals": 1, "description": "Actions need human approval"}],
        "evidence_requirements": [EVIDENCE_REQUIREMENT],
        "policy_version": POLICY.model_dump(mode="json"),
        "issued_at": iso(now - timedelta(hours=1)), "expires_at": iso(now + timedelta(hours=8)),
        "issuer_identity": ISSUER.model_dump(mode="json"),
        "revocation_reference": "REVOCATION-GRANT-001",
    }
    data.update(overrides)
    return data


def assignment_dict(now: datetime = NOW, **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "assignment_id": "ASG-001", "mission_id": "MIS-001", "grant_id": "GRANT-001",
        "worker_id": "worker-reader-1", "worker_role": "evidence-reader",
        "task_objective": "Collect log evidence",
        "task_description": "Search the permitted log source and report what the records show.",
        "success_criteria": ["Relevant records are cited with receipts"],
        "permitted_tools": ["log_search"],
        "permitted_operations": [READ_OPS[0]],
        "forbidden_actions": ["case_action", "any state-changing operation"],
        "permission_class": "READ",
        "resource_limits": {"max_tool_calls": 20, "max_wall_clock_seconds": 600, "max_tokens": 10_000,
                            "max_cost_units": 100, "max_evidence_bytes": 100_000},
        "tool_call_limits": [{"tool_id": "log_search", "max_calls": 20}],
        "required_evidence": [EVIDENCE_REQUIREMENT],
        "stopping_conditions": [{"condition_id": "stop-budget", "condition_type": "RESOURCE_EXHAUSTED",
                                 "description": "Stop when any limit is reached"}],
        "issued_at": iso(now), "expires_at": iso(now + timedelta(hours=1)),
        "policy_version": POLICY.model_dump(mode="json"),
    }
    data.update(overrides)
    return data


@dataclass
class TrustWorld:
    clock: MutableClock
    keys: SoftwareKeyManager
    issuer_signer: Ed25519Signer
    gateway_signer: Ed25519Signer
    registry_signer: Ed25519Signer
    worker_signer: Ed25519Signer
    audit_signer: Ed25519Signer
    registry: ToolRegistry
    workers: InMemoryWorkerDirectory
    status: InMemoryGrantStatusStore
    ledger: InMemoryIssuanceLedger
    authority: AuthorityService
    verifier: AssignmentVerifier
    grant: MissionGrant

    @property
    def trust_store(self):
        return self.keys.trust_store

    def sign_grant(self, **overrides: Any) -> MissionGrant:
        grant = MissionGrant.model_validate(grant_dict(self.clock.now, **overrides))
        return grant.with_signature(sign_object(grant, self.issuer_signer, now=grant.issued_at))

    def issue(self, **overrides: Any) -> AgentAssignment:
        return self.authority.issue_assignment(assignment_dict(self.clock.now, **overrides), self.grant)


def build_trust_world(now: datetime = NOW, *, enable_action_tool: bool = False,
                      recorder: "AuditRecorder | None" = None, clock: MutableClock | None = None) -> TrustWorld:
    """With ``recorder`` (P2), registry changes, grant issuance, mission status and assignment decisions
    are written to the audit ledger."""
    clock = clock if clock is not None else MutableClock(now)
    start = now - timedelta(days=1)
    keys = SoftwareKeyManager()
    issuer = keys.create_key("mission-issuer", ISSUER, (SignedObjectType.MISSION_GRANT,), start)
    authority_signer = keys.create_key("authority-assignment", AUTHORITY, (SignedObjectType.AGENT_ASSIGNMENT,), start)
    gateway = keys.create_key("tool-gateway", GATEWAY, (SignedObjectType.TOOL_RECEIPT,), start)
    registry_signer = keys.create_key("registry-admin", REGISTRY_ADMIN, (SignedObjectType.TOOL_REGISTRY,), start)
    worker_signer = keys.create_key(
        "worker-reader-1-evidence", Principal(principal_id="worker-reader-1", principal_type=PrincipalType.WORKER),
        (SignedObjectType.EVIDENCE_BUNDLE,), start)
    audit_signer = keys.create_key("audit-checkpoint", AUDITOR, (SignedObjectType.AUDIT_CHECKPOINT,), start)

    registry = build_sample_registry(POLICY, REGISTRY_ADMIN, recorder=recorder)
    if enable_action_tool:
        registry.set_enabled("case_action", "1.0.0", True, actor=REGISTRY_ADMIN)
    registry.seal(registry_signer, start)

    workers = InMemoryWorkerDirectory(tuple(
        WorkerIdentity(worker_id=wid, worker_role=role, display_name=wid, enabled=enabled, registered_at=start)
        for wid, role, enabled in [("worker-reader-1", "evidence-reader", True),
                                   ("worker-intel-1", "intel-analyst", True),
                                   ("worker-responder-1", "responder", True),
                                   ("worker-extra-1", "evidence-reader", True),
                                   ("worker-disabled-1", "evidence-reader", False)]))
    status = InMemoryGrantStatusStore(recorder, ISSUER if recorder else None)
    ledger = InMemoryIssuanceLedger()
    grant = issue_mission_grant(MissionGrant.model_validate(grant_dict(now)), issuer,
                                now=now - timedelta(hours=1), recorder=recorder)
    status.activate(grant, grant.issued_at)
    authority = AuthorityService(signer=authority_signer, trust_store=keys.trust_store, registry=registry.read_only(),
                                 workers=workers, grant_status=status, active_policy=POLICY, clock=clock,
                                 ledger=ledger, recorder=recorder)
    verifier = AssignmentVerifier(keys.trust_store, clock, recorder=recorder, actor=GATEWAY if recorder else None)
    return TrustWorld(clock, keys, issuer, gateway, registry_signer, worker_signer, audit_signer, registry, workers,
                      status, ledger, authority, verifier, grant)
