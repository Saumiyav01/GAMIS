"""Mandatory Secure Tool Gateway (P4).

Workers receive only ``execute`` and signed receipts. Adapters are private to the gateway and
authorization, revocation, schema, registry, approval, and budget checks run for every request.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from gamis.authority.directory import GrantStatusProvider, WorkerDirectory
from gamis.authority.verification import AssignmentVerificationError, AssignmentVerifier
from gamis.audit.recorder import AuditRecorder
from gamis.gateway.approval import HumanApproval, HumanApprovalProvider
from gamis.schemas.assignment import AgentAssignment
from gamis.schemas.common import ApprovalType, ExecutionStatus, MissionState, PermissionClass, Principal
from gamis.schemas.mission import MissionGrant
from gamis.schemas.tools import ToolDefinition, ToolReceipt, ToolRequest
from gamis.security.canonical import canonicalize
from gamis.security.digest import canonical_digest
from gamis.security.keys import Signer, TrustStore, b64url_decode, verify_ed25519
from gamis.security.signing import sign_object
from gamis.storage.sqlite import connect, immediate_transaction
from gamis.tools.receipts import issue_receipt
from gamis.tools.registry import RegistryIntegrityError, RegistryReader

Clock = Callable[[], datetime]
Adapter = Callable[[dict[str, Any]], Any]
ApprovalProvider = HumanApprovalProvider
ScopeValidator = Callable[[ToolRequest, AgentAssignment, MissionGrant], bool]
_AUTH_DOMAIN = b"GAMIS-WORKER-AUTH-V1\x00"


class GatewayError(Exception):
    """A tool call was rejected or could not be completed safely."""


class AuthorizationDenied(GatewayError):
    pass


class BudgetExceeded(AuthorizationDenied):
    pass


class DuplicateAction(AuthorizationDenied):
    pass


class ActionUncertain(GatewayError):
    def __init__(self, idempotency_key: str, receipt: ToolReceipt | None = None):
        self.idempotency_key, self.receipt = idempotency_key, receipt
        super().__init__(f"action outcome is UNCERTAIN; do not retry (key={idempotency_key})")


class WorkerCredentialError(AuthorizationDenied):
    pass


class GrantStatusStore:
    """SQLite-backed grant status checked by the gateway on every request.

    Unlike ``InMemoryGrantStatusStore``, revocations survive process restarts. A status row is
    keyed by grant id and cross-checked against the signed grant's mission and revocation reference.
    """

    def __init__(self, path: str | Path, *, recorder: AuditRecorder | None = None,
                 actor: Any = None):
        from gamis.schemas.common import Principal, PrincipalType

        actor = actor or Principal(principal_id="grant-status-local", principal_type=PrincipalType.MISSION_ISSUER)
        if recorder is not None and actor.principal_type is not PrincipalType.MISSION_ISSUER:
            raise ValueError("grant status changes must be audited by a MISSION_ISSUER principal")
        self._conn = connect(path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS grant_status (grant_id TEXT PRIMARY KEY, status_json TEXT NOT NULL, "
            "audit_confirmed INTEGER NOT NULL DEFAULT 1)")
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(grant_status)")}
        if "audit_confirmed" not in columns:
            self._conn.execute("ALTER TABLE grant_status ADD COLUMN audit_confirmed INTEGER NOT NULL DEFAULT 1")
        self._recorder, self._actor = recorder, actor
        self._lock = threading.RLock()

    def close(self) -> None:
        self._conn.close()

    def activate(self, grant: MissionGrant, now: datetime) -> None:
        from gamis.schemas.mission import MissionStatus

        status = MissionStatus(mission_id=grant.mission_id, grant_id=grant.grant_id,
                               revocation_reference=grant.revocation_reference, state=MissionState.ACTIVE,
                               updated_at=now)
        with self._lock, immediate_transaction(self._conn):
            if self._conn.execute("SELECT 1 FROM grant_status WHERE grant_id=?", (grant.grant_id,)).fetchone():
                raise GatewayError(f"grant status already exists for {grant.grant_id}; it cannot be reactivated")
            self._conn.execute("INSERT INTO grant_status VALUES (?, ?, 0)",
                               (grant.grant_id, status.model_dump_json()))
        if self._recorder is not None:
            self._recorder.mission_status(status, self._actor)
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("UPDATE grant_status SET audit_confirmed=1 WHERE grant_id=?", (grant.grant_id,))

    def revoke(self, grant_id: str, now: datetime, reason: str) -> None:
        from gamis.schemas.mission import MissionStatus

        with self._lock, immediate_transaction(self._conn):
            row = self._conn.execute("SELECT status_json FROM grant_status WHERE grant_id=?",
                                     (grant_id,)).fetchone()
            if row is None:
                raise GatewayError(f"cannot revoke unknown grant {grant_id}")
            current = MissionStatus.model_validate_json(row[0])
            if current.state not in (MissionState.ACTIVE, MissionState.SUSPENDED):
                raise GatewayError(f"cannot revoke grant in terminal state {current.state.value}")
            updated = current.model_copy(update={"state": MissionState.REVOKED, "reason": reason,
                                                 "updated_at": now}).revalidate()
            self._conn.execute("UPDATE grant_status SET status_json=? WHERE grant_id=?",
                               (updated.model_dump_json(), grant_id))
            self._conn.execute("UPDATE grant_status SET audit_confirmed=0 WHERE grant_id=?", (grant_id,))
        if self._recorder is not None:
            self._recorder.mission_status(updated, self._actor)
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("UPDATE grant_status SET audit_confirmed=1 WHERE grant_id=?", (grant_id,))

    def complete(self, grant_id: str, now: datetime) -> None:
        self._set_terminal_state(grant_id, MissionState.COMPLETED, now)

    def suspend(self, grant_id: str, now: datetime, reason: str) -> None:
        self._set_terminal_state(grant_id, MissionState.SUSPENDED, now, reason)

    def _set_terminal_state(self, grant_id: str, state: MissionState, now: datetime,
                            reason: str | None = None) -> None:
        from gamis.schemas.mission import MissionStatus

        with self._lock, immediate_transaction(self._conn):
            row = self._conn.execute("SELECT status_json FROM grant_status WHERE grant_id=?",
                                     (grant_id,)).fetchone()
            if row is None:
                raise GatewayError(f"unknown grant {grant_id}")
            current = MissionStatus.model_validate_json(row[0])
            if current.state is not MissionState.ACTIVE:
                raise GatewayError(f"cannot transition grant from {current.state.value} to {state.value}")
            updated = current.model_copy(update={"state": state, "reason": reason, "updated_at": now}).revalidate()
            self._conn.execute("UPDATE grant_status SET status_json=?,audit_confirmed=0 WHERE grant_id=?",
                               (updated.model_dump_json(), grant_id))
        if self._recorder is not None:
            self._recorder.mission_status(updated, self._actor)
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("UPDATE grant_status SET audit_confirmed=1 WHERE grant_id=?", (grant_id,))

    def get(self, grant_id: str):
        from gamis.schemas.mission import MissionStatus

        with self._lock:
            row = self._conn.execute("SELECT status_json,audit_confirmed FROM grant_status WHERE grant_id=?",
                                     (grant_id,)).fetchone()
        if row is None:
            return None
        status = MissionStatus.model_validate_json(row[0])
        if not row[1] and status.state is MissionState.ACTIVE:
            return status.model_copy(update={"state": MissionState.SUSPENDED,
                                             "reason": "status activation is not durably audited"}).revalidate()
        return status


class GatewayStore:
    """Durable budgets, idempotency, action lifecycle, and signed receipt records."""

    def __init__(self, path: str | Path, *, recorder=None, actor: Principal | None = None):
        self._recorder, self._actor = recorder, actor
        self._conn = connect(path)
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS gateway_usage (
                mission_id TEXT NOT NULL, grant_id TEXT NOT NULL, assignment_id TEXT NOT NULL,
                worker_id TEXT NOT NULL, tool_id TEXT NOT NULL, calls INTEGER NOT NULL,
                PRIMARY KEY (mission_id, assignment_id, tool_id));
            CREATE TABLE IF NOT EXISTS gateway_evidence_usage (
                mission_id TEXT NOT NULL, assignment_id TEXT NOT NULL, byte_count INTEGER NOT NULL,
                PRIMARY KEY(mission_id,assignment_id));
            CREATE TABLE IF NOT EXISTS gateway_worker_evidence_usage (
                mission_id TEXT NOT NULL, worker_id TEXT NOT NULL, byte_count INTEGER NOT NULL,
                PRIMARY KEY(mission_id,worker_id));
            CREATE TABLE IF NOT EXISTS gateway_actions (
                mission_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL,
                state TEXT NOT NULL, request_id TEXT NOT NULL, receipt_json TEXT,
                result_digest TEXT, updated_at TEXT NOT NULL,
                PRIMARY KEY (mission_id, idempotency_key));
            CREATE TABLE IF NOT EXISTS gateway_requests (
                request_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, state TEXT NOT NULL,
                mission_id TEXT NOT NULL, assignment_id TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS gateway_receipts (
                receipt_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE,
                receipt_json TEXT NOT NULL, result_json TEXT);
            CREATE TABLE IF NOT EXISTS gateway_reconciliations (
                mission_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, evidence_reference TEXT NOT NULL,
                verified_at TEXT NOT NULL, PRIMARY KEY(mission_id,idempotency_key));
        """)
        self._lock = threading.RLock()

    def close(self) -> None:
        self._conn.close()

    def reserve(self, request: ToolRequest, assignment: AgentAssignment, grant: MissionGrant,
                *, action: bool, definition: ToolDefinition, now: datetime) -> None:
        with self._lock, immediate_transaction(self._conn):
            previous_request = self._conn.execute(
                "SELECT request_digest FROM gateway_requests WHERE request_id=?", (request.request_id,)).fetchone()
            if previous_request is not None:
                raise AuthorizationDenied("request_id has already been reserved; request replay is rejected")
            if action:
                if request.idempotency_key is None:
                    raise AuthorizationDenied("ACTION requires a stable idempotency_key")
                prior = self._conn.execute(
                    "SELECT request_digest,state FROM gateway_actions WHERE mission_id=? AND idempotency_key=?",
                    (request.mission_id, request.idempotency_key)).fetchone()
                if prior is not None:
                    raise DuplicateAction(
                        f"ACTION key already exists in state {prior['state']}; no redispatch is allowed")

            mission_calls = self._conn.execute(
                "SELECT COALESCE(SUM(calls),0) FROM gateway_usage WHERE mission_id=?",
                (request.mission_id,)).fetchone()[0]
            assignment_calls = self._conn.execute(
                "SELECT COALESCE(SUM(calls),0) FROM gateway_usage WHERE mission_id=? AND assignment_id=?",
                (request.mission_id, assignment.assignment_id)).fetchone()[0]
            worker_calls = self._conn.execute(
                "SELECT COALESCE(SUM(calls),0) FROM gateway_usage WHERE mission_id=? AND worker_id=?",
                (request.mission_id, request.worker_id)).fetchone()[0]
            worker_tool_calls = self._conn.execute(
                "SELECT COALESCE(SUM(calls),0) FROM gateway_usage WHERE mission_id=? AND worker_id=? AND tool_id=?",
                (request.mission_id, request.worker_id, request.tool_id)).fetchone()[0]
            tool_calls = self._conn.execute(
                "SELECT calls FROM gateway_usage WHERE mission_id=? AND assignment_id=? AND tool_id=?",
                (request.mission_id, assignment.assignment_id, request.tool_id)).fetchone()
            limit = next(x.max_calls for x in assignment.tool_call_limits if x.tool_id == request.tool_id)
            if mission_calls >= grant.global_resource_limits.max_tool_calls:
                raise BudgetExceeded("mission tool-call budget exhausted")
            if assignment_calls >= assignment.resource_limits.max_tool_calls:
                raise BudgetExceeded("worker assignment tool-call budget exhausted")
            if worker_calls >= assignment.resource_limits.max_tool_calls:
                raise BudgetExceeded("worker mission-wide tool-call budget exhausted")
            if max(worker_tool_calls, 0 if tool_calls is None else tool_calls[0]) >= limit:
                raise BudgetExceeded(f"tool-call budget exhausted for {request.tool_id}")
            self._conn.execute(
                "INSERT INTO gateway_usage VALUES (?, ?, ?, ?, ?, 1) "
                "ON CONFLICT(mission_id,assignment_id,tool_id) DO UPDATE SET calls=calls+1",
                (request.mission_id, grant.grant_id, assignment.assignment_id, request.worker_id, request.tool_id))
            self._conn.execute("INSERT INTO gateway_requests VALUES (?, ?, 'RESERVED', ?, ?, ?)",
                               (request.request_id, request.request_digest(), request.mission_id,
                                assignment.assignment_id, now.isoformat()))
            if action:
                self._conn.execute("INSERT INTO gateway_actions VALUES (?, ?, ?, 'RESERVED', ?, NULL, NULL, ?)",
                                   (request.mission_id, request.idempotency_key, request.request_digest(),
                                    request.request_id, now.isoformat()))

    def transition(self, request: ToolRequest, state: str, now: datetime, *,
                   receipt: ToolReceipt | None = None, result: Any = None) -> None:
        if state not in {"DISPATCHED", "COMMITTED", "VERIFIED", "UNCERTAIN"}:
            raise ValueError(f"invalid action state {state}")
        if request.idempotency_key is None:
            raise GatewayError("ACTION lifecycle lost its idempotency key")
        with self._lock, immediate_transaction(self._conn):
            row = self._conn.execute(
                "SELECT state FROM gateway_actions WHERE mission_id=? AND idempotency_key=?",
                (request.mission_id, request.idempotency_key)).fetchone()
            allowed = {"RESERVED": {"DISPATCHED"}, "DISPATCHED": {"COMMITTED", "UNCERTAIN"},
                       "COMMITTED": {"VERIFIED", "UNCERTAIN"}}
            if row is None or state not in allowed.get(row["state"], set()):
                raise GatewayError(f"invalid action lifecycle transition to {state}")
            self._conn.execute("UPDATE gateway_actions SET state=?, receipt_json=?, result_digest=?, updated_at=? "
                               "WHERE mission_id=? AND idempotency_key=?",
                               (state, None if receipt is None else receipt.model_dump_json(),
                                None if result is None else canonical_digest(result),
                                now.isoformat(), request.mission_id, request.idempotency_key))
            self._conn.execute("UPDATE gateway_requests SET state=?, updated_at=? WHERE request_id=?",
                               (state, now.isoformat(), request.request_id))

    def charge_evidence(self, request: ToolRequest, assignment: AgentAssignment, grant: MissionGrant,
                        byte_count: int) -> None:
        with self._lock, immediate_transaction(self._conn):
            mission_bytes = self._conn.execute(
                "SELECT COALESCE(SUM(byte_count),0) FROM gateway_evidence_usage WHERE mission_id=?",
                (request.mission_id,)).fetchone()[0]
            row = self._conn.execute(
                "SELECT byte_count FROM gateway_evidence_usage WHERE mission_id=? AND assignment_id=?",
                (request.mission_id, assignment.assignment_id)).fetchone()
            assignment_bytes = 0 if row is None else row[0]
            row = self._conn.execute(
                "SELECT byte_count FROM gateway_worker_evidence_usage WHERE mission_id=? AND worker_id=?",
                (request.mission_id, request.worker_id)).fetchone()
            worker_bytes = 0 if row is None else row[0]
            if assignment_bytes + byte_count > assignment.resource_limits.max_evidence_bytes:
                raise BudgetExceeded("worker evidence-byte budget exhausted")
            if worker_bytes + byte_count > assignment.resource_limits.max_evidence_bytes:
                raise BudgetExceeded("worker mission-wide evidence-byte budget exhausted")
            if mission_bytes + byte_count > grant.global_resource_limits.max_evidence_bytes:
                raise BudgetExceeded("mission evidence-byte budget exhausted")
            self._conn.execute(
                "INSERT INTO gateway_evidence_usage VALUES (?, ?, ?) "
                "ON CONFLICT(mission_id,assignment_id) DO UPDATE SET byte_count=byte_count+excluded.byte_count",
                (request.mission_id, assignment.assignment_id, byte_count))
            self._conn.execute(
                "INSERT INTO gateway_worker_evidence_usage VALUES (?, ?, ?) "
                "ON CONFLICT(mission_id,worker_id) DO UPDATE SET byte_count=byte_count+excluded.byte_count",
                (request.mission_id, request.worker_id, byte_count))

    def uncertain(self, request: ToolRequest, now: datetime) -> None:
        with self._lock, immediate_transaction(self._conn):
            if request.idempotency_key is not None:
                self._conn.execute("UPDATE gateway_actions SET state='UNCERTAIN', updated_at=? "
                                   "WHERE mission_id=? AND idempotency_key=? "
                                   "AND state IN ('RESERVED','DISPATCHED','COMMITTED')",
                                   (now.isoformat(), request.mission_id, request.idempotency_key))
            self._conn.execute("UPDATE gateway_requests SET state='UNCERTAIN',updated_at=? WHERE request_id=?",
                               (now.isoformat(), request.request_id))
            grant = self._conn.execute(
                "SELECT grant_id FROM gateway_usage WHERE mission_id=? AND assignment_id=? LIMIT 1",
                (request.mission_id, request.assignment_id)).fetchone()
        if self._recorder is not None and request.idempotency_key is not None and grant is not None:
            from gamis.audit.events import AuditEventType
            self._recorder.recovery_event(
                AuditEventType.ACTION_RECONCILIATION_REQUIRED, self._actor, mission_id=request.mission_id,
                grant_id=grant["grant_id"], correlation_id=request.request_id,
                assignment_id=request.assignment_id, worker_id=request.worker_id,
                state="UNCERTAIN", reason="ACTION outcome is uncertain; redispatch is prohibited.")

    def store_result(self, request: ToolRequest, receipt: ToolReceipt, result: Any) -> None:
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("INSERT INTO gateway_receipts VALUES (?, ?, ?, NULL)",
                               (receipt.receipt_id, request.request_id, receipt.model_dump_json()))
            self._conn.execute("UPDATE gateway_requests SET state='COMPLETED',updated_at=? "
                               "WHERE request_id=? AND state='RESERVED'",
                               (receipt.completed_at.isoformat(), request.request_id))

    def receipt(self, receipt_id: str) -> ToolReceipt:
        with self._lock:
            row = self._conn.execute("SELECT receipt_json FROM gateway_receipts WHERE receipt_id=?",
                                     (receipt_id,)).fetchone()
        if row is None:
            raise GatewayError(f"unknown receipt {receipt_id}")
        return ToolReceipt.model_validate_json(row[0])

    def action_state(self, mission_id: str, idempotency_key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT state FROM gateway_actions WHERE mission_id=? AND idempotency_key=?",
                                     (mission_id, idempotency_key)).fetchone()
        return None if row is None else row[0]

    def checkpoint_state(self, mission_id: str) -> dict[str, Any]:
        with self._lock:
            usage = [dict(row) for row in self._conn.execute(
                "SELECT assignment_id,worker_id,tool_id,calls FROM gateway_usage WHERE mission_id=? "
                "ORDER BY assignment_id,tool_id", (mission_id,))]
            evidence_usage = [dict(row) for row in self._conn.execute(
                "SELECT assignment_id,byte_count FROM gateway_evidence_usage WHERE mission_id=? "
                "ORDER BY assignment_id", (mission_id,))]
            actions = [dict(row) for row in self._conn.execute(
                "SELECT idempotency_key,request_digest,state,request_id,result_digest,updated_at "
                "FROM gateway_actions WHERE mission_id=? ORDER BY idempotency_key", (mission_id,))]
            requests = [dict(row) for row in self._conn.execute(
                "SELECT request_id,request_digest,state,assignment_id,updated_at FROM gateway_requests "
                "WHERE mission_id=? ORDER BY request_id", (mission_id,))]
            reconciliations = [dict(row) for row in self._conn.execute(
                "SELECT idempotency_key,evidence_reference,verified_at FROM gateway_reconciliations "
                "WHERE mission_id=? ORDER BY idempotency_key", (mission_id,))]
        from gamis.security.digest import canonical_digest
        for action in actions:
            action["idempotency_key"] = canonical_digest(action["idempotency_key"])
        for item in reconciliations:
            item["idempotency_key"] = canonical_digest(item["idempotency_key"])
            item["evidence_reference"] = canonical_digest(item["evidence_reference"])
        return {
            "tool_usage": usage, "evidence_usage": evidence_usage, "actions": actions,
            "requests": requests, "reconciliations": reconciliations,
            "approval_reuse": "No approval is reused; protected ACTION requests are revalidated per dispatch.",
        }

    def list_receipts(self) -> tuple[ToolReceipt, ...]:
        with self._lock:
            rows = self._conn.execute("SELECT receipt_json FROM gateway_receipts ORDER BY rowid").fetchall()
        return tuple(ToolReceipt.model_validate_json(r[0]) for r in rows)

    def reconcile_uncertain(self, mission_id: str, idempotency_key: str, *,
                            evidence_reference: str, verified_by_operator: bool) -> None:
        """Close a known UNCERTAIN item only after a trusted operator supplied reconciliation evidence.

        This never dispatches or resets an action. A false or absent attestation leaves the record uncertain.
        """
        if not evidence_reference.strip() or not verified_by_operator:
            raise GatewayError("reconciliation requires explicit operator verification and an evidence reference")
        with self._lock, immediate_transaction(self._conn):
            row = self._conn.execute(
                "SELECT state FROM gateway_actions WHERE mission_id=? AND idempotency_key=?",
                (mission_id, idempotency_key)).fetchone()
            if row is None or row["state"] != "UNCERTAIN":
                raise GatewayError("only an UNCERTAIN action can be reconciled")
            grant = self._conn.execute(
                "SELECT grant_id FROM gateway_usage WHERE mission_id=? LIMIT 1", (mission_id,)).fetchone()
            if grant is None:
                raise GatewayError("uncertain action has no durable mission authorization record")
            self._conn.execute("UPDATE gateway_actions SET state='VERIFIED',updated_at=? "
                               "WHERE mission_id=? AND idempotency_key=?",
                               (datetime.now(timezone.utc).isoformat(), mission_id, idempotency_key))
            self._conn.execute("INSERT INTO gateway_reconciliations VALUES (?, ?, ?, ?)",
                               (mission_id, idempotency_key, evidence_reference,
                                datetime.now(timezone.utc).isoformat()))
            self._conn.execute("UPDATE gateway_requests SET state='VERIFIED',updated_at=? "
                               "WHERE mission_id=? AND request_id=(SELECT request_id FROM gateway_actions "
                               "WHERE mission_id=? AND idempotency_key=?)",
                               (datetime.now(timezone.utc).isoformat(), mission_id, mission_id, idempotency_key))
        if self._recorder is not None:
            from gamis.audit.events import AuditEventType
            self._recorder.recovery_event(
                AuditEventType.ACTION_RECONCILED, self._actor, mission_id=mission_id,
                grant_id=grant["grant_id"], correlation_id=idempotency_key, state="VERIFIED",
                reason="Operator attestation recorded; no adapter redispatch occurred.",
                evidence_reference=evidence_reference)


@dataclass(frozen=True)
class GatewayResult:
    result: Any
    receipt: ToolReceipt


def worker_auth_message(request: ToolRequest) -> bytes:
    return _AUTH_DOMAIN + canonicalize({"worker_id": request.worker_id,
                                        "request_digest": request.request_digest()})


class SecureToolGateway:
    def __init__(self, *, verifier: AssignmentVerifier, trust_store: TrustStore, registry: RegistryReader,
                 grant_status: GrantStatusProvider, signer: Signer, clock: Clock,
                 workers: WorkerDirectory,
                 adapters: Mapping[tuple[str, str], Adapter], worker_public_keys: Mapping[str, bytes],
                 store: GatewayStore, scope_validator: ScopeValidator,
                 approval_provider: ApprovalProvider | None = None,
                 recorder: AuditRecorder | None = None, evidence_store: Any = None):
        if signer.principal.principal_type.value != "TOOL_GATEWAY":
            raise ValueError("gateway receipts require a TOOL_GATEWAY signer")
        self._verifier, self._trust_store, self._registry = verifier, trust_store, registry
        self._grant_status, self._signer, self._clock = grant_status, signer, clock
        self._workers = workers
        self._adapters = dict(adapters)
        self._worker_keys = {k: bytes(v) for k, v in worker_public_keys.items()}
        self._scope_validator = scope_validator
        self._store, self._approval, self._recorder, self._evidence = store, approval_provider, recorder, evidence_store

    def execute(self, request: ToolRequest, assignment: AgentAssignment, grant: MissionGrant,
                credential_signature: str | bytes) -> GatewayResult:
        now = self._clock()
        request = request.revalidate()
        assignment = assignment.revalidate()
        grant = grant.revalidate()
        self._authenticate(request, credential_signature)
        self._check_authorization(request, assignment, grant, now)
        if not self._scope_validator(request, assignment, grant):
            self._deny(request, "OUT_OF_SCOPE")
            raise AuthorizationDenied("request arguments do not resolve inside the authorized scope")
        try:
            self._registry.verify_integrity(self._trust_store, now)
        except RegistryIntegrityError as exc:
            self._deny(request, "REGISTRY_INTEGRITY")
            raise AuthorizationDenied(f"tool registry integrity failure: {exc}") from exc
        definition = self._registry.get(request.tool_id)
        operation = None if definition is None else definition.operation(request.operation_id)
        if definition is None or not definition.enabled_status or operation is None:
            self._deny(request, "TOOL_UNAVAILABLE")
            raise AuthorizationDenied("tool or operation is not enabled in the signed registry")
        permission = assignment.permission_for(request.tool_id, request.operation_id)
        grant_permission = grant.permission_for(request.tool_id, request.operation_id)
        if (permission is None or grant_permission is None or permission.permission_class is not operation.permission_class
                or grant_permission.permission_class is not operation.permission_class):
            self._deny(request, "OPERATION_NOT_AUTHORIZED")
            raise AuthorizationDenied("operation is not separately permitted for this worker and mission")
        schema = definition.schema_for(request.operation_id)
        problems = () if schema is None else schema.validate_arguments(request.arguments)
        if problems:
            self._deny(request, "INVALID_ARGUMENTS")
            raise AuthorizationDenied("invalid arguments: " + "; ".join(problems))
        approval_reason = ()
        if operation.permission_class is PermissionClass.ACTION:
            requirements = tuple(req for req in (*grant.approval_requirements, *definition.approval_requirements)
                                 if req.applies_to is PermissionClass.ACTION
                                 and req.tool_id in (None, request.tool_id)
                                 and req.operation_id in (None, request.operation_id))
            if (self._approval is None or not requirements
                    or any(req.approval_type not in (ApprovalType.HUMAN_APPROVAL, ApprovalType.DUAL_CONTROL)
                           for req in requirements)):
                self._deny(request, "HUMAN_APPROVAL_REQUIRED")
                raise AuthorizationDenied("protected ACTION has no valid human approval provider or policy")
            approvals = self._approval.approvals_for(request, assignment, grant, requirements)
            try:
                self._validate_approvals(request, requirements, approvals, now)
            except AuthorizationDenied:
                self._deny(request, "HUMAN_APPROVAL_INVALID")
                raise
            approval_reason = ("HUMAN_APPROVAL_VERIFIED",)
        self._audit_request(request)
        action = operation.permission_class is PermissionClass.ACTION
        try:
            self._store.reserve(request, assignment, grant, action=action, definition=definition, now=now)
        except GatewayError:
            self._audit_decision(request, False, ("BUDGET_OR_IDEMPOTENCY",))
            raise
        self._audit_decision(request, True, approval_reason)
        if action:
            self._store.transition(request, "DISPATCHED", now)
        adapter = self._adapters.get((request.tool_id, request.operation_id))
        if adapter is None:
            self._store.uncertain(request, self._clock())
            raise AuthorizationDenied(f"no controlled adapter is registered for {request.tool_id}:{request.operation_id}")
        started = self._clock()
        try:
            result = adapter(dict(request.arguments))
            # Canonical serialization is also the gateway's result validation boundary.
            encoded_result = canonicalize(result)
            canonical_digest(result)
            self._store.charge_evidence(request, assignment, grant, len(encoded_result))
        except Exception as exc:
            known_budget_failure = isinstance(exc, BudgetExceeded)
            receipt = self._make_receipt(request, definition, ExecutionStatus.FAILED, None,
                                         "EVIDENCE_BUDGET_EXCEEDED" if known_budget_failure else "ADAPTER_UNCERTAIN",
                                         started, self._clock())
            if action:
                self._store.transition(request, "UNCERTAIN", self._clock(), receipt=receipt)
            self._persist_receipt(request, receipt, {"uncertain": not known_budget_failure})
            if action:
                raise ActionUncertain(request.idempotency_key or request.request_id, receipt) from exc
            if known_budget_failure:
                raise GatewayError(f"tool result exceeded the authorized evidence budget; receipt "
                                   f"{receipt.receipt_id} records the rejection") from exc
            raise GatewayError(f"READ adapter failed; receipt {receipt.receipt_id} records the failure") from exc
        completed = self._clock()
        receipt = self._make_receipt(request, definition, ExecutionStatus.SUCCEEDED, result, None, started, completed)
        try:
            if action:
                self._store.transition(request, "COMMITTED", completed, receipt=receipt, result=result)
            self._persist_receipt(request, receipt, result)
            if action:
                self._store.transition(request, "VERIFIED", self._clock(), receipt=receipt, result=result)
        except Exception as exc:
            if action:
                self._store.uncertain(request, self._clock())
                raise ActionUncertain(request.idempotency_key or request.request_id, receipt) from exc
            raise
        return GatewayResult(result, receipt)

    def assert_assignment_active(self, assignment: AgentAssignment, grant: MissionGrant) -> None:
        """Recheck a worker's authorization after a long model call without exposing any adapter."""
        assignment, grant = assignment.revalidate(), grant.revalidate()
        try:
            self._verifier.verify(assignment, grant)
        except AssignmentVerificationError as exc:
            raise AuthorizationDenied(f"assignment authorization ended: {exc}") from exc
        status = self._grant_status.get(grant.grant_id)
        if (status is None or status.mission_id != grant.mission_id
                or status.revocation_reference != grant.revocation_reference
                or status.state is not MissionState.ACTIVE):
            raise AuthorizationDenied("mission grant was suspended, revoked, or expired")
        worker = self._workers.get(assignment.worker_id)
        if worker is None or not worker.enabled or worker.worker_role != assignment.worker_role:
            raise AuthorizationDenied("worker is unknown, disabled, or no longer holds the assigned role")

    def _authenticate(self, request: ToolRequest, signature: str | bytes) -> None:
        public = self._worker_keys.get(request.worker_id)
        if public is None:
            raise WorkerCredentialError("worker has no registered cryptographic credential")
        try:
            raw = b64url_decode(signature) if isinstance(signature, str) else signature
        except ValueError as exc:
            raise WorkerCredentialError("worker credential signature is malformed") from exc
        if not verify_ed25519(public, raw, worker_auth_message(request)):
            raise WorkerCredentialError("worker credential signature is invalid")

    @staticmethod
    def _validate_approvals(request: ToolRequest, requirements: tuple, approvals: tuple[HumanApproval, ...],
                            now: datetime) -> None:
        seen: set[str] = set()
        valid = []
        for raw in approvals:
            approval = raw if isinstance(raw, HumanApproval) else HumanApproval.model_validate(raw)
            if (approval.approver_id in seen or approval.request_digest != request.request_digest()
                    or approval.approved_at > now or approval.expires_at <= now):
                raise AuthorizationDenied("human approval is stale, duplicated, or bound to another request")
            seen.add(approval.approver_id)
            valid.append(approval)
        for requirement in requirements:
            eligible = {a.approver_id for a in valid if a.approver_role in requirement.approver_roles}
            if len(eligible) < requirement.minimum_approvals:
                raise AuthorizationDenied(f"approval requirement {requirement.requirement_id} is unmet")

    def _check_authorization(self, request: ToolRequest, assignment: AgentAssignment, grant: MissionGrant,
                             now: datetime) -> None:
        if (request.assignment_id != assignment.assignment_id or request.worker_id != assignment.worker_id
                or request.mission_id != assignment.mission_id or request.mission_id != grant.mission_id):
            self._deny(request, "IDENTITY_SCOPE_MISMATCH")
            raise AuthorizationDenied("request identity does not match signed assignment and grant")
        if not assignment.authorized_scope or any(scope not in grant.authorized_scope
                                                  for scope in assignment.authorized_scope):
            self._deny(request, "ASSIGNMENT_SCOPE_INVALID")
            raise AuthorizationDenied("assignment has no authorized scope or exceeds the mission scope")
        try:
            self._verifier.verify(assignment, grant)
        except AssignmentVerificationError as exc:
            self._deny(request, "INVALID_SIGNED_AUTHORIZATION")
            raise AuthorizationDenied(f"assignment or grant verification failed: {exc}") from exc
        worker = self._workers.get(assignment.worker_id)
        if worker is None or not worker.enabled or worker.worker_role != assignment.worker_role:
            self._deny(request, "WORKER_DISABLED_OR_ROLE_CHANGED")
            raise AuthorizationDenied("worker is unknown, disabled, or no longer holds the assigned role")
        status = self._grant_status.get(grant.grant_id)
        if (status is None or status.mission_id != grant.mission_id
                or status.revocation_reference != grant.revocation_reference
                or status.state is not MissionState.ACTIVE):
            self._deny(request, "GRANT_INACTIVE_OR_REVOKED")
            raise AuthorizationDenied("grant is not active (revocation checked for this execution)")
        if request.tool_id not in assignment.permitted_tools or request.tool_id not in grant.permitted_tools:
            self._deny(request, "TOOL_NOT_PERMITTED")
            raise AuthorizationDenied("tool is outside signed assignment or grant scope")
        if request.requested_at > now + timedelta(seconds=30):
            self._deny(request, "REQUEST_FROM_FUTURE")
            raise AuthorizationDenied("request timestamp is in the future")

    def _audit_request(self, request: ToolRequest) -> None:
        if self._recorder is not None:
            self._recorder.tool_request(request, self._signer.principal)

    def _audit_decision(self, request: ToolRequest, allowed: bool, codes: tuple[str, ...] = ()) -> None:
        if self._recorder is not None:
            self._recorder.authorization_decision(request, self._signer.principal, allowed, codes)

    def _deny(self, request: ToolRequest, code: str) -> None:
        self._audit_decision(request, False, (code,))

    def _make_receipt(self, request: ToolRequest, definition: ToolDefinition, status: ExecutionStatus,
                      result: Any, error: str | None, started: datetime, completed: datetime) -> ToolReceipt:
        return issue_receipt(request, definition, receipt_id=f"receipt-{uuid.uuid4().hex}",
                             status=status, result=result, error_code=error, started_at=started,
                             completed_at=completed, policy_version=definition.policy_version, signer=self._signer)

    def _persist_receipt(self, request: ToolRequest, receipt: ToolReceipt, result: Any) -> None:
        self._store.store_result(request, receipt, result)
        if self._evidence is not None:
            self._evidence.store_receipt(receipt)
        if self._recorder is not None:
            self._recorder.tool_execution(receipt)


def worker_signature(signer: Signer, request: ToolRequest) -> str:
    """Create the per-request proof workers present to the gateway."""
    from gamis.security.keys import b64url_encode

    return b64url_encode(signer.sign(worker_auth_message(request)))


__all__ = [
    "ActionUncertain", "AuthorizationDenied", "BudgetExceeded", "DuplicateAction", "GatewayError",
    "GatewayResult", "GatewayStore", "GrantStatusStore", "SecureToolGateway", "WorkerCredentialError",
    "worker_auth_message", "worker_signature",
]
