"""AuditRecorder: turns P1 objects into typed audit events and writes them to any AuditSink.

Components (Authority Service, registry, grant status store, and later the gateway / workers) depend on this
recorder or on the AuditSink protocol, never on SQLite. Payloads carry ids, digests and codes only.
"""
from __future__ import annotations

from typing import Any, Iterable

from gamis.audit.events import (AssignmentPayload, AssignmentRejectedPayload, AuditEvent, AuditEventDraft,
                                AuditEventType, AuthorizationPayload, Decision, GrantIssuedPayload,
                                GrantVerificationPayload, MissionPayload, Outcome, RegistryPayload, AuditSink,
                                RecoveryPayload, ToolExecutionPayload, ToolRequestPayload, WorkerPayload)
from gamis.schemas.assignment import AgentAssignment, WorkerIdentity
from gamis.schemas.common import MissionState, Principal
from gamis.schemas.mission import MissionGrant, MissionStatus
from gamis.schemas.signature import SignedObjectType
from gamis.schemas.tools import RegistrySnapshot, ToolDefinition, ToolReceipt, ToolRequest
from gamis.security.canonical import CanonicalizationError
from gamis.security.digest import canonical_digest, domain_digest
from gamis.security.signing import payload_digest

_STATE_EVENTS = {MissionState.ACTIVE: AuditEventType.MISSION_ACTIVATED,
                 MissionState.SUSPENDED: AuditEventType.MISSION_SUSPENDED,
                 MissionState.COMPLETED: AuditEventType.MISSION_COMPLETED,
                 MissionState.REVOKED: AuditEventType.MISSION_REVOKED}


def _digest(obj: Any) -> str:
    return payload_digest(type(obj).OBJECT_TYPE, obj.signed_payload())


def _assignment_payload(a: AgentAssignment, proposer: Principal | None) -> AssignmentPayload:
    meta = a.signature_metadata
    return AssignmentPayload(
        assignment_digest=payload_digest(SignedObjectType.AGENT_ASSIGNMENT, a.signed_payload()),
        worker_role=a.worker_role, permission_class=a.permission_class,
        permitted_operations=tuple(p.qualified_name for p in a.permitted_operations),
        policy_version=a.policy_version, expires_at=a.expires_at,
        signing_key_id=meta.key_id if meta else None, signing_key_version=meta.key_version if meta else None,
        proposer=proposer)


class AuditRecorder:
    def __init__(self, sink: AuditSink):
        self.sink = sink

    def emit(self, event_type: AuditEventType, actor: Principal, correlation_id: str, payload: Any,
             **refs: str | None) -> AuditEvent:
        return self.sink.append_event(AuditEventDraft(event_type=event_type, actor_identity=actor,
                                                      correlation_id=correlation_id, event_payload=payload, **refs))

    def recovery_event(self, event_type: AuditEventType, actor: Principal, *, mission_id: str, grant_id: str,
                       correlation_id: str, assignment_id: str | None = None, worker_id: str | None = None,
                       checkpoint_id: str | None = None, checkpoint_digest: str | None = None,
                       task_id: str | None = None, attempt: int | None = None, state: str | None = None,
                       reason: str | None = None, evidence_reference: str | None = None) -> AuditEvent:
        return self.emit(event_type, actor, correlation_id, RecoveryPayload(
            checkpoint_id=checkpoint_id, checkpoint_digest=checkpoint_digest, task_id=task_id,
            attempt=attempt, state=state, reason=reason[:250] if reason else None,
            evidence_reference_digest=canonical_digest(evidence_reference) if evidence_reference else None),
            mission_id=mission_id, grant_id=grant_id, assignment_id=assignment_id, worker_id=worker_id)

    # -- missions and grants --------------------------------------------------------------------
    def mission_created(self, grant: MissionGrant) -> AuditEvent:
        return self.emit(AuditEventType.MISSION_CREATED, grant.issuer_identity, grant.mission_id,
                         MissionPayload(state=MissionState.PENDING, revocation_reference=grant.revocation_reference,
                                        objective_digest=canonical_digest(grant.mission_objective)),
                         mission_id=grant.mission_id, grant_id=grant.grant_id)

    def grant_issued(self, grant: MissionGrant) -> AuditEvent:
        meta = grant.signature_metadata
        if meta is None:
            raise ValueError("only signed grants can be recorded as issued")
        return self.emit(AuditEventType.GRANT_ISSUED, grant.issuer_identity, grant.grant_id, GrantIssuedPayload(
            grant_digest=_digest(grant), issuer=grant.issuer_identity, signing_key_id=meta.key_id,
            policy_version=grant.policy_version, permitted_permission_classes=grant.permitted_permission_classes,
            permitted_operation_count=len(grant.permitted_operations),
            maximum_worker_count=grant.maximum_worker_count, issued_at=grant.issued_at,
            expires_at=grant.expires_at, revocation_reference=grant.revocation_reference),
            mission_id=grant.mission_id, grant_id=grant.grant_id)

    def grant_verification(self, grant: MissionGrant, actor: Principal, violation_codes: Iterable[str] = (),
                           detail: str | None = None) -> AuditEvent:
        codes = tuple(dict.fromkeys(str(c) for c in violation_codes))
        return self.emit(AuditEventType.GRANT_VERIFICATION_FAILED if codes else AuditEventType.GRANT_VERIFIED,
                         actor, grant.grant_id, GrantVerificationPayload(
                             outcome=Outcome.FAILED if codes else Outcome.PASSED, grant_digest=_digest(grant),
                             violation_codes=codes, detail=detail[:250] if detail else None),
                         mission_id=grant.mission_id, grant_id=grant.grant_id)

    def mission_status(self, status: MissionStatus, actor: Principal, *, safe_stop: bool = False,
                       stop_condition: Any = None) -> AuditEvent:
        event_type = AuditEventType.SAFE_STOP if safe_stop else _STATE_EVENTS.get(status.state)
        if event_type is None:
            raise ValueError(f"no audit event for mission state {status.state.value}")
        return self.emit(event_type, actor, status.grant_id, MissionPayload(
            state=status.state, revocation_reference=status.revocation_reference, reason=status.reason,
            stop_condition=stop_condition), mission_id=status.mission_id, grant_id=status.grant_id)

    # -- assignments ----------------------------------------------------------------------------
    def assignment_event(self, event_type: AuditEventType, assignment: AgentAssignment, actor: Principal,
                         proposer: Principal | None = None) -> AuditEvent:
        return self.emit(event_type, actor, assignment.assignment_id, _assignment_payload(assignment, proposer),
                         mission_id=assignment.mission_id, grant_id=assignment.grant_id,
                         assignment_id=assignment.assignment_id, worker_id=assignment.worker_id)

    def assignment_rejected(self, grant: MissionGrant, actor: Principal, proposal: Any, violations: Iterable[Any],
                            proposer: Principal | None = None) -> AuditEvent:
        violations = list(violations)
        raw = proposal.model_dump(mode="json", warnings=False) if hasattr(proposal, "model_dump") else proposal
        try:
            proposal_digest = domain_digest("gamis.assignment_proposal.v1", raw)
        except (CanonicalizationError, TypeError):
            proposal_digest = None
        refs = raw if isinstance(raw, dict) else {}
        ident = lambda key: refs.get(key) if isinstance(refs.get(key), str) and len(refs[key]) <= 128 else None  # noqa
        payload = AssignmentRejectedPayload(
            proposal_digest=proposal_digest,
            violation_codes=tuple(dict.fromkeys(v.code.value for v in violations))[:64],
            violation_messages=tuple(v.message[:250] or v.code.value for v in violations)[:64], proposer=proposer)
        try:
            return self.emit(AuditEventType.ASSIGNMENT_REJECTED, actor, ident("assignment_id") or grant.grant_id,
                             payload, mission_id=grant.mission_id, grant_id=grant.grant_id,
                             assignment_id=ident("assignment_id"), worker_id=ident("worker_id"))
        except Exception:
            # attacker-shaped identifiers must not stop the rejection from being recorded
            return self.emit(AuditEventType.ASSIGNMENT_REJECTED, actor, grant.grant_id, payload,
                             mission_id=grant.mission_id, grant_id=grant.grant_id)

    # -- workers and registry -------------------------------------------------------------------
    def worker_event(self, worker: WorkerIdentity, actor: Principal, registered: bool) -> AuditEvent:
        return self.emit(AuditEventType.WORKER_REGISTERED if registered else AuditEventType.WORKER_STATUS_CHANGED,
                         actor, worker.worker_id, WorkerPayload(worker_role=worker.worker_role,
                                                                 enabled=worker.enabled), worker_id=worker.worker_id)

    def tool_registered(self, registry_id: str, revision: int, definition: ToolDefinition,
                        actor: Principal) -> AuditEvent:
        return self.emit(AuditEventType.TOOL_REGISTERED, actor, registry_id, RegistryPayload(
            registry_id=registry_id, registry_version=revision, tool_id=definition.tool_id,
            tool_version=definition.version, definition_digest=canonical_digest(definition.model_dump(mode="json")),
            enabled=definition.enabled_status))

    def tool_status_changed(self, registry_id: str, revision: int, definition: ToolDefinition,
                            actor: Principal) -> AuditEvent:
        return self.emit(AuditEventType.TOOL_STATUS_CHANGED, actor, registry_id, RegistryPayload(
            registry_id=registry_id, registry_version=revision, tool_id=definition.tool_id,
            tool_version=definition.version, definition_digest=canonical_digest(definition.model_dump(mode="json")),
            enabled=definition.enabled_status))

    def registry_sealed(self, snapshot: RegistrySnapshot) -> AuditEvent:
        meta = snapshot.signature_metadata
        return self.emit(AuditEventType.REGISTRY_SEALED, meta.signer_identity, snapshot.registry_id, RegistryPayload(
            registry_id=snapshot.registry_id, registry_version=snapshot.registry_version,
            snapshot_digest=_digest(snapshot)))

    def registry_integrity(self, registry_id: str, actor: Principal, ok: bool, detail: str | None = None,
                           snapshot: RegistrySnapshot | None = None) -> AuditEvent:
        return self.emit(AuditEventType.REGISTRY_INTEGRITY_VERIFIED if ok else
                         AuditEventType.REGISTRY_INTEGRITY_FAILED, actor, registry_id, RegistryPayload(
                             registry_id=registry_id,
                             registry_version=snapshot.registry_version if snapshot else None,
                             snapshot_digest=_digest(snapshot) if snapshot else None,
                             outcome=Outcome.PASSED if ok else Outcome.FAILED, detail=detail[:250] if detail else None))

    # -- tool interaction (metadata only; enforcement is P3/P4) ---------------------------------
    def tool_request(self, request: ToolRequest, actor: Principal) -> AuditEvent:
        return self.emit(AuditEventType.TOOL_REQUEST_RECEIVED, actor, request.correlation_id, ToolRequestPayload(
            request_id=request.request_id, tool_id=request.tool_id, operation_id=request.operation_id,
            request_digest=request.request_digest(), arguments_digest=request.arguments_digest(),
            request_sequence_number=request.sequence_number),
            mission_id=request.mission_id, assignment_id=request.assignment_id, worker_id=request.worker_id)

    def authorization_decision(self, request: ToolRequest, actor: Principal, allowed: bool,
                               reason_codes: Iterable[str] = ()) -> AuditEvent:
        return self.emit(AuditEventType.AUTHORIZATION_DECISION, actor, request.correlation_id, AuthorizationPayload(
            request_id=request.request_id, decision=Decision.ALLOW if allowed else Decision.DENY,
            reason_codes=tuple(dict.fromkeys(reason_codes))),
            mission_id=request.mission_id, assignment_id=request.assignment_id, worker_id=request.worker_id)

    def tool_execution(self, receipt: ToolReceipt) -> AuditEvent:
        meta = receipt.signature_metadata
        return self.emit(AuditEventType.TOOL_EXECUTION_COMPLETED, receipt.gateway_identity, receipt.correlation_id,
                         ToolExecutionPayload(
                             receipt_id=receipt.receipt_id, request_id=receipt.request_id, tool_id=receipt.tool_id,
                             tool_version=receipt.tool_version, operation_id=receipt.operation_id,
                             permission_class=receipt.permission_class, execution_status=receipt.execution_status,
                             result_digest=receipt.result_digest, error_code=receipt.error_code,
                             receipt_digest=_digest(receipt), receipt_signing_key_id=meta.key_id if meta else None),
                         mission_id=receipt.mission_id, assignment_id=receipt.assignment_id,
                         worker_id=receipt.worker_id)
