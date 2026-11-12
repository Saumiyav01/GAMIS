"""Initial Authority Service (P1): validates proposed assignments against a MissionGrant and signs them.

Trust boundary: this is the only component that holds the assignment-signing key. A supervisor (LLM)
may only *propose*; it receives ``AssignmentProposalPort`` and never a signer. The full authorization
engine (budget accounting at run time, approvals workflow, revocation propagation) is P3.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol

from pydantic import ValidationError

from gamis.audit.events import AuditEventType as E
from gamis.authority.containment import Violation, ViolationCode, check_assignment_within_grant
from gamis.authority.directory import (GrantStatusProvider, InMemoryIssuanceLedger, IssuanceLedger,
                                       WorkerDirectory)
from gamis.authority.verification import assignment_time_violations, grant_time_violations
from gamis.schemas.assignment import AgentAssignment
from gamis.schemas.common import MissionState, Principal, PrincipalType
from gamis.schemas.mission import MissionGrant
from gamis.schemas.policy import PolicyVersion
from gamis.schemas.signature import SignedObjectType
from gamis.security.keys import KeyManagementError, KeyStatus, Signer, TrustStore
from gamis.security.signing import DEFAULT_CLOCK_SKEW, SignatureVerificationError, sign_object, verify_object
from gamis.tools.registry import RegistryIntegrityError, RegistryReader

if TYPE_CHECKING:
    from gamis.audit.recorder import AuditRecorder

Clock = Callable[[], datetime]
_V, _C = Violation, ViolationCode


@dataclass(frozen=True)
class AuthorityDecision:
    approved: bool
    violations: tuple[Violation, ...]

    @property
    def codes(self) -> set[ViolationCode]:
        return {v.code for v in self.violations}


class AssignmentRejected(Exception):
    def __init__(self, decision: AuthorityDecision):
        self.decision = decision
        super().__init__("; ".join(f"{v.code.value}: {v.message}" for v in decision.violations))


class AssignmentProposalPort(Protocol):
    """The entire surface a supervisor is given. There is no signing method on it."""

    def issue_assignment(self, proposal: AgentAssignment | Mapping[str, Any], grant: MissionGrant, *,
                         proposer: Principal | None = None) -> AgentAssignment: ...


class AuthorityService:
    def __init__(self, *, signer: Signer, trust_store: TrustStore, registry: RegistryReader,
                 workers: WorkerDirectory, grant_status: GrantStatusProvider, active_policy: PolicyVersion,
                 clock: Clock, ledger: IssuanceLedger | None = None,
                 max_clock_skew: timedelta = DEFAULT_CLOCK_SKEW, recorder: "AuditRecorder | None" = None):
        if signer.principal.principal_type is not PrincipalType.AUTHORITY_SERVICE:
            raise KeyManagementError("the Authority Service requires an AUTHORITY_SERVICE signing key")
        record = trust_store.get(signer.key_id)
        if (record is None or record.status is not KeyStatus.ACTIVE
                or SignedObjectType.AGENT_ASSIGNMENT not in record.allowed_object_types):
            raise KeyManagementError("the Authority Service key is not an active, trusted assignment-signing key")
        self.__signer = signer
        self._trust_store, self._registry, self._workers = trust_store, registry, workers
        self._grant_status, self._policy, self._clock = grant_status, active_policy, clock
        self._ledger = ledger if ledger is not None else InMemoryIssuanceLedger()
        self._skew = max_clock_skew
        self._recorder = recorder   # P2: audit is written BEFORE a signed assignment is released
        self._lock = threading.Lock()

    # -- grant ----------------------------------------------------------------------------------
    def grant_violations(self, grant: MissionGrant, now: datetime | None = None) -> list[Violation]:
        now = now or self._clock()
        try:
            verified = verify_object(grant, self._trust_store, now=now, max_clock_skew=self._skew)
        except SignatureVerificationError as exc:
            return [_V(_C.GRANT_SIGNATURE_INVALID, f"{type(exc).__name__}: {exc}")]
        out: list[Violation] = []
        if verified.metadata.signer_identity != grant.issuer_identity:
            out.append(_V(_C.GRANT_SIGNATURE_INVALID, "grant was not signed by its stated issuer"))
        out += grant_time_violations(grant, now, self._skew)
        if grant.policy_version != self._policy:
            out.append(_V(_C.POLICY_VERSION_MISMATCH, "grant policy version is not the active policy"))
        status = self._grant_status.get(grant.grant_id)
        if (status is None or status.mission_id != grant.mission_id
                or status.revocation_reference != grant.revocation_reference):
            out.append(_V(_C.GRANT_NOT_ACTIVE, "no runtime status is recorded for this grant"))
        elif status.state is MissionState.REVOKED:
            out.append(_V(_C.GRANT_REVOKED, f"grant is revoked: {status.reason}"))
        elif not status.permits_new_assignments:
            out.append(_V(_C.GRANT_NOT_ACTIVE, f"mission state is {status.state.value}"))
        return out

    # -- assignment -----------------------------------------------------------------------------
    def evaluate(self, proposal: AgentAssignment | Mapping[str, Any], grant: MissionGrant) -> AuthorityDecision:
        """Decide without signing or recording anything."""
        return self._evaluate(proposal, grant, self._clock())[0]

    def issue_assignment(self, proposal: AgentAssignment | Mapping[str, Any], grant: MissionGrant, *,
                         proposer: Principal | None = None) -> AgentAssignment:
        """Validate and sign. Raises AssignmentRejected carrying every violation found.

        With a recorder, the proposal, decision and signature are audited; if the audit write fails the
        signed assignment is discarded (fail closed) and the audit error propagates."""
        with self._lock:
            now = self._clock()
            decision, assignment = self._evaluate(proposal, grant, now)
            rec, actor = self._recorder, self.__signer.principal
            if rec is not None and assignment is not None:
                rec.assignment_event(E.ASSIGNMENT_PROPOSED, assignment, proposer or actor, proposer)
            if not decision.approved or assignment is None:
                if rec is not None:
                    grant_codes = [v.code.value for v in decision.violations if v.code.value.startswith("GRANT_")]
                    if grant_codes:
                        rec.grant_verification(grant, actor, grant_codes)
                    rec.assignment_rejected(grant, actor, proposal, decision.violations, proposer)
                raise AssignmentRejected(decision)
            signed = assignment.with_signature(sign_object(assignment, self.__signer, now=now))
            verify_object(signed, self._trust_store, now=now, max_clock_skew=self._skew)
            if rec is not None:
                rec.assignment_event(E.ASSIGNMENT_APPROVED, assignment, actor, proposer)
                rec.assignment_event(E.ASSIGNMENT_SIGNED, signed, actor, proposer)
            self._ledger.record(grant, signed)
            return signed

    def _restore_assignments(self, grant: MissionGrant, assignments: tuple[AgentAssignment, ...]) -> None:
        """Restore signed assignment accounting after restart; this never refreshes or authorizes an assignment."""
        with self._lock:
            violations = self.grant_violations(grant, self._clock())
            if violations:
                raise ValueError(f"cannot restore assignments for an inactive or invalid grant: {violations}")
            issued_method = getattr(self._ledger, "issued", None)
            existing_ids = ({assignment.assignment_id for assignment in issued_method(grant.grant_id)}
                            if callable(issued_method) else set())
            for assignment in assignments:
                if assignment.assignment_id in existing_ids:
                    continue
                try:
                    verify_object(assignment, self._trust_store, now=self._clock(), max_clock_skew=self._skew)
                except SignatureVerificationError as exc:
                    raise ValueError(f"cannot restore unsigned or invalid assignment "
                                     f"{assignment.assignment_id}: {exc}") from exc
                if assignment.mission_id != grant.mission_id or assignment.grant_id != grant.grant_id:
                    raise ValueError("cannot restore an assignment outside the persisted mission grant")
                assignment_violations = (check_assignment_within_grant(assignment, grant)
                                         + self._worker_violations(assignment)
                                         + self._registry_violations(assignment, self._clock()))
                if assignment_violations:
                    raise ValueError(f"cannot restore assignment {assignment.assignment_id}: "
                                     f"{assignment_violations}")
                self._ledger.record(grant, assignment)
                existing_ids.add(assignment.assignment_id)

    def _evaluate(self, proposal, grant, now) -> tuple[AuthorityDecision, AgentAssignment | None]:
        try:
            raw = proposal.model_dump(mode="json", warnings=False) if isinstance(proposal, AgentAssignment) else proposal
            assignment = AgentAssignment.model_validate(raw)
        except (ValidationError, TypeError, AttributeError) as exc:
            detail = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()) \
                if isinstance(exc, ValidationError) else str(exc)
            return AuthorityDecision(False, (_V(_C.MALFORMED_PROPOSAL, detail),)), None
        if assignment.is_signed:
            return AuthorityDecision(False, (_V(_C.PROPOSAL_ALREADY_SIGNED,
                                                "proposals must be unsigned; only the Authority Service signs"),)), None
        violations = self.grant_violations(grant, now)
        if any(v.code is _C.GRANT_SIGNATURE_INVALID for v in violations):
            return AuthorityDecision(False, tuple(violations)), None  # nothing else is trustworthy

        violations += self._worker_violations(assignment)
        violations += check_assignment_within_grant(assignment, grant)
        if assignment.policy_version != self._policy:
            violations.append(_V(_C.POLICY_VERSION_MISMATCH, "assignment policy version is not the active policy"))
        violations += assignment_time_violations(assignment, now, self._skew)
        violations += self._registry_violations(assignment, now)
        violations += self._ledger.check(grant, assignment)
        unique = tuple(dict.fromkeys(violations))
        return AuthorityDecision(not unique, unique), assignment

    def _worker_violations(self, assignment: AgentAssignment) -> list[Violation]:
        worker = self._workers.get(assignment.worker_id)
        if worker is None:
            return [_V(_C.UNKNOWN_WORKER, f"worker {assignment.worker_id} is not registered")]
        out = []
        if not worker.enabled:
            out.append(_V(_C.WORKER_DISABLED, f"worker {worker.worker_id} is disabled"))
        if worker.worker_role != assignment.worker_role:
            out.append(_V(_C.WORKER_ROLE_MISMATCH,
                          f"worker {worker.worker_id} holds role {worker.worker_role}, "
                          f"not {assignment.worker_role}"))
        return out

    def _registry_violations(self, assignment: AgentAssignment, now: datetime) -> list[Violation]:
        try:
            self._registry.verify_integrity(self._trust_store, now)
        except RegistryIntegrityError as exc:
            return [_V(_C.REGISTRY_INTEGRITY, str(exc))]
        out = []
        for tool_id in assignment.permitted_tools:
            definition = self._registry.get(tool_id)
            if definition is None:
                out.append(_V(_C.TOOL_NOT_REGISTERED, f"tool {tool_id} is not registered"))
            elif not definition.enabled_status:
                out.append(_V(_C.TOOL_DISABLED, f"tool {tool_id} is disabled"))
            elif definition.policy_version.policy_id != self._policy.policy_id:
                out.append(_V(_C.POLICY_VERSION_MISMATCH, f"tool {tool_id} is registered under another policy"))
        for perm in assignment.permitted_operations:
            definition = self._registry.get(perm.tool_id)
            if definition is None:
                continue
            operation = definition.operation(perm.operation_id)
            if operation is None:
                out.append(_V(_C.OPERATION_NOT_SUPPORTED, f"{perm.qualified_name} is not a registered operation"))
            elif operation.permission_class is not perm.permission_class:
                # The registry, not the proposal, decides what an operation really is.
                out.append(_V(_C.PERMISSION_CLASS_ESCALATION,
                              f"{perm.qualified_name} is registered as {operation.permission_class.value}, "
                              f"requested as {perm.permission_class.value}"))
        return out
