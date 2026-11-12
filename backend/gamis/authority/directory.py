"""Collaborator interfaces of the Authority Service with in-memory implementations.

Durable implementations (database-backed) belong to P2; the protocols are what later phases implement.
"""
from __future__ import annotations

import threading
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

from gamis.authority.containment import Violation, ViolationCode
from gamis.schemas.assignment import AgentAssignment, WorkerIdentity
from gamis.schemas.common import MissionState
from gamis.schemas.mission import MissionGrant, MissionStatus
from gamis.schemas.common import Principal
from gamis.schemas.policy import ResourceLimits

if TYPE_CHECKING:
    from gamis.audit.recorder import AuditRecorder


class WorkerDirectory(Protocol):
    def get(self, worker_id: str) -> WorkerIdentity | None: ...


class GrantStatusProvider(Protocol):
    def get(self, grant_id: str) -> MissionStatus | None: ...


class IssuanceLedger(Protocol):
    def check(self, grant: MissionGrant, assignment: AgentAssignment) -> list[Violation]: ...
    def record(self, grant: MissionGrant, assignment: AgentAssignment) -> None: ...


class InMemoryWorkerDirectory:
    def __init__(self, workers: tuple[WorkerIdentity, ...] = ()):
        self._workers = {w.worker_id: w for w in workers}

    def register(self, worker: WorkerIdentity) -> None:
        self._workers[worker.worker_id] = worker.revalidate()

    def get(self, worker_id: str) -> WorkerIdentity | None:
        return self._workers.get(worker_id)


class InMemoryGrantStatusStore:
    """Mutable runtime state lives here, never on the signed grant."""

    def __init__(self, recorder: "AuditRecorder | None" = None, actor: Principal | None = None) -> None:
        if recorder is not None and actor is None:
            raise ValueError("an audited status store needs an actor principal")
        self._status: dict[str, MissionStatus] = {}
        self._recorder, self._actor = recorder, actor

    def _audit(self, status: MissionStatus, **kwargs: object) -> None:
        if self._recorder is not None:   # audited before the change takes effect
            self._recorder.mission_status(status, self._actor, **kwargs)

    def activate(self, grant: MissionGrant, now: datetime) -> MissionStatus:
        status = MissionStatus(mission_id=grant.mission_id, grant_id=grant.grant_id,
                               revocation_reference=grant.revocation_reference, state=MissionState.ACTIVE,
                               updated_at=now)
        self._audit(status)
        self._status[grant.grant_id] = status
        return status

    def set_state(self, grant_id: str, state: MissionState, now: datetime, reason: str | None = None) -> MissionStatus:
        current = self._status[grant_id]
        updated = MissionStatus.model_validate({**current.model_dump(mode="json"), "state": state,
                                                "reason": reason, "updated_at": now})
        self._audit(updated)
        self._status[grant_id] = updated
        return updated

    def revoke(self, grant_id: str, now: datetime, reason: str) -> MissionStatus:
        return self.set_state(grant_id, MissionState.REVOKED, now, reason)

    def safe_stop(self, grant_id: str, now: datetime, reason: str, condition: object = None) -> MissionStatus:
        """Suspend the mission and record a SAFE_STOP event (e.g. a stopping condition fired)."""
        current = self._status[grant_id]
        updated = MissionStatus.model_validate({**current.model_dump(mode="json"), "state": MissionState.SUSPENDED,
                                                "reason": reason, "updated_at": now})
        self._audit(updated, safe_stop=True, stop_condition=condition)
        self._status[grant_id] = updated
        return updated

    def get(self, grant_id: str) -> MissionStatus | None:
        return self._status.get(grant_id)


class InMemoryIssuanceLedger:
    """Tracks what has been issued per grant so the sum of assignments stays within the grant."""

    def __init__(self) -> None:
        self._issued: dict[str, dict[str, AgentAssignment]] = {}
        self._lock = threading.Lock()

    def issued(self, grant_id: str) -> tuple[AgentAssignment, ...]:
        return tuple(self._issued.get(grant_id, {}).values())

    def check(self, grant: MissionGrant, assignment: AgentAssignment) -> list[Violation]:
        out: list[Violation] = []
        existing = self._issued.get(grant.grant_id, {})
        if assignment.assignment_id in existing:
            out.append(Violation(ViolationCode.DUPLICATE_ASSIGNMENT,
                                 f"assignment {assignment.assignment_id} was already issued"))
        workers = {a.worker_id for a in existing.values()} | {assignment.worker_id}
        if len(workers) > grant.maximum_worker_count:
            out.append(Violation(ViolationCode.WORKER_COUNT_EXCEEDED,
                                 f"grant allows at most {grant.maximum_worker_count} workers"))
        for dimension in ResourceLimits.ADDITIVE:
            total = sum(getattr(a.resource_limits, dimension) for a in existing.values())
            total += getattr(assignment.resource_limits, dimension)
            if total > getattr(grant.global_resource_limits, dimension):
                out.append(Violation(ViolationCode.RESOURCE_LIMIT_EXCEEDED,
                                     f"cumulative {dimension} across assignments exceeds the grant ceiling"))
        return out

    def record(self, grant: MissionGrant, assignment: AgentAssignment) -> None:
        with self._lock:
            self._issued.setdefault(grant.grant_id, {})[assignment.assignment_id] = assignment
