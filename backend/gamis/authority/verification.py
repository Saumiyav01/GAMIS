"""Independent verification of signed grants and assignments.

Needs only public keys (a TrustStore) - no signer - so the later Secure Tool Gateway can use it as is.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Callable

from gamis.authority.containment import Violation, ViolationCode, check_assignment_within_grant
from gamis.schemas.assignment import AgentAssignment
from gamis.schemas.mission import MissionGrant
from gamis.security.keys import TrustStore
from gamis.security.signing import (DEFAULT_CLOCK_SKEW, SignatureVerificationError, VerifiedSignature,
                                    verify_object)

if TYPE_CHECKING:
    from gamis.audit.recorder import AuditRecorder
    from gamis.schemas.common import Principal

Clock = Callable[[], datetime]


class AssignmentVerificationError(Exception):
    def __init__(self, violations: list[Violation]):
        self.violations = tuple(violations)
        super().__init__("; ".join(f"{v.code.value}: {v.message}" for v in violations))

    @property
    def codes(self) -> set[ViolationCode]:
        return {v.code for v in self.violations}


def grant_time_violations(grant: MissionGrant, now: datetime, skew: timedelta) -> list[Violation]:
    out = []
    if grant.issued_at > now + skew:
        out.append(Violation(ViolationCode.GRANT_NOT_YET_VALID, "grant is not yet valid"))
    if now >= grant.expires_at:
        out.append(Violation(ViolationCode.GRANT_EXPIRED, "grant has expired"))
    return out


def assignment_time_violations(assignment: AgentAssignment, now: datetime, skew: timedelta) -> list[Violation]:
    out = []
    if assignment.issued_at > now + skew:
        out.append(Violation(ViolationCode.ASSIGNMENT_NOT_YET_VALID, "assignment is not yet valid"))
    if now >= assignment.expires_at:
        out.append(Violation(ViolationCode.ASSIGNMENT_EXPIRED, "assignment has expired"))
    return out


class AssignmentVerifier:
    def __init__(self, trust_store: TrustStore, clock: Clock, max_clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
                 recorder: "AuditRecorder | None" = None, actor: "Principal | None" = None):
        if recorder is not None and actor is None:
            raise ValueError("an audited verifier needs an actor principal")
        self._trust_store, self._clock, self._skew = trust_store, clock, max_clock_skew
        self._recorder, self._actor = recorder, actor

    def verify_grant(self, grant: MissionGrant) -> VerifiedSignature:
        try:
            verified = self._verify_grant(grant)
        except AssignmentVerificationError as exc:
            if self._recorder is not None:
                self._recorder.grant_verification(grant, self._actor, [v.code.value for v in exc.violations],
                                                  str(exc)[:250])
            raise
        if self._recorder is not None:
            self._recorder.grant_verification(grant, self._actor)
        return verified

    def _verify_grant(self, grant: MissionGrant) -> VerifiedSignature:
        now = self._clock()
        try:
            verified = verify_object(grant, self._trust_store, now=now, max_clock_skew=self._skew)
        except SignatureVerificationError as exc:
            raise AssignmentVerificationError(
                [Violation(ViolationCode.GRANT_SIGNATURE_INVALID, f"{type(exc).__name__}: {exc}")]) from exc
        if verified.metadata.signer_identity != grant.issuer_identity:
            raise AssignmentVerificationError(
                [Violation(ViolationCode.GRANT_SIGNATURE_INVALID, "grant was not signed by its stated issuer")])
        violations = grant_time_violations(grant, now, self._skew)
        if violations:
            raise AssignmentVerificationError(violations)
        return verified

    def verify(self, assignment: AgentAssignment, grant: MissionGrant | None = None) -> VerifiedSignature:
        """Verify signature and validity window; with ``grant``, also re-check containment."""
        now = self._clock()
        try:
            verified = verify_object(assignment, self._trust_store, now=now, max_clock_skew=self._skew)
        except SignatureVerificationError as exc:
            raise AssignmentVerificationError(
                [Violation(ViolationCode.ASSIGNMENT_SIGNATURE_INVALID, f"{type(exc).__name__}: {exc}")]) from exc
        violations = assignment_time_violations(assignment, now, self._skew)
        if grant is not None:
            self.verify_grant(grant)
            violations += check_assignment_within_grant(assignment, grant)
        if violations:
            raise AssignmentVerificationError(violations)
        return verified
