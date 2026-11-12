"""Typed audit events (P2).

Every event type has exactly one payload model, a fixed event_version, the references it must carry and
(for authority-bearing events) the principal types allowed to emit it. Payloads hold identifiers, digests,
codes and short redacted text - never raw evidence content, keys or credentials.

Hash chain:
    genesis_hash = SHA-256("GAMIS-DIGEST-V1" 0 "gamis.audit_genesis.v1" 0 JCS({ledger_id, created_at, schema_version}))
    event_hash   = SHA-256("GAMIS-DIGEST-V1" 0 "gamis.audit_event.v1"   0 JCS(HASHED_FIELDS of the event))
Event 1 is LEDGER_GENESIS with previous_event_hash = genesis_hash; event N links to event N-1's event_hash.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Mapping, Protocol, Self

from pydantic import AfterValidator, BaseModel, Field, model_validator

from gamis.evidence.sanitize import audit_safe_text
from gamis.schemas.common import (CompletionStatus, ExecutionStatus, Identifier, JsonObject, MissionState,
                                  PermissionClass, Principal, PrincipalType, SemVer, Sha256Hex, ShortText,
                                  SourceType, StoppingConditionType, StrictModel, UtcDatetime)
from gamis.schemas.policy import PolicyVersion
from gamis.security.digest import domain_digest

AUDIT_SCHEMA_VERSION = 1
GENESIS_DOMAIN = "gamis.audit_genesis.v1"
EVENT_HASH_DOMAIN = "gamis.audit_event.v1"
HASHED_FIELDS = ("ledger_id", "event_id", "event_type", "event_version", "mission_id", "grant_id",
                 "assignment_id", "worker_id", "actor_identity", "timestamp", "sequence_number", "correlation_id",
                 "event_payload", "previous_event_hash")

AuditText = Annotated[ShortText, AfterValidator(audit_safe_text)]
Codes = Annotated[tuple[Identifier, ...], Field(max_length=64)]


class AuditCategory(StrEnum):
    LEDGER = "LEDGER"
    MISSION = "MISSION"
    GRANT = "GRANT"
    ASSIGNMENT = "ASSIGNMENT"
    WORKER = "WORKER"
    REGISTRY = "REGISTRY"
    TOOL = "TOOL"
    EVIDENCE = "EVIDENCE"


class AuditEventType(StrEnum):
    LEDGER_GENESIS = "LEDGER_GENESIS"
    CHECKPOINT_CREATED = "CHECKPOINT_CREATED"
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    INTEGRITY_VERIFICATION_FAILED = "INTEGRITY_VERIFICATION_FAILED"
    MISSION_CREATED = "MISSION_CREATED"
    MISSION_ACTIVATED = "MISSION_ACTIVATED"
    MISSION_SUSPENDED = "MISSION_SUSPENDED"
    MISSION_COMPLETED = "MISSION_COMPLETED"
    MISSION_REVOKED = "MISSION_REVOKED"
    SAFE_STOP = "SAFE_STOP"
    MISSION_CHECKPOINT_CREATED = "MISSION_CHECKPOINT_CREATED"
    MISSION_INTERRUPTED = "MISSION_INTERRUPTED"
    MISSION_RESUMED = "MISSION_RESUMED"
    MISSION_CANCELLED = "MISSION_CANCELLED"
    PARTIAL_COMPLETION = "PARTIAL_COMPLETION"
    WORKER_FAILED = "WORKER_FAILED"
    WORKER_RETRIED = "WORKER_RETRIED"
    ACTION_RECONCILIATION_REQUIRED = "ACTION_RECONCILIATION_REQUIRED"
    ACTION_RECONCILED = "ACTION_RECONCILED"
    GRANT_ISSUED = "GRANT_ISSUED"
    GRANT_VERIFIED = "GRANT_VERIFIED"
    GRANT_VERIFICATION_FAILED = "GRANT_VERIFICATION_FAILED"
    ASSIGNMENT_PROPOSED = "ASSIGNMENT_PROPOSED"
    ASSIGNMENT_APPROVED = "ASSIGNMENT_APPROVED"
    ASSIGNMENT_SIGNED = "ASSIGNMENT_SIGNED"
    ASSIGNMENT_REJECTED = "ASSIGNMENT_REJECTED"
    WORKER_REGISTERED = "WORKER_REGISTERED"
    WORKER_STATUS_CHANGED = "WORKER_STATUS_CHANGED"
    TOOL_REGISTERED = "TOOL_REGISTERED"
    TOOL_STATUS_CHANGED = "TOOL_STATUS_CHANGED"
    REGISTRY_SEALED = "REGISTRY_SEALED"
    REGISTRY_INTEGRITY_VERIFIED = "REGISTRY_INTEGRITY_VERIFIED"
    REGISTRY_INTEGRITY_FAILED = "REGISTRY_INTEGRITY_FAILED"
    TOOL_REQUEST_RECEIVED = "TOOL_REQUEST_RECEIVED"
    AUTHORIZATION_DECISION = "AUTHORIZATION_DECISION"
    TOOL_EXECUTION_COMPLETED = "TOOL_EXECUTION_COMPLETED"
    EVIDENCE_STORED = "EVIDENCE_STORED"
    EVIDENCE_BUNDLE_STORED = "EVIDENCE_BUNDLE_STORED"
    EVIDENCE_PERSISTENCE_FAILED = "EVIDENCE_PERSISTENCE_FAILED"
    EVIDENCE_VALIDATED = "EVIDENCE_VALIDATED"
    EVIDENCE_VALIDATION_FAILED = "EVIDENCE_VALIDATION_FAILED"
    EVIDENCE_RETRIEVED = "EVIDENCE_RETRIEVED"


# --- payload models ---------------------------------------------------------------------------

class Outcome(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"


class GenesisPayload(StrictModel):
    ledger_id: Identifier
    genesis_hash: Sha256Hex
    schema_version: Annotated[int, Field(strict=True, ge=1, le=1)]


class CheckpointPayload(StrictModel):
    checkpoint_id: Identifier
    covered_sequence_number: Annotated[int, Field(strict=True, ge=1)]
    head_event_hash: Sha256Hex
    signing_key_id: Identifier
    signing_key_version: Annotated[int, Field(strict=True, ge=1)]


class IntegrityPayload(StrictModel):
    scope: Identifier
    outcome: Outcome
    events_checked: Annotated[int, Field(strict=True, ge=0)]
    last_sequence_number: Annotated[int, Field(strict=True, ge=0)]
    head_event_hash: Sha256Hex | None
    failure_codes: Codes = ()


class MissionPayload(StrictModel):
    state: MissionState
    revocation_reference: Identifier | None = None
    objective_digest: Sha256Hex | None = None   # digest only: objectives may be sensitive
    reason: AuditText | None = None
    stop_condition: StoppingConditionType | None = None


class RecoveryPayload(StrictModel):
    checkpoint_id: Identifier | None = None
    checkpoint_digest: Sha256Hex | None = None
    task_id: Identifier | None = None
    attempt: Annotated[int, Field(strict=True, ge=1)] | None = None
    state: Identifier | None = None
    reason: AuditText | None = None
    evidence_reference_digest: Sha256Hex | None = None


class GrantIssuedPayload(StrictModel):
    grant_digest: Sha256Hex
    issuer: Principal
    signing_key_id: Identifier
    policy_version: PolicyVersion
    permitted_permission_classes: tuple[PermissionClass, ...]
    permitted_operation_count: Annotated[int, Field(strict=True, ge=0)]
    maximum_worker_count: Annotated[int, Field(strict=True, ge=0)]
    issued_at: UtcDatetime
    expires_at: UtcDatetime
    revocation_reference: Identifier


class GrantVerificationPayload(StrictModel):
    outcome: Outcome
    grant_digest: Sha256Hex | None = None
    violation_codes: Codes = ()
    detail: AuditText | None = None


class AssignmentPayload(StrictModel):
    assignment_digest: Sha256Hex
    worker_role: Identifier
    permission_class: PermissionClass
    permitted_operations: Annotated[tuple[ShortText, ...], Field(max_length=1024)]
    policy_version: PolicyVersion
    expires_at: UtcDatetime
    signing_key_id: Identifier | None = None
    signing_key_version: Annotated[int, Field(strict=True, ge=1)] | None = None
    proposer: Principal | None = None


class AssignmentRejectedPayload(StrictModel):
    proposal_digest: Sha256Hex | None
    violation_codes: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=64)]
    violation_messages: Annotated[tuple[AuditText, ...], Field(max_length=64)]
    proposer: Principal | None = None


class WorkerPayload(StrictModel):
    worker_role: Identifier
    enabled: bool


class RegistryPayload(StrictModel):
    registry_id: Identifier
    registry_version: Annotated[int, Field(strict=True, ge=0)] | None = None
    tool_id: Identifier | None = None
    tool_version: SemVer | None = None
    definition_digest: Sha256Hex | None = None
    snapshot_digest: Sha256Hex | None = None
    enabled: bool | None = None
    outcome: Outcome | None = None
    detail: AuditText | None = None


class ToolRequestPayload(StrictModel):
    request_id: Identifier
    tool_id: Identifier
    operation_id: Identifier
    request_digest: Sha256Hex
    arguments_digest: Sha256Hex    # arguments themselves are never copied into the ledger
    request_sequence_number: Annotated[int, Field(strict=True, ge=0)]


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthorizationPayload(StrictModel):
    request_id: Identifier
    decision: Decision
    reason_codes: Codes = ()


class ToolExecutionPayload(StrictModel):
    receipt_id: Identifier
    request_id: Identifier
    tool_id: Identifier
    tool_version: SemVer
    operation_id: Identifier
    permission_class: PermissionClass
    execution_status: ExecutionStatus
    result_digest: Sha256Hex | None
    error_code: Identifier | None
    receipt_digest: Sha256Hex
    receipt_signing_key_id: Identifier | None


class EvidenceStoredPayload(StrictModel):
    evidence_id: Identifier
    record_digest: Sha256Hex
    integrity_digest: Sha256Hex
    source_type: SourceType
    content_storage: Identifier                 # cas | external-reference
    content_size_bytes: Annotated[int, Field(strict=True, ge=0)] | None
    receipt_id: Identifier | None
    sanitization_finding_counts: Mapping[Identifier, Annotated[int, Field(strict=True, ge=0)]]
    contains_suspicious_instructions: bool


class EvidenceBundlePayload(StrictModel):
    evidence_bundle_id: Identifier
    bundle_digest: Sha256Hex
    signed: bool
    signing_key_id: Identifier | None
    completion_status: CompletionStatus
    claim_count: Annotated[int, Field(strict=True, ge=0)]
    evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=4096)]
    supporting_evidence_count: Annotated[int, Field(strict=True, ge=0)]
    contradicting_evidence_count: Annotated[int, Field(strict=True, ge=0)]
    disputed_claim_count: Annotated[int, Field(strict=True, ge=0)]
    referenced_tool_receipts: Annotated[tuple[Identifier, ...], Field(max_length=4096)]


class EvidenceFailurePayload(StrictModel):
    subject_id: Identifier
    subject_kind: Identifier                    # item | bundle | receipt
    error_type: Identifier
    detail: AuditText


class EvidenceValidationPayload(StrictModel):
    subject_id: Identifier
    subject_kind: Identifier
    outcome: Outcome
    failure_codes: Codes = ()


class EvidenceRetrievedPayload(StrictModel):
    subject_id: Identifier
    subject_kind: Identifier
    purpose: AuditText


_M, _G, _A, _W = "mission_id", "grant_id", "assignment_id", "worker_id"
_T = PrincipalType
# event type -> (payload model, required reference fields, allowed actor types or None for any)
EVENT_SPECS: dict[AuditEventType, tuple[type[StrictModel], tuple[str, ...], frozenset[PrincipalType] | None]] = {
    AuditEventType.LEDGER_GENESIS: (GenesisPayload, (), frozenset({_T.AUDIT_SERVICE})),
    AuditEventType.CHECKPOINT_CREATED: (CheckpointPayload, (), frozenset({_T.AUDIT_SERVICE})),
    AuditEventType.INTEGRITY_VERIFIED: (IntegrityPayload, (), None),
    AuditEventType.INTEGRITY_VERIFICATION_FAILED: (IntegrityPayload, (), None),
    AuditEventType.MISSION_CREATED: (MissionPayload, (_M,), frozenset({_T.MISSION_ISSUER})),
    AuditEventType.MISSION_ACTIVATED: (MissionPayload, (_M, _G), None),
    AuditEventType.MISSION_SUSPENDED: (MissionPayload, (_M, _G), None),
    AuditEventType.MISSION_COMPLETED: (MissionPayload, (_M, _G), None),
    AuditEventType.MISSION_REVOKED: (MissionPayload, (_M, _G), None),
    AuditEventType.SAFE_STOP: (MissionPayload, (_M,), None),
    AuditEventType.MISSION_CHECKPOINT_CREATED: (RecoveryPayload, (_M, _G), None),
    AuditEventType.MISSION_INTERRUPTED: (RecoveryPayload, (_M, _G), None),
    AuditEventType.MISSION_RESUMED: (RecoveryPayload, (_M, _G), None),
    AuditEventType.MISSION_CANCELLED: (RecoveryPayload, (_M, _G), None),
    AuditEventType.PARTIAL_COMPLETION: (RecoveryPayload, (_M, _G), None),
    AuditEventType.WORKER_FAILED: (RecoveryPayload, (_M, _G), None),
    AuditEventType.WORKER_RETRIED: (RecoveryPayload, (_M, _G, _A, _W), None),
    AuditEventType.ACTION_RECONCILIATION_REQUIRED: (RecoveryPayload, (_M, _G, _A, _W), None),
    AuditEventType.ACTION_RECONCILED: (RecoveryPayload, (_M, _G), None),
    AuditEventType.GRANT_ISSUED: (GrantIssuedPayload, (_M, _G), frozenset({_T.MISSION_ISSUER})),
    AuditEventType.GRANT_VERIFIED: (GrantVerificationPayload, (_M, _G), None),
    AuditEventType.GRANT_VERIFICATION_FAILED: (GrantVerificationPayload, (_M, _G), None),
    AuditEventType.ASSIGNMENT_PROPOSED: (AssignmentPayload, (_M, _G, _A, _W), None),
    AuditEventType.ASSIGNMENT_APPROVED: (AssignmentPayload, (_M, _G, _A, _W), frozenset({_T.AUTHORITY_SERVICE})),
    AuditEventType.ASSIGNMENT_SIGNED: (AssignmentPayload, (_M, _G, _A, _W), frozenset({_T.AUTHORITY_SERVICE})),
    AuditEventType.ASSIGNMENT_REJECTED: (AssignmentRejectedPayload, (_M, _G), frozenset({_T.AUTHORITY_SERVICE})),
    AuditEventType.WORKER_REGISTERED: (WorkerPayload, (_W,), None),
    AuditEventType.WORKER_STATUS_CHANGED: (WorkerPayload, (_W,), None),
    AuditEventType.TOOL_REGISTERED: (RegistryPayload, (), frozenset({_T.REGISTRY_ADMIN})),
    AuditEventType.TOOL_STATUS_CHANGED: (RegistryPayload, (), frozenset({_T.REGISTRY_ADMIN})),
    AuditEventType.REGISTRY_SEALED: (RegistryPayload, (), frozenset({_T.REGISTRY_ADMIN})),
    AuditEventType.REGISTRY_INTEGRITY_VERIFIED: (RegistryPayload, (), None),
    AuditEventType.REGISTRY_INTEGRITY_FAILED: (RegistryPayload, (), None),
    AuditEventType.TOOL_REQUEST_RECEIVED: (ToolRequestPayload, (_M, _A, _W), None),
    AuditEventType.AUTHORIZATION_DECISION: (AuthorizationPayload, (_M, _A, _W), None),
    AuditEventType.TOOL_EXECUTION_COMPLETED: (ToolExecutionPayload, (_M, _A, _W), frozenset({_T.TOOL_GATEWAY})),
    AuditEventType.EVIDENCE_STORED: (EvidenceStoredPayload, (_M, _A, _W), None),
    AuditEventType.EVIDENCE_BUNDLE_STORED: (EvidenceBundlePayload, (_M, _A, _W), None),
    AuditEventType.EVIDENCE_PERSISTENCE_FAILED: (EvidenceFailurePayload, (), None),
    AuditEventType.EVIDENCE_VALIDATED: (EvidenceValidationPayload, (), None),
    AuditEventType.EVIDENCE_VALIDATION_FAILED: (EvidenceValidationPayload, (), None),
    AuditEventType.EVIDENCE_RETRIEVED: (EvidenceRetrievedPayload, (), None),
}
EVENT_VERSIONS = {t: 1 for t in AuditEventType}
_CATEGORY_PREFIXES = (("LEDGER", AuditCategory.LEDGER), ("CHECKPOINT", AuditCategory.LEDGER),
                      ("INTEGRITY", AuditCategory.LEDGER), ("MISSION", AuditCategory.MISSION),
                      ("SAFE_STOP", AuditCategory.MISSION), ("PARTIAL", AuditCategory.MISSION),
                      ("WORKER", AuditCategory.WORKER), ("ACTION", AuditCategory.TOOL),
                      ("GRANT", AuditCategory.GRANT),
                      ("ASSIGNMENT", AuditCategory.ASSIGNMENT), ("WORKER", AuditCategory.WORKER),
                      ("REGISTRY", AuditCategory.REGISTRY), ("TOOL_REGISTERED", AuditCategory.REGISTRY),
                      ("TOOL_STATUS", AuditCategory.REGISTRY), ("TOOL", AuditCategory.TOOL),
                      ("AUTHORIZATION", AuditCategory.TOOL), ("EVIDENCE", AuditCategory.EVIDENCE))
assert set(EVENT_SPECS) == set(AuditEventType)


def category_of(event_type: AuditEventType) -> AuditCategory:
    return next(c for prefix, c in _CATEGORY_PREFIXES if event_type.value.startswith(prefix))


def normalize_payload(event_type: AuditEventType, payload: Any) -> dict[str, Any]:
    """Validate a payload against its event type's model and return its canonical JSON form."""
    model = EVENT_SPECS[event_type][0]
    if isinstance(payload, BaseModel):
        if not isinstance(payload, model):
            raise ValueError(f"{event_type.value} requires a {model.__name__} payload, got {type(payload).__name__}")
        payload = payload.model_dump(mode="json")
    if not isinstance(payload, Mapping):
        raise ValueError("event_payload must be an object")
    return model.model_validate(dict(payload)).model_dump(mode="json")


def genesis_hash(ledger_id: str, created_at: str) -> str:
    return domain_digest(GENESIS_DOMAIN, {"ledger_id": ledger_id, "created_at": created_at,
                                          "schema_version": AUDIT_SCHEMA_VERSION})


def new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex}"


# --- events -----------------------------------------------------------------------------------

class AuditEventDraft(StrictModel):
    """What emitters submit. The ledger assigns sequence number, timestamp and hashes."""

    event_type: AuditEventType
    actor_identity: Principal
    correlation_id: Identifier
    event_payload: JsonObject
    mission_id: Identifier | None = None
    grant_id: Identifier | None = None
    assignment_id: Identifier | None = None
    worker_id: Identifier | None = None
    event_id: Identifier | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize(cls, data: Any) -> Any:
        if isinstance(data, Mapping) and "event_type" in data and "event_payload" in data:
            data = dict(data)
            data["event_payload"] = normalize_payload(AuditEventType(data["event_type"]), data["event_payload"])
        return data

    @model_validator(mode="after")
    def _check(self) -> Self:
        _check_refs_and_actor(self)
        return self


def _check_refs_and_actor(event: Any) -> None:
    _, required, actors = EVENT_SPECS[event.event_type]
    missing = [name for name in required if getattr(event, name) is None]
    if missing:
        raise ValueError(f"{event.event_type.value} requires {missing}")
    if actors is not None and event.actor_identity.principal_type not in actors:
        raise ValueError(f"{event.actor_identity.principal_type.value} may not emit {event.event_type.value}")


class AuditEventBody(StrictModel):
    """All hashed fields of an event."""

    ledger_id: Identifier
    event_id: Identifier
    event_type: AuditEventType
    event_version: Annotated[int, Field(strict=True, ge=1, le=1_000)]
    mission_id: Identifier | None
    grant_id: Identifier | None
    assignment_id: Identifier | None
    worker_id: Identifier | None
    actor_identity: Principal
    timestamp: UtcDatetime
    sequence_number: Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]
    correlation_id: Identifier
    event_payload: JsonObject
    previous_event_hash: Sha256Hex

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.event_version != EVENT_VERSIONS[self.event_type]:
            raise ValueError(f"unsupported event_version {self.event_version} for {self.event_type.value}")
        if normalize_payload(self.event_type, self.event_payload) != _thaw(self.event_payload):
            raise ValueError("event_payload is not in validated canonical form")
        if (self.event_type is AuditEventType.LEDGER_GENESIS) != (self.sequence_number == 1):
            raise ValueError("LEDGER_GENESIS must be exactly the first event")
        _check_refs_and_actor(self)
        return self

    def hashed_content(self) -> dict[str, Any]:
        data = self.model_dump(mode="json", include=set(HASHED_FIELDS))
        assert set(data) == set(HASHED_FIELDS)
        return data

    def compute_hash(self) -> str:
        return domain_digest(EVENT_HASH_DOMAIN, self.hashed_content())


class AuditEvent(AuditEventBody):
    event_hash: Sha256Hex

    @model_validator(mode="after")
    def _check_hash(self) -> Self:
        if self.compute_hash() != self.event_hash:
            raise ValueError("event_hash does not match the event content")
        return self

    @property
    def category(self) -> AuditCategory:
        return category_of(self.event_type)


def build_event(draft: AuditEventDraft, *, ledger_id: str, sequence_number: int, previous_event_hash: str,
                timestamp: datetime) -> AuditEvent:
    body = AuditEventBody(
        ledger_id=ledger_id, event_id=draft.event_id or new_event_id(), event_type=draft.event_type,
        event_version=EVENT_VERSIONS[draft.event_type], mission_id=draft.mission_id, grant_id=draft.grant_id,
        assignment_id=draft.assignment_id, worker_id=draft.worker_id, actor_identity=draft.actor_identity,
        timestamp=timestamp, sequence_number=sequence_number, correlation_id=draft.correlation_id,
        event_payload=_thaw(draft.event_payload), previous_event_hash=previous_event_hash)
    return AuditEvent(**{k: getattr(body, k) for k in AuditEventBody.model_fields}, event_hash=body.compute_hash())


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(v) for v in value]
    return value


class AuditSink(Protocol):
    """The only interface emitters (authority, registry, evidence, later gateway/workers) depend on."""

    def append_event(self, draft: AuditEventDraft) -> AuditEvent: ...
