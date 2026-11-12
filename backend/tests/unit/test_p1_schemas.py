"""P1 schema tests: strict validation, bounds, timestamps, deny-by-default, immutability."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from gamis.schemas import (AgentAssignment, EvidenceBundle, EvidenceItem, FrozenDict, MissionGrant, MissionState,
                           MissionStatus, PermissionClass, ResourceLimits, ToolReceipt, ToolRequest)
from gamis.security.digest import canonical_digest
from gamis.tools.receipts import request_problems
from gamis.tools.sample_registry import sample_tool_definitions
from tests.p1_support import (ACTION_OP, NOW, POLICY, READ_OPS, assignment_dict, bundle_dict, evidence_item_dict,
                              grant_dict, iso, receipt_dict, request_dict)

LIMITS = {"max_tool_calls": 10, "max_wall_clock_seconds": 60, "max_tokens": 100, "max_cost_units": 10,
          "max_evidence_bytes": 1000}


def without(data: dict, key: str) -> dict:
    return {k: v for k, v in data.items() if k != key}


def rejects(model, data, match: str | None = None):
    with pytest.raises(ValidationError, match=match):
        model.model_validate(data)


# --- MissionGrant -------------------------------------------------------------------------------

def test_valid_mission_grant():
    grant = MissionGrant.model_validate(grant_dict())
    assert grant.permitted_permission_classes == (PermissionClass.READ, PermissionClass.ACTION)
    assert grant.permission_for("log_search", "search").permission_class is PermissionClass.READ
    assert grant.permission_for("log_search", "delete") is None
    assert grant.issued_at.tzinfo is timezone.utc and not grant.is_signed


@pytest.mark.parametrize("overrides,match", [
    ({"permitted_operations": [{"tool_id": "other_tool", "operation_id": "x", "permission_class": "READ"}]},
     "not permitted"),
    ({"permitted_permission_classes": ["READ"]}, "permission class is not granted"),
    ({"approval_requirements": []}, "ACTION approval requirement"),
    ({"permitted_tools": ["log_search", "intel_lookup", "case_action", "unused_tool"]}, "without any permitted"),
    ({"expires_at": iso(NOW - timedelta(hours=2))}, "expires_at must be after"),
    ({"expires_at": iso(NOW + timedelta(days=400))}, "lifetime"),
    ({"issued_at": "2026-01-10T08:00:00"}, "timestamp"),            # naive
    ({"issued_at": 1767945600}, "timestamp"),                       # numeric epoch
    ({"issued_at": datetime(2026, 1, 10, 8, 0)}, None),             # naive datetime object
    ({"issuer_identity": {"principal_id": "sup-1", "principal_type": "SUPERVISOR"}}, "MISSION_ISSUER"),
    ({"maximum_worker_count": "3"}, None),
    ({"maximum_worker_count": True}, None),
    ({"maximum_worker_count": -1}, None),
    ({"maximum_worker_count": 10**9}, None),
    ({"permitted_roles": ["evidence-reader", "evidence-reader"]}, "duplicate"),
    ({"permitted_permission_classes": ["read", "ACTION"]}, None),
    ({"permitted_permission_classes": ["READ", "ACTION", "ADMIN"]}, None),
    ({"permitted_permission_classes": [b"READ", "ACTION"]}, "binary"),
    ({"permitted_tools": "log_search"}, None),
    ({"authorized_scope": []}, None),
    ({"mission_id": "bad id with spaces"}, None),
    ({"mission_id": "MIS-001\n"}, None),
    ({"unexpected_field": 1}, "Extra inputs"),
    ({"global_resource_limits": {**LIMITS, "max_tool_calls": -5}}, None),
])
def test_invalid_mission_grant(overrides, match):
    rejects(MissionGrant, grant_dict(**overrides), match)


@pytest.mark.parametrize("field", ["permitted_tools", "permitted_operations", "permitted_permission_classes",
                                   "global_resource_limits", "expires_at", "policy_version", "issuer_identity",
                                   "revocation_reference", "maximum_worker_count"])
def test_mission_grant_has_no_implicit_defaults(field):
    rejects(MissionGrant, without(grant_dict(), field), "Field required")


def test_grant_with_nothing_permitted_is_valid_and_permits_nothing():
    grant = MissionGrant.model_validate(grant_dict(permitted_tools=[], permitted_operations=[], permitted_roles=[],
                                                   permitted_permission_classes=[], approval_requirements=[]))
    assert grant.permitted_operations == () and grant.permission_for("log_search", "search") is None


def test_timestamps_are_normalised_to_utc():
    a = MissionGrant.model_validate(grant_dict(issued_at="2026-01-10T13:30:00+05:30"))
    b = MissionGrant.model_validate(grant_dict(issued_at="2026-01-10T08:00:00Z"))
    assert a.issued_at == b.issued_at
    assert canonical_digest(a.signed_payload()) == canonical_digest(b.signed_payload())
    assert a.model_dump(mode="json")["issued_at"] == "2026-01-10T08:00:00.000000Z"


def test_signed_content_is_separate_from_runtime_status():
    assert "signature_metadata" not in MissionGrant.signed_field_names()
    assert set(MissionGrant.signed_field_names()) == set(MissionGrant.model_fields) - {"signature_metadata"}
    assert not {"state", "revoked", "status"} & set(MissionGrant.model_fields)
    status = MissionStatus(mission_id="MIS-001", grant_id="GRANT-001", revocation_reference="REV-1",
                           state=MissionState.ACTIVE, updated_at=NOW)
    status.state = MissionState.COMPLETED                      # runtime status is mutable ...
    with pytest.raises(ValidationError):
        status.state = "NOT_A_STATE"                           # ... but still validated
    with pytest.raises(ValidationError, match="requires a reason"):
        MissionStatus(mission_id="M", grant_id="G", revocation_reference="R", state=MissionState.REVOKED,
                      updated_at=NOW)


def test_signed_models_are_immutable():
    grant = MissionGrant.model_validate(grant_dict())
    with pytest.raises(ValidationError, match="frozen"):
        grant.maximum_worker_count = 99
    assert isinstance(grant.permitted_tools, tuple)
    with pytest.raises(ValidationError, match="frozen"):
        grant.global_resource_limits.max_tool_calls = 10**5
    request = ToolRequest.model_validate(request_dict(arguments={"host": "web-01", "nested": {"a": [1, 2]}}))
    assert isinstance(request.arguments, FrozenDict) and isinstance(request.arguments["nested"]["a"], tuple)
    for mutate in (lambda: request.arguments.update(host="x"), lambda: request.arguments.pop("host"),
                   lambda: request.arguments["nested"].__setitem__("a", 1)):
        with pytest.raises(TypeError, match="immutable"):
            mutate()


# --- AgentAssignment ----------------------------------------------------------------------------

def test_valid_agent_assignment():
    a = AgentAssignment.model_validate(assignment_dict())
    assert a.permission_class is PermissionClass.READ and a.signature_metadata is None
    assert a.permission_for("log_search", "search") is not None and a.permission_for("case_action", "execute") is None


@pytest.mark.parametrize("value", ["read", "Read", "READ ", "WRITE", "", None, 1, True, ["READ", "ACTION"],
                                   {"READ": True}, b"READ", b"ACTION"])
def test_invalid_permission_values(value):
    rejects(AgentAssignment, assignment_dict(permission_class=value))
    op = {"tool_id": "log_search", "operation_id": "search", "permission_class": value}
    rejects(AgentAssignment, assignment_dict(permitted_operations=[op]))


def test_permission_class_has_no_default():
    rejects(AgentAssignment, without(assignment_dict(), "permission_class"), "Field required")
    op = {"tool_id": "log_search", "operation_id": "search"}
    rejects(AgentAssignment, assignment_dict(permitted_operations=[op]), "Field required")


@pytest.mark.parametrize("overrides", [
    {"permitted_tools": ["case_action"], "permitted_operations": [ACTION_OP],
     "tool_call_limits": [{"tool_id": "case_action", "max_calls": 1}], "forbidden_actions": []},
    {"permitted_tools": ["log_search", "case_action"], "permitted_operations": [READ_OPS[0], ACTION_OP],
     "tool_call_limits": [{"tool_id": "log_search", "max_calls": 1}, {"tool_id": "case_action", "max_calls": 1}],
     "forbidden_actions": []},
])
def test_read_assignment_cannot_hold_action_operations(overrides):
    rejects(AgentAssignment, assignment_dict(**overrides), "READ assignment cannot hold ACTION")


@pytest.mark.parametrize("extra", [{"can_execute_actions": True}, {"permission_classes": ["READ", "ACTION"]},
                                   {"is_admin": True}, {"action_enabled": "true"}])
def test_malformed_escalation_fields_are_rejected(extra):
    rejects(AgentAssignment, assignment_dict(**extra), "Extra inputs")


@pytest.mark.parametrize("overrides,match", [
    ({"tool_call_limits": []}, "exactly the permitted tools"),
    ({"tool_call_limits": [{"tool_id": "log_search", "max_calls": 21}]}, "exceeds resource_limits"),
    ({"permitted_operations": []}, "without any permitted operation"),
    ({"permitted_operations": [READ_OPS[1]]}, "not permitted"),
    ({"stopping_conditions": []}, None),
    ({"success_criteria": []}, None),
    ({"expires_at": iso(NOW)}, "expires_at must be after"),
    ({"forbidden_actions": ["log_search:search"]}, "both permitted and forbidden"),
    ({"stopping_conditions": [{"condition_id": "c", "condition_type": "CONSECUTIVE_FAILURES",
                               "description": "d"}]}, "requires a threshold"),
    ({"permission_class": "ACTION"}, "at least one ACTION operation"),
    ({"task_objective": "   "}, None),
    ({"worker_id": ""}, None),
])
def test_invalid_agent_assignment(overrides, match):
    rejects(AgentAssignment, assignment_dict(**overrides), match)


@pytest.mark.parametrize("field,value", [
    ("max_tool_calls", -1), ("max_tool_calls", 100_001), ("max_tool_calls", "10"), ("max_tool_calls", 10.0),
    ("max_tool_calls", True), ("max_tool_calls", None), ("max_wall_clock_seconds", 0),
    ("max_wall_clock_seconds", 604_801), ("max_tokens", 10**10), ("max_cost_units", -1),
    ("max_evidence_bytes", float("inf")),
])
def test_invalid_resource_limits(field, value):
    rejects(ResourceLimits, {**LIMITS, field: value})
    rejects(AgentAssignment, assignment_dict(resource_limits={**LIMITS, field: value}))


def test_resource_limits_have_no_implicit_unlimited():
    for field in LIMITS:
        rejects(ResourceLimits, without(LIMITS, field), "Field required")
    rejects(ResourceLimits, {**LIMITS, "max_gpu_hours": 1}, "Extra inputs")
    small, big = ResourceLimits(**LIMITS), ResourceLimits(**{**LIMITS, "max_tokens": 101})
    assert small.exceeded_dimensions(big) == () and big.exceeded_dimensions(small) == ("max_tokens",)


# --- EvidenceBundle -----------------------------------------------------------------------------

def test_valid_evidence_bundle():
    bundle = EvidenceBundle.model_validate(bundle_dict())
    assert bundle.claims[0].supporting_evidence_ids == ("EV-1",)
    assert bundle.evidence_items[0].integrity_digest == canonical_digest(bundle.evidence_items[0].content)


@pytest.mark.parametrize("overrides,match", [
    ({"claims": [{"claim_id": "C", "statement": "s", "supporting_evidence_ids": ["EV-404"],
                  "contradicting_evidence_ids": [], "confidence": 0.5, "rationale": "r"}]}, "unknown evidence"),
    ({"claims": [{"claim_id": "C", "statement": "s", "supporting_evidence_ids": [],
                  "contradicting_evidence_ids": [], "confidence": 0.5, "rationale": "r"}]}, "no supporting evidence"),
    ({"claims": [{"claim_id": "C", "statement": "s", "supporting_evidence_ids": ["EV-1"],
                  "contradicting_evidence_ids": ["EV-1"], "confidence": 0.5, "rationale": "r"}]}, "both support"),
    ({"claims": [{"claim_id": "C", "statement": "s", "supporting_evidence_ids": ["EV-1"],
                  "contradicting_evidence_ids": [], "confidence": 0.5}]}, "Field required"),          # no rationale
    ({"supporting_evidence": []}, "missing from supporting_evidence"),
    ({"contradicting_evidence": ["EV-9"]}, "unknown evidence"),
    ({"referenced_tool_receipts": []}, "not in referenced_tool_receipts"),
    ({"referenced_tool_receipts": ["RCPT-1", "RCPT-2"]}, "must equal the receipts"),
    ({"evidence_items": [evidence_item_dict(), evidence_item_dict()]}, "duplicate"),
    ({"confidence": 1.5}, None), ({"confidence": -0.1}, None), ({"confidence": "0.8"}, None),
    ({"confidence": float("nan")}, None),
    ({"completion_status": "done"}, None),
    ({"generated_at": "yesterday"}, "timestamp"),
    ({"worker_id": "someone-else"}, "collected_by"),
    ({"tool_call_history": [{"sequence_number": 0, "request_id": "REQ-1", "receipt_id": "RCPT-1",
                             "tool_id": "log_search", "operation_id": "search", "execution_status": "OK",
                             "requested_at": iso(NOW)}]}, None),
])
def test_malformed_evidence_bundle(overrides, match):
    rejects(EvidenceBundle, bundle_dict(**overrides), match)


def test_missing_provenance_is_rejected():
    rejects(EvidenceBundle, without(bundle_dict(), "provenance"), "Field required")
    rejects(EvidenceItem, without(evidence_item_dict(), "provenance"), "Field required")
    rejects(EvidenceBundle, bundle_dict(evidence_items=[without(evidence_item_dict(), "provenance")]),
            "Field required")
    item = evidence_item_dict()
    rejects(EvidenceItem, {**item, "provenance": {**item["provenance"], "receipt_id": None}}, "requires receipt_id")
    rejects(EvidenceItem, {**item, "provenance": {**item["provenance"], "source_type": "DERIVED",
                                                  "receipt_id": None}}, "requires derived_from")


@pytest.mark.parametrize("overrides,match", [
    ({"integrity_digest": "0" * 64}, "integrity_digest does not match"),
    ({"integrity_digest": "ABC"}, None),
    ({"content": None}, "content or content_reference"),
    ({"receipt_id": None}, "requires receipt_id"),
    ({"receipt_id": "RCPT-OTHER"}, "must match provenance"),
    ({"source_type": "DOCUMENT"}, "must match source_type"),
    ({"content": {"when": datetime(2026, 1, 1, tzinfo=timezone.utc)}}, "not JSON data"),
])
def test_malformed_evidence_item(overrides, match):
    rejects(EvidenceItem, {**evidence_item_dict(), **overrides}, match)


def test_evidence_may_use_protected_reference_instead_of_content():
    item = EvidenceItem.model_validate(evidence_item_dict(content=None, content_reference="vault://evidence/EV-1"))
    assert item.content is None and item.content_reference.startswith("vault://")


# --- ToolRequest / ToolReceipt ------------------------------------------------------------------

def test_valid_tool_request_digests_are_stable():
    a = ToolRequest.model_validate(request_dict(arguments={"host": "web-01", "limit": 10}))
    b = ToolRequest.model_validate(request_dict(arguments={"limit": 10, "host": "web-01"}))
    assert a.request_digest() == b.request_digest() and a.arguments_digest() == b.arguments_digest()
    assert a.request_digest() != ToolRequest.model_validate(request_dict(sequence_number=1)).request_digest()


@pytest.mark.parametrize("overrides", [
    {"arguments": ["host", "web-01"]}, {"arguments": "host=web-01"}, {"arguments": None},
    {"arguments": {"x": {1, 2}}}, {"arguments": {"x": b"bytes"}}, {"arguments": {"x": float("nan")}},
    {"arguments": {"x": 2**60}}, {"arguments": {1: "x"}},
    {"tool_id": "log search"}, {"operation_id": ""}, {"requested_at": "2026-01-10 09:00"},
    {"sequence_number": -1}, {"sequence_number": "0"}, {"correlation_id": None}, {"permission_class": "ACTION"},
])
def test_invalid_tool_request(overrides):
    rejects(ToolRequest, request_dict(**overrides))


def test_tool_request_missing_fields():
    for field in ("request_id", "assignment_id", "worker_id", "tool_id", "operation_id", "arguments",
                  "requested_at", "correlation_id"):
        rejects(ToolRequest, without(request_dict(), field), "Field required")


@pytest.mark.parametrize("arguments,problem", [
    ({"host": "web-01", "drop_table": "x"}, "unknown argument"),
    ({"limit": "10"}, "expected integer"), ({"limit": True}, "expected integer"),
    ({"limit": 0}, "below minimum"), ({"limit": 5000}, "above maximum"),
    ({"host": 5}, "expected string"), ({"host": "x" * 300}, "longer than"),
])
def test_tool_request_arguments_against_registered_schema(arguments, problem):
    log_search, intel_lookup, _ = sample_tool_definitions(POLICY)
    request = ToolRequest.model_validate(request_dict(arguments=arguments))
    assert any(problem in p for p in request_problems(request, log_search))
    assert request_problems(ToolRequest.model_validate(request_dict()), log_search) == ()
    missing = ToolRequest.model_validate(request_dict(tool_id="intel_lookup", operation_id="lookup", arguments={}))
    assert any("missing required" in p for p in request_problems(missing, intel_lookup))


def test_valid_tool_receipt():
    receipt = ToolReceipt.model_validate(receipt_dict())
    assert receipt.signed_payload()["execution_status"] == "SUCCEEDED" and not receipt.is_signed


@pytest.mark.parametrize("overrides,match", [
    ({"result_digest": None}, "requires result_digest"),
    ({"error_code": "boom"}, "must not carry error_code"),
    ({"execution_status": "FAILED"}, "requires error_code"),
    ({"execution_status": "TIMEOUT", "error_code": "tool-timeout"}, "cannot carry result_digest"),
    ({"execution_status": "DONE"}, None),
    ({"completed_at": iso(NOW - timedelta(seconds=5))}, "completed_at"),
    ({"gateway_identity": {"principal_id": "worker-reader-1", "principal_type": "WORKER"}}, "TOOL_GATEWAY"),
    ({"result_digest": "not-a-digest"}, None), ({"request_digest": "A" * 64}, None),
    ({"tool_version": "v1"}, None), ({"permission_class": "read"}, None),
    ({"started_at": "2026-01-10T09:00:00"}, "timestamp"),
    ({"trusted": True}, "Extra inputs"),
])
def test_malformed_tool_receipt(overrides, match):
    rejects(ToolReceipt, receipt_dict(**overrides), match)


def test_tool_receipt_missing_fields():
    for field in ("receipt_id", "request_digest", "result_digest", "execution_status", "gateway_identity",
                  "started_at", "completed_at", "tool_version", "permission_class"):
        rejects(ToolReceipt, without(receipt_dict(), field), "Field required")
