"""Shared builders for P1 tests."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from gamis.evaluation.trust_fixture import (ACTION_OP, AUTHORITY, EVIDENCE_REQUIREMENT, GATEWAY, ISSUER, NOW, POLICY,
                                            READ_OPS, REGISTRY_ADMIN, SUPERVISOR, MutableClock, TrustWorld,
                                            assignment_dict, build_trust_world, grant_dict, iso)
from gamis.security.digest import canonical_digest

__all__ = ["ACTION_OP", "AUTHORITY", "EVIDENCE_REQUIREMENT", "GATEWAY", "ISSUER", "NOW", "POLICY", "READ_OPS",
           "REGISTRY_ADMIN", "SUPERVISOR", "MutableClock", "TrustWorld", "assignment_dict", "build_trust_world",
           "grant_dict", "iso", "action_assignment", "evidence_item_dict", "bundle_dict", "request_dict",
           "receipt_dict"]


def action_assignment(**overrides: Any) -> dict[str, Any]:
    data = dict(assignment_id="ASG-ACT-1", worker_id="worker-responder-1", worker_role="responder",
                permission_class="ACTION", permitted_tools=["case_action"], permitted_operations=[ACTION_OP],
                tool_call_limits=[{"tool_id": "case_action", "max_calls": 1}], forbidden_actions=[])
    data.update(overrides)
    return data


def evidence_item_dict(evidence_id: str = "EV-1", receipt_id: str = "RCPT-1", **overrides: Any) -> dict[str, Any]:
    content = {"id": "L-002", "message": "Failed login for root"}
    data: dict[str, Any] = {
        "evidence_id": evidence_id, "source": "log_search", "source_type": "TOOL_RESULT",
        "source_record_id": "L-002", "content": content, "integrity_digest": canonical_digest(content),
        "timestamp": iso(NOW),
        "provenance": {"provenance_id": f"PROV-{evidence_id}", "origin": "log_search:search",
                       "source_type": "TOOL_RESULT", "collected_by": "worker-reader-1", "collected_at": iso(NOW),
                       "method": "tool call", "receipt_id": receipt_id},
        "receipt_id": receipt_id,
    }
    data.update(overrides)
    return data


def bundle_dict(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "evidence_bundle_id": "BUNDLE-1", "mission_id": "MIS-001", "assignment_id": "ASG-001",
        "worker_id": "worker-reader-1",
        "claims": [{"claim_id": "CLAIM-1", "statement": "Repeated failed logins were recorded.",
                    "supporting_evidence_ids": ["EV-1"], "contradicting_evidence_ids": [], "confidence": 0.8,
                    "rationale": "The log record shows the failed attempts."}],
        "evidence_items": [evidence_item_dict()],
        "supporting_evidence": ["EV-1"], "contradicting_evidence": [],
        "assumptions": ["Log timestamps are accurate"], "confidence": 0.8,
        "provenance": {"provenance_id": "PROV-BUNDLE-1", "origin": "worker-reader-1",
                       "source_type": "WORKER_ANALYSIS", "collected_by": "worker-reader-1",
                       "collected_at": iso(NOW), "method": "analysis of tool results"},
        "referenced_tool_receipts": ["RCPT-1"],
        "tool_call_history": [{"sequence_number": 0, "request_id": "REQ-1", "receipt_id": "RCPT-1",
                               "tool_id": "log_search", "operation_id": "search", "execution_status": "SUCCEEDED",
                               "requested_at": iso(NOW)}],
        "completion_status": "complete", "limitations": ["Only one log source was searched"],
        "generated_at": iso(NOW),
    }
    data.update(overrides)
    return data


def request_dict(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "request_id": "REQ-1", "mission_id": "MIS-001", "assignment_id": "ASG-001", "worker_id": "worker-reader-1",
        "tool_id": "log_search", "operation_id": "search", "arguments": {"host": "web-01", "limit": 10},
        "requested_at": iso(NOW), "correlation_id": "CORR-1", "sequence_number": 0,
    }
    data.update(overrides)
    return data


def receipt_dict(**overrides: Any) -> dict[str, Any]:
    digest = "a" * 64
    data: dict[str, Any] = {
        "receipt_id": "RCPT-1", "request_id": "REQ-1", "request_digest": digest, "mission_id": "MIS-001",
        "assignment_id": "ASG-001", "worker_id": "worker-reader-1", "tool_id": "log_search",
        "tool_version": "1.0.0", "operation_id": "search", "permission_class": "READ",
        "arguments_digest": digest, "result_digest": digest, "execution_status": "SUCCEEDED",
        "started_at": iso(NOW), "completed_at": iso(NOW + timedelta(seconds=1)), "correlation_id": "CORR-1",
        "gateway_identity": GATEWAY.model_dump(mode="json"), "policy_version": POLICY.model_dump(mode="json"),
    }
    data.update(overrides)
    return data
