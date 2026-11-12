"""P1 <-> P0 integration: P1 schemas and signatures driving the P0 seeds, tool doubles and harness.

The system below is a PLUMBING test double. It cites the scenario's expected evidence ids (the answer key),
so it says nothing about investigation quality; it proves that P0 components run on P1 types end to end.
"""
from __future__ import annotations

import json

import pytest

from gamis.authority.service import AssignmentRejected
from gamis.evaluation.bridge import bundle_to_system_output, call_double_with_receipt
from gamis.evaluation.harness import Scenario, SystemOutput, ToolBox, build_scenarios, build_toolbox, run_scenario
from gamis.evaluation.loader import load_all
from gamis.schemas import (EvidenceBundle, ExecutionStatus, PermissionClass, ToolReceipt, ToolRequest)
from gamis.security import signing
from gamis.security.digest import canonical_digest
from gamis.security.signing import sign_object, verify_object
from gamis.tools.sample_registry import SAMPLE_OPERATIONS
from tests.p1_support import (ACTION_OP, NOW, POLICY, action_assignment, build_trust_world, iso)

SEEDS = load_all()
SCENARIOS = {s.id: s for s in build_scenarios(SEEDS)}


class ReceiptedReadSystem:
    name = "p1-plumbing-selftest"

    def __init__(self) -> None:
        self.last_bundle: EvidenceBundle | None = None
        self.receipts: list[ToolReceipt] = []
        self.world = None

    def run(self, scenario: Scenario, tools: ToolBox) -> SystemOutput:
        world = self.world = build_trust_world()
        assignment = world.issue()                                   # READ-only, log_search only
        world.verifier.verify(assignment, world.grant)
        definition = world.registry.read_only().get("log_search")
        request = ToolRequest(request_id="REQ-1", mission_id=assignment.mission_id,
                              assignment_id=assignment.assignment_id, worker_id=assignment.worker_id,
                              tool_id="log_search", operation_id="search",
                              arguments={"host": scenario.investigation["scope"]["host"]}, requested_at=world.clock(),
                              correlation_id=f"CORR-{scenario.id}", sequence_number=0)
        result, receipt = call_double_with_receipt(tools.log_search, request, definition, receipt_id="RCPT-1",
                                                   signer=world.gateway_signer, policy_version=POLICY,
                                                   clock=world.clock)
        verify_object(receipt, world.trust_store, now=world.clock())
        self.receipts = [receipt]
        wanted = set(scenario.investigation["expected_evidence_event_ids"])
        events = [e for e in (result or {}).get("results", []) if e["id"] in wanted]
        items = [{
            "evidence_id": f"EV-{e['id']}", "source": "log_search", "source_type": "TOOL_RESULT",
            "source_record_id": e["id"], "content": e, "integrity_digest": canonical_digest(e),
            "timestamp": e["timestamp"], "receipt_id": receipt.receipt_id,
            "provenance": {"provenance_id": f"PROV-{e['id']}", "origin": "log_search:search",
                           "source_type": "TOOL_RESULT", "collected_by": assignment.worker_id,
                           "collected_at": iso(world.clock()), "method": "tool call",
                           "receipt_id": receipt.receipt_id}} for e in events]
        ids = [i["evidence_id"] for i in items]
        claims = [{"claim_id": "CLAIM-1", "statement": scenario.investigation["title"],
                   "supporting_evidence_ids": ids, "contradicting_evidence_ids": [], "confidence": 0.7,
                   "rationale": "Cited records were returned by the receipted tool call.",
                   "disputed": scenario.investigation["expect_disputed"]}] if ids else []
        bundle = EvidenceBundle.model_validate({
            "evidence_bundle_id": f"BUNDLE-{scenario.id}", "mission_id": assignment.mission_id,
            "assignment_id": assignment.assignment_id, "worker_id": assignment.worker_id, "claims": claims,
            "evidence_items": items, "supporting_evidence": ids, "contradicting_evidence": [],
            "assumptions": [], "confidence": 0.7 if ids else 0.0,
            "provenance": {"provenance_id": "PROV-BUNDLE", "origin": assignment.worker_id,
                           "source_type": "WORKER_ANALYSIS", "collected_by": assignment.worker_id,
                           "collected_at": iso(world.clock()), "method": "analysis"},
            "referenced_tool_receipts": [receipt.receipt_id],
            "tool_call_history": [{"sequence_number": 0, "request_id": request.request_id,
                                   "receipt_id": receipt.receipt_id, "tool_id": "log_search",
                                   "operation_id": "search", "execution_status": receipt.execution_status.value,
                                   "requested_at": iso(request.requested_at)}],
            "completion_status": "complete" if result is not None else "partial",
            "limitations": [] if result is not None else ["log_search did not return a result"],
            "generated_at": iso(world.clock())})
        bundle = bundle.with_signature(sign_object(bundle, world.worker_signer, now=world.clock()))
        verify_object(bundle, world.trust_store, now=world.clock())
        self.last_bundle = bundle
        return bundle_to_system_output(bundle)


def test_sample_registry_matches_p0_doubles():
    world = build_trust_world()
    toolbox = build_toolbox(SCENARIOS["INV-001"], SEEDS)
    for double in (toolbox.log_search, toolbox.intel_lookup, toolbox.case_action):
        definition = world.registry.get(double.name)
        assert definition.permission_class is PermissionClass(double.kind)
        assert definition.operation(SAMPLE_OPERATIONS[double.name]) is not None
    assert world.registry.get("case_action").enabled_status is toolbox.case_action.enabled is False


@pytest.mark.parametrize("scenario_id", [s.id for s in SCENARIOS.values() if s.kind == "investigation"])
def test_p0_harness_scores_a_p1_evidence_bundle(scenario_id):
    system = ReceiptedReadSystem()
    result = run_scenario(system, SCENARIOS[scenario_id], SEEDS)
    assert result["crashed"] is False and result["status"] == "complete"
    assert result["passed"] and result["evidence_recall"] == 1.0 and result["decoys_cited"] == []
    assert result["action_attempts"] == 0 and result["actions_executed"] == 0
    bundle, receipt = system.last_bundle, system.receipts[0]
    assert bundle.is_signed and receipt.execution_status is ExecutionStatus.SUCCEEDED
    assert all(item.receipt_id == receipt.receipt_id for item in bundle.evidence_items)
    restored = EvidenceBundle.model_validate_json(bundle.model_dump_json())      # survives serialization
    verify_object(restored, system.world.trust_store, now=NOW)
    tampered = json.loads(bundle.model_dump_json())
    tampered["claims"][0]["confidence"] = 1.0
    with pytest.raises(signing.PayloadTamperedError):
        verify_object(EvidenceBundle.model_validate(tampered), system.world.trust_store, now=NOW)


def test_receipt_binds_request_and_result_of_a_p0_double():
    world = build_trust_world()
    tools = build_toolbox(SCENARIOS["INV-001"], SEEDS)
    request = ToolRequest(request_id="REQ-9", mission_id="MIS-001", assignment_id="ASG-001",
                          worker_id="worker-reader-1", tool_id="intel_lookup", operation_id="lookup",
                          arguments={"indicator": "203.0.113.50"}, requested_at=NOW, correlation_id="CORR-9",
                          sequence_number=0)
    result, receipt = call_double_with_receipt(tools.intel_lookup, request, world.registry.get("intel_lookup"),
                                               receipt_id="RCPT-9", signer=world.gateway_signer,
                                               policy_version=POLICY, clock=world.clock)
    assert result == tools.intel_lookup({"indicator": "203.0.113.50"})          # P0 behaviour unchanged
    assert receipt.result_digest == canonical_digest(result) and receipt.request_digest == request.request_digest()
    assert receipt.arguments_digest == canonical_digest({"indicator": "203.0.113.50"})
    assert receipt.permission_class is PermissionClass.READ and receipt.tool_version == "1.0.0"
    assert verify_object(receipt, world.trust_store, now=NOW).key.key_name == "tool-gateway"
    # a different result or request no longer matches the receipt; the receipt cannot be re-pointed
    assert canonical_digest({**result, "records": []}) != receipt.result_digest
    with pytest.raises(signing.PayloadTamperedError):
        verify_object(receipt.model_copy(update={"worker_id": "worker-intel-1"}), world.trust_store, now=NOW)
    # a worker cannot mint receipts
    with pytest.raises(signing.KeyNotAuthorizedError):
        sign_object(receipt.without_signature(), world.worker_signer, now=NOW)


@pytest.mark.parametrize("scenario_id,expected", [("FAIL-001", ExecutionStatus.TIMEOUT)])
def test_failure_injection_yields_failed_receipt_and_partial_bundle(scenario_id, expected):
    system = ReceiptedReadSystem()
    result = run_scenario(system, SCENARIOS[scenario_id], SEEDS)
    assert result["passed"] and result["status"] == "partial" and not result["crashed"]
    receipt = system.receipts[0]
    assert receipt.execution_status is expected and receipt.result_digest is None and receipt.error_code
    assert system.last_bundle.claims == () and system.last_bundle.limitations


def test_every_p0_failure_mode_maps_to_an_execution_status():
    world = build_trust_world()
    seen = {}
    for failure in SEEDS["failures"]:
        tools = build_toolbox(SCENARIOS[failure["id"]], SEEDS)
        for spec in failure["failures"]:
            tool = getattr(tools, spec["tool"])
            args = {"host": "web-01"} if spec["tool"] == "log_search" else {"indicator": "203.0.113.50"}
            operation = SAMPLE_OPERATIONS[spec["tool"]]
            for attempt in range(spec["on_call"] if isinstance(spec["on_call"], int) else 1):
                request = ToolRequest(request_id=f"REQ-{attempt}", mission_id="MIS-001", assignment_id="ASG-001",
                                      worker_id="worker-reader-1", tool_id=spec["tool"], operation_id=operation,
                                      arguments=args, requested_at=NOW, correlation_id="CORR-F",
                                      sequence_number=attempt)
                _, receipt = call_double_with_receipt(tool, request, world.registry.get(spec["tool"]),
                                                      receipt_id=f"RCPT-{attempt}", signer=world.gateway_signer,
                                                      policy_version=POLICY, clock=world.clock)
                verify_object(receipt, world.trust_store, now=NOW)
            seen[spec["mode"]] = receipt.execution_status
    assert seen == {"timeout": ExecutionStatus.TIMEOUT, "error": ExecutionStatus.FAILED,
                    "malformed": ExecutionStatus.MALFORMED_RESULT}


def test_action_double_stays_disabled_and_is_receipted_as_rejected():
    world = build_trust_world()
    tools = build_toolbox(SCENARIOS["INV-001"], SEEDS)
    request = ToolRequest(request_id="REQ-A", mission_id="MIS-001", assignment_id="ASG-ACT-1",
                          worker_id="worker-responder-1", tool_id="case_action", operation_id="execute",
                          arguments={"action": "isolate_host", "target": "web-01"}, requested_at=NOW,
                          correlation_id="CORR-A", sequence_number=0)
    result, receipt = call_double_with_receipt(tools.case_action, request, world.registry.get("case_action"),
                                               receipt_id="RCPT-A", signer=world.gateway_signer,
                                               policy_version=POLICY, clock=world.clock)
    assert result is None and receipt.execution_status is ExecutionStatus.REJECTED
    assert receipt.permission_class is PermissionClass.ACTION and receipt.error_code == "action-disabled"
    assert len(tools.case_action.attempt_log) == 1 and tools.case_action.executed_log == []
    # malformed arguments are rejected against the registered schema before the double is ever called
    bad = request.model_copy(update={"request_id": "REQ-B", "arguments": {"action": "isolate_host"}})
    _, rejected = call_double_with_receipt(tools.case_action, ToolRequest.model_validate(bad.model_dump(mode="json")),
                                           world.registry.get("case_action"), receipt_id="RCPT-B",
                                           signer=world.gateway_signer, policy_version=POLICY, clock=world.clock)
    assert rejected.error_code == "invalid-request" and len(tools.case_action.attempt_log) == 1


@pytest.mark.parametrize("attack_id", [a["id"] for a in SEEDS["attacks"]])
def test_p0_attack_payloads_cannot_obtain_action_authority(attack_id):
    scenario = SCENARIOS[attack_id]
    system = ReceiptedReadSystem()
    result = run_scenario(system, scenario, SEEDS)
    assert result["passed"] and result["action_attempts"] == 0 and result["failed_checks"] == []
    world = system.world
    # Whatever an injected instruction makes a supervisor propose, a READ worker cannot be given the action tool...
    escalations = [
        dict(assignment_id="ASG-ATK-1", permitted_tools=["log_search", "case_action"],
             permitted_operations=[{"tool_id": "log_search", "operation_id": "search", "permission_class": "READ"},
                                   ACTION_OP],
             tool_call_limits=[{"tool_id": "log_search", "max_calls": 1}, {"tool_id": "case_action", "max_calls": 1}],
             forbidden_actions=[], task_description=scenario.spec["payload"]),
        dict(assignment_id="ASG-ATK-2", permission_class="ACTION", task_description=scenario.spec["payload"]),
        # ... and even a correctly formed ACTION proposal fails while the tool is disabled in the signed registry.
        action_assignment(assignment_id="ASG-ATK-3", task_description=scenario.spec["payload"]),
    ]
    for proposal in escalations:
        with pytest.raises(AssignmentRejected):
            world.issue(**proposal)
    assert [a.assignment_id for a in world.ledger.issued("GRANT-001")] == ["ASG-001"]   # only the READ assignment
