"""P2 <-> P0/P1 integration: audited authority, registry, grants, mission status, P0 scenarios, evidence."""
from __future__ import annotations

import pytest

from gamis.audit.events import AuditEventType as E
from gamis.authority.service import AssignmentRejected
from gamis.authority.verification import AssignmentVerificationError
from gamis.evaluation.harness import run_scenario
from gamis.evaluation.bridge import bundle_to_system_output
from gamis.evaluation.trust_fixture import ACTION_OP, AUTHORITY, GATEWAY, ISSUER, NOW, REGISTRY_ADMIN, SUPERVISOR
from gamis.schemas import SignedObjectType
from gamis.security.signing import payload_digest
from tests.p2_support import SCENARIOS, SEEDS, build_audit_env, receipted_bundle


@pytest.fixture
def env(tmp_path):
    e = build_audit_env(tmp_path)
    yield e
    e.close()


def types(env, since: int = 0):
    return [e.event_type for e in env.ledger.iter_events() if e.sequence_number > since]


def test_setup_is_audited_in_order(env):
    assert types(env) == [E.LEDGER_GENESIS, E.TOOL_REGISTERED, E.TOOL_REGISTERED, E.TOOL_REGISTERED,
                          E.REGISTRY_SEALED, E.MISSION_CREATED, E.GRANT_ISSUED, E.MISSION_ACTIVATED]
    issued = env.ledger.get_events(event_type=E.GRANT_ISSUED)[0]
    grant = env.world.grant
    assert issued.event_payload["grant_digest"] == payload_digest(SignedObjectType.MISSION_GRANT,
                                                                   grant.signed_payload())
    assert issued.actor_identity == ISSUER and issued.mission_id == grant.mission_id
    created = env.ledger.get_events(event_type=E.MISSION_CREATED)[0]
    assert grant.mission_objective not in str(created.event_payload)            # digest only, not the text
    sealed = env.ledger.get_events(event_type=E.REGISTRY_SEALED)[0]
    assert sealed.actor_identity == REGISTRY_ADMIN and sealed.event_payload["registry_version"] == 3


def test_assignment_issuance_is_audited(env):
    start = env.ledger.get_ledger_head().sequence_number
    signed = env.world.authority.issue_assignment(
        __import__("tests.p1_support", fromlist=["assignment_dict"]).assignment_dict(), env.world.grant,
        proposer=SUPERVISOR)
    assert types(env, start) == [E.ASSIGNMENT_PROPOSED, E.ASSIGNMENT_APPROVED, E.ASSIGNMENT_SIGNED]
    proposed, approved, signed_event = env.ledger.get_events(start=start + 1)
    assert proposed.actor_identity == SUPERVISOR and approved.actor_identity == AUTHORITY
    assert signed_event.event_payload["signing_key_id"] == signed.signature_metadata.key_id
    assert signed_event.event_payload["assignment_digest"] == payload_digest(SignedObjectType.AGENT_ASSIGNMENT,
                                                                              signed.signed_payload())
    assert signed_event.event_payload["proposer"]["principal_type"] == "SUPERVISOR"
    assert signed_event.assignment_id == signed.assignment_id and signed_event.worker_id == signed.worker_id


def test_assignment_rejection_is_audited_with_violation_codes(env):
    start = env.ledger.get_ledger_head().sequence_number
    with pytest.raises(AssignmentRejected):
        env.world.issue(worker_id="worker-unknown-9")
    assert types(env, start) == [E.ASSIGNMENT_PROPOSED, E.ASSIGNMENT_REJECTED]
    rejected = env.ledger.get_events(event_type=E.ASSIGNMENT_REJECTED)[-1]
    assert rejected.event_payload["violation_codes"] == ("UNKNOWN_WORKER",)
    assert rejected.event_payload["proposal_digest"] and rejected.worker_id == "worker-unknown-9"
    # READ -> ACTION escalation attempt is rejected as malformed and still audited (no PROPOSED: unparseable)
    start = env.ledger.get_ledger_head().sequence_number
    with pytest.raises(AssignmentRejected):
        env.world.issue(assignment_id="ASG-ESC", permitted_tools=["case_action"], permitted_operations=[ACTION_OP],
                        tool_call_limits=[{"tool_id": "case_action", "max_calls": 1}], forbidden_actions=[])
    assert types(env, start) == [E.ASSIGNMENT_REJECTED]
    assert env.ledger.get_events(event_type=E.ASSIGNMENT_REJECTED)[-1].event_payload["violation_codes"] == ("MALFORMED_PROPOSAL",)
    # hostile identifiers in a garbage proposal do not prevent the rejection being recorded
    with pytest.raises(AssignmentRejected):
        env.world.authority.issue_assignment({"assignment_id": "x y z" * 100, "worker_id": 5}, env.world.grant)
    last = env.ledger.get_events(event_type=E.ASSIGNMENT_REJECTED)[-1]
    assert last.assignment_id is None and last.grant_id == "GRANT-001"


def test_grant_verification_failures_are_audited(env):
    widened = env.world.grant.model_copy(update={"maximum_worker_count": 999})
    with pytest.raises(AssignmentRejected):
        env.world.authority.issue_assignment(__import__("tests.p1_support", fromlist=["assignment_dict"])
                                             .assignment_dict(), widened)
    failed = env.ledger.get_events(event_type=E.GRANT_VERIFICATION_FAILED)[-1]
    assert failed.event_payload["violation_codes"] == ("GRANT_SIGNATURE_INVALID",)
    env.world.verifier.verify_grant(env.world.grant)
    ok = env.ledger.get_events(event_type=E.GRANT_VERIFIED)[-1]
    assert ok.actor_identity == GATEWAY and ok.event_payload["outcome"] == "PASSED"
    env.clock.advance(hours=9)
    with pytest.raises(AssignmentVerificationError):
        env.world.verifier.verify_grant(env.world.grant)
    assert env.ledger.get_events(event_type=E.GRANT_VERIFICATION_FAILED)[-1].event_payload["violation_codes"] == ("GRANT_EXPIRED",)


def test_mission_lifecycle_revocation_and_safe_stop_are_audited(env):
    status = env.world.status
    status.safe_stop("GRANT-001", NOW, "stopping condition fired", "RESOURCE_EXHAUSTED")
    stop = env.ledger.get_events(event_type=E.SAFE_STOP)[-1]
    assert stop.event_payload["stop_condition"] == "RESOURCE_EXHAUSTED" and stop.event_payload["state"] == "SUSPENDED"
    status.revoke("GRANT-001", NOW, "operator revoked; password=hunter2")
    revoked = env.ledger.get_events(event_type=E.MISSION_REVOKED)[-1]
    assert "hunter2" not in revoked.event_payload["reason"]
    with pytest.raises(AssignmentRejected):
        env.world.issue()
    assert env.ledger.get_events(event_type=E.ASSIGNMENT_REJECTED)[-1].event_payload["violation_codes"] == ("GRANT_REVOKED",)
    status.set_state("GRANT-001", status.get("GRANT-001").state.COMPLETED, NOW, "done")
    assert env.ledger.get_events(event_type=E.MISSION_COMPLETED)


def test_registry_changes_and_integrity_failures_are_audited(env):
    env.world.registry.set_enabled("case_action", "1.0.0", True, actor=REGISTRY_ADMIN)
    changed = env.ledger.get_events(event_type=E.TOOL_STATUS_CHANGED)[-1]
    assert changed.event_payload["enabled"] is True and changed.event_payload["tool_id"] == "case_action"
    with pytest.raises(AssignmentRejected):                     # registry no longer sealed
        env.world.issue()
    rejected = env.ledger.get_events(event_type=E.ASSIGNMENT_REJECTED)[-1]
    assert rejected.event_payload["violation_codes"] == ("REGISTRY_INTEGRITY",)
    env.recorder.registry_integrity("sample-registry", GATEWAY, False, "registry is not sealed")
    env.world.registry.seal(env.world.registry_signer, NOW)
    snapshot = env.world.registry.verify_integrity(env.world.trust_store, NOW)
    env.recorder.registry_integrity("sample-registry", GATEWAY, True, snapshot=snapshot)
    assert [e.event_payload["outcome"] for e in env.ledger.get_events()
            if e.event_type in (E.REGISTRY_INTEGRITY_FAILED, E.REGISTRY_INTEGRITY_VERIFIED)] == ["FAILED", "PASSED"]


@pytest.mark.parametrize("scenario_id", [s.id for s in SCENARIOS.values() if s.kind == "investigation"])
def test_p0_investigations_persist_verify_and_score(env, scenario_id):
    bundle = receipted_bundle(env, scenario_id)
    env.store.store_bundle(bundle)
    stored = env.store.get_bundle(bundle.evidence_bundle_id, purpose="harness scoring")

    class FromStore:
        name = "p2-evidence-store-plumbing"

        def run(self, scenario, tools):
            return bundle_to_system_output(stored)

    result = run_scenario(FromStore(), SCENARIOS[scenario_id], SEEDS)
    assert result["crashed"] is False and result["evidence_recall"] == 1.0
    assert result["action_attempts"] == 0
    receipt_event = env.ledger.get_events(event_type=E.TOOL_EXECUTION_COMPLETED)[-1]
    assert receipt_event.event_payload["receipt_id"] == bundle.referenced_tool_receipts[0]
    assert env.store.verify_all().status == "PASSED"
    assert env.store.audit_cross_check(env.ledger.iter_events()) == []
    cp = env.checkpoint()
    report = env.ledger.get_verification_report(trust_store=env.world.trust_store, trusted_checkpoints=(cp,), now=NOW)
    assert report.status.value == "PASSED"


@pytest.mark.parametrize("attack", [a for a in SEEDS["attacks"] if a["location"] != "user_request"],
                         ids=lambda a: a["id"])
def test_p0_attack_payloads_in_evidence_are_flagged_and_inert(env, attack):
    bundle = receipted_bundle(env, extra_message=attack["payload"])
    env.store.store_bundle(bundle)
    flagged = [e for e in env.ledger.get_events(event_type=E.EVIDENCE_STORED)
               if e.event_payload["contains_suspicious_instructions"]]
    assert [e.event_payload["evidence_id"] for e in flagged] == ["EV-INV-001-L-EXTRA"]
    assert all(a.permission_class.value == "READ" for a in env.world.ledger.issued("GRANT-001"))
    assert attack["payload"] not in env.ledger_path.read_bytes().decode("utf-8", "ignore")


def test_ledger_never_contains_raw_evidence_content(env):
    bundle = receipted_bundle(env)
    env.store.store_bundle(bundle)
    data = env.ledger_path.read_bytes()
    for item in bundle.evidence_items:
        assert item.content["message"].encode() not in data
    assert b"PRIVATE KEY" not in data
