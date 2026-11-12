from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest

from gamis.agents.intelligence import ContradictionType, EvidenceIntelligence
from gamis.agents.models import LLMWorkerOutput
from gamis.evidence.store import EvidenceItem
from gamis.llm.provider import LLMConfiguration, MockProvider
from gamis.runtime import DEFAULT_OBJECTIVE, LocalRuntime, ROLE_TO_WORKER
from gamis.schemas.common import SourceType
from gamis.schemas.evidence import ProvenanceRecord
from gamis.security.digest import canonical_digest
from tests.p1_support import build_trust_world


def test_p6_report_correlates_verified_evidence_and_preserves_receipt_provenance(tmp_path, monkeypatch):
    monkeypatch.setenv("GAMIS_ENV", "test")
    with LocalRuntime(tmp_path / "gamis", configuration=LLMConfiguration(provider="mock"),
                      provider=MockProvider()) as runtime:
        report = runtime.submit(DEFAULT_OBJECTIVE)
        analysis = report.evidence_intelligence
        assert analysis is not None
        assert analysis.evidence_count == report.evidence_count
        assert analysis.receipt_ids == report.receipt_ids
        assert analysis.evidence_correlations
        assert all(len(group.worker_ids) > 1 for group in analysis.evidence_correlations)
        evidence_ids = set(runtime.evidence.list_evidence_ids(mission_id=report.mission_id))
        assert set(analysis.supporting_evidence_ids) <= evidence_ids
        assert set(analysis.contradicting_evidence_ids) <= evidence_ids
        assert all(claim.confidence_assessment.model_confidence >= 0
                   and claim.confidence_assessment.evidence_strength == claim.confidence
                   for claim in analysis.verified_claims)
        assert all(set(claim.supporting_evidence_ids + claim.contradicting_evidence_ids) <= evidence_ids
                   for claim in analysis.verified_claims)


def test_p6_temporal_conflict_keeps_both_evidence_versions():
    base = build_trust_world()
    now = base.clock()

    def item(evidence_id, content, timestamp):
        return EvidenceItem(
            evidence_id=evidence_id, source="synthetic-document", source_type=SourceType.DOCUMENT,
            source_record_id="RECORD-7", content=content, integrity_digest=canonical_digest(content),
            timestamp=timestamp,
            provenance=ProvenanceRecord(
                provenance_id=f"PROV-{evidence_id}", origin="synthetic-document",
                source_type=SourceType.DOCUMENT, collected_by="worker-reader-1", collected_at=now,
                method="synthetic fixture"),
        )

    findings = EvidenceIntelligence._source_contradictions((
        item("EV-A", {"status": "blocked"}, now),
        item("EV-B", {"status": "allowed"}, now + timedelta(seconds=1)),
    ))
    assert len(findings) == 1
    assert findings[0].contradiction_type is ContradictionType.TEMPORAL_INCONSISTENCY
    assert set(findings[0].evidence_ids) == {"EV-A", "EV-B"}
    assert findings[0].preserved_as_unresolved


def _prepare_interrupted_mission(runtime):
    grant = runtime.create_grant(DEFAULT_OBJECTIVE, "web-01", "203.0.113.50")
    orchestrator = runtime._orchestrator(grant)
    runtime.mission_store.create(grant, DEFAULT_OBJECTIVE, runtime.clock())
    orchestrator._checkpoint(grant)
    plan = orchestrator.supervisor.decompose(DEFAULT_OBJECTIVE)
    runtime.mission_store.save_plan(grant.mission_id, plan)
    for task in plan.tasks:
        runtime.mission_store.add_task(grant.mission_id, task, runtime.clock())
    assignments = {}
    for task in plan.tasks:
        assignment = orchestrator.supervisor.issue_assignment(task, grant)
        assignments[task.task_id] = assignment
        runtime.mission_store.set_task(grant.mission_id, task.task_id, "AUTHORIZED", runtime.clock(),
                                       assignment=assignment)
    first = plan.tasks[0]
    worker = orchestrator.workers[first.worker_role]
    worker_report = worker.run(first, assignments[first.task_id], grant, (), host="web-01",
                               indicator="203.0.113.50")
    runtime.mission_store.set_task(grant.mission_id, first.task_id, "COMPLETED", runtime.clock(),
                                   report=worker_report)
    orchestrator._checkpoint(grant)
    return grant.mission_id


def test_p7_mission_resumes_after_runtime_restart_without_reissuing_completed_work(tmp_path, monkeypatch):
    monkeypatch.setenv("GAMIS_ENV", "test")
    home = tmp_path / "gamis"
    first_runtime = LocalRuntime(home, configuration=LLMConfiguration(provider="mock"),
                                 provider=MockProvider())
    mission_id = _prepare_interrupted_mission(first_runtime)
    first_runtime.close()

    with LocalRuntime(home, configuration=LLMConfiguration(provider="mock"),
                      provider=MockProvider()) as resumed:
        report = resumed.resume(mission_id)
        assert report.status == "complete"
        assert len(report.worker_reports) == 3
        tasks = resumed.mission_store.tasks(mission_id)
        assert all(task["status"] == "COMPLETED" for task in tasks)
        assert resumed.mission_store.retry_count(mission_id, "research") == 0
        assert resumed.mission_store.verify_checkpoints(mission_id)["sequence"] >= 4
        event_types = [event.event_type.value for event in resumed.ledger.iter_events()]
        assert "MISSION_INTERRUPTED" in event_types
        assert "MISSION_RESUMED" in event_types
        assert "MISSION_CHECKPOINT_CREATED" in event_types


def test_p7_checkpoint_chain_detects_tampering_and_is_append_only(tmp_path):
    world = build_trust_world()
    path = tmp_path / "missions.db"
    from gamis.agents.orchestrator import MissionStore

    store = MissionStore(path)
    store.create(world.grant, world.grant.mission_objective, world.clock())
    first = store.create_checkpoint(world.grant.mission_id, world.clock())
    second = store.create_checkpoint(world.grant.mission_id, world.clock())
    assert second["previous_digest"] == first["digest"]
    assert store.verify_checkpoints(world.grant.mission_id)["digest"] == second["digest"]
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store._conn.execute("UPDATE mission_checkpoints SET state_json='{}' WHERE checkpoint_id=?",
                            (first["checkpoint_id"],))
    store._conn.execute("DROP TRIGGER mission_checkpoints_no_update")
    store._conn.execute("UPDATE mission_checkpoints SET state_json='{}' WHERE checkpoint_id=?",
                        (first["checkpoint_id"],))
    with pytest.raises(ValueError, match="integrity failed"):
        store.verify_checkpoints(world.grant.mission_id)
    store.close()


def test_p7_cancellation_suspends_grant_and_prevents_resume(tmp_path, monkeypatch):
    monkeypatch.setenv("GAMIS_ENV", "test")
    home = tmp_path / "gamis"
    runtime = LocalRuntime(home, configuration=LLMConfiguration(provider="mock"), provider=MockProvider())
    mission_id = _prepare_interrupted_mission(runtime)
    runtime.cancel(mission_id, "Operator stop for recovery test.")
    grant = runtime.mission_store.grant(mission_id)
    assert runtime.grant_status.get(grant.grant_id).state.value == "SUSPENDED"
    runtime.close()
    with LocalRuntime(home, configuration=LLMConfiguration(provider="mock"),
                      provider=MockProvider()) as reopened:
        with pytest.raises(RuntimeError, match="durable grant is not ACTIVE"):
            reopened.resume(mission_id)


def test_p7_worker_failure_retries_only_read_work_and_audits_retry(tmp_path, monkeypatch):
    class FailFirstResearchInference(MockProvider):
        def __init__(self):
            self.failed = False

        def generate_json(self, prompt, response_model, *, model=None):
            if response_model is LLMWorkerOutput and "Role: evidence-reader." in prompt and not self.failed:
                self.failed = True
                raise RuntimeError("injected first research inference failure")
            return super().generate_json(prompt, response_model, model=model)

    monkeypatch.setenv("GAMIS_ENV", "test")
    with LocalRuntime(tmp_path / "gamis", configuration=LLMConfiguration(provider="mock"),
                      provider=FailFirstResearchInference()) as runtime:
        report = runtime.submit(DEFAULT_OBJECTIVE)
        assert report.status == "complete"
        assert runtime.mission_store.retry_count(report.mission_id, "research") == 1
        events = tuple(runtime.ledger.iter_events())
        assert any(event.event_type.value == "WORKER_RETRIED"
                   and event.event_payload.get("task_id") == "research" for event in events)
