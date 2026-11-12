"""Shared builders for P2 tests: an audited trust world, a ledger, an evidence store and receipted bundles."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gamis.audit.checkpoints import save_checkpoint
from gamis.audit.ledger import SQLiteAuditLedger
from gamis.audit.recorder import AuditRecorder
from gamis.evaluation.bridge import call_double_with_receipt
from gamis.evaluation.harness import build_scenarios, build_toolbox
from gamis.evaluation.loader import load_all
from gamis.evaluation.trust_fixture import AUDITOR, NOW, POLICY, MutableClock, TrustWorld, build_trust_world, iso
from gamis.evidence.store import EvidenceStore
from gamis.schemas import EvidenceBundle, ToolRequest
from gamis.security.digest import canonical_digest
from gamis.security.signing import sign_object
from gamis.security.trust_io import save_trust_store

SEEDS = load_all()
SCENARIOS = {s.id: s for s in build_scenarios(SEEDS)}
LEDGER_ID = "LEDGER-TEST-1"


@dataclass
class AuditEnv:
    root: Path
    clock: MutableClock
    ledger: SQLiteAuditLedger
    recorder: AuditRecorder
    world: TrustWorld
    store: EvidenceStore

    @property
    def ledger_path(self) -> Path:
        return self.root / "audit.db"

    @property
    def evidence_path(self) -> Path:
        return self.root / "evidence.db"

    @property
    def content_dir(self) -> Path:
        return self.root / "objects"

    def checkpoint(self, checkpoint_id: str | None = None):
        return self.ledger.create_checkpoint(self.world.audit_signer, self.world.trust_store,
                                             checkpoint_id=checkpoint_id)

    def export(self, checkpoint=None) -> dict[str, Path]:
        paths = {"trust": self.root / "trust.json"}
        save_trust_store(self.world.trust_store, paths["trust"])
        if checkpoint is not None:
            paths["checkpoint"] = self.root / f"{checkpoint.checkpoint_id}.json"
            save_checkpoint(checkpoint, paths["checkpoint"])
        return paths

    def close(self) -> None:
        self.store.close()
        self.ledger.close()


def build_audit_env(root: Path, **world_kwargs: Any) -> AuditEnv:
    clock = MutableClock(NOW)
    ledger = SQLiteAuditLedger.create(root / "audit.db", ledger_id=LEDGER_ID, actor=AUDITOR, clock=clock)
    recorder = AuditRecorder(ledger)
    world = build_trust_world(recorder=recorder, clock=clock, **world_kwargs)
    store = EvidenceStore.open(root / "evidence.db", root / "objects", clock=clock, audit=ledger,
                               trust_store=world.trust_store)
    return AuditEnv(root, clock, ledger, recorder, world, store)


def receipted_bundle(env: AuditEnv, scenario_id: str = "INV-001", *, bundle_id: str | None = None,
                     sign: bool = True, extra_message: str | None = None) -> EvidenceBundle:
    """Issue a READ assignment, run log_search through a signed receipt, store the receipt and build a bundle
    with a supported claim and a disputed claim contradicted by decoy events."""
    world = env.world
    scenario = SCENARIOS[scenario_id]
    suffix = scenario_id
    assignment = world.issue(assignment_id=f"ASG-{suffix}")
    tools = build_toolbox(scenario, SEEDS)
    request = ToolRequest(request_id=f"REQ-{suffix}", mission_id=assignment.mission_id,
                          assignment_id=assignment.assignment_id, worker_id=assignment.worker_id,
                          tool_id="log_search", operation_id="search",
                          arguments={"host": scenario.investigation["scope"]["host"]}, requested_at=env.clock(),
                          correlation_id=f"CORR-{suffix}", sequence_number=0)
    env.recorder.tool_request(request, world.gateway_signer.principal)
    env.recorder.authorization_decision(request, world.gateway_signer.principal, True)
    result, receipt = call_double_with_receipt(tools.log_search, request, world.registry.get("log_search"),
                                               receipt_id=f"RCPT-{suffix}", signer=world.gateway_signer,
                                               policy_version=POLICY, clock=env.clock)
    env.recorder.tool_execution(receipt)
    env.store.store_receipt(receipt)
    events = list(result["results"])
    if extra_message is not None:
        events.append({**events[0], "id": "L-EXTRA", "message": extra_message})
    expected = set(scenario.investigation["expected_evidence_event_ids"]) | {"L-EXTRA"}
    decoys = set(scenario.investigation["decoy_event_ids"])
    keep = [e for e in events if e["id"] in expected | decoys]

    def item(e: dict) -> dict:
        return {"evidence_id": f"EV-{suffix}-{e['id']}", "source": "log_search", "source_type": "TOOL_RESULT",
                "source_record_id": e["id"], "content": e, "integrity_digest": canonical_digest(e),
                "timestamp": e["timestamp"], "receipt_id": receipt.receipt_id,
                "provenance": {"provenance_id": f"PROV-{suffix}-{e['id']}", "origin": "log_search:search",
                               "source_type": "TOOL_RESULT", "collected_by": assignment.worker_id,
                               "collected_at": iso(env.clock()), "method": "tool call",
                               "receipt_id": receipt.receipt_id}}
    items = [item(e) for e in keep]
    support = [i["evidence_id"] for i in items if i["source_record_id"] in expected]
    contra = [i["evidence_id"] for i in items if i["source_record_id"] in decoys][:2]
    claims = [{"claim_id": "CLAIM-1", "statement": scenario.investigation["title"],
               "supporting_evidence_ids": support, "contradicting_evidence_ids": [], "confidence": 0.7,
               "rationale": "Cited records were returned by the receipted tool call."},
              {"claim_id": "CLAIM-2", "statement": "The activity was benign.",
               "supporting_evidence_ids": [], "contradicting_evidence_ids": contra, "confidence": 0.2,
               "rationale": "Kept as a disputed alternative; decoy events do not support it.", "disputed": True}]
    bundle = EvidenceBundle.model_validate({
        "evidence_bundle_id": bundle_id or f"BUNDLE-{suffix}", "mission_id": assignment.mission_id,
        "assignment_id": assignment.assignment_id, "worker_id": assignment.worker_id, "claims": claims,
        "evidence_items": items, "supporting_evidence": support, "contradicting_evidence": contra,
        "assumptions": ["Synthetic seed data"], "confidence": 0.7,
        "provenance": {"provenance_id": f"PROV-BUNDLE-{suffix}", "origin": assignment.worker_id,
                       "source_type": "WORKER_ANALYSIS", "collected_by": assignment.worker_id,
                       "collected_at": iso(env.clock()), "method": "analysis"},
        "referenced_tool_receipts": [receipt.receipt_id],
        "tool_call_history": [{"sequence_number": 0, "request_id": request.request_id,
                               "receipt_id": receipt.receipt_id, "tool_id": "log_search", "operation_id": "search",
                               "execution_status": receipt.execution_status.value,
                               "requested_at": iso(request.requested_at)}],
        "completion_status": "partial", "limitations": ["Only one log source was searched"],
        "generated_at": iso(env.clock())})
    if sign:
        bundle = bundle.with_signature(sign_object(bundle, world.worker_signer, now=env.clock()))
    return bundle


def raw_db(path: Path):
    """Attacker-level access: a plain sqlite3 connection with the append-only triggers dropped."""
    import sqlite3
    conn = sqlite3.connect(path, isolation_level=None)
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
        conn.execute(f"DROP TRIGGER {name}")
    return conn


def cli_json(capsys, argv: list[str]) -> tuple[int, dict]:
    from gamis.cli import main
    code = main(argv + ["--json"])
    return code, json.loads(capsys.readouterr().out)
