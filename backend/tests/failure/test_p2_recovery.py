"""P2 failure handling: interruption, rollback, reopen, concurrency, partial persistence, audit failures."""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from gamis.audit.ledger import AuditWriteError, SQLiteAuditLedger
from gamis.audit.recorder import AuditRecorder
from gamis.authority.service import AssignmentRejected
from gamis.evaluation.trust_fixture import AUDITOR, ISSUER, NOW, REGISTRY_ADMIN, MutableClock, build_trust_world
from gamis.evidence.store import (EvidenceAuditError, EvidenceConflictError, EvidencePersistenceError,
                                  EvidenceStore)
from gamis.schemas import EvidenceBundle, ToolDefinition
from tests.p2_support import build_audit_env, receipted_bundle

BACKEND = Path(__file__).resolve().parents[2]
DRAFT = {"event_type": "MISSION_SUSPENDED", "actor_identity": ISSUER.model_dump(mode="json"),
         "correlation_id": "c", "mission_id": "MIS-001", "grant_id": "GRANT-001",
         "event_payload": {"state": "SUSPENDED", "reason": "pause"}}


def new_ledger(path: Path) -> SQLiteAuditLedger:
    return SQLiteAuditLedger.create(path, ledger_id="LEDGER-R", actor=AUDITOR, clock=MutableClock(NOW))


def run_py(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], cwd=BACKEND, capture_output=True, text=True, timeout=120)


# --- ledger ---------------------------------------------------------------------------------

def test_transaction_rollback_leaves_ledger_unchanged(tmp_path):
    class FailingCommit(SQLiteAuditLedger):
        fail = True

        def _commit(self, conn):
            if self.fail:
                raise sqlite3.OperationalError("disk I/O error (simulated)")
            conn.execute("COMMIT")

    new_ledger(tmp_path / "a.db").close()
    led = FailingCommit.open(tmp_path / "a.db", clock=lambda: NOW)
    head = led.get_ledger_head()
    with pytest.raises(AuditWriteError, match="simulated"):
        led.append_event(DRAFT)
    assert led.get_ledger_head() == head and not led._conn.in_transaction
    led.fail = False
    assert led.append_event(DRAFT).sequence_number == head.sequence_number + 1
    assert led.verify_chain().status.value == "VERIFIED"


def test_recovery_after_process_interruption_during_append(tmp_path, capsys):
    path = tmp_path / "audit.db"
    led = new_ledger(path)
    led.append_event(DRAFT)
    head = led.get_ledger_head()
    led.close()
    crash = run_py(f"""
import os
from gamis.audit.ledger import SQLiteAuditLedger
class Crash(SQLiteAuditLedger):
    def _commit(self, conn):
        os._exit(9)          # process dies after the INSERT, before COMMIT
Crash.open({str(path)!r}).append_event({DRAFT!r})
""")
    assert crash.returncode == 9, crash.stderr
    journal = Path(str(path) + "-journal")
    assert journal.exists()
    # the database file still holds only committed data; the read-only verifier sees exactly that
    from tests.p2_support import cli_json
    code, out = cli_json(capsys, ["verify", "--ledger", str(path)])
    assert code == 0 and out["ledger"]["last_sequence"] == head.sequence_number and journal.exists()
    recovered = SQLiteAuditLedger.open(path, clock=lambda: NOW)
    assert recovered.get_ledger_head() == head and recovered.verify_chain().status.value == "VERIFIED"
    assert recovered.append_event(DRAFT).sequence_number == head.sequence_number + 1
    recovered.close()
    assert not journal.exists()


def test_hot_journal_makes_read_only_verification_incomplete_until_recovered(tmp_path, capsys):
    path = tmp_path / "audit.db"
    led = new_ledger(path)
    head = led.get_ledger_head()
    led.close()
    # a crash in the middle of a large transaction whose pages were already spilled into the database file
    crash = run_py(f"""
import os, sqlite3
c = sqlite3.connect({str(path)!r}, isolation_level=None)
c.execute("PRAGMA cache_size=2"); c.execute("BEGIN IMMEDIATE"); c.execute("CREATE TABLE junk (x)")
for _ in range(300):
    c.execute("INSERT INTO junk VALUES (randomblob(4000))")
os._exit(9)
""")
    assert crash.returncode == 9, crash.stderr
    journal = Path(str(path) + "-journal")
    before = (path.read_bytes(), journal.read_bytes())
    from tests.p2_support import cli_json
    code, out = cli_json(capsys, ["verify", "--ledger", str(path)])
    assert code == 2 and out["status"] == "INCOMPLETE"
    assert (path.read_bytes(), journal.read_bytes()) == before         # verifier neither rolled back nor repaired
    recovered = SQLiteAuditLedger.open(path)                          # writer performs the rollback
    assert recovered.get_ledger_head() == head and recovered.verify_chain().status.value == "VERIFIED"
    recovered.close()
    assert cli_json(capsys, ["verify", "--ledger", str(path)])[0] == 0


def test_concurrent_writers_threads_separate_connections(tmp_path):
    path = tmp_path / "audit.db"
    new_ledger(path).close()
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            led = SQLiteAuditLedger.open(path)
            for i in range(25):
                led.append_event({**DRAFT, "correlation_id": f"t{n}-{i}"})
            led.close()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    led = SQLiteAuditLedger.open_read_only(path)
    chain = led.verify_chain()
    assert chain.status.value == "VERIFIED" and chain.events_checked == 151 and chain.last_sequence == 151
    assert len({e.correlation_id for e in led.iter_events()}) == 151
    led.close()


def test_concurrent_writers_shared_instance(tmp_path):
    led = new_ledger(tmp_path / "a.db")
    threads = [threading.Thread(target=lambda n=n: [led.append_event({**DRAFT, "correlation_id": f"s{n}-{i}"})
                                                    for i in range(20)]) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert led.verify_chain().events_checked == 101 and led.verify_chain().status.value == "VERIFIED"


def test_concurrent_writers_separate_processes(tmp_path):
    path = tmp_path / "audit.db"
    new_ledger(path).close()
    code = f"""
import sys
from gamis.audit.ledger import SQLiteAuditLedger
led = SQLiteAuditLedger.open({str(path)!r})
for i in range(30):
    led.append_event({{**{DRAFT!r}, "correlation_id": f"p{{sys.argv[1]}}-{{i}}"}})
"""
    procs = [subprocess.Popen([sys.executable, "-c", code, str(n)], cwd=BACKEND, stderr=subprocess.PIPE, text=True)
             for n in range(4)]
    for p in procs:
        assert p.wait(timeout=120) == 0, p.stderr.read()
    led = SQLiteAuditLedger.open_read_only(path)
    seqs = [e.sequence_number for e in led.iter_events()]
    assert seqs == list(range(1, 122)) and led.verify_chain().status.value == "VERIFIED"
    led.close()


# --- evidence -------------------------------------------------------------------------------

def test_partial_bundle_persistence_is_rolled_back(tmp_path):
    env = build_audit_env(tmp_path)
    bundle = receipted_bundle(env)
    data = bundle.model_dump(mode="json")
    data["signature_metadata"] = None
    # pre-store a conflicting item under the id of the bundle's LAST item
    last = data["evidence_items"][-1]
    clash = {**last, "content": {**last["content"], "message": "conflicting"}}
    from gamis.security.digest import canonical_digest
    clash["integrity_digest"] = canonical_digest(clash["content"])
    from gamis.schemas import EvidenceItem
    env.store.store_evidence(EvidenceItem.model_validate(clash), mission_id=bundle.mission_id,
                             assignment_id=bundle.assignment_id, worker_id=bundle.worker_id)
    before_items = env.store._conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0]
    with pytest.raises(EvidenceConflictError):
        env.store.store_bundle(EvidenceBundle.model_validate(data))
    assert env.store.list_bundles() == ()
    assert env.store._conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0] == before_items
    failed = [e for e in env.ledger.iter_events() if e.event_type.value == "EVIDENCE_PERSISTENCE_FAILED"]
    assert failed and failed[-1].event_payload["error_type"] == "EvidenceConflictError"
    report = env.store.verify_all()
    assert report.status == "PASSED" and any("unreferenced content object" in w for w in report.warnings)
    env.close()


def test_database_failure_during_bundle_write_is_reported_not_swallowed(tmp_path, monkeypatch):
    env = build_audit_env(tmp_path)
    bundle = receipted_bundle(env)

    def explode(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked (simulated)")
    monkeypatch.setattr(env.store, "_insert_bundle_rows", explode)
    with pytest.raises(EvidencePersistenceError, match="rolled back"):
        env.store.store_bundle(bundle)
    assert env.store._conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0] == 0
    assert env.store.list_bundles() == ()
    monkeypatch.undo()
    assert env.store.store_bundle(bundle).newly_stored            # retry succeeds cleanly
    env.close()


def test_audit_failure_after_evidence_commit_is_surfaced_and_detectable(tmp_path):
    env = build_audit_env(tmp_path)
    bundle = receipted_bundle(env)

    class BrokenSink:
        def append_event(self, draft):
            raise AuditWriteError("ledger unavailable (simulated)")
    store = EvidenceStore.open(env.evidence_path, env.content_dir, clock=env.clock, audit=BrokenSink(),
                               trust_store=env.world.trust_store)
    with pytest.raises(EvidenceAuditError, match="stored but not audited"):
        store.store_bundle(bundle)
    assert store.list_bundles() == (bundle.evidence_bundle_id,)
    codes = {f["code"] for f in env.store.audit_cross_check(env.ledger.iter_events())}
    assert codes == {"UNAUDITED_EVIDENCE"}
    store.close()
    env.close()


def test_reopened_evidence_store_still_verifies(tmp_path):
    env = build_audit_env(tmp_path)
    bundle = receipted_bundle(env)
    env.store.store_bundle(bundle)
    env.close()
    reopened = EvidenceStore.open(tmp_path / "evidence.db", tmp_path / "objects", trust_store=env.world.trust_store,
                                  clock=lambda: NOW)
    assert reopened.get_bundle(bundle.evidence_bundle_id).model_dump() == bundle.model_dump()
    assert reopened.verify_all().status == "PASSED"
    reopened.close()


# --- emitters fail closed when the audit write fails ----------------------------------------

class _FailAfter:
    def __init__(self, sink, allowed: int):
        self.sink, self.allowed = sink, allowed

    def append_event(self, draft):
        if self.allowed <= 0:
            raise AuditWriteError("ledger unavailable (simulated)")
        self.allowed -= 1
        return self.sink.append_event(draft)


def test_authority_does_not_release_unaudited_assignments(tmp_path):
    led = new_ledger(tmp_path / "a.db")
    gate = _FailAfter(led, 10_000)
    world = build_trust_world(recorder=AuditRecorder(gate))
    gate.allowed = 1                       # PROPOSED succeeds, APPROVED fails
    with pytest.raises(AuditWriteError):
        world.issue()
    assert world.ledger.issued("GRANT-001") == ()
    gate.allowed = 0                       # rejection cannot be audited -> error, never a silent rejection
    with pytest.raises(AuditWriteError):
        world.issue(worker_id="worker-unknown-9")
    gate.allowed = 10
    with pytest.raises(AssignmentRejected):
        world.issue(worker_id="worker-unknown-9")
    assert world.issue().is_signed and len(world.ledger.issued("GRANT-001")) == 1
    led.close()


def test_registry_change_not_applied_when_audit_fails(tmp_path):
    led = new_ledger(tmp_path / "a.db")
    gate = _FailAfter(led, 10_000)
    world = build_trust_world(recorder=AuditRecorder(gate))
    gate.allowed = 0
    with pytest.raises(AuditWriteError):
        world.registry.set_enabled("case_action", "1.0.0", True, actor=REGISTRY_ADMIN)
    assert world.registry.get("case_action").enabled_status is False
    world.registry.verify_integrity(world.trust_store, NOW)      # seal still valid: nothing changed
    new = ToolDefinition.model_validate({**world.registry.get("log_search").model_dump(mode="json"),
                                         "version": "2.0.0"})
    with pytest.raises(AuditWriteError):
        world.registry.register(new, actor=REGISTRY_ADMIN)
    assert world.registry.get("log_search").version == "1.0.0"
    led.close()
