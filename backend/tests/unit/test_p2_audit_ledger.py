"""P2 audit ledger: genesis, append, chaining, retrieval, verification, append-only and tamper detection."""
from __future__ import annotations

import json
import sqlite3

import pytest
from pydantic import ValidationError

from gamis.audit.events import (AuditEventBody, AuditEventDraft, AuditEventType, GenesisPayload, MissionPayload,
                                category_of, genesis_hash)
from gamis.audit.ledger import (DuplicateEventError, InvalidEventError, LedgerIntegrityError, LedgerReadOnlyError,
                                SQLiteAuditLedger, AuditWriteError)
from gamis.evaluation.trust_fixture import AUDITOR, AUTHORITY, ISSUER, NOW, SUPERVISOR, MutableClock
from tests.p2_support import raw_db

LEDGER_ID = "LEDGER-UNIT"


def draft(i: int = 0, **overrides) -> dict:
    data = {"event_type": "MISSION_SUSPENDED", "actor_identity": ISSUER.model_dump(mode="json"),
            "correlation_id": f"corr-{i}", "mission_id": "MIS-001", "grant_id": "GRANT-001",
            "event_payload": {"state": "SUSPENDED", "reason": f"pause {i}"}}
    data.update(overrides)
    return data


@pytest.fixture
def ledger(tmp_path):
    clock = MutableClock(NOW)
    led = SQLiteAuditLedger.create(tmp_path / "audit.db", ledger_id=LEDGER_ID, actor=AUDITOR, clock=clock)
    for i in range(6):
        clock.advance(seconds=1)
        led.append_event(draft(i))
    yield led
    led.close()


def failures(led) -> set[tuple[str, int | None]]:
    return {(f.code, f.sequence_number) for f in led.verify_chain().failures}


def codes(led) -> set[str]:
    return {f.code for f in led.verify_chain().failures}


# --- genesis / append / retrieval ---------------------------------------------------------------

def test_genesis_creation(tmp_path):
    led = SQLiteAuditLedger.create(tmp_path / "g.db", ledger_id=LEDGER_ID, actor=AUDITOR, clock=lambda: NOW)
    head = led.get_ledger_head()
    genesis = led.get_event(sequence_number=1)
    expected = genesis_hash(LEDGER_ID, "2026-01-10T09:00:00.000000Z")
    assert head.sequence_number == 1 and head.event_hash == genesis.event_hash
    assert genesis.event_type is AuditEventType.LEDGER_GENESIS and genesis.previous_event_hash == expected
    assert genesis.event_payload["genesis_hash"] == expected == led.genesis_hash
    assert genesis.actor_identity == AUDITOR and genesis.category.value == "LEDGER"
    assert led.verify_chain().status.value == "VERIFIED"
    with pytest.raises(AuditWriteError, match="already contains"):
        SQLiteAuditLedger.create(tmp_path / "g.db", ledger_id="OTHER", actor=AUDITOR)
    with pytest.raises(AuditWriteError, match="AUDIT_SERVICE"):
        SQLiteAuditLedger.create(tmp_path / "h.db", ledger_id="L", actor=ISSUER)
    with pytest.raises(LedgerIntegrityError):
        SQLiteAuditLedger.open(tmp_path / "missing.db")
    sqlite3.connect(tmp_path / "plain.db").execute("CREATE TABLE x (a)").connection.commit()
    with pytest.raises(LedgerIntegrityError, match="not an initialised"):
        SQLiteAuditLedger.open(tmp_path / "plain.db")
    # genesis may only ever be event 1
    with pytest.raises(InvalidEventError):
        led.append_event(draft(event_type="LEDGER_GENESIS", actor_identity=AUDITOR.model_dump(mode="json"),
                               event_payload=GenesisPayload(ledger_id=LEDGER_ID, genesis_hash=expected,
                                                            schema_version=1).model_dump()))


def test_valid_append_sequential_numbering_and_hash_chaining(ledger):
    events = list(ledger.iter_events())
    assert [e.sequence_number for e in events] == list(range(1, 8))
    for prev, cur in zip(events, events[1:]):
        assert cur.previous_event_hash == prev.event_hash
        assert cur.event_hash == cur.compute_hash() and cur.timestamp >= prev.timestamp
    assert len({e.event_hash for e in events}) == 7 and len({e.event_id for e in events}) == 7
    new = ledger.append_event(draft(99))
    assert new.sequence_number == 8 and new.previous_event_hash == events[-1].event_hash
    assert ledger.get_ledger_head().event_hash == new.event_hash and new.ledger_id == LEDGER_ID


def test_hashed_fields_are_exactly_defined(ledger):
    event = ledger.get_event(sequence_number=3)
    content = event.hashed_content()
    assert set(content) == {"ledger_id", "event_id", "event_type", "event_version", "mission_id", "grant_id",
                            "assignment_id", "worker_id", "actor_identity", "timestamp", "sequence_number",
                            "correlation_id", "event_payload", "previous_event_hash"}
    for field, value in [("timestamp", "2026-01-10T09:00:59.000000Z"), ("sequence_number", 30),
                         ("correlation_id", "other"), ("previous_event_hash", "0" * 64), ("ledger_id", "L2")]:
        changed = AuditEventBody.model_validate({**event.model_dump(mode="json", exclude={"event_hash"}),
                                                 field: value})
        assert changed.compute_hash() != event.event_hash


def test_event_retrieval(ledger):
    third = ledger.get_event(sequence_number=3)
    assert ledger.get_event(event_id=third.event_id) == third
    assert ledger.get_event(sequence_number=999) is None and ledger.get_event(event_id="nope") is None
    with pytest.raises(ValueError):
        ledger.get_event()
    assert [e.sequence_number for e in ledger.get_events(start=2, end=4)] == [2, 3, 4]
    assert len(ledger.get_events(mission_id="MIS-001")) == 6
    assert [e.event_type for e in ledger.get_events(event_type="LEDGER_GENESIS")] == [AuditEventType.LEDGER_GENESIS]
    assert len(ledger.get_events(limit=2)) == 2


def test_full_chain_verification_and_report(ledger):
    chain = ledger.verify_chain()
    assert chain.status.value == "VERIFIED" and chain.events_checked == 7
    assert (chain.first_sequence, chain.last_sequence) == (1, 7)
    assert chain.head_event_hash == ledger.get_ledger_head().event_hash
    report = ledger.get_verification_report()
    assert report.status.value == "PASSED" and report.checkpoint_signature_status.value == "NONE"
    assert any("no signed checkpoint" in w for w in report.warnings)
    assert json.loads(json.dumps(report.to_dict()))["chain_status"] == "VERIFIED"


def test_reopen_preserves_and_continues_chain(tmp_path, ledger):
    head = ledger.get_ledger_head()
    ledger.close()
    reopened = SQLiteAuditLedger.open(tmp_path / "audit.db", clock=lambda: NOW)
    assert reopened.get_ledger_head() == head and reopened.ledger_id == LEDGER_ID
    assert reopened.append_event(draft(50)).sequence_number == head.sequence_number + 1
    assert reopened.verify_chain().status.value == "VERIFIED"
    reopened.close()
    ro = SQLiteAuditLedger.open_read_only(tmp_path / "audit.db")
    assert ro.verify_chain().status.value == "VERIFIED"
    with pytest.raises(LedgerReadOnlyError):
        ro.append_event(draft(51))
    ro.close()


# --- validation ---------------------------------------------------------------------------------

@pytest.mark.parametrize("overrides,match", [
    ({"event_type": "SOMETHING_ELSE"}, None),
    ({"event_payload": {"state": "SUSPENDED", "raw_content": "x"}}, "Extra inputs"),
    ({"event_payload": {"state": "PAUSED"}}, None),
    ({"event_payload": "not an object"}, "object"),
    ({"event_payload": {"grant_digest": "a" * 64}}, None),                         # wrong payload model
    ({"mission_id": None}, "requires"),
    ({"grant_id": None}, "requires"),
    ({"event_type": "ASSIGNMENT_SIGNED"}, None),
    ({"event_type": "GRANT_ISSUED", "event_payload": {}}, None),
    ({"correlation_id": "bad id"}, None),
    ({"actor_identity": {"principal_id": "x", "principal_type": "ROOT"}}, None),
    ({"unexpected": True}, "Extra inputs"),
    ({"event_payload": {"state": "SUSPENDED", "reason": "x" * 300}}, None),
])
def test_invalid_event_payloads_are_rejected(ledger, overrides, match):
    head = ledger.get_ledger_head()
    with pytest.raises(InvalidEventError, match=match):
        ledger.append_event(draft(**overrides))
    assert ledger.get_ledger_head() == head


def test_actor_restrictions_per_event_type():
    for event_type, payload, refs, actor in [
            ("CHECKPOINT_CREATED", {"checkpoint_id": "c", "covered_sequence_number": 1, "head_event_hash": "a" * 64,
                                    "signing_key_id": "k", "signing_key_version": 1}, {}, SUPERVISOR),
            ("ASSIGNMENT_REJECTED", {"proposal_digest": None, "violation_codes": ["X"], "violation_messages": []},
             {"mission_id": "M", "grant_id": "G"}, SUPERVISOR)]:
        with pytest.raises(ValidationError, match="may not emit"):
            AuditEventDraft(event_type=event_type, actor_identity=actor, correlation_id="c", event_payload=payload,
                            **refs)
        AuditEventDraft(event_type=event_type, actor_identity=AUDITOR if event_type.startswith("CHECK") else AUTHORITY,
                        correlation_id="c", event_payload=payload, **refs)
    assert {category_of(t).value for t in AuditEventType} == {"LEDGER", "MISSION", "GRANT", "ASSIGNMENT", "WORKER",
                                                               "REGISTRY", "TOOL", "EVIDENCE"}


def test_payload_text_is_redacted_before_hashing(tmp_path, ledger):
    event = ledger.append_event(draft(event_payload={"state": "SUSPENDED", "reason":
                                                     "token leaked: password=hunter2 api_key=AKIAABCDEFGHIJKLMNOP"}))
    assert "hunter2" not in json.dumps(event.event_payload) and "AKIA" not in json.dumps(event.event_payload)
    assert "[REDACTED:" in event.event_payload["reason"]
    ledger.close()
    assert b"hunter2" not in (tmp_path / "audit.db").read_bytes()


def test_duplicate_event_ids_are_rejected(ledger):
    ledger.append_event(draft(event_id="evt-fixed-1"))
    head = ledger.get_ledger_head()
    with pytest.raises(DuplicateEventError):
        ledger.append_event(draft(event_id="evt-fixed-1"))
    assert ledger.get_ledger_head() == head
    assert ledger.append_event(draft(event_id="evt-fixed-2")).sequence_number == head.sequence_number + 1


# --- append-only enforcement --------------------------------------------------------------------

def test_api_exposes_no_mutation():
    public = {n for n in dir(SQLiteAuditLedger) if not n.startswith("_")}
    assert not {n for n in public if any(w in n for w in ("update", "delete", "remove", "edit", "truncate",
                                                          "rewrite", "replace", "set_"))}


def test_database_enforces_append_only(tmp_path, ledger):
    conn = sqlite3.connect(tmp_path / "audit.db", isolation_level=None)
    row = conn.execute("SELECT * FROM audit_events WHERE sequence_number = 7").fetchone()
    blocked = [
        "UPDATE audit_events SET correlation_id = 'x' WHERE sequence_number = 3",
        "UPDATE audit_events SET sequence_number = 99 WHERE sequence_number = 7",
        "DELETE FROM audit_events WHERE sequence_number = 7",
        "DELETE FROM audit_events",
        "UPDATE ledger_meta SET value = 'x' WHERE key = 'genesis_hash'",
        "DELETE FROM ledger_meta",
        "INSERT INTO ledger_meta VALUES ('extra', 'x')",
    ]
    for sql in blocked:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute(sql)
    cols = "sequence_number, event_id, ledger_id, event_type, event_version, mission_id, grant_id, assignment_id, " \
           "worker_id, actor_json, timestamp, correlation_id, payload_json, previous_event_hash, event_hash"
    for seq, prev, ledger_id in [(9, row[13], LEDGER_ID), (7, row[13], LEDGER_ID), (8, "0" * 64, LEDGER_ID),
                                 (8, row[14], "OTHER")]:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute(f"INSERT INTO audit_events ({cols}) VALUES (?, 'evt-x', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (seq, ledger_id, *row[3:13], prev, "e" * 64))
    with pytest.raises(sqlite3.DatabaseError, match="checkpoint does not match"):
        conn.execute("INSERT INTO audit_checkpoints VALUES ('c', ?, 3, ?, 't', 'k', 1, '{}')", (LEDGER_ID, "f" * 64))
    conn.close()
    assert ledger.verify_chain().status.value == "VERIFIED"


# --- tamper detection (attacker drops the triggers first) ---------------------------------------

def test_modified_event_payload_detected(tmp_path, ledger):
    conn = raw_db(tmp_path / "audit.db")
    conn.execute("UPDATE audit_events SET payload_json = replace(payload_json, 'pause 2', 'pause X') "
                 "WHERE sequence_number = 4")
    assert ("HASH_MISMATCH", 4) in failures(ledger) and ("BROKEN_LINK", 5) in failures(ledger)
    assert "APPEND_ONLY_TRIGGERS_MISSING" in codes(ledger)
    with pytest.raises(LedgerIntegrityError):
        ledger.get_event(sequence_number=4)
    assert ledger.get_verification_report().status.value == "FAILED"


def test_modified_timestamp_detected(tmp_path, ledger):
    raw_db(tmp_path / "audit.db").execute("UPDATE audit_events SET timestamp = '2025-01-01T00:00:00.000000Z' "
                                          "WHERE sequence_number = 3")
    assert ("HASH_MISMATCH", 3) in failures(ledger)


def test_modified_event_hash_detected(tmp_path, ledger):
    raw_db(tmp_path / "audit.db").execute("UPDATE audit_events SET event_hash = ? WHERE sequence_number = 5",
                                          ("ab" * 32,))
    assert ("HASH_MISMATCH", 5) in failures(ledger)


def test_recomputed_hash_after_edit_breaks_next_link(tmp_path, ledger):
    conn = raw_db(tmp_path / "audit.db")
    row = conn.execute("SELECT * FROM audit_events WHERE sequence_number = 3").fetchone()
    event = ledger.get_event(sequence_number=3)
    forged = AuditEventBody.model_validate({**event.model_dump(mode="json", exclude={"event_hash"}),
                                            "event_payload": {**event.model_dump(mode="json")["event_payload"],
                                                              "reason": "forged"}})
    conn.execute("UPDATE audit_events SET payload_json = ?, event_hash = ? WHERE sequence_number = 3",
                 (json.dumps(forged.model_dump(mode="json")["event_payload"], separators=(",", ":"),
                             sort_keys=True), forged.compute_hash()))
    assert row is not None
    found = failures(ledger)
    assert ("BROKEN_LINK", 4) in found and ("HASH_MISMATCH", 3) not in found


def test_deleted_event_detected(tmp_path, ledger):
    raw_db(tmp_path / "audit.db").execute("DELETE FROM audit_events WHERE sequence_number = 4")
    found = failures(ledger)
    assert ("SEQUENCE_GAP", 5) in found and ("BROKEN_LINK", 5) in found


def test_reordered_events_detected(tmp_path, ledger):
    conn = raw_db(tmp_path / "audit.db")
    a, b = (conn.execute("SELECT * FROM audit_events WHERE sequence_number = ?", (s,)).fetchone() for s in (3, 4))
    sql = ("UPDATE audit_events SET event_id = ?, correlation_id = ?, payload_json = ?, timestamp = ?, "
           "previous_event_hash = ?, event_hash = ? WHERE sequence_number = ?")
    conn.execute("UPDATE audit_events SET event_id = 'tmp', event_hash = ? WHERE sequence_number = 3", ("0" * 64,))
    conn.execute(sql, (a[1], a[11], a[12], a[10], a[13], a[14], 4))   # swap full contents of events 3 and 4
    conn.execute(sql, (b[1], b[11], b[12], b[10], b[13], b[14], 3))
    found = failures(ledger)
    assert {("BROKEN_LINK", 3), ("BROKEN_LINK", 4), ("BROKEN_LINK", 5)} <= found
    assert ("HASH_MISMATCH", 3) in found


def test_inserted_event_detected(tmp_path, ledger):
    conn = raw_db(tmp_path / "audit.db")
    for seq in range(7, 3, -1):
        conn.execute("UPDATE audit_events SET sequence_number = sequence_number + 1 WHERE sequence_number = ?", (seq,))
    template = conn.execute("SELECT * FROM audit_events WHERE sequence_number = 3").fetchone()
    conn.execute("INSERT INTO audit_events VALUES (4, 'evt-injected', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 (*template[2:13], template[14], "cd" * 32))
    found = failures(ledger)
    assert ("HASH_MISMATCH", 4) in found and ("BROKEN_LINK", 5) in found


def test_altered_previous_hash_detected(tmp_path, ledger):
    raw_db(tmp_path / "audit.db").execute("UPDATE audit_events SET previous_event_hash = ? WHERE sequence_number = 6",
                                          ("12" * 32,))
    found = failures(ledger)
    assert ("BROKEN_LINK", 6) in found and ("HASH_MISMATCH", 6) in found


def test_unexpected_sequence_gap_detected(tmp_path, ledger):
    raw_db(tmp_path / "audit.db").execute("UPDATE audit_events SET sequence_number = 20 WHERE sequence_number = 7")
    assert ("SEQUENCE_GAP", 20) in failures(ledger)


def test_genesis_metadata_tampering_detected(tmp_path, ledger):
    raw_db(tmp_path / "audit.db").execute("UPDATE ledger_meta SET value = '2020-01-01T00:00:00.000000Z' "
                                          "WHERE key = 'created_at'")
    assert {"GENESIS_HASH_MISMATCH", "BROKEN_LINK", "GENESIS_EVENT_INVALID"} <= codes(ledger)


def test_non_canonical_record_detected(tmp_path, ledger):
    """An edit that normalises back to the same hashed value must still be caught."""
    event = ledger.append_event(draft(event_payload={"state": "SUSPENDED", "reason": "password=hunter2"}))
    stored = json.dumps(event.model_dump(mode="json")["event_payload"], separators=(",", ":"), sort_keys=True)
    raw_db(tmp_path / "audit.db").execute(
        "UPDATE audit_events SET payload_json = ? WHERE sequence_number = ?",
        (stored.replace("[REDACTED:credential-assignment]", "swordfish"), event.sequence_number))
    found = {code for code, seq in failures(ledger) if seq == event.sequence_number}
    assert found & {"NON_CANONICAL_RECORD", "INVALID_EVENT"}
    # same check on a field that is not normalised: a re-ordered but equivalent JSON encoding
    other = ledger.get_event(sequence_number=3)
    reencoded = json.dumps(other.model_dump(mode="json")["event_payload"], indent=1)
    raw_db(tmp_path / "audit.db").execute("UPDATE audit_events SET payload_json = ? WHERE sequence_number = 3",
                                          (reencoded,))
    assert ("NON_CANONICAL_RECORD", 3) in failures(ledger)


def test_tail_truncation_is_not_detectable_without_a_checkpoint(tmp_path, ledger):
    """Documented limitation: removing the newest events leaves a valid chain. See checkpoint tests."""
    raw_db(tmp_path / "audit.db").execute("DELETE FROM audit_events WHERE sequence_number >= 6")
    assert codes(ledger) == {"APPEND_ONLY_TRIGGERS_MISSING"}
    report = ledger.get_verification_report()
    assert report.chain_status.value == "FAILED" and any("no signed checkpoint" in w for w in report.warnings)


def test_mission_payload_model_rejects_unknown_states():
    with pytest.raises(ValidationError):
        MissionPayload(state="DELETED")
