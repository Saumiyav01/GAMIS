"""P2 signed audit checkpoints: signing, verification, consistency and external anchoring."""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gamis.audit import ledger as ledger_module
from gamis.audit.checkpoints import AuditCheckpoint, load_checkpoint, save_checkpoint, verify_checkpoint_signature
from gamis.audit.events import AuditEventBody, AuditEventType
from gamis.audit.ledger import CheckpointError, SQLiteAuditLedger
from gamis.schemas import SignedObjectType
from gamis.security import signing
from gamis.security.canonical import canonicalize
from gamis.security.keys import SoftwareKeyManager
from gamis.security.signing import sign_object
from tests.p1_support import ISSUER, NOW, MutableClock, build_trust_world
from tests.p2_support import raw_db
from gamis.evaluation.trust_fixture import AUDITOR


def draft(i: int) -> dict:
    return {"event_type": "MISSION_SUSPENDED", "actor_identity": ISSUER.model_dump(mode="json"),
            "correlation_id": f"c-{i}", "mission_id": "MIS-001", "grant_id": "GRANT-001",
            "event_payload": {"state": "SUSPENDED", "reason": f"pause {i}"}}


@pytest.fixture
def setup(tmp_path):
    world = build_trust_world()
    clock = MutableClock(NOW)
    led = SQLiteAuditLedger.create(tmp_path / "audit.db", ledger_id="LEDGER-CP", actor=AUDITOR, clock=clock)
    for i in range(5):
        led.append_event(draft(i))
    yield world, led, clock
    led.close()


def report(led, world, *trusted, store=None):
    return led.get_verification_report(trust_store=store or world.trust_store, trusted_checkpoints=trusted, now=NOW)


def test_checkpoint_generation(setup):
    world, led, _ = setup
    head = led.get_ledger_head()
    cp = led.create_checkpoint(world.audit_signer, world.trust_store, checkpoint_id="CP-1")
    assert (cp.ledger_id, cp.sequence_number, cp.head_event_hash) == ("LEDGER-CP", head.sequence_number,
                                                                      head.event_hash)
    assert (cp.signing_key_id, cp.signing_key_version) == (world.audit_signer.key_id, 1)
    assert cp.genesis_hash == led.genesis_hash and cp.signature_metadata.object_type is SignedObjectType.AUDIT_CHECKPOINT
    event = led.get_event(sequence_number=head.sequence_number + 1)
    assert event.event_type is AuditEventType.CHECKPOINT_CREATED
    assert event.event_payload["covered_sequence_number"] == head.sequence_number
    led.append_event(draft(10))
    cp2 = led.create_checkpoint(world.audit_signer, world.trust_store, checkpoint_id="CP-2")
    assert cp2.sequence_number > cp.sequence_number and led.list_checkpoints() == (cp, cp2)
    with pytest.raises(CheckpointError):
        led.create_checkpoint(world.audit_signer, world.trust_store, checkpoint_id="CP-1")   # ids are unique
    r = report(led, world)
    assert r.status.value == "PASSED" and r.checkpoint_signature_status.value == "VERIFIED"
    assert r.checkpoint_consistency.value == "VERIFIED" and len(r.checkpoints) == 2


def test_valid_signature_verification(setup):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store)
    verified = verify_checkpoint_signature(cp, world.trust_store, now=NOW)
    assert verified.key.principal == AUDITOR and verified.object_type is SignedObjectType.AUDIT_CHECKPOINT


def test_wrong_key_rejection(setup):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store)
    other = build_trust_world()
    with pytest.raises(signing.UnknownKeyError):
        verify_checkpoint_signature(cp, other.trust_store, now=NOW)
    r = report(led, world, store=other.trust_store)
    assert r.status.value == "FAILED" and r.checkpoint_signature_status.value == "FAILED"
    # only AUDIT_SERVICE keys may sign checkpoints, at signing time and at verification time
    with pytest.raises(CheckpointError, match="KeyNotAuthorized"):
        led.create_checkpoint(world.authority._AuthorityService__signer, world.trust_store)
    relabelled = cp.with_signature(world.grant.signature_metadata)
    with pytest.raises(signing.DomainMismatchError):
        verify_checkpoint_signature(relabelled, world.trust_store, now=NOW)


def test_missing_signing_key_is_rejected_before_storing(setup):
    world, led, _ = setup
    head = led.get_ledger_head()
    rogue = SoftwareKeyManager().create_key("audit-rogue", AUDITOR, (SignedObjectType.AUDIT_CHECKPOINT,), NOW)
    with pytest.raises(CheckpointError, match="UnknownKey"):
        led.create_checkpoint(rogue, world.trust_store)
    world.trust_store.revoke(world.audit_signer.key_id)
    with pytest.raises(CheckpointError, match="KeyRevoked"):
        led.create_checkpoint(world.audit_signer, world.trust_store)
    assert led.get_ledger_head() == head and led.list_checkpoints() == ()


@pytest.mark.parametrize("update", [{"sequence_number": 2}, {"head_event_hash": "0" * 64},
                                    {"ledger_id": "OTHER"}, {"created_at": NOW.replace(year=2030)}])
def test_modified_checkpoint_detected(setup, update):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store)
    with pytest.raises(signing.PayloadTamperedError):
        verify_checkpoint_signature(cp.model_copy(update=update), world.trust_store, now=NOW)
    r = report(led, world, cp.model_copy(update=update))
    assert r.status.value == "FAILED" and r.trusted_checkpoint_status.value == "FAILED"


def test_key_fields_bound_to_signature(setup):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store)
    unsigned = cp.without_signature().model_copy(update={"signing_key_version": 7})
    resigned = unsigned.with_signature(sign_object(unsigned, world.audit_signer, now=NOW))
    with pytest.raises(signing.MalformedSignedObjectError, match="signing_key_id/version"):
        verify_checkpoint_signature(resigned, world.trust_store, now=NOW)


def test_invalid_signature_rejection(setup, tmp_path):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store)
    sig = cp.signature_metadata.signature
    bad = cp.with_signature(cp.signature_metadata.model_copy(update={"signature": ("B" if sig[0] == "A" else "A")
                                                                                  + sig[1:]}))
    with pytest.raises(signing.InvalidSignatureError):
        verify_checkpoint_signature(bad, world.trust_store, now=NOW)
    # a stored checkpoint whose signature was altered in the database is reported
    conn = raw_db(tmp_path / "audit.db")
    conn.execute("UPDATE audit_checkpoints SET checkpoint_json = ?",
                 (canonicalize(bad.model_dump(mode="json")).decode(),))
    r = report(led, world)
    assert r.checkpoint_signature_status.value == "FAILED"
    assert "CHECKPOINT_SIGNATURE_INVALID" in {f.code for f in r.failures}


def test_ledger_head_consistency(setup, tmp_path):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store)
    for i in range(3):
        led.append_event(draft(20 + i))
    assert report(led, world, cp).status.value == "PASSED"          # head moved on; checkpoint still matches
    raw_db(tmp_path / "audit.db").execute(
        "UPDATE audit_events SET correlation_id = 'edited' WHERE sequence_number = ?", (cp.sequence_number,))
    r = report(led, world, cp)
    assert "CHECKPOINT_INCONSISTENT" in {f.code for f in r.failures}
    assert r.checkpoint_consistency.value == "FAILED" and r.trusted_checkpoint_status.value == "FAILED"


def _rewrite_history(path, from_seq: int) -> None:
    """Attacker with full database control: edit one event and recompute every later hash, delete the stored
    checkpoints and restore the triggers. The hash chain alone then verifies cleanly."""
    conn = raw_db(path)
    conn.execute("DELETE FROM audit_checkpoints")
    prev = conn.execute("SELECT event_hash FROM audit_events WHERE sequence_number = ?", (from_seq - 1,)).fetchone()[0]
    conn.row_factory = __import__("sqlite3").Row
    for row in conn.execute("SELECT * FROM audit_events WHERE sequence_number >= ? ORDER BY sequence_number",
                            (from_seq,)).fetchall():
        fields = ledger_module._row_fields(row)
        fields["previous_event_hash"] = prev
        if row["sequence_number"] == from_seq:
            fields["event_payload"] = {**fields["event_payload"], "reason": "history rewritten"}
        body = AuditEventBody.model_validate(fields)
        prev = body.compute_hash()
        conn.execute("UPDATE audit_events SET payload_json = ?, previous_event_hash = ?, event_hash = ? "
                     "WHERE sequence_number = ?", (canonicalize(body.model_dump(mode="json")["event_payload"]).decode(),
                                                   body.previous_event_hash, prev, row["sequence_number"]))
    conn.executescript(ledger_module._SCHEMA)
    conn.close()


def test_external_trusted_checkpoint_detects_whole_history_rewrite(setup, tmp_path):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store, checkpoint_id="CP-EXT")
    save_checkpoint(cp, tmp_path / "cp.json")
    assert "PRIVATE" not in (tmp_path / "cp.json").read_text()
    _rewrite_history(tmp_path / "audit.db", from_seq=3)
    assert led.verify_chain().status.value == "VERIFIED"          # the limitation: chain alone is fooled
    assert report(led, world).status.value == "PASSED"
    r = report(led, world, load_checkpoint(tmp_path / "cp.json"))
    assert r.status.value == "FAILED" and r.trusted_checkpoint_status.value == "FAILED"
    assert "CHECKPOINT_INCONSISTENT" in {f.code for f in r.failures}


def test_external_trusted_checkpoint_detects_truncation_and_substitution(setup, tmp_path):
    world, led, _ = setup
    led.append_event(draft(30))
    cp = led.create_checkpoint(world.audit_signer, world.trust_store, checkpoint_id="CP-T")
    conn = raw_db(tmp_path / "audit.db")
    conn.execute("DELETE FROM audit_events WHERE sequence_number >= ?", (cp.sequence_number,))
    conn.execute("DELETE FROM audit_checkpoints")
    conn.executescript(ledger_module._SCHEMA)
    assert led.verify_chain().status.value == "VERIFIED"
    r = report(led, world, cp)
    assert "CHECKPOINT_BEYOND_HEAD" in {f.code for f in r.failures} and r.status.value == "FAILED"
    other_world = build_trust_world()
    other = SQLiteAuditLedger.create(tmp_path / "other.db", ledger_id="LEDGER-OTHER", actor=AUDITOR,
                                     clock=lambda: NOW)
    foreign = other.create_checkpoint(other_world.audit_signer, other_world.trust_store)
    r2 = led.get_verification_report(trust_store=other_world.trust_store, trusted_checkpoints=(foreign,), now=NOW)
    assert "CHECKPOINT_LEDGER_MISMATCH" in {f.code for f in r2.failures}       # validly signed, wrong ledger
    other.close()


def test_stored_checkpoint_must_match_trusted_copy(setup, tmp_path):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store, checkpoint_id="CP-SAME")
    fake = cp.without_signature().model_copy(update={"created_at": NOW.replace(minute=30)})
    fake = fake.with_signature(sign_object(fake, world.audit_signer, now=NOW.replace(minute=30)))
    r = report(led, world, fake)
    assert "TRUSTED_CHECKPOINT_MISMATCH" in {f.code for f in r.failures}


def test_checkpoint_verifiable_after_reopen(setup, tmp_path):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store)
    led.close()
    reopened = SQLiteAuditLedger.open_read_only(tmp_path / "audit.db")
    assert reopened.list_checkpoints() == (cp,)
    assert report(reopened, world, cp).status.value == "PASSED"
    reopened.close()


def test_without_trust_store_verification_is_incomplete(setup):
    world, led, _ = setup
    cp = led.create_checkpoint(world.audit_signer, world.trust_store)
    r = led.get_verification_report(trusted_checkpoints=(cp,), now=NOW)
    assert r.status.value == "INCOMPLETE" and r.checkpoint_signature_status.value == "NOT_VERIFIED"
    assert r.trusted_checkpoint_status.value == "NOT_VERIFIED"


def test_private_keys_never_stored_in_the_ledger(tmp_path):
    secret = bytes(range(1, 33))
    keys = SoftwareKeyManager()
    signer = keys.create_key("audit-known", AUDITOR, (SignedObjectType.AUDIT_CHECKPOINT,), NOW,
                             private_key=Ed25519PrivateKey.from_private_bytes(secret))
    led = SQLiteAuditLedger.create(tmp_path / "audit.db", ledger_id="LEDGER-K", actor=AUDITOR, clock=lambda: NOW)
    cp = led.create_checkpoint(signer, keys.trust_store)
    led.close()
    data = (tmp_path / "audit.db").read_bytes()
    pem = Ed25519PrivateKey.from_private_bytes(secret).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    assert secret not in data and pem not in data and b"PRIVATE KEY" not in data
    assert signer.public_key_raw() not in json.dumps(cp.model_dump(mode="json")).encode()
    assert AuditCheckpoint.model_validate_json(cp.model_dump_json()) == cp
