"""P2 evidence storage: persistence, CAS, integrity, references, bundle consistency, relations."""
from __future__ import annotations

import os
import sqlite3

import pytest

from gamis.audit.events import AuditEventType
from gamis.evidence.content_store import (ContentCorruptedError, ContentStore, ContentStoreError, cas_reference,
                                          parse_cas_reference)
from gamis.evidence.store import (CheckResult, EvidenceConflictError, EvidenceIntegrityError, EvidenceStore,
                                  EvidenceStoreError, InvalidEvidenceError)
from gamis.schemas import EvidenceBundle, EvidenceItem, ToolReceipt
from gamis.security.canonical import canonicalize
from gamis.security.digest import canonical_digest, sha256_hex
from gamis.security.signing import sign_object
from tests.p1_support import evidence_item_dict, receipt_dict
from tests.p2_support import build_audit_env, raw_db, receipted_bundle

CTX = dict(mission_id="MIS-001", assignment_id="ASG-001", worker_id="worker-reader-1")


@pytest.fixture
def env(tmp_path):
    e = build_audit_env(tmp_path)
    yield e
    e.close()


def stored_receipt(env, receipt_id="RCPT-1", **overrides) -> ToolReceipt:
    receipt = ToolReceipt.model_validate(receipt_dict(receipt_id=receipt_id, **overrides))
    receipt = receipt.with_signature(sign_object(receipt, env.world.gateway_signer, now=env.clock()))
    env.store.store_receipt(receipt)
    return receipt


_UNSET = object()


def item(evidence_id="EV-1", content=_UNSET, receipt_id="RCPT-1", **overrides) -> EvidenceItem:
    data = evidence_item_dict(evidence_id, receipt_id)
    if content is not _UNSET:
        data.update(content=content, integrity_digest=canonical_digest(content))
    data.update(overrides)
    return EvidenceItem.model_validate(data)


def events(env, event_type):
    return [e for e in env.ledger.iter_events() if e.event_type is event_type]


# --- items --------------------------------------------------------------------------------------

def test_valid_evidence_persistence_and_retrieval(env):
    stored_receipt(env)
    original = item()
    result = env.store.store_evidence(original, **CTX)
    assert result.newly_stored and result.content_digest == original.integrity_digest
    fetched = env.store.get_evidence("EV-1")
    assert fetched == original and fetched.integrity_digest == original.integrity_digest
    assert env.store.evidence_links("EV-1") == (("MIS-001", "ASG-001", "worker-reader-1", ""),)
    assert env.store.content.get(original.integrity_digest) == canonicalize(original.content)
    event = events(env, AuditEventType.EVIDENCE_STORED)[-1]
    assert event.event_payload["evidence_id"] == "EV-1" and event.event_payload["content_storage"] == "cas"
    assert event.event_payload["record_digest"] == result.record_digest
    assert "Failed login for root" not in str(event.event_payload)            # no raw content in the ledger
    # re-storing the identical item is idempotent and not re-audited
    assert not env.store.store_evidence(original, **CTX).newly_stored
    assert len(events(env, AuditEventType.EVIDENCE_STORED)) == 1


def test_stable_ids_reject_conflicting_content(env):
    stored_receipt(env)
    env.store.store_evidence(item(), **CTX)
    with pytest.raises(EvidenceConflictError):
        env.store.store_evidence(item(content={"id": "L-002", "message": "different"}), **CTX)
    assert events(env, AuditEventType.EVIDENCE_PERSISTENCE_FAILED)
    assert env.store.get_evidence("EV-1") == item()


def test_receipt_references_must_exist_and_match(env):
    with pytest.raises(InvalidEvidenceError, match="not stored"):
        env.store.store_evidence(item(), **CTX)
    stored_receipt(env)
    with pytest.raises(InvalidEvidenceError, match="different mission"):
        env.store.store_evidence(item(), **{**CTX, "assignment_id": "ASG-OTHER"})
    unsigned = ToolReceipt.model_validate(receipt_dict(receipt_id="RCPT-U"))
    with pytest.raises(InvalidEvidenceError, match="signed"):
        env.store.store_receipt(unsigned)
    forged = unsigned.with_signature(sign_object(unsigned, env.world.gateway_signer, now=env.clock()))
    with pytest.raises(InvalidEvidenceError, match="PayloadTampered"):
        env.store.store_receipt(forged.model_copy(update={"worker_id": "worker-intel-1"}))
    assert env.store.store_receipt(env.store.get_receipt("RCPT-1")) is False


def test_duplicate_content_is_deduplicated(env):
    stored_receipt(env)
    a = env.store.store_evidence(item("EV-A"), **CTX)
    b = env.store.store_evidence(item("EV-B"), **CTX)
    assert a.content_digest == b.content_digest and not a.content_deduplicated and b.content_deduplicated
    assert list(env.store.content.iter_digests()) == [a.content_digest]
    assert env.store.get_evidence("EV-A").content == env.store.get_evidence("EV-B").content


def test_digest_verification(env):
    stored_receipt(env)
    env.store.store_evidence(item(), **CTX)
    check = env.store.verify_evidence("EV-1")
    assert check.status is CheckResult.VERIFIED and check.ok
    assert events(env, AuditEventType.EVIDENCE_VALIDATED)[-1].event_payload["outcome"] == "PASSED"
    assert env.store.verify_evidence("EV-404").status is CheckResult.NOT_FOUND


def _object_path(env, digest):
    path = env.store.content.path_for(digest)
    os.chmod(path, 0o644)
    return path


def test_corrupted_content_detected(env):
    stored_receipt(env)
    original = item()
    env.store.store_evidence(original, **CTX)
    _object_path(env, original.integrity_digest).write_bytes(b'{"id":"L-002","message":"tampered"}')
    check = env.store.verify_evidence("EV-1")
    assert check.status is CheckResult.FAILED and check.failure_codes == ["CORRUPTED_CONTENT"]
    with pytest.raises(EvidenceIntegrityError):
        env.store.get_evidence("EV-1")
    with pytest.raises(ContentCorruptedError):          # never silently overwritten either
        env.store.content.put(canonicalize(original.content))
    assert events(env, AuditEventType.EVIDENCE_VALIDATION_FAILED)
    report = env.store.verify_all()
    assert report.status == "FAILED" and {f["code"] for f in report.failures} >= {"CORRUPTED_CONTENT",
                                                                                   "CONTENT_OBJECT_CORRUPTED"}


def test_missing_content_detected(env):
    stored_receipt(env)
    original = item()
    env.store.store_evidence(original, **CTX)
    _object_path(env, original.integrity_digest).unlink()
    check = env.store.verify_evidence("EV-1")
    assert check.failure_codes == ["MISSING_CONTENT"]
    with pytest.raises(EvidenceIntegrityError):
        env.store.get_evidence("EV-1")
    assert "CONTENT_OBJECT_MISSING" in {f["code"] for f in env.store.verify_all().failures}


def test_blob_references_and_invalid_references(env):
    stored_receipt(env)
    data = b"\x00binary evidence object\xff" * 1000
    put = env.store.store_blob(data)
    assert parse_cas_reference(put.reference) == put.digest == sha256_hex(data)
    blob_item = item("EV-BLOB", content=None, content_reference=put.reference, integrity_digest=put.digest)
    env.store.store_evidence(blob_item, **CTX)
    assert env.store.verify_evidence("EV-BLOB").status is CheckResult.VERIFIED
    assert env.store.get_evidence("EV-BLOB").content_reference == put.reference
    external = item("EV-EXT", content=None, content_reference="vault://case/123", integrity_digest="9" * 64)
    env.store.store_evidence(external, **CTX)
    assert env.store.verify_evidence("EV-EXT").status is CheckResult.EXTERNAL_REFERENCE
    missing = cas_reference("ab" * 32)
    with pytest.raises(InvalidEvidenceError, match="unusable"):
        env.store.store_evidence(item("EV-M", content=None, content_reference=missing, integrity_digest="ab" * 32),
                                 **CTX)
    with pytest.raises(InvalidEvidenceError, match="differs"):
        env.store.store_evidence(item("EV-D", content=None, content_reference=put.reference,
                                      integrity_digest="cd" * 32), **CTX)
    with pytest.raises(ContentStoreError):
        env.store.content.path_for("../../etc/passwd")


def test_content_store_basics(tmp_path):
    cas = ContentStore(tmp_path / "cas", max_object_bytes=10)
    first = cas.put(b"hello")
    assert not first.deduplicated and cas.put(b"hello").deduplicated and cas.get(first.digest) == b"hello"
    with pytest.raises(ContentStoreError, match="exceeds"):
        cas.put(b"x" * 11)
    ro = ContentStore(tmp_path / "cas", read_only=True)
    with pytest.raises(ContentStoreError, match="read-only"):
        ro.put(b"x")
    assert ro.get(first.digest) == b"hello"


# --- bundles ------------------------------------------------------------------------------------

def test_evidence_bundle_persistence_and_retrieval(env):
    bundle = receipted_bundle(env)
    result = env.store.store_bundle(bundle)
    assert result.newly_stored and len(result.items) == len(bundle.evidence_items)
    fetched = env.store.get_bundle(bundle.evidence_bundle_id)
    assert fetched.model_dump(mode="json") == bundle.model_dump(mode="json")
    assert fetched.signature_metadata == bundle.signature_metadata
    assert env.store.list_bundles(mission_id="MIS-001") == (bundle.evidence_bundle_id,)
    event = events(env, AuditEventType.EVIDENCE_BUNDLE_STORED)[-1]
    assert event.event_payload["bundle_digest"] == result.bundle_digest and event.event_payload["signed"] is True
    assert event.event_payload["contradicting_evidence_count"] == len(bundle.contradicting_evidence) >= 1
    assert event.event_payload["disputed_claim_count"] == 1
    assert not env.store.store_bundle(bundle).newly_stored
    changed = {**bundle.model_dump(mode="json"), "confidence": 0.1}
    with pytest.raises(InvalidEvidenceError, match="PayloadTampered"):     # still carries the old signature
        env.store.store_bundle(EvidenceBundle.model_validate(changed))
    with pytest.raises(EvidenceConflictError):                              # same id, different content
        env.store.store_bundle(EvidenceBundle.model_validate({**changed, "signature_metadata": None}))


def test_supporting_and_contradicting_evidence_preserved(env):
    bundle = receipted_bundle(env)
    env.store.store_bundle(bundle)
    fetched = env.store.get_bundle(bundle.evidence_bundle_id)
    disputed = next(c for c in fetched.claims if c.claim_id == "CLAIM-2")
    assert disputed.disputed and disputed.contradicting_evidence_ids and not disputed.supporting_evidence_ids
    assert fetched.contradicting_evidence == bundle.contradicting_evidence
    contra_id = bundle.contradicting_evidence[0]
    assert env.store.claims_for_evidence(contra_id) == ((bundle.evidence_bundle_id, "CLAIM-2", "CONTRADICTS"),)
    support_id = bundle.supporting_evidence[0]
    assert env.store.claims_for_evidence(support_id) == ((bundle.evidence_bundle_id, "CLAIM-1", "SUPPORTS"),)
    assert env.store.evidence_links(support_id)[0][3] == bundle.evidence_bundle_id


def test_bundle_with_unknown_receipt_or_bad_signature_rejected(env):
    bundle = receipted_bundle(env, sign=False)
    data = bundle.model_dump(mode="json")
    data["referenced_tool_receipts"] = ["RCPT-UNKNOWN"]
    data["tool_call_history"][0]["receipt_id"] = "RCPT-UNKNOWN"
    for it in data["evidence_items"]:
        it["receipt_id"] = it["provenance"]["receipt_id"] = "RCPT-UNKNOWN"
    with pytest.raises(InvalidEvidenceError, match="not stored"):
        env.store.store_bundle(EvidenceBundle.model_validate(data))
    signed = bundle.with_signature(sign_object(bundle, env.world.worker_signer, now=env.clock()))
    with pytest.raises(InvalidEvidenceError, match="PayloadTampered"):
        env.store.store_bundle(signed.model_copy(update={"confidence": 0.99}))
    assert env.store.list_bundles() == ()
    assert env.store.store_bundle(bundle).newly_stored           # unsigned bundles are allowed, flagged unsigned


def test_bundle_consistency_tampering_detected(env, tmp_path):
    bundle = receipted_bundle(env)
    env.store.store_bundle(bundle)
    bid = bundle.evidence_bundle_id
    conn = raw_db(tmp_path / "evidence.db")
    conn.execute("UPDATE claim_evidence SET relation = 'SUPPORTS' WHERE relation = 'CONTRADICTS'")
    assert "RELATIONS_MISMATCH" in env.store.verify_bundle(bid).failure_codes
    conn.execute("UPDATE claim_evidence SET relation = 'CONTRADICTS' WHERE claim_id = 'CLAIM-2'")
    assert env.store.verify_bundle(bid).ok
    conn.execute("UPDATE evidence_bundles SET skeleton_json = replace(skeleton_json, '\"confidence\":0.7', "
                 "'\"confidence\":0.95')")
    check = env.store.verify_bundle(bid)
    assert {"BUNDLE_DIGEST_MISMATCH", "SIGNATURE_INVALID"} <= set(check.failure_codes)
    with pytest.raises(EvidenceIntegrityError):
        env.store.get_bundle(bid)


def test_bundle_membership_tampering_detected(env, tmp_path):
    bundle = receipted_bundle(env)
    env.store.store_bundle(bundle)
    raw_db(tmp_path / "evidence.db").execute("DELETE FROM bundle_items WHERE position = 0")
    assert "BUNDLE_MEMBERSHIP_MISMATCH" in env.store.verify_bundle(bundle.evidence_bundle_id).failure_codes


def test_bundle_with_corrupted_member_fails(env):
    bundle = receipted_bundle(env)
    env.store.store_bundle(bundle)
    _object_path(env, bundle.evidence_items[0].integrity_digest).write_bytes(b"garbage")
    check = env.store.verify_bundle(bundle.evidence_bundle_id)
    assert "ITEM_CORRUPTED_CONTENT" in check.failure_codes and not check.ok


def test_evidence_record_tampering_detected(env, tmp_path):
    stored_receipt(env)
    env.store.store_evidence(item(), **CTX)
    raw_db(tmp_path / "evidence.db").execute(
        "UPDATE evidence_items SET item_json = replace(item_json, 'log_search', 'other_tool')")
    assert env.store.verify_evidence("EV-1").failure_codes == ["RECORD_DIGEST_MISMATCH"]


def test_evidence_tables_are_append_only(env, tmp_path):
    stored_receipt(env)
    env.store.store_evidence(item(), **CTX)
    conn = sqlite3.connect(tmp_path / "evidence.db")
    for sql in ("UPDATE evidence_items SET source_type = 'DOCUMENT'", "DELETE FROM evidence_items",
                "DELETE FROM tool_receipts", "UPDATE content_objects SET size_bytes = 0"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            conn.execute(sql)


def test_read_only_store_and_retrieval_audit(env, tmp_path):
    stored_receipt(env)
    env.store.store_evidence(item(), **CTX)
    env.store.get_evidence("EV-1", purpose="analyst review")
    retrieved = events(env, AuditEventType.EVIDENCE_RETRIEVED)[-1]
    assert retrieved.event_payload == {"subject_id": "EV-1", "subject_kind": "item", "purpose": "analyst review"}
    ro = EvidenceStore.open_read_only(tmp_path / "evidence.db", tmp_path / "objects")
    assert ro.get_evidence("EV-1") == item()
    with pytest.raises(EvidenceStoreError, match="read-only"):
        ro.store_evidence(item("EV-2"), **CTX)
    ro.close()


def test_verify_all_and_audit_cross_check(env):
    env.store.store_bundle(receipted_bundle(env))
    report = env.store.verify_all()
    assert report.status == "PASSED" and report.items_checked >= 4 and report.bundles_checked == 1
    assert report.receipts_checked == 1
    assert env.store.audit_cross_check(env.ledger.iter_events()) == []
    # evidence written without its audit event is reported
    unaudited = EvidenceStore.open(env.evidence_path, env.content_dir, clock=env.clock, audit=None)
    stored_receipt(env, "RCPT-2")
    unaudited.store_evidence(item("EV-SILENT", receipt_id="RCPT-2"), **CTX)
    found = env.store.audit_cross_check(env.ledger.iter_events())
    assert found == [{"code": "UNAUDITED_EVIDENCE", "subject": "item:EV-SILENT",
                      "detail": "stored without a matching audit event"}]
    unaudited.close()
