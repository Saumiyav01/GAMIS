"""Evidence storage service (P2): SQLite metadata + filesystem content-addressed objects.

- Inline JSON content is stored in the CAS as its RFC 8785 canonical bytes, so the object id equals the P1
  EvidenceItem.integrity_digest. Large raw objects go in via store_blob() and are referenced from an
  EvidenceItem as content_reference "gamis-cas:sha256:<digest>". Other references are recorded as external.
- Records are immutable: every table is append-only (triggers); re-storing identical data is idempotent and
  conflicting data under an existing id is rejected, so stable ids always mean the same thing.
- Bundles keep claims, supporting AND contradicting relations, disputes and receipt links, both inside the
  reconstructed P1 EvidenceBundle and in normalised relation tables.
- A verified digest proves the bytes are the recorded bytes, not that the evidence is true.
- Evidence and the audit ledger are separate databases; there is no cross-database transaction. Evidence is
  committed first and audited after; evidence without its audit event is reported by audit_cross_check().
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterable

from pydantic import ValidationError

from gamis.audit.events import (AuditEvent, AuditEventDraft, AuditEventType, AuditSink, EvidenceBundlePayload,
                                EvidenceFailurePayload, EvidenceRetrievedPayload, EvidenceStoredPayload,
                                EvidenceValidationPayload, Outcome)
from gamis.evidence.content_store import (ContentCorruptedError, ContentMissingError, ContentStore,
                                          ContentStoreError, PutResult, parse_cas_reference)
from gamis.evidence.sanitize import SanitizedEvidenceView, Sanitizer
from gamis.schemas.common import Principal, PrincipalType, format_timestamp
from gamis.schemas.evidence import EvidenceBundle, EvidenceItem
from gamis.schemas.signature import SignedObjectType
from gamis.schemas.tools import ToolReceipt
from gamis.security.canonical import canonicalize
from gamis.security.digest import canonical_digest
from gamis.security.keys import TrustStore
from gamis.security.signing import SignatureVerificationError, payload_digest, verify_object
from gamis.storage.sqlite import (append_only_triggers, connect, immediate_transaction, missing_triggers,
                                  quick_check)

Clock = Callable[[], datetime]
_TABLES = ("store_meta", "content_objects", "tool_receipts", "evidence_items", "evidence_links",
           "evidence_bundles", "bundle_items", "bundle_claims", "claim_evidence", "bundle_receipts",
           "sanitized_views")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS store_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS content_objects (
    digest TEXT PRIMARY KEY CHECK (length(digest) = 64), size_bytes INTEGER NOT NULL, first_stored_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tool_receipts (
    receipt_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, assignment_id TEXT NOT NULL, worker_id TEXT NOT NULL,
    tool_id TEXT NOT NULL, execution_status TEXT NOT NULL, receipt_digest TEXT NOT NULL,
    receipt_json TEXT NOT NULL, stored_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_id TEXT PRIMARY KEY, record_digest TEXT NOT NULL, integrity_digest TEXT NOT NULL,
    source_type TEXT NOT NULL, receipt_id TEXT,
    content_storage TEXT NOT NULL CHECK (content_storage IN ('cas-json', 'cas-blob', 'external-reference')),
    content_digest TEXT REFERENCES content_objects (digest), content_size INTEGER,
    item_json TEXT NOT NULL, stored_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_links (
    evidence_id TEXT NOT NULL REFERENCES evidence_items (evidence_id), mission_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL, worker_id TEXT NOT NULL, evidence_bundle_id TEXT NOT NULL, linked_at TEXT NOT NULL,
    PRIMARY KEY (evidence_id, mission_id, assignment_id, evidence_bundle_id));
CREATE TABLE IF NOT EXISTS evidence_bundles (
    evidence_bundle_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, assignment_id TEXT NOT NULL,
    worker_id TEXT NOT NULL, bundle_digest TEXT NOT NULL, signed INTEGER NOT NULL, signing_key_id TEXT,
    completion_status TEXT NOT NULL, generated_at TEXT NOT NULL, skeleton_json TEXT NOT NULL, stored_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bundle_items (
    evidence_bundle_id TEXT NOT NULL REFERENCES evidence_bundles (evidence_bundle_id), position INTEGER NOT NULL,
    evidence_id TEXT NOT NULL REFERENCES evidence_items (evidence_id),
    PRIMARY KEY (evidence_bundle_id, evidence_id), UNIQUE (evidence_bundle_id, position));
CREATE TABLE IF NOT EXISTS bundle_claims (
    evidence_bundle_id TEXT NOT NULL REFERENCES evidence_bundles (evidence_bundle_id), claim_id TEXT NOT NULL,
    position INTEGER NOT NULL, statement TEXT NOT NULL, confidence REAL NOT NULL, disputed INTEGER NOT NULL,
    PRIMARY KEY (evidence_bundle_id, claim_id));
CREATE TABLE IF NOT EXISTS claim_evidence (
    evidence_bundle_id TEXT NOT NULL, claim_id TEXT NOT NULL, evidence_id TEXT NOT NULL,
    relation TEXT NOT NULL CHECK (relation IN ('SUPPORTS', 'CONTRADICTS')),
    PRIMARY KEY (evidence_bundle_id, claim_id, evidence_id, relation),
    FOREIGN KEY (evidence_bundle_id, claim_id) REFERENCES bundle_claims (evidence_bundle_id, claim_id),
    FOREIGN KEY (evidence_bundle_id, evidence_id) REFERENCES bundle_items (evidence_bundle_id, evidence_id));
CREATE TABLE IF NOT EXISTS bundle_receipts (
    evidence_bundle_id TEXT NOT NULL REFERENCES evidence_bundles (evidence_bundle_id), receipt_id TEXT NOT NULL,
    PRIMARY KEY (evidence_bundle_id, receipt_id));
CREATE TABLE IF NOT EXISTS sanitized_views (
    evidence_id TEXT PRIMARY KEY REFERENCES evidence_items (evidence_id), sanitized_content_digest TEXT NOT NULL,
    view_json TEXT NOT NULL, created_at TEXT NOT NULL);
""" + "".join(append_only_triggers(t) for t in _TABLES)
EXPECTED_TRIGGERS = tuple(f"{t}_no_{op}" for t in _TABLES for op in ("update", "delete"))


# --- errors and results -----------------------------------------------------------------------

class EvidenceStoreError(Exception):
    pass


class InvalidEvidenceError(EvidenceStoreError):
    pass


class EvidenceConflictError(EvidenceStoreError):
    pass


class EvidencePersistenceError(EvidenceStoreError):
    pass


class EvidenceAuditError(EvidenceStoreError):
    """Evidence WAS committed but its audit event could not be written."""


class EvidenceNotFoundError(EvidenceStoreError):
    pass


class EvidenceIntegrityError(EvidenceStoreError):
    def __init__(self, check: "IntegrityCheck"):
        self.check = check
        super().__init__(f"{check.subject_kind} {check.subject_id}: {check.status.value} {list(check.failure_codes)}")


class CheckResult(StrEnum):
    VERIFIED = "VERIFIED"
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"   # record verified; content lives outside GAMIS, not checked
    FAILED = "FAILED"
    INCOMPLETE = "INCOMPLETE"                   # a required check could not run (e.g. no trust store)
    NOT_FOUND = "NOT_FOUND"


@dataclass
class IntegrityCheck:
    subject_id: str
    subject_kind: str
    status: CheckResult
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    items: list["IntegrityCheck"] = field(default_factory=list)

    def fail(self, code: str, detail: str) -> None:
        self.failure_codes.append(code)
        self.details.append(detail[:400])
        self.status = CheckResult.FAILED

    @property
    def ok(self) -> bool:
        return self.status in (CheckResult.VERIFIED, CheckResult.EXTERNAL_REFERENCE)


@dataclass(frozen=True)
class StoredEvidence:
    evidence_id: str
    record_digest: str
    content_digest: str | None
    newly_stored: bool
    content_deduplicated: bool


@dataclass(frozen=True)
class StoredBundle:
    evidence_bundle_id: str
    bundle_digest: str
    newly_stored: bool
    items: tuple[StoredEvidence, ...]


@dataclass
class EvidenceStoreReport:
    database: str
    content_root: str
    items_checked: int
    bundles_checked: int
    receipts_checked: int
    status: str
    failures: list[dict[str, Any]]
    warnings: list[str]
    checks: list[IntegrityCheck]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["checks"] = [c for c in data["checks"] if c["status"] not in ("VERIFIED", "EXTERNAL_REFERENCE")]
        return json.loads(json.dumps(data, default=str))


@dataclass
class _Prepared:
    item: EvidenceItem
    record_digest: str
    storage: str
    content_digest: str | None
    size: int | None
    put: PutResult | None
    view: SanitizedEvidenceView | None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _json(value: Any) -> str:
    return canonicalize(value).decode("utf-8")


def _record(item: EvidenceItem) -> dict[str, Any]:
    return item.model_dump(mode="json")


EVIDENCE_SERVICE = Principal(principal_id="evidence-service", principal_type=PrincipalType.EVIDENCE_SERVICE)


class EvidenceStore:
    def __init__(self, conn: sqlite3.Connection, path: Path, content: ContentStore, *, read_only: bool,
                 clock: Clock = _utc_now, audit: AuditSink | None = None, trust_store: TrustStore | None = None,
                 sanitizer: Sanitizer | None = Sanitizer(), actor: Principal = EVIDENCE_SERVICE,
                 require_known_receipts: bool = True):
        self._conn, self.path, self.content, self.read_only = conn, path, content, read_only
        self._clock, self._audit, self._trust_store, self._sanitizer = clock, audit, trust_store, sanitizer
        self._actor, self._require_receipts = actor, require_known_receipts
        self._lock = threading.RLock()

    @classmethod
    def open(cls, db_path: str | Path, content_root: str | Path, **kwargs: Any) -> "EvidenceStore":
        conn = connect(db_path)
        conn.executescript(_SCHEMA)
        return cls(conn, Path(db_path), ContentStore(content_root), read_only=False, **kwargs)

    @classmethod
    def open_read_only(cls, db_path: str | Path, content_root: str | Path, **kwargs: Any) -> "EvidenceStore":
        return cls(connect(db_path, read_only=True), Path(db_path), ContentStore(content_root, read_only=True),
                   read_only=True, audit=None, **kwargs)

    def close(self) -> None:
        self._conn.close()

    def _require_writable(self) -> None:
        if self.read_only:
            raise EvidenceStoreError("evidence store was opened read-only")

    def _emit(self, **draft: Any) -> AuditEvent | None:
        if self._audit is None:
            return None
        return self._audit.append_event(AuditEventDraft(actor_identity=self._actor, **draft))

    def _now(self) -> str:
        return format_timestamp(self._clock())

    # -- receipts -------------------------------------------------------------------------------
    def store_receipt(self, receipt: ToolReceipt) -> bool:
        """Store a gateway-signed receipt. Returns True if newly stored, False if already present."""
        self._require_writable()
        receipt = ToolReceipt.model_validate(receipt.model_dump(mode="json"))
        if not receipt.is_signed:
            raise InvalidEvidenceError("tool receipts must be signed")
        if self._trust_store is not None:
            try:
                verify_object(receipt, self._trust_store, now=self._clock())
            except SignatureVerificationError as exc:
                raise InvalidEvidenceError(f"receipt {receipt.receipt_id}: {type(exc).__name__}: {exc}") from exc
        record = receipt.model_dump(mode="json")
        digest = canonical_digest(record)
        with self._lock, immediate_transaction(self._conn):
            row = self._conn.execute("SELECT receipt_digest FROM tool_receipts WHERE receipt_id = ?",
                                     (receipt.receipt_id,)).fetchone()
            if row is not None:
                if row[0] != digest:
                    raise EvidenceConflictError(f"receipt {receipt.receipt_id} already stored with other content")
                return False
            self._conn.execute("INSERT INTO tool_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (receipt.receipt_id, receipt.mission_id, receipt.assignment_id, receipt.worker_id,
                                receipt.tool_id, receipt.execution_status.value, digest, _json(record), self._now()))
        return True

    def get_receipt(self, receipt_id: str) -> ToolReceipt:
        row = self._conn.execute("SELECT receipt_json, receipt_digest FROM tool_receipts WHERE receipt_id = ?",
                                 (receipt_id,)).fetchone()
        if row is None:
            raise EvidenceNotFoundError(f"receipt {receipt_id} not found")
        receipt = ToolReceipt.model_validate_json(row[0])
        if canonical_digest(receipt.model_dump(mode="json")) != row[1]:
            raise EvidenceStoreError(f"receipt {receipt_id} record does not match its digest")
        return receipt

    # -- blobs ----------------------------------------------------------------------------------
    def store_blob(self, data: bytes) -> PutResult:
        """Store a large raw object; reference it from an EvidenceItem via PutResult.reference."""
        self._require_writable()
        result = self.content.put(data)
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("INSERT OR IGNORE INTO content_objects VALUES (?, ?, ?)",
                               (result.digest, result.size, self._now()))
        return result

    # -- items ----------------------------------------------------------------------------------
    def _prepare(self, item: EvidenceItem) -> _Prepared:
        try:
            item = EvidenceItem.model_validate(item.model_dump(mode="json"))
        except ValidationError as exc:
            raise InvalidEvidenceError(str(exc)) from exc
        view = self._sanitizer.sanitize_item(item) if self._sanitizer is not None else None
        record_digest = canonical_digest(_record(item))
        if item.content is not None:
            put = self.content.put(canonicalize(item.content))
            if put.digest != item.integrity_digest:
                raise InvalidEvidenceError(f"{item.evidence_id}: content digest mismatch")
            return _Prepared(item, record_digest, "cas-json", put.digest, put.size, put, view)
        digest = parse_cas_reference(item.content_reference)
        if digest is None:
            return _Prepared(item, record_digest, "external-reference", None, None, None, view)
        if digest != item.integrity_digest:
            raise InvalidEvidenceError(f"{item.evidence_id}: CAS reference digest differs from integrity_digest")
        try:
            size = len(self.content.get(digest))
        except ContentStoreError as exc:
            raise InvalidEvidenceError(f"{item.evidence_id}: referenced content unusable: {exc}") from exc
        return _Prepared(item, record_digest, "cas-blob", digest, size, None, view)

    def _check_receipt_link(self, receipt_id: str | None, mission_id: str, assignment_id: str,
                            worker_id: str) -> None:
        if receipt_id is None or not self._require_receipts:
            return
        row = self._conn.execute("SELECT mission_id, assignment_id, worker_id FROM tool_receipts "
                                 "WHERE receipt_id = ?", (receipt_id,)).fetchone()
        if row is None:
            raise InvalidEvidenceError(f"receipt {receipt_id} is not stored; store receipts before evidence")
        if tuple(row) != (mission_id, assignment_id, worker_id):
            raise InvalidEvidenceError(f"receipt {receipt_id} belongs to a different mission/assignment/worker")

    def _insert_item(self, p: _Prepared, mission_id: str, assignment_id: str, worker_id: str,
                     bundle_id: str) -> bool:
        now = self._now()
        if p.content_digest is not None:
            self._conn.execute("INSERT OR IGNORE INTO content_objects VALUES (?, ?, ?)",
                               (p.content_digest, p.size, now))
        row = self._conn.execute("SELECT record_digest FROM evidence_items WHERE evidence_id = ?",
                                 (p.item.evidence_id,)).fetchone()
        new = row is None
        if not new and row[0] != p.record_digest:
            raise EvidenceConflictError(f"evidence {p.item.evidence_id} already exists with different content")
        if new:
            stored = _record(p.item)
            if p.storage == "cas-json":
                stored["content"] = None  # content lives in the CAS; the record keeps only its digest
            self._conn.execute("INSERT INTO evidence_items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                               (p.item.evidence_id, p.record_digest, p.item.integrity_digest,
                                p.item.source_type.value, p.item.receipt_id, p.storage, p.content_digest, p.size,
                                _json(stored), now))
            if p.view is not None:
                self._conn.execute("INSERT INTO sanitized_views VALUES (?, ?, ?, ?)",
                                   (p.item.evidence_id, p.view.sanitized_content_digest,
                                    _json(p.view.model_dump(mode="json")), now))
        self._conn.execute("INSERT OR IGNORE INTO evidence_links VALUES (?, ?, ?, ?, ?, ?)",
                           (p.item.evidence_id, mission_id, assignment_id, worker_id, bundle_id, now))
        return new

    def _item_event(self, p: _Prepared, mission_id: str, assignment_id: str, worker_id: str) -> None:
        counts = p.view.counts() if p.view else {}
        self._emit(event_type=AuditEventType.EVIDENCE_STORED, correlation_id=p.item.evidence_id,
                   mission_id=mission_id, assignment_id=assignment_id, worker_id=worker_id,
                   event_payload=EvidenceStoredPayload(
                       evidence_id=p.item.evidence_id, record_digest=p.record_digest,
                       integrity_digest=p.item.integrity_digest, source_type=p.item.source_type,
                       content_storage="cas" if p.content_digest else "external-reference",
                       content_size_bytes=p.size, receipt_id=p.item.receipt_id,
                       sanitization_finding_counts=counts,
                       contains_suspicious_instructions=bool(p.view and p.view.contains_suspicious_instructions)))

    def _persistence_failed(self, subject_id: str, kind: str, exc: BaseException) -> None:
        try:
            self._emit(event_type=AuditEventType.EVIDENCE_PERSISTENCE_FAILED, correlation_id=subject_id,
                       event_payload=EvidenceFailurePayload(subject_id=subject_id, subject_kind=kind,
                                                            error_type=type(exc).__name__,
                                                            detail=(str(exc) or type(exc).__name__)[:250]))
        except Exception as audit_exc:  # never mask the original failure
            exc.add_note(f"additionally, the failure could not be audited: {audit_exc}")

    def store_evidence(self, item: EvidenceItem, *, mission_id: str, assignment_id: str,
                       worker_id: str) -> StoredEvidence:
        self._require_writable()
        try:
            prepared = self._prepare(item)
            with self._lock, immediate_transaction(self._conn):
                self._check_receipt_link(prepared.item.receipt_id, mission_id, assignment_id, worker_id)
                new = self._insert_item(prepared, mission_id, assignment_id, worker_id, "")
        except (EvidenceStoreError, ContentStoreError, sqlite3.Error) as exc:
            self._persistence_failed(getattr(item, "evidence_id", "unknown"), "item", exc)
            if isinstance(exc, EvidenceStoreError):
                raise
            raise EvidencePersistenceError(f"evidence write failed: {exc}") from exc
        if new:
            try:
                self._item_event(prepared, mission_id, assignment_id, worker_id)
            except Exception as exc:
                raise EvidenceAuditError(f"evidence {prepared.item.evidence_id} stored but not audited: {exc}") from exc
        return StoredEvidence(prepared.item.evidence_id, prepared.record_digest, prepared.content_digest, new,
                              bool(prepared.put and prepared.put.deduplicated))

    # -- bundles --------------------------------------------------------------------------------
    def store_bundle(self, bundle: EvidenceBundle) -> StoredBundle:
        """Persist a bundle and all of its items atomically (metadata in one transaction)."""
        self._require_writable()
        bundle_id = getattr(bundle, "evidence_bundle_id", "unknown")
        try:
            try:
                bundle = EvidenceBundle.model_validate(bundle.model_dump(mode="json"))
            except ValidationError as exc:
                raise InvalidEvidenceError(str(exc)) from exc
            if bundle.is_signed and self._trust_store is not None:
                try:
                    verify_object(bundle, self._trust_store, now=self._clock())
                except SignatureVerificationError as exc:
                    raise InvalidEvidenceError(f"bundle signature: {type(exc).__name__}: {exc}") from exc
            digest = payload_digest(SignedObjectType.EVIDENCE_BUNDLE, bundle.signed_payload())
            prepared = [self._prepare(item) for item in bundle.evidence_items]   # CAS writes (idempotent)
            ctx = (bundle.mission_id, bundle.assignment_id, bundle.worker_id)
            with self._lock, immediate_transaction(self._conn):
                row = self._conn.execute("SELECT bundle_digest FROM evidence_bundles WHERE evidence_bundle_id = ?",
                                         (bundle.evidence_bundle_id,)).fetchone()
                if row is not None:
                    if row[0] != digest:
                        raise EvidenceConflictError(f"bundle {bundle.evidence_bundle_id} already stored with other "
                                                    "content")
                    return StoredBundle(bundle.evidence_bundle_id, digest, False, ())
                for receipt_id in bundle.referenced_tool_receipts:
                    self._check_receipt_link(receipt_id, *ctx)
                new_items = [self._insert_item(p, *ctx, bundle.evidence_bundle_id) for p in prepared]
                self._insert_bundle_rows(bundle, digest)
        except (EvidenceStoreError, ContentStoreError, sqlite3.Error) as exc:
            self._persistence_failed(bundle_id, "bundle", exc)
            if isinstance(exc, EvidenceStoreError):
                raise
            raise EvidencePersistenceError(f"bundle write failed and was rolled back: {exc}") from exc
        stored = tuple(StoredEvidence(p.item.evidence_id, p.record_digest, p.content_digest, n,
                                      bool(p.put and p.put.deduplicated)) for p, n in zip(prepared, new_items))
        try:
            for p, new in zip(prepared, new_items):
                if new:
                    self._item_event(p, *ctx)
            self._emit(event_type=AuditEventType.EVIDENCE_BUNDLE_STORED, correlation_id=bundle.evidence_bundle_id,
                       mission_id=bundle.mission_id, assignment_id=bundle.assignment_id, worker_id=bundle.worker_id,
                       event_payload=_bundle_payload(bundle, digest))
        except Exception as exc:
            raise EvidenceAuditError(f"bundle {bundle.evidence_bundle_id} stored but not audited: {exc}") from exc
        return StoredBundle(bundle.evidence_bundle_id, digest, True, stored)

    def _insert_bundle_rows(self, bundle: EvidenceBundle, digest: str) -> None:
        bid, now = bundle.evidence_bundle_id, self._now()
        skeleton = bundle.model_dump(mode="json")
        skeleton["evidence_items"] = [i.evidence_id for i in bundle.evidence_items]
        meta = bundle.signature_metadata
        self._conn.execute("INSERT INTO evidence_bundles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (bid, bundle.mission_id, bundle.assignment_id, bundle.worker_id, digest,
                            int(meta is not None), meta.key_id if meta else None, bundle.completion_status.value,
                            format_timestamp(bundle.generated_at), _json(skeleton), now))
        self._conn.executemany("INSERT INTO bundle_items VALUES (?, ?, ?)",
                               [(bid, i, item.evidence_id) for i, item in enumerate(bundle.evidence_items)])
        self._conn.executemany("INSERT INTO bundle_claims VALUES (?, ?, ?, ?, ?, ?)",
                               [(bid, c.claim_id, i, c.statement, c.confidence, int(c.disputed))
                                for i, c in enumerate(bundle.claims)])
        self._conn.executemany("INSERT INTO claim_evidence VALUES (?, ?, ?, ?)", _relations(bundle))
        self._conn.executemany("INSERT INTO bundle_receipts VALUES (?, ?)",
                               [(bid, r) for r in bundle.referenced_tool_receipts])

    # -- retrieval ------------------------------------------------------------------------------
    def get_evidence(self, evidence_id: str, *, purpose: str | None = None) -> EvidenceItem:
        """Return the ORIGINAL item, only after it passes verification. Data, never instructions."""
        check, item = self._verify_item(evidence_id)
        if not check.ok or item is None:
            raise EvidenceIntegrityError(check)
        self._retrieved(evidence_id, "item", purpose)
        return item

    def get_sanitized_view(self, evidence_id: str) -> SanitizedEvidenceView:
        row = self._conn.execute("SELECT v.view_json, v.sanitized_content_digest, i.integrity_digest "
                                 "FROM sanitized_views v JOIN evidence_items i USING (evidence_id) "
                                 "WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if row is None:
            raise EvidenceNotFoundError(f"no sanitized view for {evidence_id}")
        view = SanitizedEvidenceView.model_validate_json(row[0])
        if view.sanitized_content_digest != row[1] or view.original_integrity_digest != row[2]:
            raise EvidenceStoreError(f"sanitized view for {evidence_id} is inconsistent with its record")
        return view

    def get_bundle(self, bundle_id: str, *, purpose: str | None = None) -> EvidenceBundle:
        check, bundle = self._verify_bundle(bundle_id)
        if not check.ok or bundle is None:
            raise EvidenceIntegrityError(check)
        self._retrieved(bundle_id, "bundle", purpose)
        return bundle

    def _retrieved(self, subject_id: str, kind: str, purpose: str | None) -> None:
        if purpose is not None and not self.read_only:
            self._emit(event_type=AuditEventType.EVIDENCE_RETRIEVED, correlation_id=subject_id,
                       event_payload=EvidenceRetrievedPayload(subject_id=subject_id, subject_kind=kind,
                                                              purpose=purpose))

    def list_bundles(self, *, mission_id: str | None = None, assignment_id: str | None = None) -> tuple[str, ...]:
        sql, args = "SELECT evidence_bundle_id FROM evidence_bundles WHERE 1=1", []
        if mission_id is not None:
            sql, args = sql + " AND mission_id = ?", args + [mission_id]
        if assignment_id is not None:
            sql, args = sql + " AND assignment_id = ?", args + [assignment_id]
        return tuple(r[0] for r in self._conn.execute(sql + " ORDER BY evidence_bundle_id", args))

    def claims_for_evidence(self, evidence_id: str) -> tuple[tuple[str, str, str], ...]:
        """(bundle_id, claim_id, SUPPORTS|CONTRADICTS) for every claim that cites this evidence."""
        return tuple(tuple(r) for r in self._conn.execute(
            "SELECT evidence_bundle_id, claim_id, relation FROM claim_evidence WHERE evidence_id = ? "
            "ORDER BY evidence_bundle_id, claim_id, relation", (evidence_id,)))

    def evidence_links(self, evidence_id: str) -> tuple[tuple[str, str, str, str], ...]:
        return tuple(tuple(r) for r in self._conn.execute(
            "SELECT mission_id, assignment_id, worker_id, evidence_bundle_id FROM evidence_links "
            "WHERE evidence_id = ? ORDER BY evidence_bundle_id", (evidence_id,)))

    def list_evidence_ids(self, *, mission_id: str) -> tuple[str, ...]:
        return tuple(row[0] for row in self._conn.execute(
            "SELECT DISTINCT evidence_id FROM evidence_links WHERE mission_id=? ORDER BY evidence_id",
            (mission_id,)))

    def list_receipt_ids(self, *, mission_id: str) -> tuple[str, ...]:
        return tuple(row[0] for row in self._conn.execute(
            "SELECT receipt_id FROM tool_receipts WHERE mission_id=? ORDER BY receipt_id", (mission_id,)))

    # -- verification ---------------------------------------------------------------------------
    def verify_evidence(self, evidence_id: str) -> IntegrityCheck:
        check = self._verify_item(evidence_id)[0]
        self._validation_event(check)
        return check

    def verify_bundle(self, bundle_id: str) -> IntegrityCheck:
        check = self._verify_bundle(bundle_id)[0]
        self._validation_event(check)
        return check

    def _validation_event(self, check: IntegrityCheck) -> None:
        if self.read_only or self._audit is None:
            return
        failed = not check.ok
        self._emit(event_type=AuditEventType.EVIDENCE_VALIDATION_FAILED if failed else
                   AuditEventType.EVIDENCE_VALIDATED, correlation_id=check.subject_id,
                   event_payload=EvidenceValidationPayload(
                       subject_id=check.subject_id, subject_kind=check.subject_kind,
                       outcome=Outcome.FAILED if failed else Outcome.PASSED,
                       failure_codes=tuple(dict.fromkeys(check.failure_codes))[:64]))

    def _verify_item(self, evidence_id: str) -> tuple[IntegrityCheck, EvidenceItem | None]:
        check = IntegrityCheck(evidence_id, "item", CheckResult.VERIFIED)
        row = self._conn.execute("SELECT * FROM evidence_items WHERE evidence_id = ?", (evidence_id,)).fetchone()
        if row is None:
            check.status = CheckResult.NOT_FOUND
            check.failure_codes.append("NOT_FOUND")
            return check, None
        try:
            record = json.loads(row["item_json"])
        except ValueError as exc:
            check.fail("INVALID_RECORD", f"record is not JSON: {exc}")
            return check, None
        storage, digest = row["content_storage"], row["content_digest"]
        if storage in ("cas-json", "cas-blob"):
            if digest != row["integrity_digest"]:
                check.fail("DIGEST_MISMATCH", "content digest differs from the recorded integrity digest")
                return check, None
            try:
                data = self.content.get(digest)
            except ContentMissingError as exc:
                check.fail("MISSING_CONTENT", str(exc))
                return check, None
            except ContentCorruptedError as exc:
                check.fail("CORRUPTED_CONTENT", str(exc))
                return check, None
            if storage == "cas-json":
                try:
                    content = json.loads(data)
                    if canonicalize(content) != data:
                        raise ValueError("stored content is not canonical JSON")
                except ValueError as exc:
                    check.fail("CORRUPTED_CONTENT", str(exc))
                    return check, None
                record["content"] = content
            elif parse_cas_reference(record.get("content_reference") or "") != digest:
                check.fail("INVALID_REFERENCE", "content_reference does not point at the recorded object")
        else:
            check.status = CheckResult.EXTERNAL_REFERENCE
        try:
            item = EvidenceItem.model_validate(record)
        except ValidationError as exc:
            check.fail("INVALID_RECORD", f"record failed EvidenceItem validation: {str(exc).splitlines()[0]}")
            return check, None
        if canonical_digest(_record(item)) != row["record_digest"]:
            check.fail("RECORD_DIGEST_MISMATCH", "evidence record does not match its recorded digest")
        if (item.integrity_digest, item.source_type.value, item.receipt_id) != (
                row["integrity_digest"], row["source_type"], row["receipt_id"]):
            check.fail("RECORD_COLUMNS_MISMATCH", "indexed columns disagree with the evidence record")
        return check, (item if check.ok else None)

    def _verify_bundle(self, bundle_id: str) -> tuple[IntegrityCheck, EvidenceBundle | None]:
        check = IntegrityCheck(bundle_id, "bundle", CheckResult.VERIFIED)
        row = self._conn.execute("SELECT * FROM evidence_bundles WHERE evidence_bundle_id = ?",
                                 (bundle_id,)).fetchone()
        if row is None:
            check.status = CheckResult.NOT_FOUND
            check.failure_codes.append("NOT_FOUND")
            return check, None
        skeleton = json.loads(row["skeleton_json"])
        member_ids = [r[0] for r in self._conn.execute(
            "SELECT evidence_id FROM bundle_items WHERE evidence_bundle_id = ? ORDER BY position", (bundle_id,))]
        if member_ids != skeleton.get("evidence_items"):
            check.fail("BUNDLE_MEMBERSHIP_MISMATCH", "bundle item table disagrees with the bundle record")
        items = []
        for evidence_id in skeleton.get("evidence_items", []):
            item_check, item = self._verify_item(evidence_id)
            check.items.append(item_check)
            if item is None:
                check.fail(f"ITEM_{item_check.failure_codes[0] if item_check.failure_codes else 'FAILED'}",
                           f"evidence {evidence_id} failed verification")
            else:
                items.append(item.model_dump(mode="json"))
        if not check.ok:
            return check, None
        try:
            bundle = EvidenceBundle.model_validate({**skeleton, "evidence_items": items})
        except ValidationError as exc:
            check.fail("INVALID_RECORD", f"bundle failed EvidenceBundle validation: {str(exc).splitlines()[0]}")
            return check, None
        if payload_digest(SignedObjectType.EVIDENCE_BUNDLE, bundle.signed_payload()) != row["bundle_digest"]:
            check.fail("BUNDLE_DIGEST_MISMATCH", "reconstructed bundle does not match its recorded digest")
        if bool(row["signed"]) != bundle.is_signed or (row["mission_id"], row["assignment_id"], row["worker_id"]) != (
                bundle.mission_id, bundle.assignment_id, bundle.worker_id):
            check.fail("RECORD_COLUMNS_MISMATCH", "indexed columns disagree with the bundle record")
        claims = [(r[0], r[1], bool(r[2])) for r in self._conn.execute(
            "SELECT claim_id, statement, disputed FROM bundle_claims WHERE evidence_bundle_id = ? ORDER BY position",
            (bundle_id,))]
        if claims != [(c.claim_id, c.statement, c.disputed) for c in bundle.claims]:
            check.fail("CLAIMS_MISMATCH", "claim table disagrees with the bundle record")
        relations = sorted(tuple(r) for r in self._conn.execute(
            "SELECT evidence_bundle_id, claim_id, evidence_id, relation FROM claim_evidence "
            "WHERE evidence_bundle_id = ?", (bundle_id,)))
        if relations != sorted(_relations(bundle)):
            check.fail("RELATIONS_MISMATCH", "supporting/contradicting relations disagree with the bundle record")
        receipts = sorted(r[0] for r in self._conn.execute(
            "SELECT receipt_id FROM bundle_receipts WHERE evidence_bundle_id = ?", (bundle_id,)))
        if receipts != sorted(bundle.referenced_tool_receipts):
            check.fail("RECEIPT_LINKS_MISMATCH", "receipt links disagree with the bundle record")
        for receipt_id in bundle.referenced_tool_receipts:
            self._check_stored_receipt(check, receipt_id, bundle)
        if bundle.is_signed:
            if self._trust_store is None:
                check.details.append("bundle signature not verified: no trust store")
                if check.status is CheckResult.VERIFIED:
                    check.status = CheckResult.INCOMPLETE
            else:
                try:
                    verify_object(bundle, self._trust_store, now=self._clock())
                except SignatureVerificationError as exc:
                    check.fail("SIGNATURE_INVALID", f"{type(exc).__name__}: {exc}")
        return check, (bundle if check.ok else None)

    def _check_stored_receipt(self, check: IntegrityCheck, receipt_id: str, bundle: EvidenceBundle) -> None:
        try:
            receipt = self.get_receipt(receipt_id)
        except EvidenceNotFoundError:
            if self._require_receipts:
                check.fail("RECEIPT_MISSING", f"referenced receipt {receipt_id} is not stored")
            return
        except (EvidenceStoreError, ValidationError, ValueError) as exc:
            check.fail("RECEIPT_INVALID", f"{receipt_id}: {exc}")
            return
        if (receipt.mission_id, receipt.assignment_id, receipt.worker_id) != (
                bundle.mission_id, bundle.assignment_id, bundle.worker_id):
            check.fail("RECEIPT_CONTEXT_MISMATCH", f"receipt {receipt_id} belongs to another context")
        if self._trust_store is not None:
            try:
                verify_object(receipt, self._trust_store, now=self._clock())
            except SignatureVerificationError as exc:
                check.fail("RECEIPT_SIGNATURE_INVALID", f"{receipt_id}: {type(exc).__name__}: {exc}")

    def verify_all(self) -> EvidenceStoreReport:
        """Verify every item, bundle, receipt and content object. Read-only; repairs nothing."""
        failures: list[dict[str, Any]] = []
        warnings: list[str] = []
        checks: list[IntegrityCheck] = []
        incomplete = False
        with self._lock:
            try:
                for problem in quick_check(self._conn):
                    failures.append({"code": "SQLITE_QUICK_CHECK_FAILED", "detail": problem})
                gone = missing_triggers(self._conn, EXPECTED_TRIGGERS)
                if gone:
                    failures.append({"code": "APPEND_ONLY_TRIGGERS_MISSING", "detail": str(gone)})
                item_ids = [r[0] for r in self._conn.execute("SELECT evidence_id FROM evidence_items ORDER BY 1")]
                bundle_ids = [r[0] for r in self._conn.execute(
                    "SELECT evidence_bundle_id FROM evidence_bundles ORDER BY 1")]
                receipt_ids = [r[0] for r in self._conn.execute("SELECT receipt_id FROM tool_receipts ORDER BY 1")]
                for evidence_id in item_ids:
                    checks.append(self._verify_item(evidence_id)[0])
                    try:
                        self.get_sanitized_view(evidence_id)
                    except EvidenceNotFoundError:
                        pass
                    except (EvidenceStoreError, ValidationError, ValueError) as exc:
                        failures.append({"code": "SANITIZED_VIEW_INVALID", "subject": evidence_id,
                                         "detail": str(exc)[:300]})
                for bundle_id in bundle_ids:
                    checks.append(self._verify_bundle(bundle_id)[0])
                for receipt_id in receipt_ids:
                    rc = IntegrityCheck(receipt_id, "receipt", CheckResult.VERIFIED)
                    try:
                        receipt = self.get_receipt(receipt_id)
                        if self._trust_store is None:
                            rc.status = CheckResult.INCOMPLETE
                        else:
                            verify_object(receipt, self._trust_store, now=self._clock())
                    except (EvidenceStoreError, ValidationError, ValueError, SignatureVerificationError) as exc:
                        rc.fail("RECEIPT_INVALID", f"{type(exc).__name__}: {exc}")
                    checks.append(rc)
                recorded = {r[0]: r[1] for r in self._conn.execute("SELECT digest, size_bytes FROM content_objects")}
                for digest in recorded:
                    status = self.content.status(digest)
                    if status.value != "OK":
                        failures.append({"code": f"CONTENT_OBJECT_{status.value}", "subject": digest,
                                         "detail": "recorded content object failed verification"})
                orphans = [d for d in self.content.iter_digests() if d not in recorded]
                if orphans:
                    warnings.append(f"{len(orphans)} unreferenced content object(s) (e.g. from a rolled-back "
                                    f"write): {orphans[:5]}")
            except sqlite3.Error as exc:
                incomplete = True
                failures.append({"code": "DATABASE_ERROR", "detail": f"{type(exc).__name__}: {exc}"})
        for c in checks:
            if c.status is CheckResult.FAILED:
                failures.append({"code": c.failure_codes[0] if c.failure_codes else "FAILED",
                                 "subject": f"{c.subject_kind}:{c.subject_id}", "detail": "; ".join(c.details)[:400]})
            elif c.status is CheckResult.NOT_FOUND:
                failures.append({"code": "NOT_FOUND", "subject": f"{c.subject_kind}:{c.subject_id}", "detail": ""})
            elif c.status is CheckResult.INCOMPLETE:
                incomplete = True
        if any(c.status is CheckResult.EXTERNAL_REFERENCE for c in checks):
            warnings.append("some evidence is stored as an external reference; its content was not verified")
        if incomplete and self._trust_store is None:
            warnings.append("signatures of receipts/signed bundles were not verified: no trust store supplied")
        status = "FAILED" if failures else ("INCOMPLETE" if incomplete else "PASSED")
        kinds = [c.subject_kind for c in checks]
        return EvidenceStoreReport(str(self.path), str(self.content.root), kinds.count("item"), kinds.count("bundle"),
                                   kinds.count("receipt"), status, failures, warnings, checks)

    def audit_cross_check(self, events: Iterable[AuditEvent]) -> list[dict[str, Any]]:
        """Every stored item/bundle must have a matching EVIDENCE_*_STORED audit event, and vice versa."""
        audited_items, audited_bundles = {}, {}
        for event in events:
            payload = event.event_payload
            if event.event_type is AuditEventType.EVIDENCE_STORED:
                audited_items[payload["evidence_id"]] = payload["record_digest"]
            elif event.event_type is AuditEventType.EVIDENCE_BUNDLE_STORED:
                audited_bundles[payload["evidence_bundle_id"]] = payload["bundle_digest"]
        failures = []
        for kind, sql, audited in (
                ("item", "SELECT evidence_id, record_digest FROM evidence_items", audited_items),
                ("bundle", "SELECT evidence_bundle_id, bundle_digest FROM evidence_bundles", audited_bundles)):
            stored = {r[0]: r[1] for r in self._conn.execute(sql)}
            for subject, digest in stored.items():
                if subject not in audited:
                    failures.append({"code": "UNAUDITED_EVIDENCE", "subject": f"{kind}:{subject}",
                                     "detail": "stored without a matching audit event"})
                elif audited[subject] != digest:
                    failures.append({"code": "AUDIT_DIGEST_MISMATCH", "subject": f"{kind}:{subject}",
                                     "detail": "stored digest differs from the audited digest"})
            for subject in sorted(set(audited) - set(stored)):
                failures.append({"code": "AUDITED_EVIDENCE_MISSING", "subject": f"{kind}:{subject}",
                                 "detail": "audit ledger records evidence that is not in the store"})
        return failures


def _relations(bundle: EvidenceBundle) -> list[tuple[str, str, str, str]]:
    out = []
    for claim in bundle.claims:
        out += [(bundle.evidence_bundle_id, claim.claim_id, e, "SUPPORTS") for e in claim.supporting_evidence_ids]
        out += [(bundle.evidence_bundle_id, claim.claim_id, e, "CONTRADICTS") for e in claim.contradicting_evidence_ids]
    return out


def _bundle_payload(bundle: EvidenceBundle, digest: str) -> EvidenceBundlePayload:
    meta = bundle.signature_metadata
    return EvidenceBundlePayload(
        evidence_bundle_id=bundle.evidence_bundle_id, bundle_digest=digest, signed=meta is not None,
        signing_key_id=meta.key_id if meta else None, completion_status=bundle.completion_status,
        claim_count=len(bundle.claims), evidence_ids=tuple(i.evidence_id for i in bundle.evidence_items),
        supporting_evidence_count=len(bundle.supporting_evidence),
        contradicting_evidence_count=len(bundle.contradicting_evidence),
        disputed_claim_count=sum(c.disputed for c in bundle.claims),
        referenced_tool_receipts=bundle.referenced_tool_receipts)
