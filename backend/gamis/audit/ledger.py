"""SQLite tamper-evident audit ledger (P2).

Guarantees and their limits:
- The API exposes append and read only. SQLite triggers reject UPDATE/DELETE on events, checkpoints and
  metadata, and an INSERT trigger rejects any event that is not exactly head+1 linked to the head hash.
- verify_chain() recomputes every hash from canonical content, so edits, deletions, insertions,
  reordering, broken links and sequence gaps made by anyone who bypasses the triggers are detected.
- An attacker controlling the whole database can drop the triggers and rewrite the ENTIRE history with
  fresh hashes, or truncate the tail; the chain alone cannot detect that. Only a signed checkpoint retained
  outside the database (verify against it with ``trusted_checkpoints``) detects such rewrites, and only for
  history up to that checkpoint.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from pydantic import ValidationError

from gamis.audit.checkpoints import AuditCheckpoint, verify_checkpoint_signature
from gamis.audit.events import (AUDIT_SCHEMA_VERSION, AuditEvent, AuditEventBody, AuditEventDraft, AuditEventType,
                                CheckpointPayload, GenesisPayload, build_event, genesis_hash, new_event_id)
from gamis.schemas.common import Principal, PrincipalType, format_timestamp
from gamis.security.canonical import canonicalize
from gamis.security.keys import Signer, TrustStore
from gamis.security.signing import SignatureVerificationError, sign_object
from gamis.storage.sqlite import (StorageError, append_only_triggers, connect, immediate_transaction,
                                  missing_triggers, quick_check)

Clock = Callable[[], datetime]
SCHEMA_VERSION = str(AUDIT_SCHEMA_VERSION)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS audit_events (
    sequence_number     INTEGER PRIMARY KEY CHECK (sequence_number >= 1),
    event_id            TEXT NOT NULL UNIQUE,
    ledger_id           TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    event_version       INTEGER NOT NULL,
    mission_id          TEXT,
    grant_id            TEXT,
    assignment_id       TEXT,
    worker_id           TEXT,
    actor_json          TEXT NOT NULL,
    timestamp           TEXT NOT NULL,
    correlation_id      TEXT NOT NULL,
    payload_json        TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL CHECK (length(previous_event_hash) = 64),
    event_hash          TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64)
);
CREATE INDEX IF NOT EXISTS audit_events_mission ON audit_events (mission_id, sequence_number);
CREATE INDEX IF NOT EXISTS audit_events_type ON audit_events (event_type, sequence_number);
CREATE TABLE IF NOT EXISTS audit_checkpoints (
    checkpoint_id       TEXT PRIMARY KEY,
    ledger_id           TEXT NOT NULL,
    sequence_number     INTEGER NOT NULL,
    head_event_hash     TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    signing_key_id      TEXT NOT NULL,
    signing_key_version INTEGER NOT NULL,
    checkpoint_json     TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_events_chain_insert BEFORE INSERT ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'append-only: sequence_number must be head + 1')
     WHERE NEW.sequence_number != COALESCE((SELECT MAX(sequence_number) FROM audit_events), 0) + 1;
    SELECT RAISE(ABORT, 'append-only: previous_event_hash must equal the head event hash')
     WHERE NEW.previous_event_hash != COALESCE(
        (SELECT event_hash FROM audit_events ORDER BY sequence_number DESC LIMIT 1),
        (SELECT value FROM ledger_meta WHERE key = 'genesis_hash'));
    SELECT RAISE(ABORT, 'append-only: ledger_id mismatch')
     WHERE NEW.ledger_id != (SELECT value FROM ledger_meta WHERE key = 'ledger_id');
END;
CREATE TRIGGER IF NOT EXISTS audit_checkpoints_head_insert BEFORE INSERT ON audit_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'checkpoint does not match a ledger event')
     WHERE NOT EXISTS (SELECT 1 FROM audit_events
                        WHERE sequence_number = NEW.sequence_number AND event_hash = NEW.head_event_hash);
END;
CREATE TRIGGER IF NOT EXISTS ledger_meta_frozen BEFORE INSERT ON ledger_meta
WHEN (SELECT COUNT(*) FROM audit_events) > 0
BEGIN SELECT RAISE(ABORT, 'append-only: ledger metadata is fixed at genesis'); END;
""" + append_only_triggers("audit_events") + append_only_triggers("audit_checkpoints") \
    + append_only_triggers("ledger_meta")

EXPECTED_TRIGGERS = ("audit_events_chain_insert", "audit_checkpoints_head_insert", "ledger_meta_frozen",
                     "audit_events_no_update", "audit_events_no_delete", "audit_checkpoints_no_update",
                     "audit_checkpoints_no_delete", "ledger_meta_no_update", "ledger_meta_no_delete")


# --- errors -----------------------------------------------------------------------------------

class AuditError(Exception):
    pass


class AuditWriteError(AuditError):
    pass


class InvalidEventError(AuditWriteError):
    pass


class DuplicateEventError(AuditWriteError):
    pass


class LedgerReadOnlyError(AuditWriteError):
    pass


class LedgerIntegrityError(AuditError):
    pass


class CheckpointError(AuditError):
    pass


# --- reports ----------------------------------------------------------------------------------

class CheckStatus(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    NOT_VERIFIED = "NOT_VERIFIED"   # check required but could not be performed (e.g. no trust store)
    NONE = "NONE"                   # nothing to check


class OverallStatus(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True)
class IntegrityFailure:
    code: str
    detail: str
    sequence_number: int | None = None
    subject: str | None = None


@dataclass(frozen=True)
class LedgerHead:
    ledger_id: str
    sequence_number: int
    event_hash: str
    timestamp: datetime


@dataclass
class ChainVerification:
    ledger_id: str | None
    genesis_hash: str | None
    events_checked: int = 0
    first_sequence: int | None = None
    last_sequence: int | None = None
    head_event_hash: str | None = None
    failures: list[IntegrityFailure] = field(default_factory=list)
    complete: bool = True
    verified_hashes: dict[int, str] = field(default_factory=dict, repr=False)

    @property
    def status(self) -> CheckStatus:
        if not self.complete:
            return CheckStatus.NOT_VERIFIED
        return CheckStatus.FAILED if self.failures else CheckStatus.VERIFIED


@dataclass
class CheckpointResult:
    checkpoint_id: str
    source: str                    # stored | trusted
    sequence_number: int | None
    signature: CheckStatus
    consistency: CheckStatus
    detail: str = ""


@dataclass
class AuditVerificationReport:
    database: str
    ledger_id: str | None
    events_checked: int
    first_sequence: int | None
    last_sequence: int | None
    head_event_hash: str | None
    chain_status: CheckStatus
    checkpoint_signature_status: CheckStatus
    checkpoint_consistency: CheckStatus
    trusted_checkpoint_status: CheckStatus
    checkpoints: list[CheckpointResult]
    failures: list[IntegrityFailure]
    warnings: list[str]
    status: OverallStatus

    def to_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(asdict(self), default=str))


def _aggregate(results: list[CheckpointResult], attr: str) -> CheckStatus:
    values = [getattr(r, attr) for r in results]
    for status in (CheckStatus.FAILED, CheckStatus.NOT_VERIFIED, CheckStatus.VERIFIED):
        if status in values:
            return status
    return CheckStatus.NONE


# --- ledger -----------------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SQLiteAuditLedger:
    """Append-only audit ledger. Implements the AuditSink protocol via append_event()."""

    def __init__(self, conn: sqlite3.Connection, path: Path, *, clock: Clock, read_only: bool):
        self._conn, self.path, self._clock, self.read_only = conn, path, clock, read_only
        self._lock = threading.RLock()
        try:
            meta = self._meta()
        except sqlite3.Error:
            conn.close()
            raise
        if not {"ledger_id", "genesis_hash", "created_at", "schema_version"} <= set(meta):
            conn.close()
            raise LedgerIntegrityError(f"{path} is not an initialised GAMIS audit ledger")
        if meta["schema_version"] != SCHEMA_VERSION:
            conn.close()
            raise LedgerIntegrityError(f"unsupported ledger schema version {meta['schema_version']}")
        self.ledger_id: str = meta["ledger_id"]
        self.genesis_hash: str = meta["genesis_hash"]

    # -- construction -------------------------------------------------------------------------
    @classmethod
    def create(cls, path: str | Path, *, ledger_id: str, actor: Principal, clock: Clock = _utc_now
               ) -> "SQLiteAuditLedger":
        if actor.principal_type is not PrincipalType.AUDIT_SERVICE:
            raise AuditWriteError("the genesis event must be written by an AUDIT_SERVICE principal")
        path = Path(path)
        conn = connect(path)
        try:
            conn.executescript(_SCHEMA)
            with immediate_transaction(conn):
                if conn.execute("SELECT COUNT(*) FROM ledger_meta").fetchone()[0]:
                    raise AuditWriteError(f"{path} already contains a ledger")
                created = format_timestamp(clock())
                ghash = genesis_hash(ledger_id, created)
                conn.executemany("INSERT INTO ledger_meta (key, value) VALUES (?, ?)",
                                 [("ledger_id", ledger_id), ("genesis_hash", ghash), ("created_at", created),
                                  ("schema_version", SCHEMA_VERSION)])
                draft = AuditEventDraft(event_type=AuditEventType.LEDGER_GENESIS, actor_identity=actor,
                                        correlation_id=ledger_id,
                                        event_payload=GenesisPayload(ledger_id=ledger_id, genesis_hash=ghash,
                                                                     schema_version=AUDIT_SCHEMA_VERSION))
                event = build_event(draft, ledger_id=ledger_id, sequence_number=1, previous_event_hash=ghash,
                                    timestamp=datetime.fromisoformat(created.replace("Z", "+00:00")))
                _insert(conn, event)
        except BaseException:
            conn.close()
            raise
        return cls(conn, path, clock=clock, read_only=False)

    @classmethod
    def open(cls, path: str | Path, *, clock: Clock = _utc_now) -> "SQLiteAuditLedger":
        path = Path(path)
        if not path.exists():
            raise LedgerIntegrityError(f"no ledger at {path}")
        return cls(connect(path), path, clock=clock, read_only=False)

    @classmethod
    def open_read_only(cls, path: str | Path) -> "SQLiteAuditLedger":
        path = Path(path)
        return cls(connect(path, read_only=True), path, clock=_utc_now, read_only=True)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteAuditLedger":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _meta(self) -> dict[str, str]:
        try:
            return {r["key"]: r["value"] for r in self._conn.execute("SELECT key, value FROM ledger_meta")}
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):
                return {}
            raise

    def _commit(self, conn: sqlite3.Connection) -> None:
        conn.execute("COMMIT")

    # -- writes ---------------------------------------------------------------------------------
    def append_event(self, draft: AuditEventDraft | Mapping[str, Any]) -> AuditEvent:
        if self.read_only:
            raise LedgerReadOnlyError("ledger was opened read-only")
        try:
            draft = draft if isinstance(draft, AuditEventDraft) else AuditEventDraft.model_validate(draft)
        except ValidationError as exc:
            raise InvalidEventError(str(exc)) from exc
        with self._lock:
            try:
                with immediate_transaction(self._conn, commit=self._commit):
                    return self._append_locked(draft)
            except sqlite3.IntegrityError as exc:
                if "event_id" in str(exc):
                    raise DuplicateEventError(f"event_id {draft.event_id} already exists") from exc
                raise AuditWriteError(f"append rejected by the database: {exc}") from exc
            except sqlite3.Error as exc:
                raise AuditWriteError(f"append failed: {exc}") from exc

    def _append_locked(self, draft: AuditEventDraft) -> AuditEvent:
        head = self._conn.execute(
            "SELECT sequence_number, event_hash FROM audit_events ORDER BY sequence_number DESC LIMIT 1").fetchone()
        if head is None:
            raise LedgerIntegrityError("ledger has no genesis event")
        try:
            event = build_event(draft, ledger_id=self.ledger_id, sequence_number=head[0] + 1,
                                previous_event_hash=head[1], timestamp=self._clock())
        except ValidationError as exc:
            raise InvalidEventError(str(exc)) from exc
        _insert(self._conn, event)
        return event

    def create_checkpoint(self, signer: Signer, trust_store: TrustStore, *, checkpoint_id: str | None = None
                          ) -> AuditCheckpoint:
        """Sign the current head. The checkpoint is verified against ``trust_store`` before it is stored,
        so an unusable or untrusted key is rejected here. A CHECKPOINT_CREATED event is appended after it."""
        if self.read_only:
            raise LedgerReadOnlyError("ledger was opened read-only")
        with self._lock:
            try:
                with immediate_transaction(self._conn, commit=self._commit):
                    head = self._head_locked()
                    now = self._clock()
                    body = AuditCheckpoint(checkpoint_id=checkpoint_id or f"ckpt-{new_event_id()[4:]}",
                                           ledger_id=self.ledger_id, genesis_hash=self.genesis_hash,
                                           sequence_number=head.sequence_number, head_event_hash=head.event_hash,
                                           created_at=now, signing_key_id=signer.key_id,
                                           signing_key_version=signer.key_version)
                    try:
                        signed = body.with_signature(sign_object(body, signer, now=now))
                        verify_checkpoint_signature(signed, trust_store, now=now)
                    except SignatureVerificationError as exc:
                        raise CheckpointError(f"checkpoint signing failed: {type(exc).__name__}: {exc}") from exc
                    self._conn.execute(
                        "INSERT INTO audit_checkpoints VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (signed.checkpoint_id, signed.ledger_id, signed.sequence_number, signed.head_event_hash,
                         format_timestamp(signed.created_at), signed.signing_key_id, signed.signing_key_version,
                         canonicalize(signed.model_dump(mode="json")).decode("utf-8")))
                    self._append_locked(AuditEventDraft(
                        event_type=AuditEventType.CHECKPOINT_CREATED, actor_identity=signer.principal,
                        correlation_id=signed.checkpoint_id,
                        event_payload=CheckpointPayload(checkpoint_id=signed.checkpoint_id,
                                                        covered_sequence_number=signed.sequence_number,
                                                        head_event_hash=signed.head_event_hash,
                                                        signing_key_id=signed.signing_key_id,
                                                        signing_key_version=signed.signing_key_version)))
                    return signed
            except sqlite3.IntegrityError as exc:
                raise CheckpointError(f"checkpoint rejected by the database: {exc}") from exc

    # -- reads ----------------------------------------------------------------------------------
    def _head_locked(self) -> LedgerHead:
        row = self._conn.execute("SELECT sequence_number, event_hash, timestamp FROM audit_events "
                                 "ORDER BY sequence_number DESC LIMIT 1").fetchone()
        if row is None:
            raise LedgerIntegrityError("ledger has no events")
        return LedgerHead(self.ledger_id, row[0], row[1], datetime.fromisoformat(row[2].replace("Z", "+00:00")))

    def get_ledger_head(self) -> LedgerHead:
        with self._lock:
            return self._head_locked()

    def get_event(self, *, event_id: str | None = None, sequence_number: int | None = None) -> AuditEvent | None:
        """Return one event after re-validating its schema and hash. Chain links need verify_chain()."""
        if (event_id is None) == (sequence_number is None):
            raise ValueError("pass exactly one of event_id or sequence_number")
        column, value = ("event_id", event_id) if event_id is not None else ("sequence_number", sequence_number)
        with self._lock:
            row = self._conn.execute(f"SELECT * FROM audit_events WHERE {column} = ?", (value,)).fetchone()
        return None if row is None else _row_to_event(row)

    def get_events(self, *, start: int = 1, end: int | None = None, mission_id: str | None = None,
                   event_type: AuditEventType | str | None = None, limit: int = 1000) -> tuple[AuditEvent, ...]:
        if not 1 <= limit <= 100_000:
            raise ValueError("limit must be between 1 and 100000")
        sql, args = "SELECT * FROM audit_events WHERE sequence_number >= ?", [start]
        if end is not None:
            sql, args = sql + " AND sequence_number <= ?", args + [end]
        if mission_id is not None:
            sql, args = sql + " AND mission_id = ?", args + [mission_id]
        if event_type is not None:
            sql, args = sql + " AND event_type = ?", args + [AuditEventType(event_type).value]
        with self._lock:
            rows = self._conn.execute(sql + " ORDER BY sequence_number LIMIT ?", args + [limit]).fetchall()
        return tuple(_row_to_event(r) for r in rows)

    def iter_events(self) -> Iterator[AuditEvent]:
        last = 0
        while True:
            batch = self.get_events(start=last + 1, limit=1000)
            if not batch:
                return
            yield from batch
            last = batch[-1].sequence_number

    def list_checkpoints(self) -> tuple[AuditCheckpoint, ...]:
        with self._lock:
            rows = self._conn.execute("SELECT checkpoint_json FROM audit_checkpoints ORDER BY sequence_number, "
                                      "created_at").fetchall()
        return tuple(AuditCheckpoint.model_validate_json(r[0]) for r in rows)

    # -- verification ---------------------------------------------------------------------------
    def verify_chain(self) -> ChainVerification:
        with self._lock:
            return self._verify_chain_locked()

    def _verify_chain_locked(self) -> ChainVerification:
        F = IntegrityFailure
        meta = self._meta()
        result = ChainVerification(ledger_id=meta.get("ledger_id"), genesis_hash=meta.get("genesis_hash"))
        try:
            problems = quick_check(self._conn)
            if problems:
                result.failures.append(F("SQLITE_QUICK_CHECK_FAILED", "; ".join(problems)[:500]))
            gone = missing_triggers(self._conn, EXPECTED_TRIGGERS)
            if gone:
                result.failures.append(F("APPEND_ONLY_TRIGGERS_MISSING", f"missing triggers: {gone}"))
            expected_genesis = genesis_hash(meta.get("ledger_id", ""), meta.get("created_at", ""))
            if meta.get("genesis_hash") != expected_genesis:
                result.failures.append(F("GENESIS_HASH_MISMATCH", "genesis hash does not match ledger metadata"))
            expected_prev, expected_seq = expected_genesis, 1
            total = self._conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            for row in self._conn.execute("SELECT * FROM audit_events ORDER BY sequence_number"):
                seq = row["sequence_number"]
                result.events_checked += 1
                result.first_sequence = seq if result.first_sequence is None else result.first_sequence
                result.last_sequence = seq
                if seq != expected_seq:
                    result.failures.append(F("SEQUENCE_GAP", f"expected sequence {expected_seq}, found {seq}", seq))
                if row["previous_event_hash"] != expected_prev:
                    result.failures.append(F("BROKEN_LINK", "previous_event_hash does not match the preceding "
                                                            "event", seq, row["event_id"]))
                if row["ledger_id"] != result.ledger_id:
                    result.failures.append(F("LEDGER_ID_MISMATCH", "event belongs to another ledger", seq))
                computed = row["event_hash"]
                try:
                    body = _row_to_body(row)
                    computed = body.compute_hash()
                    if not _row_is_canonical(row, body):
                        result.failures.append(F("NON_CANONICAL_RECORD", "stored columns are not the canonical "
                                                                         "form of the event", seq, row["event_id"]))
                    if computed != row["event_hash"]:
                        result.failures.append(F("HASH_MISMATCH", "stored event_hash does not match the event "
                                                                  "content", seq, row["event_id"]))
                    if seq == 1 and _thaw(body.event_payload).get("genesis_hash") != expected_genesis:
                        result.failures.append(F("GENESIS_EVENT_INVALID", "genesis event payload mismatch", seq))
                except (ValidationError, ValueError, KeyError, TypeError) as exc:
                    result.failures.append(F("INVALID_EVENT", f"event failed schema validation: "
                                                              f"{str(exc).splitlines()[0][:300]}", seq,
                                             row["event_id"]))
                result.verified_hashes[seq] = computed
                expected_prev, expected_seq = computed, seq + 1
            if result.events_checked != total:
                result.failures.append(F("ROW_COUNT_MISMATCH", f"read {result.events_checked} of {total} events"))
            if result.events_checked == 0:
                result.failures.append(F("EMPTY_LEDGER", "ledger has no genesis event"))
            if result.last_sequence is not None:
                result.head_event_hash = result.verified_hashes[result.last_sequence]
        except sqlite3.Error as exc:
            result.complete = False
            result.failures.append(F("DATABASE_ERROR", f"{type(exc).__name__}: {exc}"))
        return result

    def get_verification_report(self, *, trust_store: TrustStore | None = None,
                                trusted_checkpoints: tuple[AuditCheckpoint, ...] = (),
                                now: datetime | None = None) -> AuditVerificationReport:
        now = now or _utc_now()
        with self._lock:
            chain = self._verify_chain_locked()
            failures, warnings, results = list(chain.failures), [], []
            stored: dict[str, AuditCheckpoint] = {}
            if chain.complete:
                try:
                    rows = self._conn.execute("SELECT * FROM audit_checkpoints ORDER BY sequence_number").fetchall()
                except sqlite3.Error as exc:
                    rows, chain.complete = [], False
                    failures.append(IntegrityFailure("DATABASE_ERROR", f"{type(exc).__name__}: {exc}"))
                for row in rows:
                    try:
                        cp = AuditCheckpoint.model_validate_json(row["checkpoint_json"])
                        if (cp.checkpoint_id, cp.sequence_number, cp.head_event_hash, cp.signing_key_id) != (
                                row["checkpoint_id"], row["sequence_number"], row["head_event_hash"],
                                row["signing_key_id"]):
                            raise ValueError("checkpoint columns disagree with the stored checkpoint record")
                    except (ValidationError, ValueError) as exc:
                        failures.append(IntegrityFailure("CHECKPOINT_RECORD_INVALID", str(exc).splitlines()[0][:300],
                                                         row["sequence_number"], row["checkpoint_id"]))
                        results.append(CheckpointResult(row["checkpoint_id"], "stored", row["sequence_number"],
                                                        CheckStatus.FAILED, CheckStatus.FAILED, "invalid record"))
                        continue
                    stored[cp.checkpoint_id] = cp
                    results.append(self._check_checkpoint(cp, "stored", chain, trust_store, now, failures))
            for cp in trusted_checkpoints:
                result = self._check_checkpoint(cp, "trusted", chain, trust_store, now, failures)
                local = stored.get(cp.checkpoint_id)
                if local is not None and local.model_dump(mode="json") != cp.model_dump(mode="json"):
                    failures.append(IntegrityFailure("TRUSTED_CHECKPOINT_MISMATCH", "stored checkpoint differs from "
                                                     "the trusted copy", cp.sequence_number, cp.checkpoint_id))
                    result.consistency = CheckStatus.FAILED
                results.append(result)

        stored_results = [r for r in results if r.source == "stored"]
        trusted_results = [r for r in results if r.source == "trusted"]
        trusted_status = CheckStatus.NONE
        if trusted_results:
            worst = [r.signature for r in trusted_results] + [r.consistency for r in trusted_results]
            trusted_status = (CheckStatus.FAILED if CheckStatus.FAILED in worst else
                              CheckStatus.NOT_VERIFIED if CheckStatus.NOT_VERIFIED in worst else CheckStatus.VERIFIED)
        if not results:
            warnings.append("no signed checkpoint: truncation of the newest events or a rewrite of the entire "
                            "history cannot be detected from the hash chain alone")
        elif not trusted_results:
            warnings.append("checkpoints were read from the ledger itself; supply an externally retained trusted "
                            "checkpoint to detect a complete history rewrite")
        incomplete = (not chain.complete or any(CheckStatus.NOT_VERIFIED in (r.signature, r.consistency)
                                                for r in results))
        status = (OverallStatus.FAILED if failures else
                  OverallStatus.INCOMPLETE if incomplete else OverallStatus.PASSED)
        return AuditVerificationReport(
            database=str(self.path), ledger_id=chain.ledger_id, events_checked=chain.events_checked,
            first_sequence=chain.first_sequence, last_sequence=chain.last_sequence,
            head_event_hash=chain.head_event_hash, chain_status=chain.status,
            checkpoint_signature_status=_aggregate(stored_results, "signature"),
            checkpoint_consistency=_aggregate(stored_results, "consistency"),
            trusted_checkpoint_status=trusted_status, checkpoints=results, failures=failures, warnings=warnings,
            status=status)

    def _check_checkpoint(self, cp: AuditCheckpoint, source: str, chain: ChainVerification,
                          trust_store: TrustStore | None, now: datetime,
                          failures: list[IntegrityFailure]) -> CheckpointResult:
        F = IntegrityFailure
        result = CheckpointResult(cp.checkpoint_id, source, cp.sequence_number, CheckStatus.NOT_VERIFIED,
                                  CheckStatus.VERIFIED)
        if trust_store is None:
            result.detail = "no trust store supplied; signature not verified"
        else:
            try:
                verify_checkpoint_signature(cp, trust_store, now=now)
                result.signature = CheckStatus.VERIFIED
            except SignatureVerificationError as exc:
                result.signature = CheckStatus.FAILED
                failures.append(F("CHECKPOINT_SIGNATURE_INVALID", f"{type(exc).__name__}: {exc}", cp.sequence_number,
                                  cp.checkpoint_id))
        problems = []
        if cp.ledger_id != chain.ledger_id or cp.genesis_hash != chain.genesis_hash:
            problems.append(("CHECKPOINT_LEDGER_MISMATCH", "checkpoint belongs to a different ledger"))
        if chain.last_sequence is None or cp.sequence_number > chain.last_sequence:
            problems.append(("CHECKPOINT_BEYOND_HEAD", f"checkpoint covers sequence {cp.sequence_number} but the "
                             f"ledger ends at {chain.last_sequence} (truncated or rolled back)"))
        elif chain.verified_hashes.get(cp.sequence_number) != cp.head_event_hash:
            problems.append(("CHECKPOINT_INCONSISTENT", "event at the checkpointed sequence does not have the "
                             "checkpointed hash (history was rewritten)"))
        for code, detail in problems:
            failures.append(F(code, detail, cp.sequence_number, cp.checkpoint_id))
        if problems:
            result.consistency, result.detail = CheckStatus.FAILED, "; ".join(d for _, d in problems)
        return result


# --- row mapping ------------------------------------------------------------------------------

def _insert(conn: sqlite3.Connection, event: AuditEvent) -> None:
    data = event.model_dump(mode="json")
    conn.execute(
        "INSERT INTO audit_events (sequence_number, event_id, ledger_id, event_type, event_version, mission_id, "
        "grant_id, assignment_id, worker_id, actor_json, timestamp, correlation_id, payload_json, "
        "previous_event_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event.sequence_number, event.event_id, event.ledger_id, data["event_type"], event.event_version,
         event.mission_id, event.grant_id, event.assignment_id, event.worker_id,
         canonicalize(data["actor_identity"]).decode(), data["timestamp"], event.correlation_id,
         canonicalize(data["event_payload"]).decode(), event.previous_event_hash, event.event_hash))


def _row_fields(row: sqlite3.Row) -> dict[str, Any]:
    return {"ledger_id": row["ledger_id"], "event_id": row["event_id"], "event_type": row["event_type"],
            "event_version": row["event_version"], "mission_id": row["mission_id"], "grant_id": row["grant_id"],
            "assignment_id": row["assignment_id"], "worker_id": row["worker_id"],
            "actor_identity": json.loads(row["actor_json"]), "timestamp": row["timestamp"],
            "sequence_number": row["sequence_number"], "correlation_id": row["correlation_id"],
            "event_payload": json.loads(row["payload_json"]), "previous_event_hash": row["previous_event_hash"]}


def _row_to_body(row: sqlite3.Row) -> AuditEventBody:
    return AuditEventBody.model_validate(_row_fields(row))


def _row_is_canonical(row: sqlite3.Row, body: AuditEventBody) -> bool:
    data = body.model_dump(mode="json")
    return (row["payload_json"] == canonicalize(data["event_payload"]).decode()
            and row["actor_json"] == canonicalize(data["actor_identity"]).decode()
            and row["timestamp"] == data["timestamp"])


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    try:
        event = AuditEvent.model_validate({**_row_fields(row), "event_hash": row["event_hash"]})
    except (ValidationError, ValueError) as exc:
        raise LedgerIntegrityError(f"event {row['sequence_number']} failed validation: "
                                   f"{str(exc).splitlines()[0]}") from exc
    if not _row_is_canonical(row, event):
        raise LedgerIntegrityError(f"event {row['sequence_number']} is not stored in canonical form")
    return event


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(v) for v in value]
    return value


__all__ = ["AuditError", "AuditVerificationReport", "AuditWriteError", "ChainVerification", "CheckStatus",
           "CheckpointError", "CheckpointResult", "DuplicateEventError", "IntegrityFailure", "InvalidEventError",
           "LedgerHead", "LedgerIntegrityError", "LedgerReadOnlyError", "OverallStatus", "SQLiteAuditLedger",
           "StorageError"]
