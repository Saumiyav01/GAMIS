"""SQLite connection helpers shared by the P2 audit ledger and evidence store.

Durability: rollback journal (journal_mode=DELETE) with synchronous=FULL, so a committed transaction is on
disk and an interrupted one is rolled back from the hot journal on the next open. DELETE mode (not WAL) is
used so that independent verifiers can open the database strictly read-only.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DEFAULT_TIMEOUT_SECONDS = 30.0


class StorageError(Exception):
    pass


class ReadOnlyStorageError(StorageError):
    pass


def connect(path: str | Path, *, read_only: bool = False,
            timeout: float = DEFAULT_TIMEOUT_SECONDS) -> sqlite3.Connection:
    path = Path(path)
    if read_only:
        if not path.exists():
            raise StorageError(f"database does not exist: {path}")
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, isolation_level=None,
                               check_same_thread=False, timeout=timeout)
        conn.execute("PRAGMA query_only=ON")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False, timeout=timeout)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
    conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def immediate_transaction(conn: sqlite3.Connection, commit=None) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE ... COMMIT, rolling back on any exception. Serializes writers across processes."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        (commit or (lambda c: c.execute("COMMIT")))(conn)
    except BaseException:
        if conn.in_transaction:   # covers a failed COMMIT too: never leave a half-open transaction behind
            conn.execute("ROLLBACK")
        raise


def append_only_triggers(table: str) -> str:
    """DDL forbidding UPDATE and DELETE on ``table`` for ordinary SQL operations."""
    return f"""
CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table}
BEGIN SELECT RAISE(ABORT, 'append-only: {table} rows cannot be updated'); END;
CREATE TRIGGER IF NOT EXISTS {table}_no_delete BEFORE DELETE ON {table}
BEGIN SELECT RAISE(ABORT, 'append-only: {table} rows cannot be deleted'); END;
"""


def missing_triggers(conn: sqlite3.Connection, expected: tuple[str, ...]) -> list[str]:
    present = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    return [name for name in expected if name not in present]


def quick_check(conn: sqlite3.Connection) -> list[str]:
    rows = [r[0] for r in conn.execute("PRAGMA quick_check")]
    return [] if rows == ["ok"] else rows
