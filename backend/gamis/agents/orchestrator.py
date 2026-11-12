"""Persistent mission scheduler with dependency tracking, bounded concurrency and cancellation."""
from __future__ import annotations

import threading
import time
import json
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from gamis.agents.models import InvestigationReport, MissionPlan, MissionTask, WorkerReport
from gamis.agents.supervisor import Supervisor
from gamis.agents.workers import WorkerAgent
from gamis.schemas.assignment import AgentAssignment
from gamis.schemas.mission import MissionGrant
from gamis.security.digest import canonical_digest
from gamis.storage.sqlite import append_only_triggers, connect, immediate_transaction

Clock = Callable[[], datetime]


class MissionStore:
    def __init__(self, path: str | Path):
        self._conn = connect(path)
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS missions (
                mission_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, objective TEXT NOT NULL,
                status TEXT NOT NULL, report_json TEXT, failure TEXT, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, grant_json TEXT, plan_json TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0, cancel_reason TEXT);
            CREATE TABLE IF NOT EXISTS mission_tasks (
                mission_id TEXT NOT NULL REFERENCES missions(mission_id), task_id TEXT NOT NULL,
                worker_role TEXT NOT NULL, status TEXT NOT NULL, assignment_json TEXT,
                report_json TEXT, error TEXT, updated_at TEXT NOT NULL,
                PRIMARY KEY(mission_id, task_id));
            CREATE TABLE IF NOT EXISTS mission_budget (
                mission_id TEXT PRIMARY KEY REFERENCES missions(mission_id), tokens INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS mission_worker_budget (
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                assignment_id TEXT NOT NULL, tokens INTEGER NOT NULL,
                PRIMARY KEY(mission_id, assignment_id));
            CREATE TABLE IF NOT EXISTS mission_worker_token_usage (
                mission_id TEXT NOT NULL REFERENCES missions(mission_id),
                worker_id TEXT NOT NULL, tokens INTEGER NOT NULL,
                PRIMARY KEY(mission_id, worker_id));
            CREATE TABLE IF NOT EXISTS mission_task_retries (
                mission_id TEXT NOT NULL, task_id TEXT NOT NULL, attempts INTEGER NOT NULL,
                PRIMARY KEY(mission_id, task_id));
            CREATE TABLE IF NOT EXISTS mission_checkpoints (
                checkpoint_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                state_json TEXT NOT NULL, digest TEXT NOT NULL, previous_digest TEXT, created_at TEXT NOT NULL,
                UNIQUE(mission_id, sequence));
            CREATE TABLE IF NOT EXISTS mission_execution_config (
                mission_id TEXT PRIMARY KEY REFERENCES missions(mission_id), config_json TEXT NOT NULL);
        """)
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(missions)")}
        for column, declaration in (("failure", "TEXT"), ("grant_json", "TEXT"), ("plan_json", "TEXT"),
                                    ("cancel_requested", "INTEGER NOT NULL DEFAULT 0"),
                                    ("cancel_reason", "TEXT")):
            if column not in columns:
                self._conn.execute(f"ALTER TABLE missions ADD COLUMN {column} {declaration}")
        self._conn.executescript(append_only_triggers("mission_checkpoints"))
        self._lock = threading.RLock()

    def close(self) -> None:
        self._conn.close()

    def create(self, grant: MissionGrant, objective: str, now: datetime) -> None:
        with self._lock, immediate_transaction(self._conn):
            existing = self._conn.execute(
                "SELECT grant_id,objective FROM missions WHERE mission_id=?", (grant.mission_id,)).fetchone()
            if existing is not None:
                if (existing["grant_id"], existing["objective"]) != (grant.grant_id, objective):
                    raise ValueError(f"mission {grant.mission_id} already exists with different grant or objective")
                return
            self._conn.execute("INSERT INTO missions "
                               "(mission_id,grant_id,objective,status,report_json,failure,created_at,updated_at,"
                               "grant_json) VALUES (?, ?, ?, 'RUNNING', NULL, NULL, ?, ?, ?)",
                               (grant.mission_id, grant.grant_id, objective, now.isoformat(), now.isoformat(),
                                grant.model_dump_json()))
            self._conn.execute("INSERT INTO mission_budget VALUES (?, 0)", (grant.mission_id,))

    def save_plan(self, mission_id: str, plan: MissionPlan) -> None:
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("UPDATE missions SET plan_json=? WHERE mission_id=?",
                               (plan.model_dump_json(), mission_id))

    def plan(self, mission_id: str) -> MissionPlan:
        with self._lock:
            row = self._conn.execute("SELECT plan_json FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None or row[0] is None:
            raise KeyError(f"mission {mission_id} has no persisted plan")
        return MissionPlan.model_validate_json(row[0])

    def grant(self, mission_id: str) -> MissionGrant:
        with self._lock:
            row = self._conn.execute("SELECT grant_json FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None or row[0] is None:
            raise KeyError(f"mission {mission_id} has no persisted signed grant")
        return MissionGrant.model_validate_json(row[0])

    def add_task(self, mission_id: str, task: MissionTask, now: datetime) -> None:
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("INSERT INTO mission_tasks "
                               "(mission_id,task_id,worker_role,status,updated_at) VALUES (?,?,?,'PENDING',?)",
                               (mission_id, task.task_id, task.worker_role, now.isoformat()))

    def task_state(self, mission_id: str, task_id: str) -> str:
        with self._lock:
            row = self._conn.execute("SELECT status FROM mission_tasks WHERE mission_id=? AND task_id=?",
                                     (mission_id, task_id)).fetchone()
        if row is None:
            raise KeyError(f"unknown mission task {task_id}")
        return row[0]

    def set_task(self, mission_id: str, task_id: str, state: str, now: datetime, *,
                 assignment: AgentAssignment | None = None, report: WorkerReport | None = None,
                 error: str | None = None) -> None:
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("UPDATE mission_tasks SET status=?, assignment_json=COALESCE(?,assignment_json), "
                               "report_json=COALESCE(?,report_json), error=?, updated_at=? "
                               "WHERE mission_id=? AND task_id=?",
                               (state, None if assignment is None else assignment.model_dump_json(),
                                None if report is None else report.model_dump_json(), error, now.isoformat(),
                                mission_id, task_id))

    def reserve_tokens(self, mission_id: str, assignment: AgentAssignment, count: int, grant: MissionGrant) -> None:
        if count < 0:
            raise ValueError("token reservation cannot be negative")
        with self._lock, immediate_transaction(self._conn):
            row = self._conn.execute("SELECT tokens FROM mission_budget WHERE mission_id=?",
                                     (mission_id,)).fetchone()
            if row is None:
                raise KeyError(f"unknown mission {mission_id}")
            spent = row[0]
            if spent + count > grant.global_resource_limits.max_tokens:
                raise RuntimeError("mission token budget exhausted")
            # One task may make a bounded prompt set; this row is its cumulative per-worker allowance.
            row = self._conn.execute(
                "SELECT tokens FROM mission_worker_budget WHERE mission_id=? AND assignment_id=?",
                (mission_id, assignment.assignment_id)).fetchone()
            spent_by_worker = 0 if row is None else row[0]
            if spent_by_worker + count > assignment.resource_limits.max_tokens:
                raise RuntimeError("worker or mission token budget exhausted")
            row = self._conn.execute(
                "SELECT tokens FROM mission_worker_token_usage WHERE mission_id=? AND worker_id=?",
                (mission_id, assignment.worker_id)).fetchone()
            spent_by_identity = 0 if row is None else row[0]
            if spent_by_identity + count > assignment.resource_limits.max_tokens:
                raise RuntimeError("worker mission-wide token budget exhausted")
            self._conn.execute("UPDATE mission_budget SET tokens=tokens+? WHERE mission_id=?",
                               (count, mission_id))
            self._conn.execute(
                "INSERT INTO mission_worker_budget VALUES (?, ?, ?) "
                "ON CONFLICT(mission_id,assignment_id) DO UPDATE SET tokens=tokens+excluded.tokens",
                (mission_id, assignment.assignment_id, count))
            self._conn.execute(
                "INSERT INTO mission_worker_token_usage VALUES (?, ?, ?) "
                "ON CONFLICT(mission_id,worker_id) DO UPDATE SET tokens=tokens+excluded.tokens",
                (mission_id, assignment.worker_id, count))

    def increment_retry(self, mission_id: str, task_id: str) -> int:
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute(
                "INSERT INTO mission_task_retries VALUES (?, ?, 1) "
                "ON CONFLICT(mission_id,task_id) DO UPDATE SET attempts=attempts+1",
                (mission_id, task_id))
            row = self._conn.execute("SELECT attempts FROM mission_task_retries WHERE mission_id=? AND task_id=?",
                                     (mission_id, task_id)).fetchone()
        return row[0]

    def retry_count(self, mission_id: str, task_id: str) -> int:
        with self._lock:
            row = self._conn.execute("SELECT attempts FROM mission_task_retries WHERE mission_id=? AND task_id=?",
                                     (mission_id, task_id)).fetchone()
        return 0 if row is None else row[0]

    def budget(self, mission_id: str) -> dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT tokens FROM mission_budget WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown mission {mission_id}")
        return {"tokens_used": row[0]}

    def save_execution_config(self, mission_id: str, config: Mapping[str, Any]) -> None:
        encoded = json.dumps(dict(config), sort_keys=True, separators=(",", ":"))
        with self._lock, immediate_transaction(self._conn):
            if self._conn.execute("SELECT 1 FROM missions WHERE mission_id=?", (mission_id,)).fetchone() is None:
                raise KeyError(f"unknown mission {mission_id}")
            self._conn.execute(
                "INSERT INTO mission_execution_config VALUES (?, ?) "
                "ON CONFLICT(mission_id) DO UPDATE SET config_json=excluded.config_json",
                (mission_id, encoded))

    def execution_config(self, mission_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT config_json FROM mission_execution_config WHERE mission_id=?", (mission_id,)).fetchone()
        return None if row is None else json.loads(row["config_json"])

    def checkpoint_summary(self, mission_id: str) -> dict[str, Any]:
        with self._lock:
            count = self._conn.execute(
                "SELECT COUNT(*) FROM mission_checkpoints WHERE mission_id=?", (mission_id,)).fetchone()[0]
        latest = self.verify_checkpoints(mission_id)
        return {"count": count, "latest": latest}

    def request_cancel(self, mission_id: str, reason: str) -> None:
        with self._lock, immediate_transaction(self._conn):
            cursor = self._conn.execute(
                "UPDATE missions SET cancel_requested=1,cancel_reason=?,updated_at=? "
                "WHERE mission_id=? AND status IN ('RUNNING','PARTIAL')",
                (reason[:250], datetime.now(timezone.utc).isoformat(), mission_id))
            if cursor.rowcount != 1:
                raise ValueError(f"mission {mission_id} is not cancellable")

    def cancel_requested(self, mission_id: str) -> tuple[bool, str | None]:
        with self._lock:
            row = self._conn.execute("SELECT cancel_requested,cancel_reason FROM missions WHERE mission_id=?",
                                     (mission_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown mission {mission_id}")
        return bool(row[0]), row[1]

    def resume(self, mission_id: str, now: datetime) -> None:
        with self._lock, immediate_transaction(self._conn):
            row = self._conn.execute("SELECT status,cancel_requested FROM missions WHERE mission_id=?",
                                     (mission_id,)).fetchone()
            if row is None or row["status"] not in {"RUNNING", "PARTIAL", "INTERRUPTED"} or row["cancel_requested"]:
                raise ValueError(f"mission {mission_id} cannot be resumed from its persisted state")
            self._conn.execute("UPDATE missions SET status='RUNNING',report_json=NULL,failure=NULL,updated_at=? "
                               "WHERE mission_id=?", (now.isoformat(), mission_id))

    def create_checkpoint(self, mission_id: str, now: datetime, *,
                          external_state: Mapping[str, Any] | None = None) -> dict[str, Any]:
        mission = self.mission(mission_id)
        tasks = self.tasks(mission_id)
        with self._lock:
            budgets = [dict(row) for row in self._conn.execute(
                "SELECT 'mission' AS scope, mission_id AS subject_id, tokens FROM mission_budget WHERE mission_id=? "
                "UNION ALL SELECT 'assignment', assignment_id, tokens FROM mission_worker_budget WHERE mission_id=? "
                "UNION ALL SELECT 'worker', worker_id, tokens FROM mission_worker_token_usage WHERE mission_id=? "
                "ORDER BY scope,subject_id", (mission_id, mission_id, mission_id))]
            retries = [dict(row) for row in self._conn.execute(
                "SELECT task_id,attempts FROM mission_task_retries WHERE mission_id=? ORDER BY task_id",
                (mission_id,))]
            previous = self._conn.execute(
                "SELECT sequence,digest FROM mission_checkpoints WHERE mission_id=? ORDER BY sequence DESC LIMIT 1",
                (mission_id,)).fetchone()
            seq = 1 if previous is None else previous["sequence"] + 1
            previous_digest = None if previous is None else previous["digest"]
        state = {
            "mission_id": mission_id, "grant_id": mission["grant_id"], "mission_status": mission["status"],
            "objective": mission["objective"], "cancel_requested": bool(mission["cancel_requested"]),
            "cancel_reason": mission["cancel_reason"],
            "tasks": [{
                "task_id": task["task_id"], "worker_role": task["worker_role"], "status": task["status"],
                "assignment": None if task["assignment"] is None else task["assignment"].model_dump(mode="json"),
                "report": None if task["report"] is None else task["report"].model_dump(mode="json"),
                "error": task["error"],
            } for task in tasks],
            "budgets": budgets, "retries": retries, "external_state": dict(external_state or {}),
        }
        digest = canonical_digest({"mission_id": mission_id, "sequence": seq,
                                   "previous_digest": previous_digest, "state": state})
        checkpoint_id = f"CHK-{uuid.uuid4().hex}"
        state_json = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("INSERT INTO mission_checkpoints VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (checkpoint_id, mission_id, seq, state_json, digest, previous_digest,
                                now.isoformat()))
        return {"checkpoint_id": checkpoint_id, "mission_id": mission_id, "sequence": seq,
                "digest": digest, "previous_digest": previous_digest, "created_at": now.isoformat()}

    def verify_checkpoints(self, mission_id: str) -> dict[str, Any] | None:
        with self._lock:
            rows = self._conn.execute(
                "SELECT checkpoint_id,sequence,state_json,digest,previous_digest,created_at "
                "FROM mission_checkpoints WHERE mission_id=? ORDER BY sequence", (mission_id,)).fetchall()
        previous_digest = None
        latest = None
        for expected_sequence, row in enumerate(rows, start=1):
            try:
                state = json.loads(row["state_json"])
            except json.JSONDecodeError as exc:
                raise ValueError(f"checkpoint {row['checkpoint_id']} contains invalid JSON") from exc
            envelope = {"mission_id": mission_id, "sequence": row["sequence"],
                        "previous_digest": row["previous_digest"], "state": state}
            if (state.get("mission_id") != mission_id or row["sequence"] != expected_sequence
                    or row["previous_digest"] != previous_digest
                    or canonical_digest(envelope) != row["digest"]):
                raise ValueError(f"checkpoint chain integrity failed at {row['checkpoint_id']}")
            previous_digest = row["digest"]
            latest = {"checkpoint_id": row["checkpoint_id"], "sequence": row["sequence"],
                      "state": state, "digest": row["digest"], "created_at": row["created_at"]}
        return latest

    def finish(self, report: InvestigationReport, now: datetime) -> None:
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("UPDATE missions SET status=?,report_json=?,failure=NULL,updated_at=? "
                               "WHERE mission_id=?",
                               (report.status.upper(), report.model_dump_json(), now.isoformat(), report.mission_id))

    def fail(self, mission_id: str, now: datetime, error: str) -> None:
        with self._lock, immediate_transaction(self._conn):
            self._conn.execute("UPDATE missions SET status='FAILED',failure=?,updated_at=? WHERE mission_id=?",
                               (error[:1000], now.isoformat(), mission_id))

    def mission(self, mission_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT mission_id,grant_id,objective,status,report_json,failure,created_at,"
                                     "updated_at,grant_json,plan_json,cancel_requested,cancel_reason "
                                     "FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown mission {mission_id}")
        return {**dict(row), "report": None if row["report_json"] is None else
                InvestigationReport.model_validate_json(row["report_json"])}

    def tasks(self, mission_id: str) -> tuple[dict[str, Any], ...]:
        with self._lock:
            rows = self._conn.execute("SELECT task_id,worker_role,status,assignment_json,report_json,error "
                                      "FROM mission_tasks WHERE mission_id=? ORDER BY rowid", (mission_id,)).fetchall()
        return tuple({**dict(r), "assignment": None if r["assignment_json"] is None else
                      AgentAssignment.model_validate_json(r["assignment_json"]),
                      "report": None if r["report_json"] is None else
                      WorkerReport.model_validate_json(r["report_json"])} for r in rows)

    def list_missions(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            rows = self._conn.execute("SELECT mission_id,grant_id,objective,status,updated_at FROM missions "
                                      "ORDER BY created_at DESC").fetchall()
        return tuple(dict(r) for r in rows)


class MissionOrchestrator:
    def __init__(self, *, supervisor: Supervisor, workers: Mapping[str, WorkerAgent],
                 store: MissionStore, clock: Clock, concurrency: int = 3,
                 task_timeout_seconds: float = 300, mission_timeout_seconds: float = 900,
                 checkpoint_context: Callable[[MissionGrant], Mapping[str, Any]] | None = None,
                 checkpoint_callback: Callable[[MissionGrant, Mapping[str, Any]], None] | None = None,
                 recovery_callback: Callable[..., None] | None = None, max_task_retries: int = 1):
        if concurrency < 1 or concurrency > 32 or task_timeout_seconds <= 0 or mission_timeout_seconds <= 0:
            raise ValueError("invalid concurrency or mission timeout configuration")
        if max_task_retries < 0 or max_task_retries > 3:
            raise ValueError("max_task_retries must be between 0 and 3")
        self.supervisor, self.workers, self.store, self.clock = supervisor, dict(workers), store, clock
        self.concurrency, self.task_timeout = concurrency, task_timeout_seconds
        self.mission_timeout = mission_timeout_seconds
        self.checkpoint_context = checkpoint_context or (lambda _grant: {})
        self.checkpoint_callback = checkpoint_callback
        self.recovery_callback = recovery_callback
        self.max_task_retries = max_task_retries

    def run(self, grant: MissionGrant, objective: str, *, host: str, indicator: str) -> InvestigationReport:
        self.store.create(grant, objective, self.clock())
        started = time.monotonic()
        try:
            self._checkpoint(grant)
            plan = self.supervisor.decompose(objective)
            self.store.save_plan(grant.mission_id, plan)
            for task in plan.tasks:
                self.store.add_task(grant.mission_id, task, self.clock())
            self._checkpoint(grant)
        except Exception as exc:
            self.store.fail(grant.mission_id, self.clock(), f"{type(exc).__name__}: {exc}")
            raise
        return self._execute(grant, objective, plan, host=host, indicator=indicator, started=started, resuming=False)

    def resume(self, mission_id: str, *, host: str, indicator: str) -> InvestigationReport:
        checkpoint = self.store.verify_checkpoints(mission_id)
        if checkpoint is None:
            raise ValueError(f"mission {mission_id} has no verified recovery checkpoint")
        mission = self.store.mission(mission_id)
        if mission["status"] == "RUNNING" and self.recovery_callback is not None:
            self.recovery_callback("MISSION_INTERRUPTED", self.store.grant(mission_id),
                                   reason="A prior process ended before mission completion.")
        grant = self.store.grant(mission_id)
        self.store.resume(mission_id, self.clock())
        if self.recovery_callback is not None:
            self.recovery_callback("MISSION_RESUMED", grant, checkpoint_id=checkpoint["checkpoint_id"],
                                   checkpoint_digest=checkpoint["digest"], state="RUNNING")
        try:
            plan = self.store.plan(mission_id)
        except KeyError:
            plan = self.supervisor.decompose(mission["objective"])
            self.store.save_plan(mission_id, plan)
            for task in plan.tasks:
                self.store.add_task(mission_id, task, self.clock())
            self._checkpoint(grant)
        return self._execute(grant, mission["objective"], plan, host=host,
                             indicator=indicator, started=time.monotonic(), resuming=True)

    def _checkpoint(self, grant: MissionGrant) -> None:
        record = self.store.create_checkpoint(
            grant.mission_id, self.clock(), external_state=self.checkpoint_context(grant))
        if self.checkpoint_callback is not None:
            self.checkpoint_callback(grant, record)

    @staticmethod
    def _read_only(assignment: AgentAssignment | None) -> bool:
        return (assignment is not None and assignment.permission_class.value == "READ"
                and all(operation.permission_class.value == "READ" for operation in assignment.permitted_operations))

    def _execute(self, grant: MissionGrant, objective: str, plan: MissionPlan, *, host: str, indicator: str,
                 started: float, resuming: bool) -> InvestigationReport:
        assignments: dict[str, AgentAssignment] = {}
        failures: dict[str, str] = {}
        reports: dict[str, WorkerReport] = {}
        existing_tasks = {task["task_id"]: task for task in self.store.tasks(grant.mission_id)}
        for task in plan.tasks:
            previous = existing_tasks.get(task.task_id)
            if resuming and previous is not None:
                assignment = previous["assignment"]
                if assignment is not None:
                    assignments[task.task_id] = assignment
                if previous["status"] == "COMPLETED" and previous["report"] is not None:
                    reports[task.task_id] = previous["report"]
                    continue
                attempt_count = self.store.retry_count(grant.mission_id, task.task_id)
                retryable_state = previous["status"] in {"RUNNING", "FAILED", "TIMED_OUT", "INTERRUPTED"}
                if (retryable_state and self._read_only(assignment)
                        and attempt_count < self.max_task_retries):
                    attempt = self.store.increment_retry(grant.mission_id, task.task_id)
                    self.store.set_task(grant.mission_id, task.task_id, "AUTHORIZED", self.clock(),
                                        error="Resuming an incomplete READ-only task.")
                    if self.recovery_callback is not None:
                        self.recovery_callback("WORKER_RETRIED", grant, assignment_id=assignment.assignment_id,
                                               worker_id=assignment.worker_id, task_id=task.task_id,
                                               attempt=attempt, reason="Safe READ-only task recovery.")
                    self._checkpoint(grant)
                    continue
                if previous["status"] not in {"PENDING", "AUTHORIZED"}:
                    failures[task.task_id] = previous["error"] or "task cannot be safely resumed"
                    continue
                if assignment is not None:
                    continue
            try:
                assignment = self.supervisor.issue_assignment(task, grant)
                assignments[task.task_id] = assignment
                self.store.set_task(grant.mission_id, task.task_id, "AUTHORIZED", self.clock(),
                                    assignment=assignment)
                self._checkpoint(grant)
            except Exception as exc:
                failures[task.task_id] = f"{type(exc).__name__}: {exc}"
                self.store.set_task(grant.mission_id, task.task_id, "FAILED", self.clock(), error=failures[task.task_id])
                if self.recovery_callback is not None:
                    self.recovery_callback("WORKER_FAILED", grant, task_id=task.task_id,
                                           reason=failures[task.task_id])
                self._checkpoint(grant)

        task_map = {t.task_id: t for t in plan.tasks}
        running: dict[Future[WorkerReport], tuple[MissionTask, threading.Event, float, float]] = {}
        executor = ThreadPoolExecutor(max_workers=self.concurrency, thread_name_prefix="gamis-worker")
        try:
            while len(reports) + len(failures) < len(task_map):
                cancel_requested, cancel_reason = self.store.cancel_requested(grant.mission_id)
                if cancel_requested:
                    for future, (task, cancellation, _, _) in list(running.items()):
                        cancellation.set()
                        future.cancel()
                    for future, (task, _, _, _) in list(running.items()):
                        if not future.cancelled():
                            try:
                                report = future.result()
                            except Exception as exc:
                                failures[task.task_id] = f"{type(exc).__name__}: {exc}"
                            else:
                                reports[task.task_id] = report
                                self.store.set_task(grant.mission_id, task.task_id, "COMPLETED", self.clock(),
                                                    report=report)
                        running.pop(future, None)
                        self._checkpoint(grant)
                    for task in plan.tasks:
                        if task.task_id not in reports and task.task_id not in failures:
                            failures[task.task_id] = cancel_reason or "mission cancelled"
                            self.store.set_task(grant.mission_id, task.task_id, "CANCELLED", self.clock(),
                                                error=failures[task.task_id])
                    break
                mission_deadline = min(self.mission_timeout, grant.global_resource_limits.max_wall_clock_seconds)
                if time.monotonic() - started >= mission_deadline:
                    for future, (task, cancel, _, _) in list(running.items()):
                        cancel.set()
                        future.cancel()
                        failures[task.task_id] = "mission deadline exceeded"
                        self.store.set_task(grant.mission_id, task.task_id, "TIMED_OUT", self.clock(),
                                            error=failures[task.task_id])
                        if self.recovery_callback is not None:
                            self.recovery_callback("WORKER_FAILED", grant, task_id=task.task_id,
                                                   reason=failures[task.task_id])
                        self._checkpoint(grant)
                    running.clear()
                    for task in plan.tasks:
                        if task.task_id not in reports and task.task_id not in failures:
                            failures[task.task_id] = "mission deadline exceeded"
                            self.store.set_task(grant.mission_id, task.task_id, "TIMED_OUT", self.clock(),
                                                error=failures[task.task_id])
                            if self.recovery_callback is not None:
                                self.recovery_callback("WORKER_FAILED", grant, task_id=task.task_id,
                                                       reason=failures[task.task_id])
                            self._checkpoint(grant)
                    break
                for task in plan.tasks:
                    if len(running) >= self.concurrency:
                        break
                    if task.task_id in reports or task.task_id in failures or any(
                            queued.task_id == task.task_id for _, (queued, _, _, _) in running.items()):
                        continue
                    states = [self.store.task_state(grant.mission_id, dep) for dep in task.depends_on]
                    if any(s not in {"COMPLETED"} for s in states):
                        if any(s in {"FAILED", "TIMED_OUT", "SKIPPED", "CANCELLED"} for s in states):
                            failures[task.task_id] = "dependency did not complete"
                            self.store.set_task(grant.mission_id, task.task_id, "SKIPPED", self.clock(),
                                                error=failures[task.task_id])
                        continue
                    assignment = assignments.get(task.task_id)
                    worker = self.workers.get(task.worker_role)
                    if assignment is None or worker is None:
                        failures[task.task_id] = "assignment or worker is unavailable"
                        self.store.set_task(grant.mission_id, task.task_id, "FAILED", self.clock(),
                                            error=failures[task.task_id])
                        continue
                    cancel = threading.Event()
                    upstream = tuple(reports[dep] for dep in task.depends_on)
                    effective_timeout = min(self.task_timeout, assignment.resource_limits.max_wall_clock_seconds,
                                            grant.global_resource_limits.max_wall_clock_seconds)
                    self.store.set_task(grant.mission_id, task.task_id, "RUNNING", self.clock())
                    self._checkpoint(grant)
                    future = executor.submit(worker.run, task, assignment, grant, upstream,
                                             host=host, indicator=indicator, cancellation=cancel,
                                             timeout_seconds=effective_timeout)
                    running[future] = (task, cancel, time.monotonic(), effective_timeout)
                if not running:
                    if len(reports) + len(failures) < len(task_map):
                        for task in plan.tasks:
                            if task.task_id not in reports and task.task_id not in failures:
                                failures[task.task_id] = "no runnable dependency path"
                                self.store.set_task(grant.mission_id, task.task_id, "SKIPPED", self.clock(),
                                                    error=failures[task.task_id])
                                self._checkpoint(grant)
                    break
                nearest = min(max(0.01, timeout - (time.monotonic() - launched))
                              for _, _, launched, timeout in running.values())
                done, _ = wait(tuple(running), timeout=min(nearest, 0.25), return_when=FIRST_COMPLETED)
                now_mono = time.monotonic()
                for future, (task, cancellation, launch_time, timeout) in list(running.items()):
                    if future not in done and now_mono - launch_time >= timeout:
                        cancellation.set()
                        future.cancel()
                        failures[task.task_id] = "task timeout exceeded"
                        self.store.set_task(grant.mission_id, task.task_id, "TIMED_OUT", self.clock(),
                                            error=failures[task.task_id])
                        if self.recovery_callback is not None:
                            self.recovery_callback("WORKER_FAILED", grant, task_id=task.task_id,
                                                   reason=failures[task.task_id])
                        self._checkpoint(grant)
                        del running[future]
                for future in done:
                    entry = running.pop(future, None)
                    if entry is None:
                        continue
                    task, _, _, _ = entry
                    try:
                        report = future.result()
                    except Exception as exc:
                        error = f"{type(exc).__name__}: {exc}"
                        assignment = assignments.get(task.task_id)
                        attempt_count = self.store.retry_count(grant.mission_id, task.task_id)
                        if self._read_only(assignment) and attempt_count < self.max_task_retries:
                            attempt = self.store.increment_retry(grant.mission_id, task.task_id)
                            self.store.set_task(grant.mission_id, task.task_id, "AUTHORIZED", self.clock(),
                                                error=error)
                            if self.recovery_callback is not None:
                                self.recovery_callback("WORKER_RETRIED", grant,
                                                       assignment_id=assignment.assignment_id,
                                                       worker_id=assignment.worker_id, task_id=task.task_id,
                                                       attempt=attempt, reason="Retrying a failed READ-only task.")
                        else:
                            failures[task.task_id] = error
                            self.store.set_task(grant.mission_id, task.task_id, "FAILED", self.clock(), error=error)
                            if self.recovery_callback is not None:
                                self.recovery_callback("WORKER_FAILED", grant, task_id=task.task_id,
                                                       reason=error)
                        self._checkpoint(grant)
                    else:
                        reports[task.task_id] = report
                        self.store.set_task(grant.mission_id, task.task_id, "COMPLETED", self.clock(), report=report)
                        self._checkpoint(grant)
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

        ordered = tuple(reports[t.task_id] for t in plan.tasks if t.task_id in reports)
        followup: MissionTask | None = None
        if (self.supervisor.should_request_followup(ordered)
                and not any(task.task_id == "followup-verification-gap" for task in plan.tasks)
                and time.monotonic() - started < min(
                    self.mission_timeout, grant.global_resource_limits.max_wall_clock_seconds)):
            verifier_task = next(t for t in reversed(plan.tasks) if t.worker_role == "responder")
            followup = MissionTask(
                task_id="followup-verification-gap", worker_role="evidence-reader",
                objective="Re-check the authorized host and indicator for source records omitted by verification.",
                success_criteria=("Confirm or resolve the source-record discrepancy using gateway receipts.",),
                depends_on=(verifier_task.task_id,))
            try:
                self.store.add_task(grant.mission_id, followup, self.clock())
                assignment = self.supervisor.issue_assignment(followup, grant)
                self.store.set_task(grant.mission_id, followup.task_id, "AUTHORIZED", self.clock(),
                                    assignment=assignment)
                plan = MissionPlan(tasks=(*plan.tasks, followup))
                self.store.save_plan(grant.mission_id, plan)
                self._checkpoint(grant)
                worker = self.workers[followup.worker_role]
                report = worker.run(followup, assignment, grant, (reports[verifier_task.task_id],),
                                    host=host, indicator=indicator, timeout_seconds=min(
                                        self.task_timeout, assignment.resource_limits.max_wall_clock_seconds,
                                        grant.global_resource_limits.max_wall_clock_seconds))
            except Exception as exc:
                failures[followup.task_id] = f"{type(exc).__name__}: {exc}"
                self.store.set_task(grant.mission_id, followup.task_id, "FAILED", self.clock(),
                                    error=failures[followup.task_id])
            else:
                reports[followup.task_id] = report
                self.store.set_task(grant.mission_id, followup.task_id, "COMPLETED", self.clock(), report=report)
                self._checkpoint(grant)
        ordered = tuple(reports[t.task_id] for t in plan.tasks if t.task_id in reports)
        state = "complete" if len(ordered) == len(plan.tasks) and not failures else "partial"
        try:
            if ordered:
                report = self.supervisor.consolidate(grant, objective, ordered, status=state)
            else:
                report = InvestigationReport(
                    mission_id=grant.mission_id, grant_id=grant.grant_id, objective=objective, status="partial",
                    conclusion="No worker produced evidence; no investigative conclusion can be drawn.",
                    executive_summary="The mission stopped before evidence collection completed.",
                    worker_reports=(), evidence_count=0, receipt_count=0, confidence=0.0,
                    limitations=("No worker completed; the report contains no evidence-backed findings.",),
                    missing_information=("All assigned investigation evidence.",))
            self.store.finish(report, self.clock())
            self._checkpoint(grant)
            if state != "complete" and self.recovery_callback is not None:
                self.recovery_callback("PARTIAL_COMPLETION", grant, state=state,
                                       reason="One or more assigned tasks did not complete.")
            return report
        except Exception as exc:
            self.store.fail(grant.mission_id, self.clock(), f"{type(exc).__name__}: {exc}")
            raise
