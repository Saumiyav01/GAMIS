"""GAMIS command line (P2): read-only integrity verification.

    python -m gamis verify --ledger audit.db [--evidence-db evidence.db --content-dir objects/]
                           [--trust-store trust.json] [--trusted-checkpoint cp.json ...] [--json]

Exit codes: 0 = everything verified; 1 = an integrity failure was detected; 2 = verification could not be
completed (missing inputs, unreadable database, hot journal from an interrupted write, unverifiable
signatures). The command opens every database with SQLite mode=ro and never writes or repairs anything.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

EXIT_OK, EXIT_FAILED, EXIT_INCOMPLETE = 0, 1, 2


def _parse_time(text: str) -> datetime:
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise argparse.ArgumentTypeError("--now must include a timezone")
    return value.astimezone(timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m gamis", description="GAMIS local mission and integrity tools")
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="read-only verification of the audit ledger and evidence store")
    v.add_argument("--ledger", required=True, type=Path, help="audit ledger SQLite file")
    v.add_argument("--evidence-db", type=Path, help="evidence store SQLite file")
    v.add_argument("--content-dir", type=Path, help="evidence content-addressed store directory")
    v.add_argument("--trust-store", type=Path, help="public trust store JSON (gamis.trust_store.v1)")
    v.add_argument("--trusted-checkpoint", type=Path, action="append", default=[],
                   help="externally retained checkpoint JSON; may be repeated")
    v.add_argument("--now", type=_parse_time, help="verification time (ISO-8601 with offset); default: now")
    v.add_argument("--json", action="store_true", help="machine-readable JSON output")
    mission = sub.add_parser("mission", help="submit and inspect local synthetic investigation missions")
    mission_sub = mission.add_subparsers(dest="mission_command", required=True)
    submit = mission_sub.add_parser("submit", help="run a synthetic investigation")
    submit.add_argument("--objective", default=None, help="investigation objective")
    submit.add_argument("--host", default="web-01", help="synthetic host scope")
    submit.add_argument("--indicator", default="203.0.113.50", help="synthetic indicator scope")
    submit.add_argument("--provider", choices=("ollama", "mock"), help="override configured LLM provider")
    submit.add_argument("--concurrency", type=int, help="maximum concurrent workers (1-32)")
    resume = mission_sub.add_parser("resume", help="resume a checkpointed mission after authorization checks")
    resume.add_argument("mission_id")
    resume.add_argument("--provider", choices=("ollama", "mock"), help="override configured LLM provider")
    cancel = mission_sub.add_parser("cancel", help="cancel an active mission and suspend its grant")
    cancel.add_argument("mission_id")
    cancel.add_argument("--reason", default="Operator requested cancellation.")
    for name, help_text in (("list", "list persisted missions"), ("status", "show mission and worker task status"),
                            ("report", "show the final investigation report"),
                            ("receipts", "list signed ToolReceipts for a mission"),
                            ("evidence", "list persisted evidence for a mission")):
        command = mission_sub.add_parser(name, help=help_text)
        if name != "list":
            command.add_argument("mission_id")
    revoke = mission_sub.add_parser("revoke", help="persistently revoke a mission grant")
    revoke.add_argument("grant_id")
    revoke.add_argument("--reason", required=True)
    models = sub.add_parser("models", help="list models available from the configured local provider")
    models.add_argument("--provider", choices=("ollama", "mock"), help="override configured LLM provider")
    return parser


def verify(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    from gamis.audit.checkpoints import load_checkpoint
    from gamis.audit.ledger import LedgerIntegrityError, SQLiteAuditLedger
    from gamis.evidence.store import EvidenceStore
    from gamis.security.trust_io import load_trust_store
    from gamis.storage.sqlite import StorageError

    now = args.now or datetime.now(timezone.utc)
    out: dict[str, Any] = {"command": "verify", "read_only": True, "verified_at": now.isoformat(),
                           "status": "INCOMPLETE", "ledger": None, "evidence": None, "audit_cross_check": None,
                           "failures": [], "warnings": []}

    def incomplete(message: str) -> tuple[int, dict[str, Any]]:
        out["failures"].append({"code": "VERIFICATION_INCOMPLETE", "detail": message})
        out["status"] = "INCOMPLETE"
        return EXIT_INCOMPLETE, out

    if (args.evidence_db is None) != (args.content_dir is None):
        return incomplete("--evidence-db and --content-dir must be given together")
    try:
        trust_store = load_trust_store(args.trust_store) if args.trust_store else None
        trusted = tuple(load_checkpoint(p) for p in args.trusted_checkpoint)
    except (OSError, ValueError) as exc:
        return incomplete(f"could not load verification inputs: {exc}")
    if trust_store is None:
        out["warnings"].append("no --trust-store: signatures cannot be verified")

    try:
        ledger = SQLiteAuditLedger.open_read_only(args.ledger)
    except (sqlite3.Error, StorageError) as exc:
        return incomplete(f"could not read the ledger read-only (an interrupted write leaves a hot journal that "
                          f"only a writer can roll back): {exc}")
    except LedgerIntegrityError as exc:
        out["status"] = "FAILED"
        out["failures"].append({"code": "LEDGER_UNREADABLE", "detail": str(exc)})
        return EXIT_FAILED, out
    statuses = []
    try:
        report = ledger.get_verification_report(trust_store=trust_store, trusted_checkpoints=trusted, now=now)
        out["ledger"] = report.to_dict()
        statuses.append(report.status.value)
        out["failures"] += [{"source": "ledger", **f} for f in out["ledger"]["failures"]]
        out["warnings"] += out["ledger"]["warnings"]
        if args.evidence_db is not None:
            try:
                store = EvidenceStore.open_read_only(args.evidence_db, args.content_dir, trust_store=trust_store,
                                                     clock=lambda: now)
            except Exception as exc:  # noqa: BLE001 - reported as INCOMPLETE, never hidden
                statuses.append("INCOMPLETE")
                out["failures"].append({"source": "evidence", "code": "VERIFICATION_INCOMPLETE",
                                        "detail": f"could not open evidence store read-only: {exc}"})
            else:
                try:
                    ev = store.verify_all()
                    out["evidence"] = ev.to_dict()
                    statuses.append(ev.status)
                    out["failures"] += [{"source": "evidence", **f} for f in ev.failures]
                    out["warnings"] += ev.warnings
                    if report.chain_status.value == "VERIFIED":
                        cross = store.audit_cross_check(ledger.iter_events())
                        out["audit_cross_check"] = {"status": "FAILED" if cross else "PASSED", "failures": cross}
                        statuses.append("FAILED" if cross else "PASSED")
                        out["failures"] += [{"source": "audit-cross-check", **f} for f in cross]
                    else:
                        out["audit_cross_check"] = {"status": "NOT_VERIFIED", "failures": []}
                        out["warnings"].append("evidence/audit cross-check skipped: ledger chain did not verify")
                finally:
                    store.close()
    except sqlite3.Error as exc:
        statuses.append("INCOMPLETE")
        out["failures"].append({"code": "VERIFICATION_INCOMPLETE", "detail": f"database error: {exc}"})
    finally:
        ledger.close()
    out["status"] = ("FAILED" if "FAILED" in statuses else "INCOMPLETE" if "INCOMPLETE" in statuses
                     else "PASSED")
    return {"PASSED": EXIT_OK, "FAILED": EXIT_FAILED}.get(out["status"], EXIT_INCOMPLETE), out


def _human(out: dict[str, Any]) -> str:
    lines = [f"GAMIS verify: {out['status']}"]
    led = out.get("ledger")
    if led:
        lines += [f"  ledger id          : {led['ledger_id']}",
                  f"  events checked     : {led['events_checked']} (sequence {led['first_sequence']}.."
                  f"{led['last_sequence']})",
                  f"  head hash          : {led['head_event_hash']}",
                  f"  hash chain         : {led['chain_status']}",
                  f"  checkpoint sigs    : {led['checkpoint_signature_status']}",
                  f"  checkpoint consist.: {led['checkpoint_consistency']}",
                  f"  trusted checkpoint : {led['trusted_checkpoint_status']}"]
    ev = out.get("evidence")
    if ev:
        lines.append(f"  evidence           : {ev['status']} ({ev['items_checked']} items, {ev['bundles_checked']} "
                     f"bundles, {ev['receipts_checked']} receipts)")
    if out.get("audit_cross_check"):
        lines.append(f"  evidence/audit     : {out['audit_cross_check']['status']}")
    for f in out["failures"]:
        where = f.get("sequence_number") or f.get("subject") or ""
        lines.append(f"  FAILURE {f.get('code')} {where}: {f.get('detail', '')}")
    for w in dict.fromkeys(out["warnings"]):
        lines.append(f"  warning: {w}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "mission":
        return mission_command(args)
    if args.command == "models":
        from gamis.llm.provider import LLMConfiguration, create_provider
        from gamis.runtime import with_provider

        try:
            config = with_provider(LLMConfiguration.from_environment(), args.provider)
            provider = create_provider(config)
            available = provider.list_models()
            selected = ({"supervisor": config.supervisor_model,
                         "research": config.model_for_role("evidence-reader"),
                         "analysis": config.model_for_role("intel-analyst"),
                         "verification": config.model_for_role("responder")}
                        if config.provider == "ollama" else
                        {"supervisor": "gamis-deterministic-mock", "research": "gamis-deterministic-mock",
                         "analysis": "gamis-deterministic-mock", "verification": "gamis-deterministic-mock"})
            print(json.dumps({"active_provider": config.provider, "configured_models": selected,
                              "available_models": available,
                              "model_availability": {name: name in available for name in set(selected.values())}},
                             indent=2))
            return 0
        except Exception as exc:
            print(f"GAMIS model listing failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
    try:
        code, out = verify(args)
    except Exception as exc:  # noqa: BLE001 - never report success after an unexpected error
        code, out = EXIT_INCOMPLETE, {"command": "verify", "status": "INCOMPLETE",
                                      "failures": [{"code": "VERIFIER_ERROR", "detail": f"{type(exc).__name__}: "
                                                                                       f"{exc}"}], "warnings": []}
    print(json.dumps(out, indent=2, sort_keys=True) if args.json else _human(out))
    return code


def mission_command(args: argparse.Namespace) -> int:
    from gamis.gateway import GatewayStore
    from gamis.runtime import DEFAULT_OBJECTIVE, default_state_dir, open_runtime

    home = default_state_dir()
    try:
        if args.mission_command == "submit":
            objective = args.objective or DEFAULT_OBJECTIVE
            with open_runtime(provider=args.provider, concurrency=args.concurrency) as runtime:
                report = runtime.submit(objective, host=args.host, indicator=args.indicator)
                tasks = runtime.mission_store.tasks(report.mission_id)
                out = {
                    "active_provider": report.active_provider,
                    "models": {"supervisor": report.supervisor_model,
                               "workers": report.worker_models or {"default": report.worker_model}},
                    "mission_id": report.mission_id,
                    "worker_statuses": [{
                        "worker_name": {"evidence-reader": "Research Worker", "intel-analyst": "Analysis Worker",
                                        "responder": "Verification Worker"}.get(task["worker_role"],
                                                                                task["worker_role"]),
                        "task_id": task["task_id"], "status": task["status"],
                    } for task in tasks],
                    "receipt_count": report.receipt_count,
                    "evidence_count": report.evidence_count,
                    "final_status": report.status,
                    "report": report.model_dump(mode="json"),
                }
                print(json.dumps(out, indent=2, sort_keys=True))
            return 0 if report.status == "complete" else 1
        if args.mission_command == "revoke":
            with open_runtime(provider="mock") as runtime:
                runtime.grant_status.revoke(args.grant_id, runtime.clock(), args.reason)
            print(f"Revoked grant {args.grant_id}")
            return 0
        if args.mission_command == "cancel":
            with open_runtime(provider="mock") as runtime:
                runtime.cancel(args.mission_id, args.reason)
            print(json.dumps({"mission_id": args.mission_id, "status": "CANCEL_REQUESTED"}, indent=2))
            return 0
        if args.mission_command == "resume":
            with open_runtime(provider=args.provider) as runtime:
                report = runtime.resume(args.mission_id)
                tasks = runtime.mission_store.tasks(args.mission_id)
            print(json.dumps({
                "active_provider": report.active_provider,
                "mission_id": report.mission_id,
                "worker_statuses": [{"task_id": task["task_id"], "worker_role": task["worker_role"],
                                     "status": task["status"]} for task in tasks],
                "receipt_count": report.receipt_count, "evidence_count": report.evidence_count,
                "final_status": report.status, "report": report.model_dump(mode="json"),
            }, indent=2, sort_keys=True))
            return 0 if report.status == "complete" else 1
        if args.mission_command == "list":
            path = home / "missions.db"
            if not path.exists():
                print("[]")
                return 0
            import sqlite3
            with sqlite3.connect(path) as conn:
                rows = conn.execute("SELECT mission_id,grant_id,objective,status,updated_at "
                                    "FROM missions ORDER BY created_at DESC").fetchall()
            print(json.dumps([dict(zip(("mission_id", "grant_id", "objective", "status", "updated_at"), row))
                              for row in rows], indent=2))
            return 0
        if args.mission_command in ("status", "report"):
            path = home / "missions.db"
            if not path.exists():
                raise ValueError(f"no local mission database at {path}")
            import sqlite3
            with sqlite3.connect(path) as conn:
                conn.row_factory = sqlite3.Row
                mission = conn.execute("SELECT mission_id,grant_id,objective,status,report_json,failure "
                                       "FROM missions WHERE mission_id=?", (args.mission_id,)).fetchone()
                if mission is None:
                    raise ValueError(f"unknown mission {args.mission_id}")
                if args.mission_command == "status":
                    tasks = conn.execute("SELECT task_id,worker_role,status,assignment_json,error "
                                         "FROM mission_tasks WHERE mission_id=? ORDER BY rowid",
                                         (args.mission_id,)).fetchall()
                    out = {k: mission[k] for k in ("mission_id", "grant_id", "objective", "status", "failure")}
                    report = None if mission["report_json"] is None else json.loads(mission["report_json"])
                    if report is not None:
                        out["active_provider"] = report.get("active_provider")
                        out["models"] = {"supervisor": report.get("supervisor_model"),
                                         "workers": report.get("worker_models") or
                                         {"default": report.get("worker_model")}}
                    out["tasks"] = [{"task_id": r["task_id"], "worker_role": r["worker_role"],
                                     "worker_name": {"evidence-reader": "Research Worker",
                                                     "intel-analyst": "Analysis Worker",
                                                     "responder": "Verification Worker"}.get(r["worker_role"]),
                                     "status": r["status"], "error": r["error"]} for r in tasks]
                else:
                    out = None if mission["report_json"] is None else json.loads(mission["report_json"])
            print(json.dumps(out, indent=2, sort_keys=True))
            return 0
        if args.mission_command == "receipts":
            path = home / "gateway.db"
            if not path.exists():
                raise ValueError(f"no local gateway database at {path}")
            store = GatewayStore(path)
            try:
                receipts = [r.model_dump(mode="json") for r in store.list_receipts()
                            if r.mission_id == args.mission_id]
            finally:
                store.close()
            print(json.dumps(receipts, indent=2, sort_keys=True))
            return 0
        if args.mission_command == "evidence":
            path = home / "evidence.db"
            if not path.exists():
                raise ValueError(f"no local evidence database at {path}")
            import sqlite3
            with sqlite3.connect(path) as conn:
                rows = conn.execute(
                    "SELECT e.evidence_id,e.record_digest,e.integrity_digest,e.receipt_id,e.item_json "
                    "FROM evidence_items e JOIN evidence_links l USING(evidence_id) "
                    "WHERE l.mission_id=? ORDER BY e.evidence_id", (args.mission_id,)).fetchall()
            out = [{"evidence_id": row[0], "record_digest": row[1], "integrity_digest": row[2],
                    "receipt_id": row[3], "item": json.loads(row[4])} for row in rows]
            print(json.dumps(out, indent=2, sort_keys=True))
            return 0
        raise ValueError(f"unsupported mission command {args.mission_command}")
    except Exception as exc:
        print(f"GAMIS mission {args.mission_command} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
