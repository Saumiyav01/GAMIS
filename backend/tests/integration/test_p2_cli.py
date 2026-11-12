"""P2 verification CLI: valid/tampered ledgers, exit codes, read-only behaviour, JSON, restart."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gamis.cli import main
from gamis.evidence.store import EvidenceStore
from tests.p2_support import build_audit_env, cli_json, raw_db, receipted_bundle

BACKEND = Path(__file__).resolve().parents[2]


@pytest.fixture
def populated(tmp_path):
    env = build_audit_env(tmp_path)
    env.store.store_bundle(receipted_bundle(env))
    cp = env.checkpoint("CP-CLI")
    paths = env.export(cp)
    env.close()
    args = ["verify", "--ledger", str(env.ledger_path), "--evidence-db", str(env.evidence_path),
            "--content-dir", str(env.content_dir), "--trust-store", str(paths["trust"]),
            "--trusted-checkpoint", str(paths["checkpoint"])]
    return env, args


def snapshot(root: Path) -> dict[str, tuple[str, int]]:
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_valid_ledger_verification_json(populated, capsys):
    env, args = populated
    code, out = cli_json(capsys, args)
    assert code == 0 and out["status"] == "PASSED" and out["read_only"] is True and out["failures"] == []
    led = out["ledger"]
    assert led["ledger_id"] == "LEDGER-TEST-1" and led["events_checked"] == led["last_sequence"] > 10
    assert led["first_sequence"] == 1 and len(led["head_event_hash"]) == 64
    assert (led["chain_status"], led["checkpoint_signature_status"], led["checkpoint_consistency"],
            led["trusted_checkpoint_status"]) == ("VERIFIED", "VERIFIED", "VERIFIED", "VERIFIED")
    assert out["evidence"]["status"] == "PASSED" and out["evidence"]["bundles_checked"] == 1
    assert out["audit_cross_check"]["status"] == "PASSED"


def test_human_output(populated, capsys):
    _, args = populated
    assert main(args) == 0
    text = capsys.readouterr().out
    for label in ("GAMIS verify: PASSED", "ledger id", "events checked", "head hash", "hash chain",
                  "checkpoint sigs", "checkpoint consist.", "trusted checkpoint", "evidence"):
        assert label in text


def test_tampered_ledger_fails_with_nonzero_exit(populated, capsys):
    env, args = populated
    raw_db(env.ledger_path).execute("UPDATE audit_events SET correlation_id = 'forged' WHERE sequence_number = 5")
    code, out = cli_json(capsys, args)
    assert code == 1 and out["status"] == "FAILED" and out["ledger"]["chain_status"] == "FAILED"
    found = {(f["code"], f.get("sequence_number")) for f in out["failures"]}
    assert ("HASH_MISMATCH", 5) in found and ("BROKEN_LINK", 6) in found
    assert out["audit_cross_check"]["status"] == "NOT_VERIFIED"


def test_tampered_evidence_fails(populated, capsys):
    env, args = populated
    obj = next(p for p in (env.content_dir / "objects").rglob("*") if p.is_file())
    os.chmod(obj, 0o644)
    obj.write_bytes(b"{}")
    code, out = cli_json(capsys, args)
    assert code == 1 and out["evidence"]["status"] == "FAILED"
    assert "CORRUPTED_CONTENT" in {f["code"] for f in out["failures"]}


def test_unaudited_evidence_fails(populated, capsys):
    env, args = populated
    store = EvidenceStore.open(env.evidence_path, env.content_dir, audit=None, require_known_receipts=False,
                               clock=env.clock)
    from gamis.schemas import EvidenceItem
    from tests.p1_support import evidence_item_dict
    store.store_evidence(EvidenceItem.model_validate(evidence_item_dict("EV-SILENT", "RCPT-X")),
                         mission_id="MIS-001", assignment_id="ASG-001", worker_id="worker-reader-1")
    store.close()
    code, out = cli_json(capsys, args)
    assert code == 1 and {"UNAUDITED_EVIDENCE"} <= {f["code"] for f in out["failures"]}


def test_cli_is_read_only(populated, capsys):
    env, args = populated
    before = snapshot(env.root)
    assert cli_json(capsys, args)[0] == 0
    raw_db(env.ledger_path).execute("UPDATE audit_events SET correlation_id = 'x' WHERE sequence_number = 3")
    tampered = snapshot(env.root)
    assert cli_json(capsys, args)[0] == 1
    assert snapshot(env.root) == tampered != before            # nothing repaired, nothing created
    assert not list(env.root.glob("*-journal"))


def test_incomplete_inputs_return_exit_2(populated, capsys, tmp_path):
    env, args = populated
    no_trust = [a for a in args if a not in args[args.index("--trust-store"):args.index("--trust-store") + 2]]
    code, out = cli_json(capsys, no_trust)
    assert code == 2 and out["status"] == "INCOMPLETE"
    assert out["ledger"]["checkpoint_signature_status"] == "NOT_VERIFIED"
    assert cli_json(capsys, ["verify", "--ledger", str(tmp_path / "nope.db")])[0] == 2
    assert cli_json(capsys, ["verify", "--ledger", str(env.ledger_path), "--evidence-db",
                             str(env.evidence_path)])[0] == 2
    bad_trust = tmp_path / "bad.json"
    bad_trust.write_text("{}")
    assert cli_json(capsys, args[:args.index("--trust-store") + 1] + [str(bad_trust)]
                    + args[args.index("--trust-store") + 2:])[0] == 2


def test_wrong_trust_store_fails(populated, capsys, tmp_path):
    env, args = populated
    other = build_audit_env(tmp_path / "other")
    other.close()
    paths = other.export()
    swapped = list(args)
    swapped[swapped.index("--trust-store") + 1] = str(paths["trust"])
    code, out = cli_json(capsys, swapped)
    assert code == 1 and out["ledger"]["checkpoint_signature_status"] == "FAILED"


def test_verification_after_restart_in_a_new_process(populated):
    _, args = populated
    proc = subprocess.run([sys.executable, "-m", "gamis", *args, "--json"], cwd=BACKEND, capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["status"] == "PASSED" and out["ledger"]["trusted_checkpoint_status"] == "VERIFIED"
