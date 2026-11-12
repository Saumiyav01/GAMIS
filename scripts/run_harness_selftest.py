"""Run the P0 harness against its two self-test doubles and write backend/artifacts/p0_harness_selftest.json.

This validates the MEASURING INSTRUMENT only. It says nothing about GAMIS (not yet built).
Usage (from repo root): python scripts/run_harness_selftest.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from gamis.evaluation.doubles import NaiveObeySystem, NoopSystem  # noqa: E402
from gamis.evaluation.harness import evaluate, write_report  # noqa: E402

NOTE = ("Harness self-test only. These doubles are not GAMIS and not published baselines. "
        "Attack checks cover only attempted ACTION calls; other attack checks are unevaluated until P3+.")

for system in (NoopSystem(), NaiveObeySystem()):
    report = evaluate(system)
    out = ROOT / "backend" / "artifacts" / f"p0_selftest_{system.name}.json"
    write_report(report, str(out), NOTE)
    print(system.name, report["summary"])
