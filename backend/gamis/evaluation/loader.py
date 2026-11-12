"""Seed dataset loading and validation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SEEDS_DIR = Path(__file__).resolve().parents[2] / "seeds"
ATTACK_LOCATIONS = ("user_request", "log_message", "intel_note")


def load_seed(name: str, seeds_dir: Path = SEEDS_DIR) -> list[dict[str, Any]]:
    path = seeds_dir / f"{name}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list")
    return data


def load_all(seeds_dir: Path = SEEDS_DIR) -> dict[str, list[dict[str, Any]]]:
    seeds = {n: load_seed(n, seeds_dir) for n in ("logs", "intel", "investigations", "attacks", "failures")}
    validate(seeds)
    return seeds


def validate(seeds: dict[str, list[dict[str, Any]]]) -> None:
    """Referential-integrity checks. Raises ValueError on the first problem."""
    log_ids = {e["id"] for e in seeds["logs"]}
    inv_ids = {i["id"] for i in seeds["investigations"]}
    for coll in seeds.values():
        ids = [r["id"] for r in coll if "id" in r]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate ids in a seed file")
    for inv in seeds["investigations"]:
        for lid in inv["expected_evidence_event_ids"] + inv["decoy_event_ids"]:
            if lid not in log_ids:
                raise ValueError(f"{inv['id']} references unknown log {lid}")
        if set(inv["expected_evidence_event_ids"]) & set(inv["decoy_event_ids"]):
            raise ValueError(f"{inv['id']} has ids both expected and decoy")
    for atk in seeds["attacks"]:
        if atk["investigation_id"] not in inv_ids:
            raise ValueError(f"{atk['id']} references unknown investigation")
        if atk["location"] not in ATTACK_LOCATIONS:
            raise ValueError(f"{atk['id']} has unknown location {atk['location']}")
    for fl in seeds["failures"]:
        if fl["investigation_id"] not in inv_ids:
            raise ValueError(f"{fl['id']} references unknown investigation")
