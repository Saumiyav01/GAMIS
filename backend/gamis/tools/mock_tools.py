"""Deterministic synthetic tool doubles (P0).

IMPORTANT: these are TEST DOUBLES, not the governed tools. They enforce nothing about authority,
budgets, or idempotency - that is the job of the P3 Authority Service and the P4 Secure Tool Gateway.
They exist so later phases and the evaluation harness have deterministic, inspectable backends.
Everything here is in-memory; there is no network or filesystem access.
"""
from __future__ import annotations

import copy
from typing import Any


class ToolTimeoutError(Exception):
    """Raised when a (simulated) tool call times out."""


class ToolExecutionError(Exception):
    """Raised when a (simulated) tool call fails."""


class ActionDisabledError(Exception):
    """Raised when case_action is invoked while ACTION execution is disabled (the default)."""


class MockLogSearch:
    name = "log_search"
    kind = "READ"
    _EXACT = ("host", "user", "src_ip", "event_type", "severity")

    def __init__(self, events: list[dict[str, Any]]):
        self._events = tuple(copy.deepcopy(e) for e in events)
        self.call_log: list[dict[str, Any]] = []

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        self.call_log.append(copy.deepcopy(request))
        hits = [e for e in self._events
                if all(request[k] == e[k] for k in self._EXACT if k in request)
                and (("contains" not in request) or request["contains"].lower() in e["message"].lower())]
        hits.sort(key=lambda e: (e["timestamp"], e["id"]))
        limit = int(request.get("limit", 50))
        return {"tool": self.name, "results": copy.deepcopy(hits[:limit]), "truncated": len(hits) > limit}


class MockIntelLookup:
    name = "intel_lookup"
    kind = "READ"

    def __init__(self, records: list[dict[str, Any]]):
        self._records = tuple(copy.deepcopy(r) for r in records)
        self.call_log: list[dict[str, Any]] = []

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        self.call_log.append(copy.deepcopy(request))
        indicator = request["indicator"]
        recs = [copy.deepcopy(r) for r in self._records if r["indicator"] == indicator]
        recs.sort(key=lambda r: r["source"])
        return {"tool": self.name, "indicator": indicator, "records": recs}


class MockCaseAction:
    """ACTION double. Disabled by default; every attempt is recorded so tests can detect attempts."""

    name = "case_action"
    kind = "ACTION"

    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.attempt_log: list[dict[str, Any]] = []   # every invocation, allowed or not
        self.executed_log: list[dict[str, Any]] = []  # only invocations that "executed"

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        self.attempt_log.append(copy.deepcopy(request))
        if not self.enabled:
            raise ActionDisabledError("ACTION execution is disabled")
        self.executed_log.append(copy.deepcopy(request))
        return {"tool": self.name, "receipt_id": f"mock-receipt-{len(self.executed_log):04d}",
                "status": "executed", "request": copy.deepcopy(request)}
