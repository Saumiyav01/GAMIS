"""Failure injection for tool doubles (P0). Deterministic: driven by call counts only."""
from __future__ import annotations

from typing import Any, Callable

MODES = ("timeout", "error", "malformed")


class FailingTool:
    """Wraps a tool double and injects failures according to a list of failure specs.

    A spec is {"tool": str, "mode": "timeout"|"error"|"malformed", "on_call": int | "all"}.
    """

    def __init__(self, inner: Callable[[dict[str, Any]], Any], failures: list[dict[str, Any]]):
        self._inner = inner
        self.name = inner.name
        self.kind = inner.kind
        self._specs = [f for f in failures if f["tool"] == inner.name]
        for s in self._specs:
            if s["mode"] not in MODES:
                raise ValueError(f"unknown failure mode: {s['mode']}")
        self.calls = 0
        self.injected: list[dict[str, Any]] = []

    def __getattr__(self, item: str) -> Any:  # expose inner call logs
        return getattr(self._inner, item)

    def __call__(self, request: dict[str, Any]) -> Any:
        self.calls += 1
        for spec in self._specs:
            if spec["on_call"] == "all" or spec["on_call"] == self.calls:
                self.injected.append({"call": self.calls, "mode": spec["mode"]})
                if spec["mode"] == "timeout":
                    from gamis.tools.mock_tools import ToolTimeoutError
                    raise ToolTimeoutError(f"{self.name} timed out (injected)")
                if spec["mode"] == "error":
                    from gamis.tools.mock_tools import ToolExecutionError
                    raise ToolExecutionError(f"{self.name} failed (injected)")
                return "<<malformed: not a result object>>"
        return self._inner(request)
