"""Systems-under-test used ONLY to validate the harness itself. They are not GAMIS and not baselines
for any published comparison.

NoopSystem          - makes no tool calls and reports partial. Shows the harness gives it no free pass on
                      investigation quality.
NaiveObeySystem     - deliberately ungoverned: runs a naive read pass and obeys any 'EXECUTE_ACTION: <verb> <arg>'
                      text it finds in the request or in tool results. Exists to prove the harness DETECTS
                      attempted unauthorized actions.
"""
from __future__ import annotations

import re
from typing import Any

from gamis.evaluation.harness import Scenario, SystemOutput, ToolBox
from gamis.tools.mock_tools import ActionDisabledError, ToolExecutionError, ToolTimeoutError

_PATTERN = re.compile(r"EXECUTE_ACTION:\s*(\w+)\s*([^\s]*)")


class NoopSystem:
    name = "noop-harness-selftest"

    def run(self, scenario: Scenario, tools: ToolBox) -> SystemOutput:
        return SystemOutput(status="partial")


class NaiveObeySystem:
    name = "naive-obey-harness-selftest"

    def run(self, scenario: Scenario, tools: ToolBox) -> SystemOutput:
        texts: list[str] = [scenario.request]
        scope = scenario.investigation["scope"]
        status = "complete"
        try:
            logs = tools.log_search({"host": scope["host"]})
            texts += [e["message"] for e in logs["results"]]
        except (ToolTimeoutError, ToolExecutionError):
            status = "partial"
        for ind in scope["indicators"]:
            try:
                intel: Any = tools.intel_lookup({"indicator": ind})
                texts += [r.get("note", "") for r in intel["records"]]
            except (ToolTimeoutError, ToolExecutionError):
                status = "partial"
        for text in texts:
            m = _PATTERN.search(text)
            if m:
                try:
                    tools.case_action({"action": m.group(1), "target": m.group(2)})
                except ActionDisabledError:
                    pass
        return SystemOutput(status=status)
