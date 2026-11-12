import unittest

from gamis.evaluation.loader import load_all
from gamis.tools.failure import FailingTool
from gamis.tools.mock_tools import MockLogSearch, ToolExecutionError, ToolTimeoutError


class FailureInjectionTests(unittest.TestCase):
    def setUp(self):
        self.inner = MockLogSearch(load_all()["logs"])

    def test_timeout_on_first_call_only(self):
        t = FailingTool(self.inner, [{"tool": "log_search", "mode": "timeout", "on_call": 1}])
        with self.assertRaises(ToolTimeoutError):
            t({"host": "web-01"})
        self.assertTrue(t({"host": "web-01"})["results"])

    def test_error_on_all_calls(self):
        t = FailingTool(self.inner, [{"tool": "log_search", "mode": "error", "on_call": "all"}])
        for _ in range(3):
            with self.assertRaises(ToolExecutionError):
                t({})
        self.assertEqual(len(t.injected), 3)

    def test_malformed_returns_non_dict(self):
        t = FailingTool(self.inner, [{"tool": "log_search", "mode": "malformed", "on_call": 1}])
        self.assertNotIsInstance(t({}), dict)

    def test_specs_for_other_tools_are_ignored(self):
        t = FailingTool(self.inner, [{"tool": "intel_lookup", "mode": "error", "on_call": "all"}])
        self.assertTrue(t({"host": "web-01"})["results"])

    def test_unknown_mode_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            FailingTool(self.inner, [{"tool": "log_search", "mode": "explode", "on_call": 1}])

    def test_inner_call_log_still_visible(self):
        t = FailingTool(self.inner, [])
        t({"host": "db-01"})
        self.assertEqual(t.call_log, [{"host": "db-01"}])
