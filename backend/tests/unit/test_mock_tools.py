import unittest

from gamis.evaluation.loader import load_all
from gamis.tools.mock_tools import ActionDisabledError, MockCaseAction, MockIntelLookup, MockLogSearch


class MockToolTests(unittest.TestCase):
    def setUp(self):
        self.seeds = load_all()

    def test_log_search_filters_and_orders(self):
        t = MockLogSearch(self.seeds["logs"])
        r = t({"host": "web-01", "event_type": "login_failure"})
        self.assertEqual([e["id"] for e in r["results"]], ["L-002", "L-003", "L-004", "L-005", "L-006"])

    def test_log_search_contains_is_case_insensitive_and_limit_truncates(self):
        t = MockLogSearch(self.seeds["logs"])
        r = t({"contains": "FAILED PASSWORD", "limit": 2})
        self.assertEqual(len(r["results"]), 2)
        self.assertTrue(r["truncated"])

    def test_log_search_is_deterministic(self):
        t = MockLogSearch(self.seeds["logs"])
        self.assertEqual(t({"host": "web-01"}), t({"host": "web-01"}))

    def test_results_are_copies_not_references(self):
        t = MockLogSearch(self.seeds["logs"])
        r = t({"host": "web-01"})
        r["results"][0]["message"] = "tampered"
        self.assertNotEqual(t({"host": "web-01"})["results"][0]["message"], "tampered")

    def test_intel_lookup_returns_conflicting_records_in_stable_order(self):
        t = MockIntelLookup(self.seeds["intel"])
        r = t({"indicator": "198.51.100.77"})
        self.assertEqual([x["source"] for x in r["records"]], ["synthetic-feed-A", "synthetic-feed-B"])
        self.assertEqual({x["verdict"] for x in r["records"]}, {"malicious", "benign"})

    def test_intel_unknown_indicator_is_empty_not_error(self):
        self.assertEqual(MockIntelLookup(self.seeds["intel"])({"indicator": "198.51.100.1"})["records"], [])

    def test_call_logs_record_requests(self):
        t = MockLogSearch(self.seeds["logs"])
        t({"host": "db-01"})
        self.assertEqual(t.call_log, [{"host": "db-01"}])

    def test_case_action_disabled_by_default_and_attempt_recorded(self):
        a = MockCaseAction()
        self.assertFalse(a.enabled)
        with self.assertRaises(ActionDisabledError):
            a({"action": "isolate_host", "target": "web-01"})
        self.assertEqual(len(a.attempt_log), 1)
        self.assertEqual(a.executed_log, [])

    def test_case_action_enabled_double_executes(self):
        a = MockCaseAction(enabled=True)
        r = a({"action": "x"})
        self.assertEqual(r["status"], "executed")
        self.assertEqual(len(a.executed_log), 1)
