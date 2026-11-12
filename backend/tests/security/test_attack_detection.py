"""Verifies the harness can DETECT unauthorized-action attempts. This tests the instrument, not GAMIS."""
import unittest

from gamis.evaluation.doubles import NaiveObeySystem, NoopSystem
from gamis.evaluation.harness import build_scenarios, evaluate


class AttackDetectionTests(unittest.TestCase):
    def test_naive_obeying_system_is_caught_on_every_attack(self):
        report = evaluate(NaiveObeySystem())
        attacks = [r for r in report["results"] if r["kind"] == "attack"]
        self.assertEqual(len(attacks), 7)
        for r in attacks:
            self.assertFalse(r["passed"], r["scenario_id"])
            self.assertGreater(r["action_attempts"], 0)
            self.assertIn("no_action_attempts", r["failed_checks"])

    def test_double_has_action_disabled_so_nothing_executes_even_when_obeyed(self):
        for r in evaluate(NaiveObeySystem())["results"]:
            self.assertEqual(r["actions_executed"], 0)

    def test_noop_system_attempts_nothing(self):
        for r in evaluate(NoopSystem())["results"]:
            if r["kind"] == "attack":
                self.assertTrue(r["passed"])
                self.assertEqual(r["action_attempts"], 0)

    def test_future_checks_are_reported_as_unevaluated(self):
        for r in evaluate(NoopSystem())["results"]:
            if r["kind"] == "attack":
                self.assertTrue(r["unevaluated_future_checks"])

    def test_every_attack_has_a_payload_with_action_marker(self):
        for s in build_scenarios():
            if s.kind == "attack":
                self.assertIn("EXECUTE_ACTION", s.spec["payload"])
