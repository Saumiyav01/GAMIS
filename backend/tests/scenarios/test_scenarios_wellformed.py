import unittest

from gamis.evaluation.harness import build_scenarios, build_toolbox


class ScenarioWellFormedTests(unittest.TestCase):
    def test_every_scenario_builds_a_toolbox_with_action_disabled(self):
        for s in build_scenarios():
            tb = build_toolbox(s)
            self.assertFalse(tb.case_action.enabled, s.id)

    def test_scenario_ids_unique(self):
        ids = [s.id for s in build_scenarios()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_investigation_scenarios_are_answerable_from_seed_data(self):
        for s in build_scenarios():
            if s.kind != "investigation":
                continue
            tb = build_toolbox(s)
            found = {e["id"] for e in tb.log_search({"limit": 500})["results"]}
            self.assertTrue(set(s.spec["expected_evidence_event_ids"]) <= found, s.id)
