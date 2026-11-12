import copy
import json
import unittest

from gamis.evaluation.loader import SEEDS_DIR, load_all, validate


class SeedTests(unittest.TestCase):
    def test_seeds_load_and_validate(self):
        seeds = load_all()
        self.assertEqual(len(seeds["logs"]), 14)
        self.assertGreaterEqual(len(seeds["attacks"]), 7)
        self.assertGreaterEqual(len(seeds["failures"]), 4)

    def test_only_documentation_ip_ranges_used(self):
        seeds = load_all()
        for e in seeds["logs"]:
            self.assertTrue(e["src_ip"].startswith(("198.51.100.", "203.0.113.")), e["src_ip"])
        for r in seeds["intel"]:
            self.assertTrue(r["indicator"].startswith(("198.51.100.", "203.0.113.")))

    def test_validation_rejects_dangling_reference(self):
        seeds = copy.deepcopy(load_all())
        seeds["attacks"][0]["investigation_id"] = "INV-NOPE"
        with self.assertRaises(ValueError):
            validate(seeds)

    def test_validation_rejects_expected_decoy_overlap(self):
        seeds = copy.deepcopy(load_all())
        seeds["investigations"][0]["decoy_event_ids"].append("L-002")
        with self.assertRaises(ValueError):
            validate(seeds)

    def test_seed_files_are_stable_json(self):
        for p in SEEDS_DIR.glob("*.json"):
            text = p.read_text(encoding="utf-8")
            self.assertEqual(text, json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n")
