import json
import os
import tempfile
import unittest

from gamis.evaluation.doubles import NoopSystem
from gamis.evaluation.harness import evaluate, write_report


class P0IntegrationTests(unittest.TestCase):
    def test_full_harness_run_writes_valid_report(self):
        report = evaluate(NoopSystem())
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            write_report(report, path, "test")
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
        self.assertEqual(loaded["system"], "noop-harness-selftest")
        self.assertEqual(sum(v["total"] for v in loaded["summary"].values()), 14)
