"""Tests for static/import_anomaly.py (TC-DET-03, FR3, FR10, FR11)."""

import json
import os
import unittest

from static.import_anomaly import detect_import_anomaly

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class TestStaticImportAnomaly(unittest.TestCase):
    def test_tc_det_03_import_anomaly_detected(self):
        """TC-DET-03 happy path: small IAT + many runtime APIs emits weight-1 evidence."""
        evidence = detect_import_anomaly(load("tc_det_03_anomaly.json"))
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["area"], "static")
        self.assertEqual(evidence["detector"], "import_anomaly")
        self.assertEqual(evidence["weight"], 1)
        self.assertLessEqual(evidence["details"]["import_count"], 5)
        self.assertGreaterEqual(evidence["details"]["runtime_api_count"], 10)

    def test_tc_det_03_large_iat_emits_nothing(self):
        """Edge: a large IAT emits nothing even with many runtime APIs."""
        self.assertIsNone(detect_import_anomaly(load("tc_det_03_large_iat.json")))

    def test_tc_det_03_low_runtime_count_emits_nothing(self):
        """Edge: a small IAT with few runtime APIs emits nothing."""
        self.assertIsNone(detect_import_anomaly(load("tc_det_03_low_runtime.json")))

    def test_tc_det_03_malformed_input_raises_with_context(self):
        """Edge: malformed input raises with context; engine turns it into a warning."""
        with self.assertRaises(ValueError) as ctx:
            detect_import_anomaly({"imports": "not-a-list", "runtime_api_count": 17})
        self.assertIn("import_anomaly", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
