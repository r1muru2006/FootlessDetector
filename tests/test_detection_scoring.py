"""Tests for detection/evidence.py + detection/scoring.py (BR1.2-1.4, BR1.6)."""

import unittest

from detection.evidence import (
    collect_evidence,
    make_evidence,
    validate_evidence,
)
from detection.scoring import correlate, score_evidence
from static.hash_loop import detect_hash_loop


def stub(detector, area, weight, evidence_id):
    return make_evidence(area, detector, {"note": detector}, weight, evidence_id)


class TestDetectionScoring(unittest.TestCase):
    def test_evidence_shape_requires_keys(self):
        """BR1.2: missing required keys raise naming the key."""
        with self.assertRaises(ValueError) as ctx:
            validate_evidence({"area": "static"})
        self.assertIn("detector", str(ctx.exception))

    def test_threshold_tiers(self):
        """BR1.3: 6+ across 2 areas alerts; 3-5 suspicious; below 3 clean."""
        alert_items = [
            stub("hash_loop", "static", 2, "ev-a"),
            stub("hash_loop", "static", 2, "ev-b"),
            stub("api_chain", "runtime", 1, "ev-c"),
            stub("source_target", "runtime", 1, "ev-d"),
        ]
        self.assertEqual(score_evidence(alert_items)[2], "alert")
        mid = [
            stub("hash_loop", "static", 2, "ev-e"),
            stub("api_chain", "runtime", 1, "ev-f"),
        ]
        self.assertEqual(score_evidence(mid)[2], "suspicious")
        low = [stub("api_chain", "runtime", 1, "ev-g")]
        _, verdict = correlate(low)
        self.assertEqual(verdict, "clean")

    def test_single_indicator_guard_blocks_alert(self):
        """BR1.4: a single indicator alone never produces an alert (merge gate)."""
        heavy = [stub("hash_loop", "static", 3, "ev-heavy")]
        alert, verdict = correlate(heavy)
        self.assertIsNone(alert)
        self.assertNotEqual(verdict, "alert")

    def test_single_hash_loop_evidence_is_at_most_suspicious(self):
        """Skeleton slice: one hash_loop evidence (weight 2) stays below alert."""
        evidence = [stub("hash_loop", "static", 2, "ev-solo")]
        alert, verdict = correlate(evidence)
        self.assertIsNone(alert)
        self.assertEqual(verdict, "clean")

    def test_correlated_alert_carries_chains(self):
        """Alert verdict chains the evidence ids with score attached."""
        items = [
            stub("hash_loop", "static", 2, "ev-1"),
            stub("hash_loop", "static", 2, "ev-2"),
            stub("api_chain", "runtime", 1, "ev-3"),
            stub("source_target", "runtime", 1, "ev-4"),
        ]
        alert, verdict = correlate(items)
        self.assertEqual(verdict, "alert")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["score"], 6)
        self.assertEqual(len(alert["chains"]), 4)

    def test_warning_collection_continues_run(self):
        """BR1.6: malformed single input yields a warning; the run continues."""
        items = [
            {
                "function": "0x1",
                "loop": "0x2",
                "traverses_bytes": True,
                "operations": ["XOR", "ROL"],
                "comparison_constants": 1,
            },
            {"function": "0x3"},
            "not-a-dict",
        ]
        evidence, warnings = collect_evidence(items, "hash_loop", detect_hash_loop)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(len(warnings), 2)
        for warning in warnings:
            self.assertIn("input", warning)
            self.assertIn("detector", warning)
            self.assertIn("reason", warning)


if __name__ == "__main__":
    unittest.main()
