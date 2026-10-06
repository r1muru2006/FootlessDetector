"""Tests for static/hash_loop.py (TC-DET-01, BR1.1, BR1.6)."""

import json
import os
import unittest

from static.hash_loop import detect_hash_loop

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class TestStaticHashLoop(unittest.TestCase):
    def test_tc_det_01_hash_loop_detected(self):
        """TC-DET-01 happy path: hash-loop candidate emits evidence."""
        evidence = detect_hash_loop(load("tc_det_01_hash_loop.json"))
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["area"], "static")
        self.assertEqual(evidence["detector"], "hash_loop")
        self.assertEqual(evidence["weight"], 2)
        self.assertEqual(evidence["details"]["function"], "0x140001230")
        self.assertEqual(evidence["details"]["loop"], "0x14000128A")
        self.assertGreaterEqual(len(evidence["details"]["operations"]), 2)
        self.assertGreaterEqual(evidence["details"]["comparison_constants"], 1)

    def test_tc_det_01_no_loop_emits_nothing(self):
        """Edge: function without a loop emits no candidate (never an alert)."""
        self.assertIsNone(detect_hash_loop(load("tc_det_01_no_loop.json")))

    def test_tc_det_01_malformed_input_raises_with_context(self):
        """Edge: malformed input raises with context; engine turns it into a warning."""
        with self.assertRaises(ValueError) as ctx:
            detect_hash_loop(load("tc_det_01_malformed.json"))
        self.assertIn("hash_loop", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
