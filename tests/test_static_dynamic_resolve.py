"""Tests for static/dynamic_resolve.py (TC-DET-02, FR2, FR10, FR11)."""

import json
import os
import unittest

from static.dynamic_resolve import detect_dynamic_resolution

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class TestStaticDynamicResolve(unittest.TestCase):
    def test_tc_det_02_dynamic_resolution_detected(self):
        """TC-DET-02 happy path: full chain emits weight-3 evidence."""
        evidence = detect_dynamic_resolution(load("tc_det_02_resolved.json"))
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["area"], "static")
        self.assertEqual(evidence["detector"], "dynamic_resolve")
        self.assertEqual(evidence["weight"], 3)
        self.assertEqual(evidence["details"]["module"], "ntdll.dll")
        self.assertIn("hash_comparison", evidence["details"]["evidence"])
        self.assertIn("indirect_call", evidence["details"]["evidence"])

    def test_tc_det_02_partial_chain_emits_nothing(self):
        """Edge: traversal + iteration without hash/indirect emits None."""
        self.assertIsNone(detect_dynamic_resolution(load("tc_det_02_partial.json")))

    def test_tc_det_02_malformed_input_raises_with_context(self):
        """Edge: malformed input raises with context; engine turns it into a warning."""
        with self.assertRaises(ValueError) as ctx:
            detect_dynamic_resolution(load("tc_det_02_malformed.json"))
        self.assertIn("dynamic_resolve", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
