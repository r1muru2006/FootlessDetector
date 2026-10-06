"""Tests for runtime/access_rights.py (FR7, TC-DET-08)."""

import json
import os
import unittest

from runtime.access_rights import detect_access_event

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class TestRuntimeAccessRights(unittest.TestCase):
    def test_tc_det_08_access_event_detected(self):
        """TC-DET-08 happy path: qualifying rights emit weight-2 evidence."""
        evidence = detect_access_event(load("tc_det_08_access.json"))
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["area"], "access")
        self.assertEqual(evidence["detector"], "access")
        self.assertEqual(evidence["weight"], 2)
        self.assertEqual(evidence["details"]["source_pid"], 4210)
        self.assertEqual(evidence["details"]["target_pid"], 3312)
        self.assertIn(
            "PROCESS_VM_WRITE", evidence["details"]["matched_rights"]
        )
        self.assertIn(
            "PROCESS_VM_OPERATION", evidence["details"]["matched_rights"]
        )

    def test_tc_det_08_short_forms_canonicalized(self):
        """Edge: short right spellings map to canonical qualifying rights."""
        event = load("tc_det_08_access.json")
        event["requested_access"] = ["VM_WRITE", "CREATE_THREAD"]
        evidence = detect_access_event(event)
        self.assertIsNotNone(evidence)
        self.assertIn(
            "PROCESS_VM_WRITE", evidence["details"]["matched_rights"]
        )
        self.assertIn(
            "PROCESS_CREATE_THREAD", evidence["details"]["matched_rights"]
        )

    def test_tc_det_08_weak_rights_emit_nothing(self):
        """Edge: weak-only rights yield no access event."""
        self.assertIsNone(
            detect_access_event(load("tc_det_08_weak_rights.json"))
        )

    def test_malformed_input_raises_with_context(self):
        """Edge: malformed input raises with context naming access."""
        with self.assertRaises(ValueError) as ctx:
            detect_access_event({"source_pid": 4210})
        self.assertIn("access", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            detect_access_event(
                {
                    "source_pid": 4210,
                    "target_pid": 3312,
                    "requested_access": [],
                }
            )
        self.assertIn("access", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            detect_access_event("not-a-dict")
        self.assertIn("access", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
