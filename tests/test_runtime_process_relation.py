"""Tests for runtime/process_relation.py (FR5, TC-DET-04/05)."""

import json
import os
import unittest

from runtime.process_relation import detect_remote_thread, track_relation

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class TestRuntimeProcessRelation(unittest.TestCase):
    def test_tc_det_04_source_target_relation(self):
        """TC-DET-04 happy path: cross-process op emits relation."""
        evidence = track_relation(load("tc_det_04_relation.json"))
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["area"], "runtime")
        self.assertEqual(evidence["detector"], "source_target")
        self.assertEqual(evidence["weight"], 1)
        self.assertEqual(evidence["details"]["source_pid"], 4210)
        self.assertEqual(evidence["details"]["source_name"], "loader.exe")
        self.assertEqual(evidence["details"]["target_pid"], 3312)
        self.assertEqual(evidence["details"]["target_name"], "target.exe")
        self.assertEqual(evidence["details"]["operation"], "write_memory")

    def test_tc_det_05_remote_thread_detected(self):
        """TC-DET-05 happy path: cross-process thread creation emits."""
        evidence = detect_remote_thread(
            load("tc_det_05_remote_thread.json")
        )
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["area"], "runtime")
        self.assertEqual(evidence["detector"], "remote_thread")
        self.assertEqual(evidence["weight"], 3)
        self.assertEqual(evidence["details"]["source_pid"], 4210)
        self.assertEqual(evidence["details"]["target_pid"], 3312)

    def test_same_process_operations_emit_nothing(self):
        """Edge: same-process thread creation is not a remote thread."""
        event = load("tc_det_05_same_process.json")
        self.assertIsNone(detect_remote_thread(event))
        self.assertIsNone(track_relation(event))

    def test_non_thread_operation_emits_no_remote_thread(self):
        """Edge: cross-process non-thread op is a relation, not remote."""
        event = load("tc_det_04_relation.json")
        self.assertIsNone(detect_remote_thread(event))
        self.assertIsNotNone(track_relation(event))

    def test_malformed_input_raises_with_context(self):
        """Edge: malformed input raises with context naming the detector."""
        with self.assertRaises(ValueError) as ctx:
            track_relation({"source_pid": 4210})
        self.assertIn("source_target", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            detect_remote_thread({"source_pid": 4210})
        self.assertIn("remote_thread", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            track_relation("not-a-dict")
        self.assertIn("source_target", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
