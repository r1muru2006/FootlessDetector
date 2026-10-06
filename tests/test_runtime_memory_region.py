"""Tests for runtime/memory_region.py (FR6, TC-DET-06/07)."""

import json
import os
import unittest

from runtime.memory_region import detect_rwx_region, detect_rx_anomaly

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class TestRuntimeMemoryRegion(unittest.TestCase):
    def test_tc_det_06_rwx_region_detected(self):
        """TC-DET-06 happy path: RWX region emits weight-3 evidence."""
        evidence = detect_rwx_region(load("tc_det_06_rwx.json"))
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["area"], "memory")
        self.assertEqual(evidence["detector"], "rwx")
        self.assertEqual(evidence["weight"], 3)
        self.assertEqual(evidence["details"]["memory_protection"], "RWX")
        self.assertEqual(evidence["details"]["base_address"], "0x200000")

    def test_tc_det_06_non_rwx_emits_nothing(self):
        """Edge: RX region is not an RWX finding."""
        self.assertIsNone(
            detect_rwx_region(load("tc_det_07_rx_region.json"))
        )

    def test_tc_det_07_rx_anomaly_with_prior_write(self):
        """TC-DET-07 happy path: RX plus foreign write emits anomaly."""
        evidence = detect_rx_anomaly(
            load("tc_det_07_rx_region.json"),
            [load("tc_det_07_prior_write.json")],
        )
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["area"], "memory")
        self.assertEqual(evidence["detector"], "rx_anomaly")
        self.assertEqual(evidence["weight"], 2)
        self.assertEqual(evidence["details"]["writer_pid"], 4210)
        self.assertEqual(
            evidence["details"]["writer_operation"], "write_memory"
        )

    def test_tc_det_07_bare_rx_emits_nothing(self):
        """Edge: bare RX with no prior write context yields nothing."""
        self.assertIsNone(detect_rx_anomaly(load("tc_det_07_bare_rx.json"), []))
        self.assertIsNone(
            detect_rx_anomaly(
                load("tc_det_07_rx_region.json"),
                [load("tc_det_05_same_process.json")],
            )
        )

    def test_malformed_input_raises_with_context(self):
        """Edge: malformed input raises with context naming the detector."""
        with self.assertRaises(ValueError) as ctx:
            detect_rwx_region({"size": 4096})
        self.assertIn("rwx", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            detect_rx_anomaly(load("tc_det_07_rx_region.json"), "nope")
        self.assertIn("rx_anomaly", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            detect_rwx_region("not-a-dict")
        self.assertIn("rwx", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
