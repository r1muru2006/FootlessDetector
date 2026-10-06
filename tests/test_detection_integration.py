"""Integration tests for the full runtime chain (FR7.1, FR8).

Drives the loader behavior chain open -> allocate -> write ->
executable-region through the real runtime detectors into the
correlation engine: correlated evidence alerts, a single indicator
never does.
"""

import json
import os
import unittest

from detection.evidence import validate_evidence
from detection.scoring import (
    correlate,
    detect_injection_behavior,
    weight_for,
)
from runtime.access_rights import detect_access_event
from runtime.api_behavior import normalize_api_event
from runtime.memory_region import detect_rwx_region
from runtime.process_relation import track_relation

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


def loader_chain():
    """Build the loader chain evidence in behavior order."""
    chain = [
        detect_access_event(load("tc_det_08_access.json")),
        normalize_api_event(load("tc_api_open.json")),
        normalize_api_event(load("tc_api_write.json")),
        track_relation(load("tc_det_04_relation.json")),
        detect_rwx_region(load("tc_det_06_rwx.json")),
    ]
    assert all(item is not None for item in chain)
    return chain


class TestDetectionIntegration(unittest.TestCase):
    def test_runtime_weights_cover_all_detectors(self):
        """FR8: every runtime detector carries its affirmed weight."""
        self.assertEqual(weight_for("api_chain"), 1)
        self.assertEqual(weight_for("source_target"), 1)
        self.assertEqual(weight_for("remote_thread"), 3)
        self.assertEqual(weight_for("rwx"), 3)
        self.assertEqual(weight_for("rx_anomaly"), 2)
        self.assertEqual(weight_for("access"), 2)

    def test_integration_chain_correlates_to_alert(self):
        """Full loader chain scores to the alert tier with chained ids."""
        chain = loader_chain()
        for item in chain:
            validate_evidence(item)
        alert, verdict = correlate(chain)
        self.assertEqual(verdict, "alert")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["score"], 8)
        self.assertEqual(len(alert["chains"]), 5)
        areas = {item["area"] for item in chain}
        self.assertGreaterEqual(len(areas), 2)

    def test_integration_chain_emits_injection_behavior(self):
        """FR7.1: open+memory+executable on one pair chains in order."""
        injection = detect_injection_behavior(loader_chain())
        self.assertIsNotNone(injection)
        self.assertEqual(injection["detector"], "injection_behavior")
        self.assertEqual(
            injection["details"]["behavior"], "PROCESS_INJECTION_BEHAVIOR"
        )
        self.assertEqual(injection["details"]["source_pid"], 4210)
        self.assertEqual(injection["details"]["target_pid"], 3312)
        self.assertEqual(len(injection["details"]["stages"]), 3)
        validate_evidence(injection)

    def test_integration_single_indicator_never_alerts(self):
        """Guard: one RWX region alone yields no alert and no behavior."""
        solo = [detect_rwx_region(load("tc_det_06_rwx.json"))]
        alert, verdict = correlate(solo)
        self.assertIsNone(alert)
        self.assertNotEqual(verdict, "alert")
        self.assertIsNone(detect_injection_behavior(solo))

    def test_integration_out_of_order_chain_emits_nothing(self):
        """Edge: executable-before-open order chains to no behavior."""
        chain = list(reversed(loader_chain()))
        self.assertIsNone(detect_injection_behavior(chain))


if __name__ == "__main__":
    unittest.main()
