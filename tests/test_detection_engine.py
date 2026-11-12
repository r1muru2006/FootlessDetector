"""End-to-end engine tests: routing, layers, correlation, warnings."""

import json
import os
import tempfile
import unittest

from detection.engine import Engine, analyze_path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TELEMETRY = os.path.join(REPO, "datasets", "telemetry")
PE = os.path.join(REPO, "datasets", "pe")


class TestEngine(unittest.TestCase):
    def test_stub_chain_alerts_with_all_layers(self):
        document = analyze_path(os.path.join(TELEMETRY, "P03_stub.jsonl"))
        self.assertEqual(document["verdict"], "alert")
        self.assertIsNotNone(document["alert"])
        layers = set(document["stats"]["layers"])
        self.assertEqual(layers, {"runtime", "access", "memory", "graph"})
        detectors = {item["detector"] for item in document["evidence"]}
        self.assertIn("injection_behavior", detectors)
        self.assertIn("process_graph", detectors)
        self.assertIn("rx_anomaly", detectors)

    def test_apc_without_remote_thread_alerts(self):
        document = analyze_path(os.path.join(TELEMETRY, "P04_apc.jsonl"))
        self.assertEqual(document["verdict"], "alert")
        detectors = {item["detector"] for item in document["evidence"]}
        self.assertNotIn("remote_thread", detectors)
        self.assertIn("injection_behavior", detectors)

    def test_quiet_telemetry_alerts_without_api_names(self):
        document = analyze_path(os.path.join(TELEMETRY, "P06_quiet_stub.jsonl"))
        self.assertEqual(document["verdict"], "alert")

    def test_benign_labels_do_not_alert(self):
        for name in (
            "B01_target_only.jsonl",
            "B02_self_dll.jsonl",
            "B03_benign_app.jsonl",
            "B04_loader_noise.jsonl",
            "B06_weak_query.jsonl",
        ):
            document = analyze_path(os.path.join(TELEMETRY, name))
            self.assertIsNone(
                document["alert"], "%s unexpectedly alerted" % name
            )

    def test_single_rwx_is_at_most_suspicious(self):
        document = analyze_path(os.path.join(TELEMETRY, "B05_jit_rwx.jsonl"))
        self.assertIsNone(document["alert"])
        self.assertEqual(document["verdict"], "suspicious")

    def test_static_pe_ablation(self):
        document = analyze_path(
            os.path.join(PE, "footless_loader.exe"),
            only_layers=["runtime", "memory", "access", "graph"],
        )
        self.assertEqual(document["evidence"], [])
        self.assertIsNone(document["alert"])
        document = analyze_path(
            os.path.join(PE, "footless_loader.exe"),
            only_layers=["static", "static_pe"],
        )
        self.assertEqual(document["verdict"], "alert")

    def test_allowlist_suppresses_runtime_evidence(self):
        document = analyze_path(
            os.path.join(TELEMETRY, "P03_stub.jsonl"),
            allowlist=["loader.exe"],
        )
        self.assertIsNone(document["alert"])
        self.assertEqual(document["evidence"], [])

    def test_malformed_json_is_warning_not_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{not-json")
            document = analyze_path(path)
            self.assertEqual(document["evidence"], [])
            self.assertEqual(len(document["warnings"]), 1)
            self.assertEqual(document["verdict"], "clean")

    def test_directory_aggregates_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("P03_stub.jsonl", "P04_apc.jsonl"):
                target = os.path.join(directory, name)
                with open(
                    os.path.join(TELEMETRY, name), "r", encoding="utf-8"
                ) as source, open(target, "w", encoding="utf-8") as out:
                    out.write(source.read())
            document = analyze_path(directory)
            self.assertEqual(document["verdict"], "alert")
            self.assertGreaterEqual(document["stats"]["event_count"], 10)


if __name__ == "__main__":
    unittest.main()
