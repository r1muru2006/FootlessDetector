"""Evaluator metric math and manifest smoke tests."""

import os
import unittest

import evaluate

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def item(label_positive, predicted, excluded=False, latency=1.0):
    return {
        "label_positive": label_positive,
        "predicted_alert": predicted,
        "excluded": excluded,
        "latency_ms": latency,
    }


class TestEvaluate(unittest.TestCase):
    def test_confusion_and_metrics(self):
        results = [
            item(True, True, latency=1.0),
            item(True, True, latency=2.0),
            item(True, False, latency=3.0),
            item(False, False, latency=4.0),
            item(False, True, latency=5.0),
            item(False, False, latency=6.0),
        ]
        metrics = evaluate.compute_metrics(results)
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]), (2, 1, 2, 1))
        self.assertAlmostEqual(metrics["precision"], 2 / 3)
        self.assertAlmostEqual(metrics["recall"], 2 / 3)
        self.assertAlmostEqual(metrics["f1"], 2 / 3)
        self.assertAlmostEqual(metrics["fpr"], 1 / 3)

    def test_excluded_rows_are_not_true_negatives(self):
        results = [item(True, False, excluded=True)]
        metrics = evaluate.compute_metrics(results)
        self.assertEqual(metrics["evaluated"], 0)
        self.assertEqual(metrics["excluded"], 1)
        self.assertIsNone(metrics["precision"])
        self.assertIsNone(metrics["recall"])

    def test_percentile(self):
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        self.assertEqual(evaluate.percentile(values, 0.5), 3.0)
        self.assertEqual(evaluate.percentile(values, 0.95), 5.0)
        self.assertIsNone(evaluate.percentile([], 0.5))

    def test_manifest_run_row(self):
        rows = evaluate.load_manifest(
            os.path.join(REPO, "datasets", "manifest.csv")
        )
        row = next(r for r in rows if r["scenario_id"] == "P03_stub")
        result = evaluate.run_row(row, [], None, None)
        self.assertFalse(result["excluded"])
        self.assertTrue(result["predicted_alert"])
        self.assertEqual(result["verdict"], "alert")

    def test_missing_file_is_excluded(self):
        row = {
            "scenario_id": "missing",
            "label": "malicious",
            "format": "pe",
            "path": "does/not/exist.exe",
        }
        result = evaluate.run_row(row, [], None, None)
        self.assertTrue(result["excluded"])
        self.assertEqual(result["verdict"], "not_evaluated")


if __name__ == "__main__":
    unittest.main()
