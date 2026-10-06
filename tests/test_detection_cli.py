"""Tests for main.py CLI (BR1.5, FR9, FR10, C3 envelope)."""

import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(REPO, "tests", "fixtures")


def run_cli(target):
    """Run the CLI as a subprocess; return (exit_code, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "main.py"), target],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


class TestDetectionCli(unittest.TestCase):
    def test_tc_cli_stdout_json_shape(self):
        """C3 envelope: stdout is one JSON doc with evidence/warnings/alert/verdict."""
        code, stdout, _ = run_cli(os.path.join(FIXTURES, "tc_det_01_hash_loop.json"))
        self.assertEqual(code, 0)
        document = json.loads(stdout)
        for key in ("evidence", "warnings", "alert", "verdict"):
            self.assertIn(key, document)
        self.assertEqual(len(document["evidence"]), 1)
        self.assertEqual(document["warnings"], [])
        # Single indicator alone never alerts.
        self.assertIsNone(document["alert"])
        self.assertNotEqual(document["verdict"], "alert")

    def test_tc_cli_correlated_alert(self):
        """Correlated batch reaches the alert tier with chained evidence."""
        code, stdout, _ = run_cli(
            os.path.join(FIXTURES, "skeleton_correlated.json")
        )
        self.assertEqual(code, 0)
        document = json.loads(stdout)
        self.assertEqual(document["verdict"], "alert")
        self.assertIsNotNone(document["alert"])
        self.assertEqual(document["alert"]["score"], 6)
        self.assertEqual(len(document["alert"]["chains"]), 4)

    def test_tc_cli_malformed_input_warnings(self):
        """FR10: malformed input yields warnings, stdout stays valid, exit 0."""
        code, stdout, _ = run_cli(
            os.path.join(FIXTURES, "tc_det_01_malformed.json")
        )
        self.assertEqual(code, 0)
        document = json.loads(stdout)
        self.assertEqual(document["evidence"], [])
        self.assertEqual(len(document["warnings"]), 1)
        self.assertIsNone(document["alert"])
        self.assertEqual(document["verdict"], "clean")

    def test_tc_cli_exit_codes(self):
        """BR1.5: missing target exits 2 with the reason on stderr."""
        code, _, stderr = run_cli(os.path.join(FIXTURES, "does-not-exist.json"))
        self.assertEqual(code, 2)
        self.assertTrue(stderr.strip())
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, "main.py")],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
