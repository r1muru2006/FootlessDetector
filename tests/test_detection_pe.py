"""PE static-analysis tests on the real lab binaries (no Windows needed)."""

import os
import unittest

from detection import pe

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(REPO, "datasets", "pe")
LOADER = os.path.join(SAMPLES, "footless_loader.exe")
QUIET = os.path.join(SAMPLES, "footless_loader_quiet.exe")
BENIGN = os.path.join(SAMPLES, "benign_app.exe")
TARGET = os.path.join(SAMPLES, "footless_target.exe")


@unittest.skipUnless(os.path.exists(LOADER), "lab PE samples not built")
class TestPESamples(unittest.TestCase):
    def test_loader_has_hash_loop_and_peb_access(self):
        features, evidence = pe.analyze_file(LOADER)
        self.assertTrue(features["peb_access"])
        self.assertGreaterEqual(features["hash_loop_count"], 1)
        self.assertIn("fnv1a_prime", features["hash_constants"])
        detectors = {item["detector"] for item in evidence}
        self.assertIn("hash_loop", detectors)
        self.assertIn("dynamic_resolve", detectors)
        self.assertIn("import_anomaly", detectors)
        self.assertFalse(features["sensitive_imports"])

    def test_quiet_variant_hides_api_strings(self):
        with open(QUIET, "rb") as handle:
            quiet = handle.read()
        with open(LOADER, "rb") as handle:
            normal = handle.read()
        for name in (b"NtOpenProcess", b"NtCreateThreadEx", b"NtQueueApcThread"):
            self.assertNotIn(name, quiet)
        self.assertIn(b"NtOpenProcess", normal)

    def test_benign_control_has_no_evidence(self):
        features, evidence = pe.analyze_file(BENIGN)
        self.assertFalse(features["peb_access"])
        self.assertEqual(features["hash_constants"], [])
        self.assertEqual(evidence, [])

    def test_target_is_benign_but_imports_loader(self):
        features, evidence = pe.analyze_file(TARGET)
        self.assertIn("LoadLibraryW", features["sensitive_imports"])
        self.assertFalse(features["peb_access"])
        self.assertEqual(evidence, [])

    def test_malformed_pe_raises(self):
        path = os.path.join(REPO, "tests", "fixtures", "tc_det_01_hash_loop.json")
        with self.assertRaises(pe.PEError):
            pe.parse_pe(path)


if __name__ == "__main__":
    unittest.main()
