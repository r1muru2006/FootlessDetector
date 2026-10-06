"""Tests for runtime/api_behavior.py (FR4, FR10, FR11)."""

import json
import os
import unittest

from runtime.api_behavior import assemble_chain, normalize_api_event

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class TestRuntimeApiBehavior(unittest.TestCase):
    def test_fr4_api_chain_assembly(self):
        """FR4: open/allocate/write events normalize to GUIDE evidence."""
        chain = assemble_chain(
            [
                load("tc_api_open.json"),
                load("tc_api_allocate.json"),
                load("tc_api_write.json"),
            ]
        )
        self.assertEqual(len(chain), 3)
        for evidence in chain:
            self.assertEqual(evidence["area"], "runtime")
            self.assertEqual(evidence["detector"], "api_chain")
            self.assertEqual(evidence["weight"], 1)
            for key in (
                "timestamp",
                "source_pid",
                "source_name",
                "target_pid",
                "target_name",
                "api",
                "operation",
                "result",
            ):
                self.assertIn(key, evidence["details"])
        self.assertEqual(
            [item["details"]["operation"] for item in chain],
            ["open_process", "allocate_memory", "write_memory"],
        )

    def test_fr4_out_of_order_events_reordered(self):
        """Edge: out-of-order input is reordered by timestamp."""
        chain = assemble_chain(
            [
                load("tc_api_write.json"),
                load("tc_api_open.json"),
                load("tc_api_allocate.json"),
            ]
        )
        self.assertEqual(
            [item["details"]["timestamp"] for item in chain],
            sorted(item["details"]["timestamp"] for item in chain),
        )
        self.assertEqual(
            chain[0]["details"]["operation"], "open_process"
        )

    def test_fr4_malformed_event_raises_with_context(self):
        """Edge: malformed input raises with context, naming api_chain."""
        with self.assertRaises(ValueError) as ctx:
            normalize_api_event({"api": "NtOpenProcess"})
        self.assertIn("api_chain", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            assemble_chain([load("tc_api_open.json"), {"bogus": True}])
        self.assertIn("api_chain", str(ctx.exception))
        self.assertIn("event#1", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            normalize_api_event("not-a-dict")
        self.assertIn("api_chain", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
