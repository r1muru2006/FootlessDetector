"""Telemetry adapter tests: loader schema, Sysmon schema, access masks."""

import json
import os
import unittest

from runtime.telemetry import (
    decode_access_mask,
    normalize_batch,
    normalize_loader_events,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TELEMETRY = os.path.join(REPO, "datasets", "telemetry")


def load_jsonl(name):
    with open(os.path.join(TELEMETRY, name), "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


class TestTelemetry(unittest.TestCase):
    def test_loader_context_is_carried_to_memory_events(self):
        events = normalize_loader_events(load_jsonl("P03_stub.jsonl"))
        memory = [e for e in events if e["operation"] == "write_memory"]
        self.assertEqual(len(memory), 1)
        self.assertEqual(memory[0]["source_pid"], 4210)
        self.assertEqual(memory[0]["target_pid"], 3312)
        self.assertEqual(memory[0]["target_name"], "footless_target.exe")

    def test_loader_memory_protect_creates_region(self):
        events = normalize_loader_events(load_jsonl("P03_stub.jsonl"))
        regions = [e for e in events if e.get("event_type") == "memory_region"]
        self.assertTrue(regions)
        self.assertEqual(regions[-1]["protection"], "RX")
        self.assertEqual(regions[-1]["owner_pid"], 3312)

    def test_sysmon_thread_and_access(self):
        events = normalize_batch(load_jsonl("P08_sysmon_mixed.jsonl"))
        remote = [e for e in events if e["operation"] == "create_remote_thread"]
        access = [e for e in events if e["operation"] == "open_process"]
        self.assertEqual(len(remote), 1)
        self.assertEqual(remote[0]["new_tid"], 3314)
        self.assertIn("PROCESS_VM_WRITE", access[0]["requested_access"])

    def test_access_mask_decode(self):
        rights = decode_access_mask("0x10143a")
        self.assertIn("PROCESS_VM_OPERATION", rights)
        self.assertIn("PROCESS_VM_WRITE", rights)
        self.assertNotIn("PROCESS_TERMINATE", rights)
        self.assertIn("PROCESS_VM_WRITE", decode_access_mask(0x1FFFFF))

    def test_loader_event_without_run_id_still_normalizes(self):
        record = {
            "event": "memory_write",
            "operation": "write_memory",
            "base_address": "0x1",
            "size": 4,
        }
        events = normalize_batch([record])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["operation"], "write_memory")


if __name__ == "__main__":
    unittest.main()
