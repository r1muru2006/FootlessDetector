"""Process graph feature tests."""

import unittest

from detection.graph import build_graph, detect_graph_behavior


def event(source, target, operation):
    return {
        "source_pid": source,
        "source_name": "loader.exe" if source == 1 else "target.exe",
        "target_pid": target,
        "target_name": "target.exe" if target == 2 else "other.exe",
        "operation": operation,
    }


class TestGraph(unittest.TestCase):
    def test_complete_edge_is_suspicious(self):
        events = [
            event(1, 2, "open_process"),
            event(1, 2, "allocate_memory"),
            event(1, 2, "write_memory"),
            event(1, 2, "create_remote_thread"),
        ]
        graph = build_graph(events)
        self.assertEqual(len(graph["edges"]), 1)
        evidence = detect_graph_behavior(events)
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["details"]["source_pid"], 1)
        self.assertEqual(evidence["details"]["target_pid"], 2)
        self.assertIn("create_remote_thread", evidence["details"]["operations"])

    def test_missing_execution_primitive_is_not_emitted(self):
        events = [
            event(1, 2, "open_process"),
            event(1, 2, "write_memory"),
        ]
        self.assertIsNone(detect_graph_behavior(events))

    def test_same_process_edge_is_ignored(self):
        events = [
            event(1, 1, "open_process"),
            event(1, 1, "write_memory"),
            event(1, 1, "create_remote_thread"),
        ]
        self.assertIsNone(detect_graph_behavior(events))


if __name__ == "__main__":
    unittest.main()
