"""Process-relation graph features.

Builds a directed source -> target graph from normalized telemetry and
emits one graph evidence item when a single edge combines a process
handle, a memory operation and an execution primitive.  A graph edge on
its own is not proof; detection/scoring.py applies the alert rules.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

DETECTOR_NAME = "process_graph"
AREA = "graph"
WEIGHT = 2

MEMORY_OPS = ("ALLOC", "WRITE", "MAP", "PROTECT")
EXEC_OPS = ("THREAD", "APC", "TAMPER")
OPEN_OPS = ("OPEN", "ACCESS")


def _op(operation: Any) -> str:
    if not isinstance(operation, str):
        return ""
    return (
        operation.upper()
        .replace(" ", "_")
        .replace("-", "_")
    )


def build_graph(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    nodes: Dict[int, Dict[str, Any]] = {}
    edges: Dict[Any, Dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        source = event.get("source_pid")
        target = event.get("target_pid")
        if not isinstance(source, int) or isinstance(source, bool):
            continue
        if not isinstance(target, int) or isinstance(target, bool):
            continue
        if source <= 0 or target <= 0 or source == target:
            continue
        nodes.setdefault(
            source,
            {
                "pid": source,
                "name": event.get("source_name", "unknown"),
                "role": "source",
            },
        )
        nodes.setdefault(
            target,
            {
                "pid": target,
                "name": event.get("target_name", "unknown"),
                "role": "target",
            },
        )
        key = (source, target)
        edge = edges.setdefault(
            key,
            {
                "source_pid": source,
                "source_name": event.get("source_name", "unknown"),
                "target_pid": target,
                "target_name": event.get("target_name", "unknown"),
                "operations": [],
                "count": 0,
            },
        )
        raw_operation = event.get("operation")
        operation = _op(raw_operation)
        if operation and operation not in {
            _op(value) for value in edge["operations"]
        }:
            edge["operations"].append(
                raw_operation if isinstance(raw_operation, str) else operation
            )
        edge["count"] += 1
    return {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
    }


def suspicious_edges(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for edge in graph.get("edges", []):
        operations = edge.get("operations", [])
        joined = " ".join(_op(value) for value in operations)
        has_memory = any(marker in joined for marker in MEMORY_OPS)
        has_exec = any(marker in joined for marker in EXEC_OPS)
        has_open = any(marker in joined for marker in OPEN_OPS)
        if has_memory and has_exec and has_open:
            result.append(edge)
    return result


def detect_graph_behavior(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    graph = build_graph(events)
    edges = suspicious_edges(graph)
    if not edges:
        return None
    edge = edges[0]
    return {
        "evidence_id": "ev-graph-%d-%d"
        % (edge["source_pid"], edge["target_pid"]),
        "area": AREA,
        "detector": DETECTOR_NAME,
        "details": {
            "behavior": "PROCESS_GRAPH_INJECTION_EDGE",
            "source_pid": edge["source_pid"],
            "source_name": edge["source_name"],
            "target_pid": edge["target_pid"],
            "target_name": edge["target_name"],
            "operations": edge["operations"],
            "edge_count": edge["count"],
            "node_count": len(graph.get("nodes", [])),
            "edge_count_total": len(graph.get("edges", [])),
            "graph": graph,
        },
        "weight": WEIGHT,
    }
