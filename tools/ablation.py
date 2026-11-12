#!/usr/bin/env python3
"""Ablation: measure how each evidence layer contributes to detection.

Runs the same manifest with different layer subsets so the report can show
the static/runtime trade-off instead of only the headline F1.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import evaluate

CONFIGURATIONS = (
    ("full", None),
    ("static-only", ["static", "static_pe"]),
    ("runtime-only", ["runtime", "memory", "access", "graph"]),
    ("no-graph", ["static", "static_pe", "runtime", "memory", "access"]),
    ("no-static-pe", ["static", "runtime", "memory", "access", "graph"]),
)


def run_configuration(
    rows: List[Dict[str, str]],
    allowlist: List[str],
    threshold,
    layers,
) -> Dict[str, Any]:
    results = [
        evaluate.run_row(row, allowlist, threshold, layers) for row in rows
    ]
    return {
        "metrics": evaluate.compute_metrics(results),
        "by_format": evaluate.group_metrics(results),
        "results": results,
    }


def render(document: Dict[str, Any]) -> str:
    lines = [
        "# Layer ablation",
        "",
        "Generated: %s UTC" % document["generated_utc"],
        "Manifest: `%s`" % document["manifest"],
        "",
        "| Configuration | TP | FP | TN | FN | Precision | Recall | F1 | FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, item in document["configurations"].items():
        m = item["metrics"]
        lines.append(
            "| %s | %d | %d | %d | %d | %s | %s | %s | %s |"
            % (
                name,
                m["tp"],
                m["fp"],
                m["tn"],
                m["fn"],
                evaluate._fmt(m["precision"]),
                evaluate._fmt(m["recall"]),
                evaluate._fmt(m["f1"]),
                evaluate._fmt(m["fpr"]),
            )
        )
    lines += [
        "",
        "## Per format",
        "",
        "| Configuration | Format | TP | FP | TN | FN | Precision | Recall |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, item in document["configurations"].items():
        for fmt, m in item["by_format"].items():
            lines.append(
                "| %s | %s | %d | %d | %d | %d | %s | %s |"
                % (
                    name,
                    fmt,
                    m["tp"],
                    m["fp"],
                    m["tn"],
                    m["fn"],
                    evaluate._fmt(m["precision"]),
                    evaluate._fmt(m["recall"]),
                )
            )
    lines.append("")
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    manifest = (
        argv[argv.index("--manifest") + 1]
        if "--manifest" in argv
        else os.path.join(ROOT, "datasets", "manifest.csv")
    )
    threshold = None
    allowlist: List[str] = []
    rows = evaluate.load_manifest(manifest)
    configurations: Dict[str, Any] = {}
    for name, layers in CONFIGURATIONS:
        configurations[name] = run_configuration(rows, allowlist, threshold, layers)
    document = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "manifest": os.path.relpath(manifest, ROOT),
        "configurations": configurations,
    }
    out_json = os.path.join(ROOT, "reports", "ablation.json")
    out_md = os.path.join(ROOT, "reports", "ablation.md")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    with open(out_md, "w", encoding="utf-8") as handle:
        handle.write(render(document))
    for name, item in configurations.items():
        m = item["metrics"]
        print(
            "%-14s P=%s R=%s F1=%s FPR=%s"
            % (
                name,
                evaluate._fmt(m["precision"]),
                evaluate._fmt(m["recall"]),
                evaluate._fmt(m["f1"]),
                evaluate._fmt(m["fpr"]),
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
