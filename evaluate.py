#!/usr/bin/env python3
"""Evaluate the detector against a labelled scenario manifest.

Metrics: TP/FP/TN/FN, precision, recall, F1, FPR, accuracy and latency.
The endpoint is "did the detector alert", not "did the marker execute".
Files that are missing or explicitly marked not_evaluated are excluded and
listed, never counted as true negatives.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from detection.engine import analyze_path
from main import load_allowlist

ROOT = os.path.dirname(os.path.abspath(__file__))
POSITIVE_LABELS = {"malicious", "positive", "injection_attempt", "poc"}
NEGATIVE_LABELS = {"benign", "negative", "clean"}


def load_manifest(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def percentile(values: List[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(math.ceil(fraction * len(ordered))) - 1))
    return ordered[index]


def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    for item in results:
        if item.get("excluded"):
            continue
        predicted = bool(item["predicted_alert"])
        positive = item["label_positive"]
        if positive and predicted:
            tp += 1
        elif positive and not predicted:
            fn += 1
        elif not positive and predicted:
            fp += 1
        else:
            tn += 1

    def ratio(numerator: int, denominator: int) -> Optional[float]:
        if denominator == 0:
            return None
        return numerator / denominator

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = (
        None
        if precision is None or recall is None or (precision + recall) == 0
        else 2 * precision * recall / (precision + recall)
    )
    latencies = [item["latency_ms"] for item in results if not item.get("excluded")]
    return {
        "evaluated": tp + fp + tn + fn,
        "excluded": sum(1 for item in results if item.get("excluded")),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": ratio(fp, fp + tn),
        "accuracy": ratio(tp + tn, tp + fp + tn + fn),
        "latency_ms_p50": percentile(latencies, 0.50),
        "latency_ms_p95": percentile(latencies, 0.95),
        "latency_ms_max": max(latencies) if latencies else None,
    }


def run_row(
    row: Dict[str, str],
    allowlist: List[str],
    threshold: Optional[int],
    layers: Optional[List[str]] = None,
) -> Dict[str, Any]:
    scenario_id = row.get("scenario_id", "")
    label = (row.get("label") or "").strip().lower()
    path = row.get("path", "")
    full_path = path if os.path.isabs(path) else os.path.join(ROOT, path)
    result: Dict[str, Any] = {
        "scenario_id": scenario_id,
        "label": label,
        "format": row.get("format", "auto"),
        "path": path,
        "technique": row.get("technique", ""),
        "expected_marker": row.get("expected_marker", ""),
        "controlled_change": row.get("controlled_change", ""),
    }
    if label not in POSITIVE_LABELS | NEGATIVE_LABELS:
        result.update(
            {
                "excluded": True,
                "exclusion_reason": "unsupported label %r" % label,
                "label_positive": False,
                "predicted_alert": False,
                "verdict": "not_evaluated",
                "score": None,
            }
        )
        return result
    if not os.path.exists(full_path):
        result.update(
            {
                "excluded": True,
                "exclusion_reason": "missing file",
                "label_positive": label in POSITIVE_LABELS,
                "predicted_alert": False,
                "verdict": "not_evaluated",
                "score": None,
            }
        )
        return result
    start = time.perf_counter()
    document = analyze_path(
        full_path,
        allowlist=allowlist,
        threshold=threshold,
        force_format=row.get("format", "auto"),
        only_layers=layers,
    )
    latency_ms = (time.perf_counter() - start) * 1000.0
    alert = document.get("alert")
    evidence = document.get("evidence", [])
    result.update(
        {
            "excluded": False,
            "label_positive": label in POSITIVE_LABELS,
            "predicted_alert": alert is not None,
            "verdict": document.get("verdict", "clean"),
            "score": alert.get("score") if alert else sum(
                int(item.get("weight", 0)) for item in evidence
            ),
            "evidence_count": len(evidence),
            "detectors": sorted(
                {item.get("detector") for item in evidence if item.get("detector")}
            ),
            "layers": sorted(
                {item.get("area") for item in evidence if item.get("area")}
            ),
            "warnings": len(document.get("warnings", [])),
            "latency_ms": round(latency_ms, 3),
            "evidence_ids": [item.get("evidence_id") for item in evidence],
        }
    )
    return result


def group_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    groups: Dict[str, Any] = {}
    for fmt in sorted({item["format"] for item in results}):
        subset = [item for item in results if item["format"] == fmt]
        groups[fmt] = compute_metrics(subset)
    return groups


def render_markdown(document: Dict[str, Any]) -> str:
    metrics = document["metrics"]
    lines = [
        "# Detector evaluation",
        "",
        "Generated: %s UTC" % document["generated_utc"],
        "Manifest: `%s`" % document["manifest"],
        "Alert threshold: %s" % document["threshold"],
        "",
        "## Confusion matrix",
        "",
        "| TP | FP | TN | FN | Evaluated | Excluded |",
        "|---:|---:|---:|---:|---:|---:|",
        "| %d | %d | %d | %d | %d | %d |"
        % (
            metrics["tp"],
            metrics["fp"],
            metrics["tn"],
            metrics["fn"],
            metrics["evaluated"],
            metrics["excluded"],
        ),
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key in (
        "precision",
        "recall",
        "f1",
        "fpr",
        "accuracy",
        "latency_ms_p50",
        "latency_ms_p95",
        "latency_ms_max",
    ):
        value = metrics[key]
        if value is None:
            text = "n/a"
        elif key.startswith("latency"):
            text = "%.3f ms" % value
        else:
            text = "%.4f" % value
        lines.append("| %s | %s |" % (key, text))
    lines += [
        "",
        "## Per scenario",
        "",
        "| Scenario | Label | Format | Alert | Verdict | Score | Evidence | Latency |",
        "|---|---|---|---:|---|---:|---:|---:|",
    ]
    for item in document["scenarios"]:
        if item.get("excluded"):
            lines.append(
                "| %s | %s | %s | n/a | not_evaluated | - | - | - |"
                % (item["scenario_id"], item["label"], item["format"])
            )
            continue
        lines.append(
            "| %s | %s | %s | %s | %s | %s | %d | %.3f ms |"
            % (
                item["scenario_id"],
                item["label"],
                item["format"],
                "yes" if item["predicted_alert"] else "no",
                item["verdict"],
                item["score"],
                item["evidence_count"],
                item["latency_ms"],
            )
        )
    lines += ["", "## By format", ""]
    for fmt, group in document["by_format"].items():
        lines.append(
            "- **%s**: P=%s R=%s F1=%s FPR=%s (n=%d)"
            % (
                fmt,
                _fmt(group["precision"]),
                _fmt(group["recall"]),
                _fmt(group["f1"]),
                _fmt(group["fpr"]),
                group["evaluated"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", default=os.path.join(ROOT, "datasets", "manifest.csv")
    )
    parser.add_argument("--threshold", type=int, default=None)
    parser.add_argument("--allowlist", default=None)
    parser.add_argument(
        "--layers",
        default=None,
        help="comma-separated evidence areas to keep (ablation); default all",
    )
    parser.add_argument("--out", default=os.path.join(ROOT, "reports", "evaluation.json"))
    parser.add_argument(
        "--markdown",
        default=os.path.join(ROOT, "reports", "evaluation.md"),
    )
    args = parser.parse_args(argv)

    allowlist = load_allowlist(args.allowlist)
    layers = (
        [name.strip() for name in args.layers.split(",") if name.strip()]
        if args.layers
        else None
    )
    rows = load_manifest(args.manifest)
    results = [run_row(row, allowlist, args.threshold, layers) for row in rows]
    document = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "manifest": os.path.relpath(args.manifest, ROOT),
        "threshold": args.threshold,
        "layers": args.layers,
        "metrics": compute_metrics(results),
        "by_format": group_metrics(results),
        "scenarios": results,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    with open(args.markdown, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(document))
    metrics = document["metrics"]
    print(
        "evaluated=%d tp=%d fp=%d tn=%d fn=%d precision=%s recall=%s f1=%s fpr=%s"
        % (
            metrics["evaluated"],
            metrics["tp"],
            metrics["fp"],
            metrics["tn"],
            metrics["fn"],
            _fmt(metrics["precision"]),
            _fmt(metrics["recall"]),
            _fmt(metrics["f1"]),
            _fmt(metrics["fpr"]),
        )
    )
    if metrics["evaluated"] == 0:
        return 2
    return 0


def _fmt(value: Optional[float]) -> str:
    return "n/a" if value is None else "%.4f" % value


if __name__ == "__main__":
    sys.exit(main())
