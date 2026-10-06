"""Skeleton CLI (BR1.5, FR9, C3 envelope).

Usage: python main.py <target>  (target: JSON file or directory of JSON files)

Prints one JSON document (evidence, warnings, alert or null, verdict tier)
to stdout. Exit 0 on a clean run regardless of verdict, 2 on bad
target/usage, 1 on unexpected internal failure. Thin orchestration only:
no detection or correlation logic lives here.
"""

import json
import os
import sys
from typing import Any, Dict, List, Tuple

from detection.evidence import make_warning, validate_evidence
from detection.scoring import correlate
from static.hash_loop import DETECTOR_NAME, detect_hash_loop

EVIDENCE_KEYS = ("area", "detector", "details", "weight")


def looks_like_evidence(item: Any) -> bool:
    """True when a dict already carries the evidence-shape keys."""
    return isinstance(item, dict) and all(key in item for key in EVIDENCE_KEYS)


def process_item(item: Any, label: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Route one parsed item to evidence validation or hash-loop detection."""
    try:
        if looks_like_evidence(item):
            return [validate_evidence(item)], []
        result = detect_hash_loop(item)
        if result is None:
            return [], []
        return [validate_evidence(result)], []
    except Exception as exc:
        return [], [make_warning(label, DETECTOR_NAME, str(exc))]


def process_payload(payload: Any, label: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Handle one parsed JSON payload (dict, evidence batch, or list)."""
    evidence: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    if isinstance(payload, dict) and isinstance(payload.get("evidence"), list):
        items = payload["evidence"]
    elif isinstance(payload, list):
        items = payload
    else:
        items = [payload]
    for index, item in enumerate(items):
        found, problems = process_item(item, "%s#%d" % (label, index))
        evidence.extend(found)
        warnings.extend(problems)
    return evidence, warnings


def run_target(target: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Collect evidence + warnings for one file or directory of JSON files."""
    evidence: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    if os.path.isdir(target):
        names = sorted(
            name for name in os.listdir(target) if name.endswith(".json")
        )
        if not names:
            raise FileNotFoundError("no JSON fixtures in directory: %s" % target)
        for name in names:
            path = os.path.join(target, name)
            found, problems = run_file(path)
            evidence.extend(found)
            warnings.extend(problems)
        return evidence, warnings
    return run_file(target)


def run_file(path: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parse one JSON file into evidence + warnings (malformed -> warning)."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        return [], [make_warning(path, DETECTOR_NAME, str(exc))]
    return process_payload(payload, path)


def build_document(
    evidence: List[Dict[str, Any]], warnings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Assemble the C3 CLI envelope from scored evidence."""
    alert, verdict = correlate(evidence)
    return {
        "evidence": evidence,
        "warnings": warnings,
        "alert": alert,
        "verdict": verdict,
    }


def main(argv: List[str]) -> int:
    """CLI entry point; returns the process exit code."""
    if len(argv) != 2 or not argv[1]:
        print("usage: python main.py <target>", file=sys.stderr)
        return 2
    target = argv[1]
    if not os.path.exists(target):
        print("error: target not found: %s" % target, file=sys.stderr)
        return 2
    try:
        evidence, warnings = run_target(target)
        document = build_document(evidence, warnings)
    except Exception as exc:  # unexpected internal failure -> exit 1
        print("error: internal failure: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(document, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
