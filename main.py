"""Footless detector CLI.

Usage:
    python main.py <target> [--format auto|json|jsonl|pe|telemetry]
        [--allowlist FILE] [--threshold N] [--out FILE]

Target may be a PE file, a JSON/JSONL telemetry file, an evidence batch,
or a directory of these.  Stdout is one JSON document:
evidence, warnings, alert or null, verdict, stats (and features/graph).

Exit codes: 0 clean run (any verdict), 2 bad target/usage, 1 internal
failure.  Thin orchestration only; all detection lives in detection/ and
runtime/.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from detection.engine import analyze_path
from detection.scoring import correlate

USAGE = (
    "usage: python main.py <target> [--format auto|json|jsonl|pe|telemetry]\n"
    "       [--allowlist FILE] [--threshold N] [--out FILE]"
)


def load_allowlist(path: Optional[str]) -> List[str]:
    if not path:
        return []
    entries: List[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(os.path.basename(line.replace("\\", "/")))
    return entries


def build_document(
    evidence: List[Dict[str, Any]], warnings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Legacy helper kept for callers/tests that assemble evidence directly."""
    alert, verdict = correlate(evidence)
    return {
        "evidence": evidence,
        "warnings": warnings,
        "alert": alert,
        "verdict": verdict,
    }


def parse_arguments(argv: List[str]) -> Tuple[Optional[str], Dict[str, Any]]:
    target: Optional[str] = None
    options: Dict[str, Any] = {
        "format": "auto",
        "allowlist": None,
        "threshold": None,
        "out": None,
    }
    index = 1
    while index < len(argv):
        arg = argv[index]
        value = argv[index + 1] if index + 1 < len(argv) else None
        if arg in ("-h", "--help"):
            return None, {"help": True}
        if arg == "--format" and value:
            options["format"] = value
            index += 2
        elif arg == "--allowlist" and value:
            options["allowlist"] = value
            index += 2
        elif arg == "--threshold" and value:
            try:
                options["threshold"] = int(value)
            except ValueError:
                raise ValueError("--threshold expects an integer")
            index += 2
        elif arg == "--out" and value:
            options["out"] = value
            index += 2
        elif arg.startswith("-"):
            raise ValueError("unknown option: %s" % arg)
        elif target is None:
            target = arg
            index += 1
        else:
            raise ValueError("unexpected argument: %s" % arg)
    return target, options


def main(argv: List[str]) -> int:
    try:
        target, options = parse_arguments(argv)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if options.get("help"):
        print(USAGE)
        return 0
    if not target:
        print(USAGE, file=sys.stderr)
        return 2
    if not os.path.exists(target):
        print("error: target not found: %s" % target, file=sys.stderr)
        return 2
    try:
        allowlist = load_allowlist(options["allowlist"])
        document = analyze_path(
            target,
            allowlist=allowlist,
            threshold=options["threshold"],
            force_format=options["format"],
        )
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except Exception as exc:  # unexpected internal failure
        print("error: internal failure: %s" % exc, file=sys.stderr)
        return 1
    text = json.dumps(document, indent=2, sort_keys=False)
    if options["out"]:
        with open(options["out"], "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
