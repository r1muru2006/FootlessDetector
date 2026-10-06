"""Hash-loop detector (TC-DET-01, BR1.1).

Reports a hash-loop candidate only when one function body combines:
  loop + byte/string traversal + 2+ arithmetic/bitwise transforms
  + comparison against a constant.

Inputs are minimal-stub dicts (FR11); no binary parsing here.
"""

from typing import Any, Dict, List, Optional

DETECTOR_NAME = "hash_loop"
AREA = "static"
WEIGHT = 2

# Operations counted as arithmetic/bitwise transforms for BR1.1.
TRANSFORM_OPS = frozenset(
    {
        "ADD",
        "SUB",
        "MUL",
        "IMUL",
        "XOR",
        "ROL",
        "ROR",
        "SHL",
        "SHR",
        "AND",
        "OR",
        "NOT",
        "NEG",
        "ADC",
        "SBB",
    }
)

_REQUIRED_KEYS = ("function", "loop", "operations", "comparison_constants")


def _describe_input(func: Any) -> str:
    """Short identity for error context (never raises)."""
    if isinstance(func, dict):
        for key in ("function", "name", "file"):
            if func.get(key) is not None:
                return "function %r" % (func.get(key),)
    return "input %r" % (type(func).__name__,)


def _has_traversal(func: Dict[str, Any]) -> bool:
    """Byte/string traversal signal from stub fields."""
    if "traverses_bytes" in func:
        return bool(func["traverses_bytes"])
    traversal = func.get("traversal", "")
    if isinstance(traversal, str):
        lowered = traversal.lower()
        return any(word in lowered for word in ("byte", "char", "string"))
    return False


def _count_transforms(operations: List[Any]) -> int:
    count = 0
    for op in operations:
        if isinstance(op, str) and op.upper() in TRANSFORM_OPS:
            count += 1
    return count


def detect_hash_loop(func: Any) -> Optional[Dict[str, Any]]:
    """Scan one function stub; return an evidence dict or None.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    if not isinstance(func, dict):
        raise ValueError(
            "hash_loop: expected dict for %s, got %s"
            % (_describe_input(func), type(func).__name__)
        )
    for key in _REQUIRED_KEYS:
        if key not in func:
            raise ValueError(
                "hash_loop: missing key %r for %s" % (key, _describe_input(func))
            )
    operations = func["operations"]
    if not isinstance(operations, list):
        raise ValueError(
            "hash_loop: key 'operations' must be a list for %s"
            % _describe_input(func)
        )
    comparison_constants = func["comparison_constants"]
    if not isinstance(comparison_constants, int) or isinstance(
        comparison_constants, bool
    ):
        raise ValueError(
            "hash_loop: key 'comparison_constants' must be an int count for %s"
            % _describe_input(func)
        )
    if not func.get("loop"):
        return None
    if not _has_traversal(func):
        return None
    if _count_transforms(operations) < 2:
        return None
    if comparison_constants < 1:
        return None
    return {
        "evidence_id": "ev-hash-loop-%s" % (func["function"],),
        "area": AREA,
        "detector": DETECTOR_NAME,
        "details": {
            "function": func["function"],
            "loop": func["loop"],
            "operations": [op for op in operations if isinstance(op, str)],
            "comparison_constants": comparison_constants,
        },
        "weight": WEIGHT,
    }
