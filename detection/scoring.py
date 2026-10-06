"""Minimal scoring path (BR1.3, BR1.4).

Tiers: score >= 6 across >= 2 distinct areas -> alert;
3..5 -> suspicious; below 3 -> clean. One indicator alone never alerts.
"""

from typing import Any, Dict, List, Optional, Tuple

ALERT_THRESHOLD = 6
SUSPICIOUS_THRESHOLD = 3

# Per-detector weights (U1 static + U3 runtime, FR8). Score math is a
# weighted count of evidence items; the tier rules below are unchanged.
WEIGHTS = {
    "hash_loop": 2,
    "dynamic_resolve": 3,
    "import_anomaly": 1,
    "api_chain": 1,
    "source_target": 1,
    "remote_thread": 3,
    "rwx": 3,
    "rx_anomaly": 2,
    "access": 2,
    "injection_behavior": 2,
}

# Detectors whose evidence marks an executable memory region (FR7.1).
EXECUTABLE_REGION_DETECTORS = frozenset({"rwx", "rx_anomaly"})

DETECTOR_INJECTION_BEHAVIOR = "injection_behavior"

_alert_counter = 0


def score_evidence(
    evidence: List[Dict[str, Any]],
) -> Tuple[int, int, str]:
    """Return (weighted_sum, distinct_area_count, tier) without side effects."""
    total = sum(int(item.get("weight", 0)) for item in evidence)
    areas = {item.get("area") for item in evidence if "area" in item}
    if len(evidence) == 1:
        # BR1.4 single-indicator guard: at most suspicious.
        if total >= SUSPICIOUS_THRESHOLD:
            return total, len(areas), "suspicious"
        return total, len(areas), "clean"
    if total >= ALERT_THRESHOLD and len(areas) >= 2:
        return total, len(areas), "alert"
    if total >= SUSPICIOUS_THRESHOLD:
        return total, len(areas), "suspicious"
    return total, len(areas), "clean"


def correlate(
    evidence: List[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Apply tiers + guard; return (alert_or_None, verdict).

    Never raises on a single indicator: below-threshold input yields a
    verdict string with alert None.
    """
    global _alert_counter
    score, _, verdict = score_evidence(evidence)
    if verdict != "alert":
        return None, verdict
    _alert_counter += 1
    chains = [
        item.get("evidence_id", "ev-unknown-%d" % index)
        for index, item in enumerate(evidence)
    ]
    alert: Dict[str, Any] = {
        "alert_id": "alert-%d" % _alert_counter,
        "verdict": "alert",
        "score": score,
        "chains": chains,
    }
    return alert, verdict


def verdict_for(items: Any) -> str:
    """Tier string for already-validated evidence; empty input is clean."""
    if not items:
        return "clean"
    _, verdict = correlate(list(items))
    return verdict


def weight_for(detector: Any) -> int:
    """Return the scoring weight for a detector name (0 when unknown)."""
    return WEIGHTS.get(detector, 0)


def _stage_of(item: Dict[str, Any]) -> Optional[str]:
    """Classify one evidence item as open/memory/executable chain stage."""
    details = item.get("details")
    if not isinstance(details, dict):
        return None
    if item.get("detector") in EXECUTABLE_REGION_DETECTORS:
        return "executable"
    operation = details.get("operation")
    if not isinstance(operation, str) or not operation:
        return None
    upper = operation.upper().replace(" ", "_").replace("-", "_")
    if "OPEN" in upper:
        return "open"
    if "WRITE" in upper or "ALLOC" in upper:
        return "memory"
    return None


def _pair_of(item: Dict[str, Any]) -> Optional[Any]:
    """Return the (source_pid, target_pid) pair an item speaks about."""
    details = item.get("details")
    if not isinstance(details, dict):
        return None
    source = details.get("source_pid", details.get("writer_pid"))
    target = details.get("target_pid", details.get("owner_pid"))
    if (
        isinstance(source, int)
        and not isinstance(source, bool)
        and isinstance(target, int)
        and not isinstance(target, bool)
    ):
        return (source, target)
    return None


def detect_injection_behavior(evidence: Any) -> Optional[Dict[str, Any]]:
    """Emit PROCESS_INJECTION_BEHAVIOR for an open->memory->exec chain.

    Returns an evidence dict when open-process, memory-operation, and
    executable-region evidence share one pid pair in order (FR7.1);
    otherwise None. Never raises: below-threshold input yields None.
    """
    if not isinstance(evidence, list) or not evidence:
        return None
    opens: Dict[Any, Any] = {}
    memories: Dict[Any, Any] = {}
    executables: List[Any] = []
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            continue
        stage = _stage_of(item)
        if stage is None:
            continue
        evidence_id = item.get("evidence_id", "ev-unknown-%d" % index)
        if stage == "executable":
            executables.append((index, evidence_id, item))
            continue
        pair = _pair_of(item)
        if pair is None:
            continue
        slot = opens if stage == "open" else memories
        if pair not in slot:
            slot[pair] = (index, evidence_id)
    for pair in sorted(set(opens) & set(memories)):
        open_index, open_id = opens[pair]
        memory_index, memory_id = memories[pair]
        if not open_index < memory_index:
            continue
        source, target = pair
        for exec_index, exec_id, exec_item in executables:
            if not memory_index < exec_index:
                continue
            exec_pair = _pair_of(exec_item)
            if exec_pair is None:
                exec_details = exec_item.get("details")
                if not isinstance(exec_details, dict):
                    continue
                owner = exec_details.get("owner_pid")
                if owner != target:
                    continue
            elif exec_pair != pair:
                continue
            details: Dict[str, Any] = {
                "source_pid": source,
                "target_pid": target,
                "behavior": "PROCESS_INJECTION_BEHAVIOR",
                "stages": [open_id, memory_id, exec_id],
            }
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                item_details = item.get("details")
                if not isinstance(item_details, dict):
                    continue
                if _pair_of(item) != pair:
                    continue
                for key in ("source_name", "target_name"):
                    if key not in details and key in item_details:
                        details[key] = item_details[key]
            return {
                "evidence_id": "ev-injection-%d-%d" % (source, target),
                "area": "runtime",
                "detector": DETECTOR_INJECTION_BEHAVIOR,
                "details": details,
                "weight": WEIGHTS[DETECTOR_INJECTION_BEHAVIOR],
            }
    return None
