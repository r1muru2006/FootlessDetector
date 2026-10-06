"""Minimal scoring path (BR1.3, BR1.4).

Tiers: score >= 6 across >= 2 distinct areas -> alert;
3..5 -> suspicious; below 3 -> clean. One indicator alone never alerts.
"""

from typing import Any, Dict, List, Optional, Tuple

ALERT_THRESHOLD = 6
SUSPICIOUS_THRESHOLD = 3

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
