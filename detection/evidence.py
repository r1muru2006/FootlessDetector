"""Evidence-shape contract (C1/C2, BR1.2, BR1.6).

Shared-schema plain dicts: every evidence dict carries area, detector,
details, and weight with verbatim GUIDE keys; new fields are additive
only and consumers ignore unknown fields.
"""

from typing import Any, Dict, List

REQUIRED_EVIDENCE_KEYS = ("area", "detector", "details", "weight")

ALLOWED_AREAS = ("static", "static_pe", "runtime", "memory", "access", "graph")

# U1 scoring weights (functional-design Q1 table, U1 scope).
WEIGHTS = {
    "hash_loop": 2,
    "dynamic_resolve": 3,
    "import_anomaly": 2,
    "packed": 2,
    "rwx_section": 3,
    "api_chain": 1,
    "source_target": 1,
    "remote_thread": 3,
    "rwx": 3,
    "rx_anomaly": 2,
    "access": 2,
    "injection_behavior": 2,
    "process_graph": 2,
}

_evidence_counter = 0


def validate_evidence(evidence: Any) -> Dict[str, Any]:
    """Accept evidence with all required keys; else raise naming the key."""
    if not isinstance(evidence, dict):
        raise ValueError(
            "evidence: expected dict, got %s" % type(evidence).__name__
        )
    for key in REQUIRED_EVIDENCE_KEYS:
        if key not in evidence:
            raise ValueError("evidence: missing key %r" % (key,))
    if evidence["area"] not in ALLOWED_AREAS:
        raise ValueError(
            "evidence: unknown area %r" % (evidence["area"],)
        )
    weight = evidence["weight"]
    if not isinstance(weight, int) or isinstance(weight, bool):
        raise ValueError("evidence: weight must be an int")
    if not 1 <= weight <= 3:
        raise ValueError("evidence: weight must be in 1..3")
    return evidence


def make_evidence(
    area: str,
    detector: str,
    details: Dict[str, Any],
    weight: int,
    evidence_id: str = "",
) -> Dict[str, Any]:
    """Build one validated evidence dict (raises ValueError on bad input)."""
    global _evidence_counter
    if not evidence_id:
        _evidence_counter += 1
        evidence_id = "ev-%s-%d" % (detector, _evidence_counter)
    return validate_evidence(
        {
            "evidence_id": evidence_id,
            "area": area,
            "detector": detector,
            "details": details,
            "weight": weight,
        }
    )


def make_warning(input_name: Any, detector: str, reason: str) -> Dict[str, Any]:
    """Build one structured warning dict for a skipped malformed input."""
    return {"input": input_name, "detector": detector, "reason": reason}


def collect_evidence(
    items: List[Any], detector_name: str, detect_fn: Any
) -> Any:
    """Run one detector over many inputs; malformed inputs become warnings.

    Returns (evidence_list, warning_list); never raises on a single input.
    """
    evidence: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        try:
            result = detect_fn(item)
        except Exception as exc:
            warnings.append(make_warning("input#%d" % index, detector_name, str(exc)))
            continue
        if result is None:
            continue
        try:
            evidence.append(validate_evidence(result))
        except Exception as exc:
            warnings.append(make_warning("input#%d" % index, detector_name, str(exc)))
    return evidence, warnings
