"""Access-rights detector (FR7, TC-DET-08).

Records the rights a source process requests on a target process and
emits PROCESS_ACCESS_EVENT for strong memory/process rights. A single
access event never alerts alone: it must correlate with the
source-target relationship and follow-on operations (FR7.1, FR8).
Pure ingestion/normalization only: no alert logic, and no imports from
static/ or detection/ (one-way deps toward detection/).
"""

from typing import Any, Dict, List, Optional

DETECTOR_NAME = "access"
AREA = "access"
WEIGHT = 2

# Strong memory/process rights that warrant a PROCESS_ACCESS_EVENT.
QUALIFYING_ACCESS = frozenset(
    {
        "PROCESS_VM_OPERATION",
        "PROCESS_VM_WRITE",
        "PROCESS_VM_READ",
        "PROCESS_CREATE_THREAD",
    }
)

# Short spellings accepted and mapped to the canonical right above.
SHORT_FORMS = {
    "VM_OPERATION": "PROCESS_VM_OPERATION",
    "VM_WRITE": "PROCESS_VM_WRITE",
    "VM_READ": "PROCESS_VM_READ",
    "CREATE_THREAD": "PROCESS_CREATE_THREAD",
}

_REQUIRED_KEYS = ("source_pid", "target_pid", "requested_access")

_OPTIONAL_KEYS = (
    "source_name",
    "target_name",
    "timestamp",
    "granted_access",
    "event_type",
    "operation",
)


def _describe_event(event: Any) -> str:
    """Short identity for error context (never raises)."""
    if isinstance(event, dict):
        source = event.get("source_name", event.get("source_pid"))
        target = event.get("target_name", event.get("target_pid"))
        return "access event %s->%s" % (source, target)
    return "input %r" % (type(event).__name__,)


def _canonical_right(right: Any, label: str) -> str:
    """Map one requested right to canonical form; raise with context."""
    if not isinstance(right, str) or not right:
        raise ValueError(
            "access: requested_access entries must be non-empty str "
            "for %s, got %r" % (label, type(right).__name__)
        )
    upper = right.upper().replace(" ", "_").replace("-", "_")
    return SHORT_FORMS.get(upper, upper)


def detect_access_event(event: Any) -> Optional[Dict[str, Any]]:
    """Record one access request; emit on qualifying rights (TC-DET-08).

    Emits PROCESS_ACCESS_EVENT when the requested rights intersect the
    qualifying set; weak-only requests yield None.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    label = _describe_event(event)
    if not isinstance(event, dict):
        raise ValueError(
            "access: expected dict for %s, got %s"
            % (label, type(event).__name__)
        )
    for key in _REQUIRED_KEYS:
        if key not in event:
            raise ValueError(
                "access: missing key %r for %s" % (key, label)
            )
    for key in ("source_pid", "target_pid"):
        value = event[key]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(
                "access: key %r must be an int pid for %s, got %r"
                % (key, label, type(value).__name__)
            )
        if value < 0:
            raise ValueError(
                "access: key %r must be >= 0 for %s" % (key, label)
            )
    requested = event["requested_access"]
    if isinstance(requested, str):
        requested = [requested]
    if not isinstance(requested, list) or not requested:
        raise ValueError(
            "access: key 'requested_access' must be a non-empty "
            "str-or-list for %s" % (label,)
        )
    canonical = [_canonical_right(right, label) for right in requested]
    matched = sorted(set(canonical) & set(QUALIFYING_ACCESS))
    if not matched:
        return None
    details: Dict[str, Any] = {
        "source_pid": event["source_pid"],
        "target_pid": event["target_pid"],
        "event_type": event.get("event_type", "process_access"),
        "requested_access": list(canonical),
        "matched_rights": matched,
    }
    for key in _OPTIONAL_KEYS:
        if key in event and key not in details:
            details[key] = event[key]
    granted = details.get("granted_access")
    if granted is not None and not isinstance(granted, (str, list)):
        raise ValueError(
            "access: optional key 'granted_access' must be a str or "
            "list for %s" % (label,)
        )
    return {
        "evidence_id": "ev-access-%d-%d"
        % (event["source_pid"], event["target_pid"]),
        "area": AREA,
        "detector": DETECTOR_NAME,
        "details": details,
        "weight": WEIGHT,
    }


def qualifying_rights() -> List[str]:
    """Return the sorted qualifying rights set (for tests/docs)."""
    return sorted(QUALIFYING_ACCESS)
