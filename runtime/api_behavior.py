"""API-behavior detector (FR4).

Normalizes raw runtime API event dicts into GUIDE evidence chains
(timestamp, source/target process, api, operation, result) for the
correlation engine. Pure ingestion/normalization only: no alert logic,
and no imports from static/ or detection/ (one-way deps toward
detection/).
"""

from typing import Any, Dict, List, Optional

DETECTOR_NAME = "api_chain"
AREA = "runtime"
WEIGHT = 1

_REQUIRED_KEYS = (
    "timestamp",
    "source_pid",
    "source_name",
    "target_pid",
    "target_name",
    "api",
    "operation",
)

_OPTIONAL_KEYS = (
    "event_type",
    "result",
    "access",
    "memory_protection",
)


def _describe_event(event: Any) -> str:
    """Short identity for error context (never raises)."""
    if isinstance(event, dict):
        api = event.get("api")
        source = event.get("source_name", event.get("source_pid"))
        target = event.get("target_name", event.get("target_pid"))
        if isinstance(api, str) and api:
            return "event %r %s->%s" % (api, source, target)
    return "input %r" % (type(event).__name__,)


def _require_non_empty_str(
    event: Dict[str, Any], key: str, label: str
) -> str:
    """Fetch a required non-empty string field or raise with context."""
    value = event[key]
    if not isinstance(value, str) or not value:
        raise ValueError(
            "api_chain: key %r must be a non-empty str for %s, got %r"
            % (key, label, type(value).__name__)
        )
    return value


def _require_pid(event: Dict[str, Any], key: str, label: str) -> int:
    """Fetch a required integer PID field or raise with context."""
    value = event[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(
            "api_chain: key %r must be an int pid for %s, got %r"
            % (key, label, type(value).__name__)
        )
    if value < 0:
        raise ValueError(
            "api_chain: key %r must be >= 0 for %s" % (key, label)
        )
    return value


def normalize_api_event(event: Any) -> Dict[str, Any]:
    """Normalize one raw API event dict into an evidence dict.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    label = _describe_event(event)
    if not isinstance(event, dict):
        raise ValueError(
            "api_chain: expected dict for %s, got %s"
            % (label, type(event).__name__)
        )
    for key in _REQUIRED_KEYS:
        if key not in event:
            raise ValueError(
                "api_chain: missing key %r for %s" % (key, label)
            )
    timestamp = _require_non_empty_str(event, "timestamp", label)
    source_pid = _require_pid(event, "source_pid", label)
    source_name = _require_non_empty_str(event, "source_name", label)
    target_pid = _require_pid(event, "target_pid", label)
    target_name = _require_non_empty_str(event, "target_name", label)
    api = _require_non_empty_str(event, "api", label)
    operation = _require_non_empty_str(event, "operation", label)
    details: Dict[str, Any] = {
        "timestamp": timestamp,
        "source_pid": source_pid,
        "source_name": source_name,
        "target_pid": target_pid,
        "target_name": target_name,
        "event_type": event.get("event_type", "api_event"),
        "api": api,
        "operation": operation,
        "result": event.get("result", "unknown"),
    }
    event_type = details["event_type"]
    if not isinstance(event_type, str) or not event_type:
        raise ValueError(
            "api_chain: key 'event_type' must be a non-empty str "
            "for %s" % (label,)
        )
    result = details["result"]
    if not isinstance(result, str) or not result:
        raise ValueError(
            "api_chain: key 'result' must be a non-empty str for %s"
            % (label,)
        )
    for key in ("access", "memory_protection"):
        if key in event:
            if not isinstance(event[key], str):
                raise ValueError(
                    "api_chain: optional key %r must be a str for %s"
                    % (key, label)
                )
            details[key] = event[key]
    return {
        "evidence_id": "ev-api-chain-%s-%d-%d"
        % (api, source_pid, target_pid),
        "area": AREA,
        "detector": DETECTOR_NAME,
        "details": details,
        "weight": WEIGHT,
    }


def assemble_chain(events: Any) -> List[Dict[str, Any]]:
    """Normalize many raw events into timestamp-ordered evidence.

    Out-of-order input is reordered by timestamp so the correlation
    engine always sees the open -> allocate -> write -> protect ->
    execute chain in sequence.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    if not isinstance(events, list):
        raise ValueError(
            "api_chain: expected list of events for %s, got %s"
            % (
                _describe_event(events),
                type(events).__name__,
            )
        )
    normalized = []
    for index, event in enumerate(events):
        try:
            normalized.append(normalize_api_event(event))
        except ValueError as exc:
            raise ValueError(
                "api_chain: event#%d malformed: %s" % (index, exc)
            )
    normalized.sort(key=lambda item: item["details"]["timestamp"])
    return normalized


def detect_api_chain(event: Any) -> Optional[Dict[str, Any]]:
    """Alias for normalize_api_event (single-event entry point)."""
    return normalize_api_event(event)
