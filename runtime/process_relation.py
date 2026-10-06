"""Source-target and remote-thread detectors (FR5, TC-DET-04/05).

Tracks which process operates on which process (SOURCE_TARGET_RELATION)
and flags cross-process thread creation (REMOTE_THREAD_DETECTED).
Pure ingestion/normalization only: no alert logic, and no imports from
static/ or detection/ (one-way deps toward detection/).
"""

from typing import Any, Dict, Optional

DETECTOR_SOURCE_TARGET = "source_target"
AREA_SOURCE_TARGET = "runtime"
WEIGHT_SOURCE_TARGET = 1

DETECTOR_REMOTE_THREAD = "remote_thread"
AREA_REMOTE_THREAD = "runtime"
WEIGHT_REMOTE_THREAD = 3

_REQUIRED_KEYS = (
    "timestamp",
    "source_pid",
    "source_name",
    "target_pid",
    "target_name",
    "operation",
)

# Operations that create a thread in the target process (TC-DET-05).
THREAD_CREATION_OPS = frozenset(
    {
        "CREATE_THREAD",
        "CREATE_REMOTE_THREAD",
        "THREAD_CREATE",
        "THREAD_CREATION",
        "REMOTE_THREAD_CREATION",
        "NTCREATETHREAD",
        "NTCREATETHREADEX",
        "CREATEREMOTETHREAD",
    }
)


def _describe_event(event: Any, detector: str) -> str:
    """Short identity for error context (never raises)."""
    if isinstance(event, dict):
        source = event.get("source_name", event.get("source_pid"))
        target = event.get("target_name", event.get("target_pid"))
        operation = event.get("operation")
        return "%s event %r %s->%s" % (
            detector,
            operation,
            source,
            target,
        )
    return "%s input %r" % (detector, type(event).__name__,)


def _validate_relation_event(event: Any, detector: str) -> Dict[str, Any]:
    """Validate shared source-target fields; raise with context."""
    label = _describe_event(event, detector)
    if not isinstance(event, dict):
        raise ValueError(
            "%s: expected dict for %s, got %s"
            % (detector, label, type(event).__name__)
        )
    for key in _REQUIRED_KEYS:
        if key not in event:
            raise ValueError(
                "%s: missing key %r for %s" % (detector, key, label)
            )
    for key in ("source_pid", "target_pid"):
        value = event[key]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(
                "%s: key %r must be an int pid for %s, got %r"
                % (detector, key, label, type(value).__name__)
            )
        if value < 0:
            raise ValueError(
                "%s: key %r must be >= 0 for %s"
                % (detector, key, label)
            )
    for key in ("source_name", "target_name", "operation", "timestamp"):
        value = event[key]
        if not isinstance(value, str) or not value:
            raise ValueError(
                "%s: key %r must be a non-empty str for %s, got %r"
                % (detector, key, label, type(value).__name__)
            )
    return event


def track_relation(event: Any) -> Optional[Dict[str, Any]]:
    """Track one operation between a source and a target process.

    Emits SOURCE_TARGET_RELATION for cross-process operations
    (TC-DET-04); same-process operations yield None.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    event = _validate_relation_event(event, DETECTOR_SOURCE_TARGET)
    if event["source_pid"] == event["target_pid"]:
        return None
    details: Dict[str, Any] = {
        "timestamp": event["timestamp"],
        "source_pid": event["source_pid"],
        "source_name": event["source_name"],
        "target_pid": event["target_pid"],
        "target_name": event["target_name"],
        "event_type": event.get("event_type", "process_relation"),
        "operation": event["operation"],
    }
    return {
        "evidence_id": "ev-source-target-%d-%d"
        % (event["source_pid"], event["target_pid"]),
        "area": AREA_SOURCE_TARGET,
        "detector": DETECTOR_SOURCE_TARGET,
        "details": details,
        "weight": WEIGHT_SOURCE_TARGET,
    }


def detect_remote_thread(event: Any) -> Optional[Dict[str, Any]]:
    """Flag thread creation in another process (TC-DET-05).

    Emits REMOTE_THREAD_DETECTED only when source_pid != target_pid
    and the operation is a thread-creation operation; same-process or
    non-thread operations yield None.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    event = _validate_relation_event(event, DETECTOR_REMOTE_THREAD)
    if event["source_pid"] == event["target_pid"]:
        return None
    operation = str(event["operation"]).upper().replace(" ", "_")
    operation = operation.replace("-", "_")
    if operation not in THREAD_CREATION_OPS:
        return None
    details: Dict[str, Any] = {
        "timestamp": event["timestamp"],
        "source_pid": event["source_pid"],
        "source_name": event["source_name"],
        "target_pid": event["target_pid"],
        "target_name": event["target_name"],
        "event_type": event.get("event_type", "thread_creation"),
        "operation": event["operation"],
        "event": "remote thread creation",
    }
    return {
        "evidence_id": "ev-remote-thread-%d-%d"
        % (event["source_pid"], event["target_pid"]),
        "area": AREA_REMOTE_THREAD,
        "detector": DETECTOR_REMOTE_THREAD,
        "details": details,
        "weight": WEIGHT_REMOTE_THREAD,
    }
