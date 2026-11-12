"""Memory-region detectors (FR6, TC-DET-06/07).

Flags read-write-execute regions (RWX_REGION_DETECTED) and executable
regions tied to a prior write/allocation by another process
(EXECUTABLE_MEMORY_ANOMALY). A bare RX region never emits: valid
executable code normally lives as RX. Pure ingestion/normalization
only: no alert logic, and no imports from static/ or detection/.
"""

from typing import Any, Dict, List, Optional

DETECTOR_RWX = "rwx"
AREA_MEMORY = "memory"
WEIGHT_RWX = 3

DETECTOR_RX_ANOMALY = "rx_anomaly"
WEIGHT_RX_ANOMALY = 2

# Region keys passed through into evidence details when present.
_REGION_PASSTHROUGH = (
    "base_address",
    "size",
    "state",
    "type",
    "owner_pid",
    "owner_process",
)


def _describe_region(region: Any, detector: str) -> str:
    """Short identity for error context (never raises)."""
    if isinstance(region, dict):
        base = region.get("base_address")
        owner = region.get("owner_process", region.get("owner_pid"))
        if base is not None or owner is not None:
            return "%s region %s owner %s" % (detector, base, owner)
    return "%s input %r" % (detector, type(region).__name__,)


def _protection_flags(protection: str) -> Any:
    """Split a protection string into its {R, W, X} flag set."""
    compact = protection.upper()
    for sep in ("_", "-", " ", "/", "+", "|"):
        compact = compact.replace(sep, "")
    if compact and set(compact) <= set("RWX"):
        return set(compact)
    flags = set()
    if "READ" in compact:
        flags.add("R")
    if "WRITE" in compact:
        flags.add("W")
    if "EXEC" in compact:
        flags.add("X")
    return flags


def _validate_region(region: Any, detector: str) -> Dict[str, Any]:
    """Validate the shared region shape; raise with context."""
    label = _describe_region(region, detector)
    if not isinstance(region, dict):
        raise ValueError(
            "%s: expected dict for %s, got %s"
            % (detector, label, type(region).__name__)
        )
    if "protection" not in region:
        raise ValueError(
            "%s: missing key 'protection' for %s" % (detector, label)
        )
    protection = region["protection"]
    if not isinstance(protection, str) or not protection:
        raise ValueError(
            "%s: key 'protection' must be a non-empty str for %s, "
            "got %r" % (detector, label, type(protection).__name__)
        )
    return region


def _region_details(region: Dict[str, Any]) -> Dict[str, Any]:
    """GUIDE region details: verbatim protection plus known context."""
    details: Dict[str, Any] = {"memory_protection": region["protection"]}
    for key in _REGION_PASSTHROUGH:
        if key in region:
            details[key] = region[key]
    return details


def detect_rwx_region(region: Any) -> Optional[Dict[str, Any]]:
    """Flag read-write-execute regions (TC-DET-06); else None.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    region = _validate_region(region, DETECTOR_RWX)
    if _protection_flags(region["protection"]) != set("RWX"):
        return None
    return {
        "evidence_id": "ev-rwx-%s"
        % (region.get("base_address", "unknown"),),
        "area": AREA_MEMORY,
        "detector": DETECTOR_RWX,
        "details": _region_details(region),
        "weight": WEIGHT_RWX,
    }


def _is_write_or_alloc(operation: Any) -> bool:
    """True for memory-write/allocation operations (case-insensitive)."""
    if not isinstance(operation, str):
        return False
    upper = operation.upper().replace(" ", "_").replace("-", "_")
    return "WRITE" in upper or "ALLOC" in upper


def _linked_prior_write(
    region: Dict[str, Any], prior_events: List[Any]
) -> Optional[Dict[str, Any]]:
    """Find a prior write/alloc by another process linked to the region."""
    owner = region.get("owner_pid")
    base = region.get("base_address")
    for event in prior_events:
        if not isinstance(event, dict):
            raise ValueError(
                "rx_anomaly: prior event must be a dict, got %r"
                % (type(event).__name__,)
            )
        if not _is_write_or_alloc(event.get("operation")):
            continue
        source = event.get("source_pid")
        target = event.get("target_pid")
        if source is None or target is None:
            continue
        if owner is not None and source == owner:
            continue  # self-write carries no injection signal
        address_match = (
            base is not None
            and base
            in (
                event.get("target_address"),
                event.get("base"),
                event.get("base_address"),
            )
        )
        if owner is not None and target != owner and not address_match:
            continue
        if owner is None and not address_match:
            continue
        return event
    return None


def detect_rx_anomaly(region: Any, prior_events: Any) -> Optional[Any]:
    """Flag executable regions with prior foreign-write context (TC-DET-07).

    Emits EXECUTABLE_MEMORY_ANOMALY only when an executable region is
    tied to a prior write/allocation event by another process; bare RX
    regions and non-executable regions yield None.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    region = _validate_region(region, DETECTOR_RX_ANOMALY)
    if not isinstance(prior_events, list):
        raise ValueError(
            "rx_anomaly: prior_events must be a list for %s, got %r"
            % (
                _describe_region(region, DETECTOR_RX_ANOMALY),
                type(prior_events).__name__,
            )
        )
    flags = _protection_flags(region["protection"])
    if "X" not in flags:
        return None
    if flags == set("RWX"):
        return None  # owned by the RWX detector, not the RX path
    linked = _linked_prior_write(region, prior_events)
    if linked is None:
        return None
    details = _region_details(region)
    details["writer_pid"] = linked.get("source_pid")
    details["writer_operation"] = linked.get("operation")
    details["writer_timestamp"] = linked.get("timestamp")
    return {
        "evidence_id": "ev-rx-anomaly-%s"
        % (region.get("base_address", "unknown"),),
        "area": AREA_MEMORY,
        "detector": DETECTOR_RX_ANOMALY,
        "details": details,
        "weight": WEIGHT_RX_ANOMALY,
    }
