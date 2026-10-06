"""Dynamic-resolution detector (TC-DET-02, FR2).

Reports a dynamic-resolution candidate only when a stub trace combines:
  export-table traversal + API-name iteration
  + (hash comparison OR indirect call).

``peb_access`` is a supporting signal only: it is recorded in the
evidence details but never decides the verdict alone.

Inputs are minimal-stub dicts (FR11); no binary parsing here.
"""

from typing import Any, Dict, Optional

DETECTOR_NAME = "dynamic_resolve"
AREA = "static"
WEIGHT = 3

_REQUIRED_KEYS = (
    "peb_access",
    "export_traversal",
    "name_iteration",
    "hash_compare",
    "indirect_call",
    "module",
)

_FLAG_KEYS = (
    "peb_access",
    "export_traversal",
    "name_iteration",
    "hash_compare",
    "indirect_call",
)


def _describe_input(trace: Any) -> str:
    """Short identity for error context (never raises)."""
    if isinstance(trace, dict):
        module = trace.get("module")
        if isinstance(module, str) and module:
            return "trace for module %r" % (module,)
    return "input %r" % (type(trace).__name__,)


def detect_dynamic_resolution(trace: Any) -> Optional[Dict[str, Any]]:
    """Scan one stub trace; return an evidence dict or None.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    if not isinstance(trace, dict):
        raise ValueError(
            "dynamic_resolve: expected dict for %s, got %s"
            % (_describe_input(trace), type(trace).__name__)
        )
    for key in _REQUIRED_KEYS:
        if key not in trace:
            raise ValueError(
                "dynamic_resolve: missing key %r for %s"
                % (key, _describe_input(trace))
            )
    for key in _FLAG_KEYS:
        if not isinstance(trace[key], bool):
            raise ValueError(
                "dynamic_resolve: key %r must be a bool for %s, got %s"
                % (key, _describe_input(trace), type(trace[key]).__name__)
            )
    module = trace["module"]
    if not isinstance(module, str) or not module:
        raise ValueError(
            "dynamic_resolve: key 'module' must be a non-empty str for %s"
            % _describe_input(trace)
        )
    if not trace["export_traversal"]:
        return None
    if not trace["name_iteration"]:
        return None
    if not (trace["hash_compare"] or trace["indirect_call"]):
        return None
    observed = ["export_table_traversal", "api_name_iteration"]
    if trace["hash_compare"]:
        observed.append("hash_comparison")
    if trace["indirect_call"]:
        observed.append("indirect_call")
    if trace["peb_access"]:
        observed.append("peb_access")
    return {
        "evidence_id": "ev-dynamic-resolve-%s" % (module,),
        "area": AREA,
        "detector": DETECTOR_NAME,
        "details": {
            "module": module,
            "peb_access": trace["peb_access"],
            "export_traversal": trace["export_traversal"],
            "name_iteration": trace["name_iteration"],
            "hash_compare": trace["hash_compare"],
            "indirect_call": trace["indirect_call"],
            "evidence": observed,
        },
        "weight": WEIGHT,
    }
