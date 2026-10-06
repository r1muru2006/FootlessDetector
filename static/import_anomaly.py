"""PE import-anomaly detector (TC-DET-03, FR3).

Reports a supporting indicator only when a PE carries a suspiciously
small import table (5 or fewer static imports) while the runtime
observes many distinct APIs (10 or more):

  len(imports) <= 5 AND runtime_api_count >= 10.

A small IAT alone is never malicious; this evidence must correlate
with other indicators before any alert (BR1.4).

Inputs are minimal-stub dicts (FR11); no PE parsing here.
"""

from typing import Any, Dict, List, Optional

DETECTOR_NAME = "import_anomaly"
AREA = "static"
WEIGHT = 1

MAX_STATIC_IMPORTS = 5
MIN_RUNTIME_APIS = 10

_REQUIRED_KEYS = ("imports", "runtime_api_count")


def _describe_input(pe: Any) -> str:
    """Short identity for error context (never raises)."""
    if isinstance(pe, dict):
        for key in ("file", "name", "module"):
            if pe.get(key) is not None:
                return "pe %r" % (pe.get(key),)
    return "input %r" % (type(pe).__name__,)


def detect_import_anomaly(pe: Any) -> Optional[Dict[str, Any]]:
    """Scan one PE stub; return an evidence dict or None.

    Raises:
        ValueError: malformed input, with context naming the problem.
    """
    if not isinstance(pe, dict):
        raise ValueError(
            "import_anomaly: expected dict for %s, got %s"
            % (_describe_input(pe), type(pe).__name__)
        )
    for key in _REQUIRED_KEYS:
        if key not in pe:
            raise ValueError(
                "import_anomaly: missing key %r for %s" % (key, _describe_input(pe))
            )
    imports = pe["imports"]
    if not isinstance(imports, list):
        raise ValueError(
            "import_anomaly: key 'imports' must be a list for %s, got %s"
            % (_describe_input(pe), type(imports).__name__)
        )
    for entry in imports:
        if not isinstance(entry, str):
            raise ValueError(
                "import_anomaly: key 'imports' must be a list of str for %s, got entry %r"
                % (_describe_input(pe), type(entry).__name__)
            )
    runtime_api_count = pe["runtime_api_count"]
    if not isinstance(runtime_api_count, int) or isinstance(runtime_api_count, bool):
        raise ValueError(
            "import_anomaly: key 'runtime_api_count' must be an int for %s, got %s"
            % (_describe_input(pe), type(runtime_api_count).__name__)
        )
    if runtime_api_count < 0:
        raise ValueError(
            "import_anomaly: key 'runtime_api_count' must be >= 0 for %s"
            % _describe_input(pe)
        )
    if len(imports) > MAX_STATIC_IMPORTS:
        return None
    if runtime_api_count < MIN_RUNTIME_APIS:
        return None
    return {
        "evidence_id": "ev-import-anomaly-%d-%d" % (len(imports), runtime_api_count),
        "area": AREA,
        "detector": DETECTOR_NAME,
        "details": {
            "imports": list(imports),
            "import_count": len(imports),
            "runtime_api_count": runtime_api_count,
        },
        "weight": WEIGHT,
    }
