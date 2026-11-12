"""Detection engine: routing, multi-layer evidence collection, correlation.

The engine is independent from the loader.  It accepts PE files, evidence
batches, GUIDE event fixtures, loader.jsonl records and Sysmon-shaped
telemetry.  Every malformed record becomes a warning; one bad input never
aborts a run (FR10).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from detection import pe
from detection.evidence import make_warning, validate_evidence
from detection.graph import build_graph, detect_graph_behavior
from detection.scoring import correlate, detect_injection_behavior
from runtime.access_rights import detect_access_event
from runtime.api_behavior import normalize_api_event
from runtime.memory_region import detect_rwx_region, detect_rx_anomaly
from runtime.process_relation import detect_remote_thread, track_relation
from runtime.telemetry import is_loader_event, normalize_any, normalize_batch
from static.dynamic_resolve import detect_dynamic_resolution
from static.hash_loop import detect_hash_loop
from static.import_anomaly import detect_import_anomaly

EVIDENCE_KEYS = ("area", "detector", "details", "weight")
PE_SUFFIXES = (".exe", ".dll", ".sys", ".scr", ".cpl", ".efi")


def looks_like_evidence(item: Any) -> bool:
    return isinstance(item, dict) and all(key in item for key in EVIDENCE_KEYS)


def _is_pe_path(path: str) -> bool:
    return path.lower().endswith(PE_SUFFIXES)


def _basename(path: Any) -> str:
    if not isinstance(path, str):
        return ""
    return os.path.basename(path.replace("\\", "/")).lower()


@dataclass
class Analysis:
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    features: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def extend(self, other: "Analysis") -> None:
        self.evidence.extend(other.evidence)
        self.warnings.extend(other.warnings)
        self.features.extend(other.features)
        self.events.extend(other.events)


class Engine:
    def __init__(
        self,
        allowlist: Optional[Iterable[str]] = None,
        threshold: Optional[int] = None,
        only_layers: Optional[Iterable[str]] = None,
    ) -> None:
        self.allowlist = {name.lower() for name in (allowlist or [])}
        self.threshold = threshold
        self.only_layers = set(only_layers) if only_layers else None

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def analyze_path(self, path: str, force_format: str = "auto") -> Analysis:
        if os.path.isdir(path):
            result = Analysis()
            names = sorted(os.listdir(path))
            if not names:
                raise FileNotFoundError("empty directory: %s" % path)
            for name in names:
                child = os.path.join(path, name)
                if os.path.isdir(child):
                    continue
                if force_format == "auto":
                    extension = os.path.splitext(name)[1].lower()
                    if extension not in PE_SUFFIXES + (".json", ".jsonl"):
                        continue
                result.extend(self.analyze_path(child, force_format))
            return result
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        if force_format == "pe" or (
            force_format == "auto" and _is_pe_path(path)
        ):
            return self.analyze_pe(path)
        if force_format in ("jsonl", "telemetry"):
            return self.analyze_jsonl(path)
        if force_format == "json":
            return self.analyze_file(path)
        # auto: JSON first when it parses, otherwise try PE.
        if path.lower().endswith((".json", ".jsonl")):
            return self.analyze_jsonl(path) if path.lower().endswith(".jsonl") else self.analyze_file(path)
        try:
            with open(path, "rb") as handle:
                if handle.read(2) == b"MZ":
                    return self.analyze_pe(path)
        except OSError:
            pass
        return self.analyze_file(path)

    def analyze_pe(self, path: str) -> Analysis:
        result = Analysis()
        if _basename(path) in self.allowlist:
            result.warnings.append(
                make_warning(path, "pe", "suppressed by allowlist")
            )
            return result
        try:
            features, evidence = pe.analyze_file(path)
            result.features.append(features)
            result.evidence.extend(validate_evidence(item) for item in evidence)
        except (pe.PEError, OSError, ValueError) as exc:
            result.warnings.append(make_warning(path, "pe", str(exc)))
        return result

    def analyze_file(self, path: str) -> Analysis:
        """Analyze one .json payload (evidence batch, events, or stubs)."""
        result = Analysis()
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError) as exc:
            result.warnings.append(make_warning(path, "json", str(exc)))
            return result
        return self.analyze_payload(payload, path)

    def analyze_jsonl(self, path: str) -> Analysis:
        result = Analysis()
        records: List[Any] = []
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except ValueError as exc:
                        result.warnings.append(
                            make_warning(
                                "%s:%d" % (path, line_number), "jsonl", str(exc)
                            )
                        )
        except OSError as exc:
            result.warnings.append(make_warning(path, "jsonl", str(exc)))
            return result
        result.extend(self.analyze_payload(records, path))
        return result

    # ------------------------------------------------------------------
    # Payload routing
    # ------------------------------------------------------------------
    def analyze_payload(self, payload: Any, label: str) -> Analysis:
        result = Analysis()
        if isinstance(payload, dict) and isinstance(payload.get("evidence"), list):
            # Pre-built evidence batch (legacy and hand-authored fixtures).
            for index, item in enumerate(payload["evidence"]):
                self._collect_evidence(item, "%s#%d" % (label, index), result)
            return result
        if isinstance(payload, list):
            return self._analyze_list(payload, label)
        if isinstance(payload, dict):
            return self._analyze_dict(payload, label)
        result.warnings.append(
            make_warning(label, "engine", "expected JSON object or list")
        )
        return result

    def _analyze_list(self, items: List[Any], label: str) -> Analysis:
        result = Analysis()
        evidence_items: List[Any] = []
        event_items: List[Dict[str, Any]] = []
        stub_items: List[Any] = []
        for index, item in enumerate(items):
            item_label = "%s#%d" % (label, index)
            if looks_like_evidence(item):
                evidence_items.append(item)
                continue
            if isinstance(item, dict) and (
                "api" in item
                or "EventID" in item
                or "Event" in item
                or is_loader_event(item)
            ):
                event_items.append(item)
                continue
            stub_items.append((item_label, item))
        for index, item in enumerate(evidence_items):
            self._collect_evidence(item, "%s/ev#%d" % (label, index), result)
        if event_items:
            result.extend(self._analyze_events(event_items, label))
        for item_label, item in stub_items:
            result.extend(self._analyze_stub(item, item_label))
        return result

    def _analyze_dict(self, payload: Dict[str, Any], label: str) -> Analysis:
        result = Analysis()
        if looks_like_evidence(payload):
            self._collect_evidence(payload, label, result)
            return result
        if payload.get("function") is not None and "loop" in payload:
            self._run(detect_hash_loop, payload, label, result)
            return result
        if "export_traversal" in payload:
            self._run(detect_dynamic_resolution, payload, label, result)
            return result
        if "imports" in payload and "runtime_api_count" in payload:
            self._run(detect_import_anomaly, payload, label, result)
            return result
        if "protection" in payload and "operation" not in payload:
            self._analyze_region(payload, [], label, result)
            return result
        if "EventID" in payload or "Event" in payload or "event" in payload:
            return self._analyze_events([payload], label)
        if "api" in payload or "operation" in payload:
            return self._analyze_events([payload], label)
        if isinstance(payload.get("events"), list):
            return self._analyze_events(payload["events"], label)
        if isinstance(payload.get("telemetry"), list):
            return self._analyze_events(payload["telemetry"], label)
        if "pe_path" in payload and isinstance(payload["pe_path"], str):
            return self.analyze_pe(payload["pe_path"])
        result.warnings.append(
            make_warning(label, "engine", "unrecognized JSON object")
        )
        return result

    def _analyze_stub(self, item: Any, label: str) -> Analysis:
        result = Analysis()
        if not isinstance(item, dict):
            result.warnings.append(
                make_warning(label, "engine", "expected dict, got %s" % type(item).__name__)
            )
            return result
        if "function" in item and "loop" in item:
            self._run(detect_hash_loop, item, label, result)
        elif "protection" in item:
            self._analyze_region(item, [], label, result)
        elif "requested_access" in item:
            self._run(detect_access_event, item, label, result)
            self._run(track_relation, item, label, result)
        else:
            # Try telemetry as a last resort.
            normalized = normalize_any(item)
            if normalized is not None:
                result.extend(self._analyze_events([item], label))
            else:
                result.warnings.append(
                    make_warning(label, "engine", "unrecognized JSON item")
                )
        return result

    def _run(self, detector: Any, item: Any, label: str, result: Analysis) -> None:
        try:
            self._collect_evidence(detector(item), label, result)
        except Exception as exc:
            name = getattr(detector, "__name__", "detector")
            if name.startswith("detect_"):
                name = name[len("detect_") :]
            elif name.startswith("track_"):
                name = name[len("track_") :]
            result.warnings.append(make_warning(label, name, str(exc)))

    def _collect_evidence(
        self, item: Any, label: str, result: Analysis
    ) -> None:
        if item is None:
            return
        try:
            if isinstance(item, list):
                for index, child in enumerate(item):
                    self._collect_evidence(child, "%s[%d]" % (label, index), result)
                return
            result.evidence.append(validate_evidence(item))
        except Exception as exc:
            result.warnings.append(make_warning(label, "engine", str(exc)))

    # ------------------------------------------------------------------
    # Event pipeline
    # ------------------------------------------------------------------
    def _allowed(self, event: Dict[str, Any]) -> bool:
        source = _basename(event.get("source_name"))
        return not source or source not in self.allowlist

    def _analyze_events(self, raw_events: Sequence[Any], label: str) -> Analysis:
        result = Analysis()
        events = normalize_batch(list(raw_events))
        if not events:
            result.warnings.append(
                make_warning(label, "telemetry", "no recognizable events")
            )
            return result
        events = [event for event in events if self._allowed(event)]
        result.events.extend(events)
        evidence: List[Dict[str, Any]] = []
        prior_events: List[Dict[str, Any]] = []

        for index, event in enumerate(events):
            event_label = "%s/ev#%d" % (label, index)
            if event.get("event_type") == "memory_region":
                self._analyze_region(event, prior_events, event_label, result)
                prior_events.append(event)
                evidence.extend(result.evidence)
                result.evidence = []
                continue
            try:
                evidence.append(validate_evidence(normalize_api_event(event)))
            except Exception as exc:
                result.warnings.append(
                    make_warning(event_label, "api_chain", str(exc))
                )
            try:
                relation = track_relation(event)
                if relation is not None:
                    evidence.append(validate_evidence(relation))
            except Exception as exc:
                result.warnings.append(
                    make_warning(event_label, "source_target", str(exc))
                )
            try:
                remote = detect_remote_thread(event)
                if remote is not None:
                    evidence.append(validate_evidence(remote))
            except Exception as exc:
                result.warnings.append(
                    make_warning(event_label, "remote_thread", str(exc))
                )
            if event.get("requested_access"):
                try:
                    access = detect_access_event(event)
                    if access is not None:
                        evidence.append(validate_evidence(access))
                except Exception as exc:
                    result.warnings.append(
                        make_warning(event_label, "access", str(exc))
                    )
            if event.get("event_type") == "process_tampering":
                evidence.append(
                    {
                        "evidence_id": "ev-tampering-%s"
                        % (event.get("target_pid"),),
                        "area": "runtime",
                        "detector": "process_tampering",
                        "details": dict(event),
                        "weight": 3,
                    }
                )
            prior_events.append(event)

        graph_evidence = detect_graph_behavior(events)
        if graph_evidence is not None:
            try:
                evidence.append(validate_evidence(graph_evidence))
            except Exception as exc:
                result.warnings.append(
                    make_warning(label, "process_graph", str(exc))
                )
        injection = detect_injection_behavior(evidence)
        if injection is not None:
            try:
                evidence.append(validate_evidence(injection))
            except Exception as exc:
                result.warnings.append(
                    make_warning(label, "injection_behavior", str(exc))
                )
        result.evidence.extend(evidence)
        return result

    def _analyze_region(
        self,
        region: Dict[str, Any],
        prior_events: Sequence[Dict[str, Any]],
        label: str,
        result: Analysis,
    ) -> None:
        try:
            rwx = detect_rwx_region(region)
            if rwx is not None:
                result.evidence.append(validate_evidence(rwx))
        except Exception as exc:
            result.warnings.append(make_warning(label, "rwx", str(exc)))
        try:
            rx = detect_rx_anomaly(region, list(prior_events))
            if rx is not None:
                result.evidence.append(validate_evidence(rx))
        except Exception as exc:
            result.warnings.append(make_warning(label, "rx_anomaly", str(exc)))

    # ------------------------------------------------------------------
    # Final assembly
    # ------------------------------------------------------------------
    def finalize(self, analysis: Analysis) -> Dict[str, Any]:
        evidence = _dedupe(analysis.evidence)
        if self.only_layers is not None:
            evidence = [
                item
                for item in evidence
                if item.get("area") in self.only_layers
            ]
        alert, verdict = correlate(
            evidence, allowlist=self.allowlist, threshold=self.threshold
        )
        document: Dict[str, Any] = {
            "evidence": evidence,
            "warnings": analysis.warnings,
            "alert": alert,
            "verdict": verdict,
            "stats": {
                "evidence_count": len(evidence),
                "warning_count": len(analysis.warnings),
                "event_count": len(analysis.events),
                "layers": sorted(
                    {item.get("area") for item in evidence if item.get("area")}
                ),
            },
        }
        if analysis.features:
            document["features"] = analysis.features
        if analysis.events:
            document["graph"] = build_graph(analysis.events)
        return document


def _dedupe(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[Any, Dict[str, Any]] = {}
    order: List[Any] = []
    for item in evidence:
        key = item.get("evidence_id")
        if key is None:
            key = (item.get("detector"), item.get("area"), len(seen))
        if key not in seen:
            seen[key] = item
            order.append(key)
    return [seen[key] for key in order]


def analyze_path(
    path: str,
    allowlist: Optional[Iterable[str]] = None,
    threshold: Optional[int] = None,
    force_format: str = "auto",
    only_layers: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    engine = Engine(
        allowlist=allowlist, threshold=threshold, only_layers=only_layers
    )
    analysis = engine.analyze_path(path, force_format=force_format)
    return engine.finalize(analysis)
