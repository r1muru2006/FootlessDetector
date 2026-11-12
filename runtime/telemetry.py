"""Telemetry normalization (loader JSONL, Sysmon/ETW-shaped JSON, generic).

Every adapter returns the same normalized event dict consumed by
runtime/* detectors and detection/graph.py.  Raw telemetry is never
trusted: missing fields become explicit placeholders and the engine
turns malformed records into warnings instead of aborting the run.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_RESULT = "unknown"

ACCESS_FLAGS = (
    (0x0001, "PROCESS_TERMINATE"),
    (0x0002, "PROCESS_CREATE_THREAD"),
    (0x0008, "PROCESS_VM_OPERATION"),
    (0x0010, "PROCESS_VM_READ"),
    (0x0020, "PROCESS_VM_WRITE"),
    (0x0040, "PROCESS_DUP_HANDLE"),
    (0x0080, "PROCESS_SET_INFORMATION"),
    (0x0100, "PROCESS_SET_QUOTA"),
    (0x0200, "PROCESS_SUSPEND_RESUME"),
    (0x0400, "PROCESS_QUERY_INFORMATION"),
    (0x0800, "PROCESS_SUSPEND_RESUME"),
    (0x1000, "PROCESS_QUERY_LIMITED_INFORMATION"),
    (0x100000, "SYNCHRONIZE"),
)

FULL_ACCESS = {0x1FFFFF, 0x1F0FFF, 0x001FFFFF, 0xFFFFFFFF}


def decode_access_mask(value: Any) -> List[str]:
    """Translate a Sysmon GrantedAccess mask into canonical right names."""
    if isinstance(value, str):
        try:
            mask = int(value, 0)
        except ValueError:
            return [value]
    elif isinstance(value, int) and not isinstance(value, bool):
        mask = value
    else:
        return []
    if mask in FULL_ACCESS or mask > 0x1FFFFF:
        return [
            "PROCESS_CREATE_THREAD",
            "PROCESS_VM_OPERATION",
            "PROCESS_VM_WRITE",
            "PROCESS_VM_READ",
            "PROCESS_QUERY_INFORMATION",
            "SYNCHRONIZE",
        ]
    rights = [name for bit, name in ACCESS_FLAGS if mask & bit]
    # Collapse the duplicate suspend/resume spelling.
    return sorted(set(rights))


def _basename(path: Any) -> str:
    if not isinstance(path, str) or not path:
        return "unknown"
    return os.path.basename(path.replace("\\", "/"))


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _text(value: Any, fallback: str = "unknown") -> str:
    if isinstance(value, str) and value:
        return value
    return fallback


def _event_time(event: Dict[str, Any]) -> str:
    for key in ("utc", "UtcTime", "timestamp", "time", "@timestamp"):
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    system = event.get("System")
    if isinstance(system, dict):
        created = system.get("TimeCreated")
        if isinstance(created, dict) and isinstance(created.get("SystemTime"), str):
            return created["SystemTime"]
    return "1970-01-01T00:00:00Z"


LOADER_EVENT_NAMES = frozenset(
    {
        "source_target",
        "process_open",
        "memory_allocate",
        "memory_write",
        "memory_protect",
        "memory_map",
        "memory_free",
        "remote_thread",
        "apc_queue",
        "apc_observation",
        "image_load",
        "dll_load",
        "thread_wait",
        "thread_exit",
        "opened_thread",
        "result",
        "error",
    }
)


def is_loader_event(event: Any) -> bool:
    return isinstance(event, dict) and _looks_loader(event)


def _looks_loader(event: Dict[str, Any]) -> bool:
    if not isinstance(event.get("event"), str):
        return False
    if event["event"] in LOADER_EVENT_NAMES:
        return True
    return "run_id" in event or "scenario_id" in event or "tick_ms" in event


def _looks_sysmon(event: Dict[str, Any]) -> bool:
    if "EventID" in event or "event_id" in event:
        return True
    system = event.get("System")
    return isinstance(system, dict) and "EventID" in system


def _sysmon_data(event: Dict[str, Any]) -> Dict[str, Any]:
    system = event.get("System")
    data = event.get("EventData")
    merged: Dict[str, Any] = {}
    if isinstance(system, dict):
        merged.update(system)
    if isinstance(data, dict):
        merged.update(data)
    collector_data = event.get("data")
    if isinstance(collector_data, dict):
        merged.update(collector_data)
    # Flat collector output is already the EventData map.
    for key, value in event.items():
        if key not in ("Event", "System", "EventData", "data"):
            merged.setdefault(key, value)
    if "EventID" not in merged and "event_id" in event:
        merged["EventID"] = event["event_id"]
    return merged


def normalize_sysmon_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map one Sysmon event to the normalized schema; None if irrelevant."""
    data = _sysmon_data(event)
    event_id = _int(data.get("EventID"))
    timestamp = _text(
        data.get("UtcTime") or data.get("SystemTime") or event.get("utc"),
        _event_time(event),
    )
    if event_id == 8:
        source_pid = _int(data.get("SourceProcessId") or data.get("SourceProcessGUID"))
        target_pid = _int(data.get("TargetProcessId"))
        return {
            "timestamp": timestamp,
            "source_pid": source_pid if source_pid is not None else -1,
            "source_name": _basename(data.get("SourceImage")),
            "target_pid": target_pid if target_pid is not None else -1,
            "target_name": _basename(data.get("TargetImage")),
            "api": "CreateRemoteThread",
            "operation": "create_remote_thread",
            "event_type": "thread_creation",
            "result": _text(data.get("Result"), "observed"),
            "start_address": _text(data.get("StartAddress"), ""),
            "new_tid": _int(data.get("NewThreadId")),
            "source": "sysmon",
        }
    if event_id == 10:
        source_pid = _int(data.get("SourceProcessId"))
        target_pid = _int(data.get("TargetProcessId"))
        rights = decode_access_mask(data.get("GrantedAccess"))
        return {
            "timestamp": timestamp,
            "source_pid": source_pid if source_pid is not None else -1,
            "source_name": _basename(data.get("SourceImage")),
            "target_pid": target_pid if target_pid is not None else -1,
            "target_name": _basename(data.get("TargetImage")),
            "api": "OpenProcess",
            "operation": "open_process",
            "event_type": "process_access",
            "result": "observed",
            "requested_access": rights,
            "source": "sysmon",
        }
    if event_id == 7:
        pid = _int(data.get("ProcessId"))
        image = _text(data.get("Image"))
        loaded = _text(data.get("ImageLoaded"), "")
        return {
            "timestamp": timestamp,
            "source_pid": pid if pid is not None else -1,
            "source_name": _basename(image),
            "target_pid": pid if pid is not None else -1,
            "target_name": _basename(image),
            "api": "LoadLibrary",
            "operation": "image_load",
            "event_type": "image_load",
            "result": "observed",
            "image_loaded": _basename(loaded),
            "source": "sysmon",
        }
    if event_id == 25:
        pid = _int(data.get("ProcessId"))
        image = _text(data.get("Image"))
        return {
            "timestamp": timestamp,
            "source_pid": pid if pid is not None else -1,
            "source_name": _basename(image),
            "target_pid": pid if pid is not None else -1,
            "target_name": _basename(image),
            "api": "ProcessTampering",
            "operation": "process_tampering",
            "event_type": "process_tampering",
            "result": "observed",
            "tampering_type": _text(data.get("Type"), "unknown"),
            "source": "sysmon",
        }
    return None


def _context_from_loader(event: Dict[str, Any]) -> Dict[str, Any]:
    target_image = event.get("target_image") or event.get("image")
    return {
        "timestamp": _event_time(event),
        "source_pid": _int(event.get("source_pid")),
        "source_name": _basename(event.get("source_image")) or "loader.exe",
        "target_pid": _int(event.get("target_pid")),
        "target_name": _basename(target_image) or "target.exe",
        "method": event.get("method"),
        "source": "loader",
    }


def normalize_loader_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize loader.jsonl records, carrying source/target context."""
    normalized: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {
        "timestamp": "1970-01-01T00:00:00Z",
        "source_pid": -1,
        "source_name": "loader.exe",
        "target_pid": -1,
        "target_name": "target.exe",
        "source": "loader",
    }
    for raw in events:
        if not isinstance(raw, dict):
            continue
        kind = raw.get("event")
        if kind in ("source_target", "process_open"):
            update = _context_from_loader(raw)
            for key in ("source_pid", "source_name", "target_pid", "target_name"):
                if update.get(key) not in (None, -1, "unknown", ""):
                    context[key] = update[key]
            if kind == "source_target":
                continue
        def merged(extra: Dict[str, Any]) -> Dict[str, Any]:
            item = dict(context)
            item.update(extra)
            item["timestamp"] = extra.get("timestamp") or _event_time(raw)
            item["source"] = "loader"
            return item

        if kind == "process_open":
            normalized.append(
                merged(
                    {
                        "api": raw.get("api") or "NtOpenProcess",
                        "operation": raw.get("operation") or "open_process",
                        "event_type": "process_access",
                        "result": _text(raw.get("result"), "success"),
                        "requested_access": raw.get("requested_access") or [],
                    }
                )
            )
        elif kind in ("memory_allocate", "memory_write", "memory_protect", "memory_map"):
            operation = _text(raw.get("operation"))
            protection = raw.get("memory_protection") or raw.get("new_protection")
            item = merged(
                {
                    "api": raw.get("api") or operation,
                    "operation": operation,
                    "event_type": "process_memory_operation",
                    "result": "success",
                    "base_address": raw.get("base_address"),
                    "size": raw.get("size"),
                }
            )
            if protection:
                item["memory_protection"] = protection
            if raw.get("memory_backing"):
                item["memory_backing"] = raw["memory_backing"]
            normalized.append(item)
            if protection and raw.get("base_address"):
                region = dict(item)
                region["event_type"] = "memory_region"
                region["owner_pid"] = item.get("target_pid")
                region["owner_process"] = item.get("target_name")
                region["type"] = raw.get("memory_backing", "private")
                region["protection"] = protection
                normalized.append(region)
        elif kind == "remote_thread":
            normalized.append(
                merged(
                    {
                        "api": raw.get("api") or "CreateRemoteThread",
                        "operation": raw.get("operation") or "create_remote_thread",
                        "event_type": "thread_creation",
                        "result": "success",
                        "start_address": raw.get("start_address"),
                        "new_tid": raw.get("new_tid"),
                    }
                )
            )
        elif kind == "apc_queue":
            normalized.append(
                merged(
                    {
                        "api": raw.get("api") or "NtQueueApcThread",
                        "operation": raw.get("operation") or "queue_apc",
                        "event_type": "thread_apc",
                        "result": "queued",
                        "new_tid": raw.get("target_tid"),
                        "start_address": raw.get("callback_address"),
                    }
                )
            )
        elif kind == "image_load" or kind == "dll_load":
            normalized.append(
                merged(
                    {
                        "api": "LoadLibrary",
                        "operation": "image_load",
                        "event_type": "image_load",
                        "result": "success",
                        "image_loaded": _basename(raw.get("image_loaded")),
                    }
                )
            )
    return normalized


def normalize_generic_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Accept an already GUIDE-shaped event; fill only obvious defaults."""
    if "api" not in event and "operation" not in event:
        return None
    source_pid = _int(event.get("source_pid"))
    target_pid = _int(event.get("target_pid"))
    item = dict(event)
    item["timestamp"] = _event_time(event)
    item["source_pid"] = source_pid if source_pid is not None else -1
    item["target_pid"] = target_pid if target_pid is not None else -1
    item["source_name"] = _text(event.get("source_name"))
    item["target_name"] = _text(event.get("target_name"))
    item["api"] = _text(event.get("api"), "unknown")
    item["operation"] = _text(event.get("operation"), "unknown")
    item["event_type"] = _text(event.get("event_type"), "api_event")
    item["result"] = _text(event.get("result"), DEFAULT_RESULT)
    item["source"] = event.get("source", "generic")
    return item


def normalize_any(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if _looks_loader(event):
        records = normalize_loader_events([event])
        return records[0] if records else None
    if _looks_sysmon(event):
        return normalize_sysmon_event(event)
    return normalize_generic_event(event)


def normalize_batch(payload: Any) -> List[Dict[str, Any]]:
    """Normalize a list of raw events or a loader log file body."""
    if isinstance(payload, dict):
        if _looks_loader(payload) or _looks_sysmon(payload):
            payload = [payload]
        elif isinstance(payload.get("events"), list):
            payload = payload["events"]
        elif isinstance(payload.get("telemetry"), list):
            payload = payload["telemetry"]
        else:
            payload = [payload]
    if not isinstance(payload, list):
        return []
    if any(_looks_loader(item) for item in payload if isinstance(item, dict)):
        return normalize_loader_events(item for item in payload if isinstance(item, dict))
    result: List[Dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        normalized = normalize_any(item)
        if normalized is not None:
            result.append(normalized)
    return result
