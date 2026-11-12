#!/usr/bin/env python3
"""Generate deterministic, schema-conformant telemetry for the lab dataset.

These files replay the event contract emitted by Footless-loader.  They are
NOT real VM captures: they exist so the detector and the evaluator can be
run and re-run without a Windows guest.  Replace a file with a real
loader.jsonl capture (same schema) and the result becomes measured lab
telemetry; docs/RUNBOOK.md covers the capture procedure.

Run: python datasets/generate_telemetry.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent
TELEMETRY = ROOT / "telemetry"

LOADER_PID = 4210
TARGET_PID = 3312
TARGET_THREAD = 3313
NEW_THREAD = 3314
TARGET_IMAGE = r"C:\Lab\footless_target.exe"
LOADER_IMAGE = r"C:\Lab\footless_loader.exe"
MARKER_DLL = r"C:\Lab\footless_marker.dll"
REMOTE_BUFFER = "0x1f0000"
REMOTE_STUB = "0x1f1000"

RIGHT_MEMORY = [
    "PROCESS_CREATE_THREAD",
    "PROCESS_QUERY_INFORMATION",
    "PROCESS_VM_OPERATION",
    "PROCESS_VM_WRITE",
    "PROCESS_VM_READ",
    "SYNCHRONIZE",
]
RIGHT_QUERY = ["PROCESS_QUERY_INFORMATION"]


def record(
    scenario: str,
    index: int,
    event: str,
    **fields: Any,
) -> Dict[str, Any]:
    base = {
        "utc": "2026-11-13T01:00:%02d.%03dZ" % (index // 10, index * 10),
        "tick_ms": 1000 + index,
        "run_id": scenario,
        "scenario_id": scenario,
        "pid": LOADER_PID,
        "tid": 4211,
        "event": event,
    }
    base.update(fields)
    return base


def base_source(scenario: str, method: str) -> List[Dict[str, Any]]:
    return [
        record(
            scenario,
            0,
            "source_target",
            method=method,
            source_pid=LOADER_PID,
            target_pid=TARGET_PID,
            target_tid=TARGET_THREAD,
            target_image=TARGET_IMAGE,
            marker_dll=MARKER_DLL,
            process_access_mask="0x10143a",
        ),
        record(
            scenario,
            1,
            "process_open",
            operation="open_process",
            api="NtOpenProcess",
            source_pid=LOADER_PID,
            target_pid=TARGET_PID,
            requested_access=RIGHT_MEMORY,
            access_mask="0x10143a",
            ntstatus="0x00000000",
        ),
    ]


def remote_memory(scenario: str, start: int) -> List[Dict[str, Any]]:
    return [
        record(
            scenario,
            start,
            "memory_allocate",
            operation="allocate_memory",
            base_address=REMOTE_BUFFER,
            size=512,
            memory_protection="RW",
            ntstatus="0x00000000",
        ),
        record(
            scenario,
            start + 1,
            "memory_write",
            operation="write_memory",
            base_address=REMOTE_BUFFER,
            size=64,
            bytes_written=64,
            ntstatus="0x00000000",
        ),
    ]


def protect_rx(scenario: str, start: int) -> Dict[str, Any]:
    return record(
        scenario,
        start,
        "memory_protect",
        operation="protect_memory",
        base_address=REMOTE_BUFFER,
        size=64,
        old_protection="0x4",
        memory_protection="RX",
        ntstatus="0x00000000",
    )


def remote_thread(scenario: str, index: int, api: str, start: str) -> Dict[str, Any]:
    return record(
        scenario,
        index,
        "remote_thread",
        operation="create_remote_thread",
        api=api,
        target_pid=TARGET_PID,
        new_tid=NEW_THREAD,
        start_address=start,
        argument=REMOTE_BUFFER,
        result="success",
    )


def scenario_crt() -> List[Dict[str, Any]]:
    records = base_source("P01_crt", "crt")
    records += remote_memory("P01_crt", 2)
    records.append(remote_thread("P01_crt", 4, "CreateRemoteThread", "0x7ffb00001000"))
    return records


def scenario_nt() -> List[Dict[str, Any]]:
    records = base_source("P02_nt", "nt")
    records += remote_memory("P02_nt", 2)
    records.append(remote_thread("P02_nt", 4, "NtCreateThreadEx", "0x7ffb00001000"))
    return records


def scenario_stub(quiet: bool = False) -> List[Dict[str, Any]]:
    name = "P06_quiet_stub" if quiet else "P03_stub"
    api = "api" if quiet else "NtCreateThreadEx"
    records = base_source(name, "stub")
    records += remote_memory(name, 2)
    records.append(protect_rx(name, 4))
    records.append(remote_thread(name, 5, api, REMOTE_BUFFER))
    return records


def scenario_apc() -> List[Dict[str, Any]]:
    records = base_source("P04_apc", "apc")
    records += remote_memory("P04_apc", 2)
    records.append(protect_rx("P04_apc", 4))
    records.append(
        record(
            "P04_apc",
            5,
            "apc_queue",
            operation="queue_apc",
            api="NtQueueApcThread",
            target_pid=TARGET_PID,
            target_tid=TARGET_THREAD,
            callback_address=REMOTE_BUFFER,
            ntstatus="0x00000000",
        )
    )
    records.append(
        record(
            "P04_apc",
            6,
            "apc_observation",
            observation_limit_ms=5000,
            cleanup="deferred_until_target_exit",
        )
    )
    return records


def scenario_section() -> List[Dict[str, Any]]:
    records = base_source("P05_section", "section")
    records.append(
        record(
            "P05_section",
            2,
            "memory_map",
            operation="map_section",
            base_address=REMOTE_STUB,
            size=4096,
            memory_protection="RW",
            memory_backing="pagefile_section",
            ntstatus="0x00000000",
        )
    )
    records.append(
        record(
            "P05_section",
            3,
            "memory_write",
            operation="write_memory",
            base_address=REMOTE_STUB,
            size=64,
            bytes_written=64,
            ntstatus="0x00000000",
        )
    )
    records.append(
        record(
            "P05_section",
            4,
            "memory_protect",
            operation="protect_memory",
            base_address=REMOTE_STUB,
            size=4096,
            old_protection="0x4",
            memory_protection="RX",
            memory_backing="pagefile_section",
            ntstatus="0x00000000",
        )
    )
    records.append(remote_thread("P05_section", 5, "NtCreateThreadEx", REMOTE_STUB))
    return records


def scenario_nt_image() -> List[Dict[str, Any]]:
    records = base_source("P07_nt_image", "nt-image")
    records.append(remote_thread("P07_nt_image", 2, "NtCreateThreadEx", "0x7ffb00002000"))
    return records


def scenario_benign_target() -> List[Dict[str, Any]]:
    records = [
        record(
            "B01_target_only",
            0,
            "source_target",
            method="none",
            source_pid=TARGET_PID,
            target_pid=TARGET_PID,
            target_tid=TARGET_THREAD,
            target_image=TARGET_IMAGE,
        ),
        record(
            "B01_target_only",
            1,
            "memory_allocate",
            operation="allocate_memory",
            base_address="0x800000",
            size=4096,
            memory_protection="RW",
        ),
    ]
    return records


def scenario_benign_selfdll() -> List[Dict[str, Any]]:
    records = [
        record(
            "B02_self_dll",
            0,
            "source_target",
            method="selfdll",
            source_pid=TARGET_PID,
            target_pid=TARGET_PID,
            target_tid=TARGET_THREAD,
            target_image=TARGET_IMAGE,
        ),
        record(
            "B02_self_dll",
            1,
            "image_load",
            source_pid=TARGET_PID,
            target_pid=TARGET_PID,
            image_loaded=MARKER_DLL,
        ),
        record(
            "B02_self_dll",
            2,
            "memory_allocate",
            operation="allocate_memory",
            base_address="0x800000",
            size=4096,
            memory_protection="RW",
        ),
    ]
    return records


def scenario_benign_app() -> List[Dict[str, Any]]:
    records = [
        record(
            "B03_benign_app",
            0,
            "source_target",
            method="none",
            source_pid=5150,
            target_pid=5150,
            target_image=r"C:\Windows\System32\notepad.exe",
        ),
        record(
            "B03_benign_app",
            1,
            "memory_allocate",
            source_pid=5150,
            target_pid=5150,
            operation="allocate_memory",
            base_address="0x900000",
            size=8192,
            memory_protection="RW",
        ),
        record(
            "B03_benign_app",
            2,
            "process_open",
            source_pid=5150,
            target_pid=5150,
            operation="open_process",
            api="OpenProcess",
            requested_access=RIGHT_QUERY,
        ),
    ]
    return records


def scenario_benign_query() -> List[Dict[str, Any]]:
    records = [
        record(
            "B06_weak_query",
            0,
            "process_open",
            source_pid=LOADER_PID,
            target_pid=TARGET_PID,
            operation="open_process",
            api="OpenProcess",
            requested_access=RIGHT_QUERY,
        )
    ]
    return records


def scenario_benign_rwx() -> List[Dict[str, Any]]:
    return [
        record(
            "B05_jit_rwx",
            0,
            "memory_allocate",
            source_pid=5150,
            target_pid=5150,
            operation="allocate_memory",
            base_address="0xa00000",
            size=65536,
            memory_protection="RWX",
        )
    ]


def write_jsonl(name: str, records: List[Dict[str, Any]]) -> None:
    path = TELEMETRY / name
    with path.open("w", encoding="utf-8") as handle:
        for item in records:
            handle.write(json.dumps(item, separators=(",", ":")) + "\n")
    print("wrote %s (%d records)" % (path, len(records)))


def write_sysmon() -> None:
    events = [
        {
            "EventID": 10,
            "UtcTime": "2026-11-13T01:10:00.000Z",
            "SourceImage": LOADER_IMAGE,
            "TargetImage": TARGET_IMAGE,
            "SourceProcessId": LOADER_PID,
            "TargetProcessId": TARGET_PID,
            "GrantedAccess": "0x10143a",
        },
        {
            "EventID": 8,
            "UtcTime": "2026-11-13T01:10:00.010Z",
            "SourceImage": LOADER_IMAGE,
            "TargetImage": TARGET_IMAGE,
            "SourceProcessId": LOADER_PID,
            "TargetProcessId": TARGET_PID,
            "NewThreadId": NEW_THREAD,
            "StartAddress": "0x1f1000",
        },
        {
            "EventID": 10,
            "UtcTime": "2026-11-13T01:10:00.020Z",
            "SourceImage": r"C:\Windows\System32\taskmgr.exe",
            "TargetImage": r"C:\Windows\System32\notepad.exe",
            "SourceProcessId": 6200,
            "TargetProcessId": 6201,
            "GrantedAccess": "0x1000",
        },
        {
            "EventID": 7,
            "UtcTime": "2026-11-13T01:10:00.030Z",
            "Image": r"C:\Windows\System32\notepad.exe",
            "ImageLoaded": r"C:\Windows\System32\shell32.dll",
            "ProcessId": 6201,
        },
    ]
    write_jsonl("P08_sysmon_mixed.jsonl", events)


def scenario_debugger_like() -> List[Dict[str, Any]]:
    """Authorized debugger: behaviourally identical to injection, so it is
    expected to alert.  Kept in the stress set to expose this limit."""
    records = [
        record(
            "X01_debugger_like",
            0,
            "process_open",
            source_pid=5200,
            target_pid=6201,
            source_name="windbg.exe",
            operation="open_process",
            api="OpenProcess",
            requested_access=RIGHT_MEMORY,
        ),
        record(
            "X01_debugger_like",
            1,
            "memory_allocate",
            source_pid=5200,
            target_pid=6201,
            source_name="windbg.exe",
            operation="allocate_memory",
            base_address="0x2a0000",
            size=4096,
            memory_protection="RW",
        ),
        record(
            "X01_debugger_like",
            2,
            "memory_write",
            source_pid=5200,
            target_pid=6201,
            source_name="windbg.exe",
            operation="write_memory",
            base_address="0x2a0000",
            size=16,
        ),
        record(
            "X01_debugger_like",
            3,
            "memory_protect",
            source_pid=5200,
            target_pid=6201,
            source_name="windbg.exe",
            operation="protect_memory",
            base_address="0x2a0000",
            size=16,
            memory_protection="RX",
        ),
        record(
            "X01_debugger_like",
            4,
            "remote_thread",
            source_pid=5200,
            target_pid=6201,
            source_name="windbg.exe",
            operation="create_remote_thread",
            api="CreateRemoteThread",
            new_tid=6202,
            start_address="0x2a0000",
        ),
    ]
    return records


def scenario_benign_installer() -> List[Dict[str, Any]]:
    return [
        record(
            "X02_benign_installer",
            0,
            "process_open",
            source_pid=7000,
            target_pid=7001,
            source_name="setup.exe",
            operation="open_process",
            api="OpenProcess",
            requested_access=["PROCESS_QUERY_INFORMATION"],
        ),
        record(
            "X02_benign_installer",
            1,
            "image_load",
            source_pid=7000,
            target_pid=7000,
            source_name="setup.exe",
            image_loaded=r"C:\Program Files\Vendor\setup_helper.dll",
        ),
    ]


def scenario_injectionlab_runtime() -> List[Dict[str, Any]]:
    records = [
        record(
            "X04_injectionlab_runtime",
            0,
            "process_open",
            source_pid=8000,
            target_pid=8001,
            source_name="NT230_injector.exe",
            target_image="C:\\Lab\\NT230_target.exe",
            operation="open_process",
            api="OpenProcess",
            requested_access=RIGHT_MEMORY,
        )
    ]
    for index, (event, fields) in enumerate(
        (
            (
                "memory_allocate",
                {
                    "operation": "allocate_memory",
                    "base_address": "0x3b0000",
                    "size": 4096,
                    "memory_protection": "RW",
                },
            ),
            (
                "memory_write",
                {
                    "operation": "write_memory",
                    "base_address": "0x3b0000",
                    "size": 12,
                },
            ),
            (
                "memory_protect",
                {
                    "operation": "protect_memory",
                    "base_address": "0x3b0000",
                    "size": 12,
                    "memory_protection": "RX",
                },
            ),
            (
                "remote_thread",
                {
                    "operation": "create_remote_thread",
                    "api": "NtCreateThreadEx",
                    "new_tid": 8002,
                    "start_address": "0x3b0000",
                },
            ),
        ),
        start=1,
    ):
        records.append(
            record(
                "X04_injectionlab_runtime",
                index,
                event,
                source_pid=8000,
                target_pid=8001,
                source_name="NT230_injector.exe",
                target_name="NT230_target.exe",
                **fields,
            )
        )
    return records


def write_loader_log_sample() -> None:
    """A realistic single-run loader.log with benign control noise."""
    write_jsonl(
        "B04_loader_noise.jsonl",
        [
            record(
                "B04_loader_noise",
                0,
                "source_target",
                method="none",
                source_pid=LOADER_PID,
                target_pid=LOADER_PID,
                target_image=LOADER_IMAGE,
            ),
            record(
                "B04_loader_noise",
                1,
                "memory_allocate",
                operation="allocate_memory",
                base_address="0x1e0000",
                size=1024,
                memory_protection="RW",
            ),
            record(
                "B04_loader_noise",
                2,
                "memory_free",
                operation="free_memory",
                base_address="0x1e0000",
                ntstatus="0x00000000",
            ),
        ],
    )


def main() -> None:
    TELEMETRY.mkdir(parents=True, exist_ok=True)
    write_jsonl("B01_target_only.jsonl", scenario_benign_target())
    write_jsonl("B02_self_dll.jsonl", scenario_benign_selfdll())
    write_jsonl("B03_benign_app.jsonl", scenario_benign_app())
    write_jsonl("B05_jit_rwx.jsonl", scenario_benign_rwx())
    write_jsonl("B06_weak_query.jsonl", scenario_benign_query())
    write_loader_log_sample()
    write_jsonl("P01_crt.jsonl", scenario_crt())
    write_jsonl("P02_nt.jsonl", scenario_nt())
    write_jsonl("P03_stub.jsonl", scenario_stub())
    write_jsonl("P04_apc.jsonl", scenario_apc())
    write_jsonl("P05_section.jsonl", scenario_section())
    write_jsonl("P06_quiet_stub.jsonl", scenario_stub(quiet=True))
    write_jsonl("P07_nt_image.jsonl", scenario_nt_image())
    write_sysmon()
    write_jsonl("X01_debugger_like.jsonl", scenario_debugger_like())
    write_jsonl("X02_benign_installer.jsonl", scenario_benign_installer())
    write_jsonl("X04_injectionlab_runtime.jsonl", scenario_injectionlab_runtime())


if __name__ == "__main__":
    main()
