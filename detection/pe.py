"""Dependency-free PE parser and static feature extractor.

This module is deliberately independent from the loader: it reads only
the file bytes.  It implements the subset of PE needed for triage:

* headers, sections, entropy and overlay
* import and export tables
* security directory / mitigation flags
* byte-level heuristics for PEB access and hash loops

The heuristics are indicators, not proof.  They are combined with
runtime telemetry by detection/engine.py.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_SECURITY = 4

SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

DLL_ASLR = 0x0040
DLL_DEP = 0x0100
DLL_CFG = 0x4000

# APIs that matter for injection / dynamic resolution.  Their absence from
# the IAT while the code resolves APIs dynamically is the anomaly.
SENSITIVE_IMPORTS = frozenset(
    {
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "OpenProcess",
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "QueueUserAPC",
        "SetThreadContext",
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
        "MapViewOfFile",
        "CreateFileMappingA",
        "CreateFileMappingW",
    }
)

INJECTION_CLUSTER = frozenset(
    {
        "OpenProcess",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "VirtualProtectEx",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "QueueUserAPC",
        "SetThreadContext",
        "MapViewOfFile",
        "NtCreateThreadEx",
        "NtMapViewOfSection",
    }
)

HASH_CONSTANTS = {
    0x01000193: "fnv1a_prime",
    0x811C9DC5: "fnv1a_offset",
    0x9E3779B9: "golden_ratio32",
    0xA5A5A5A5: "lab_seed_mix",
    0xEDB88320: "crc32_poly",
}

TRANSFORM_BYTES = frozenset(
    {
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x28,
        0x29,
        0x2B,
        0x2D,
        0x30,
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x69,
        0x6B,
        0xC0,
        0xC1,
        0xD0,
        0xD1,
        0xD2,
        0xD3,
        0xF7,
    }
)


class PEError(ValueError):
    """Raised when the input is not a parseable PE file."""


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float = 0.0
    data: bytes = b""

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_READ)

    @property
    def rwx(self) -> bool:
        return self.executable and self.writable


@dataclass
class PEInfo:
    path: str
    file_size: int
    machine: int
    timestamp: int
    is_64: bool
    image_base: int
    entry_point: int
    size_of_image: int
    size_of_headers: int
    subsystem: int
    dll_characteristics: int
    sections: List[Section] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    exports: List[str] = field(default_factory=list)
    has_security_directory: bool = False
    overlay_size: int = 0
    parse_warnings: List[str] = field(default_factory=list)

    @property
    def import_count(self) -> int:
        return sum(len(names) for names in self.imports.values())

    @property
    def imported_names(self) -> List[str]:
        return [name for names in self.imports.values() for name in names]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = float(len(data))
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def _cstring(data: bytes, offset: int, limit: int) -> str:
    end = data.find(b"\x00", offset, min(offset + limit, len(data)))
    if end < 0:
        end = min(offset + limit, len(data))
    return data[offset:end].decode("ascii", "replace")


def parse_pe(path: str) -> PEInfo:
    """Parse one PE file; raise PEError on malformed input."""
    raw = Path(path).read_bytes()
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        raise PEError("missing MZ signature")
    e_lfanew = _u32(raw, 0x3C)
    if e_lfanew + 0x18 > len(raw):
        raise PEError("e_lfanew outside file")
    if raw[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("missing PE signature")
    coff = e_lfanew + 4
    machine = _u16(raw, coff)
    number_of_sections = _u16(raw, coff + 2)
    timestamp = _u32(raw, coff + 4)
    optional_size = _u16(raw, coff + 16)
    optional = coff + 20
    if optional + optional_size > len(raw) or optional_size < 0x60:
        raise PEError("optional header outside file")
    magic = _u16(raw, optional)
    if magic not in (PE32_MAGIC, PE32_PLUS_MAGIC):
        raise PEError("unsupported optional header magic 0x%x" % magic)
    is_64 = magic == PE32_PLUS_MAGIC
    entry_point = _u32(raw, optional + 16)
    image_base = struct.unpack_from(
        "<Q" if is_64 else "<I", raw, optional + 24
    )[0]
    size_of_image = _u32(raw, optional + 56)
    size_of_headers = _u32(raw, optional + 60)
    subsystem = _u16(raw, optional + 68)
    dll_characteristics = _u16(raw, optional + 70)
    directory_offset = optional + (112 if is_64 else 96)
    directory_count = _u32(raw, optional + (108 if is_64 else 92))
    directories: List[Tuple[int, int]] = []
    for index in range(min(directory_count, 16)):
        entry = directory_offset + index * 8
        if entry + 8 > optional + optional_size or entry + 8 > len(raw):
            break
        directories.append((_u32(raw, entry), _u32(raw, entry + 4)))

    info = PEInfo(
        path=str(path),
        file_size=len(raw),
        machine=machine,
        timestamp=timestamp,
        is_64=is_64,
        image_base=image_base,
        entry_point=entry_point,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
    )

    section_offset = optional + optional_size
    for index in range(number_of_sections):
        offset = section_offset + index * 40
        if offset + 40 > len(raw):
            info.parse_warnings.append("section %d truncated" % index)
            break
        name = raw[offset : offset + 8].rstrip(b"\x00").decode("ascii", "replace")
        virtual_size = _u32(raw, offset + 8)
        virtual_address = _u32(raw, offset + 12)
        raw_size = _u32(raw, offset + 16)
        raw_offset = _u32(raw, offset + 20)
        characteristics = _u32(raw, offset + 36)
        data = b""
        if (
            raw_offset < len(raw)
            and raw_size > 0
            and raw_offset + min(raw_size, len(raw) - raw_offset) <= len(raw)
        ):
            data = raw[raw_offset : raw_offset + raw_size]
        info.sections.append(
            Section(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=characteristics,
                entropy=shannon_entropy(data),
                data=data,
            )
        )

    if info.sections:
        image_end = max(
            section.raw_offset + section.raw_size for section in info.sections
        )
        info.overlay_size = max(0, len(raw) - image_end)

    for index in directories:
        if index[1]:
            if index is directories[IMAGE_DIRECTORY_ENTRY_SECURITY]:
                info.has_security_directory = True

    try:
        info.imports = _parse_imports(raw, info, directories)
    except (struct.error, IndexError) as exc:
        info.parse_warnings.append("import table: %s" % exc)
    try:
        info.exports = _parse_exports(raw, info, directories)
    except (struct.error, IndexError) as exc:
        info.parse_warnings.append("export table: %s" % exc)
    return info


def _rva_to_offset(info: PEInfo, rva: int) -> Optional[int]:
    if rva < info.size_of_headers:
        return rva if rva < info.file_size else None
    for section in info.sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            delta = rva - section.virtual_address
            if delta < section.raw_size:
                return section.raw_offset + delta
    return None


def _directory(info: PEInfo, raw: bytes, index: int) -> Tuple[int, int]:
    # Directories are re-read from the header because PEInfo keeps only
    # the values used by the caller.
    e_lfanew = _u32(raw, 0x3C)
    optional = e_lfanew + 4 + 20
    is_64 = info.is_64
    directory_offset = optional + (112 if is_64 else 96)
    entry = directory_offset + index * 8
    if entry + 8 > len(raw):
        return 0, 0
    return _u32(raw, entry), _u32(raw, entry + 4)


def _parse_imports(
    raw: bytes, info: PEInfo, directories: List[Tuple[int, int]]
) -> Dict[str, List[str]]:
    if len(directories) <= IMAGE_DIRECTORY_ENTRY_IMPORT:
        return {}
    import_rva, import_size = directories[IMAGE_DIRECTORY_ENTRY_IMPORT]
    if not import_rva or not import_size:
        return {}
    offset = _rva_to_offset(info, import_rva)
    if offset is None:
        return {}
    result: Dict[str, List[str]] = {}
    for descriptor_index in range(512):
        base = offset + descriptor_index * 20
        if base + 20 > len(raw):
            break
        original_thunk = _u32(raw, base)
        name_rva = _u32(raw, base + 12)
        first_thunk = _u32(raw, base + 16)
        if not any((original_thunk, name_rva, first_thunk)):
            break
        name_offset = _rva_to_offset(info, name_rva)
        dll_name = (
            _cstring(raw, name_offset, 256) if name_offset is not None else "?"
        )
        thunk_rva = original_thunk or first_thunk
        thunk_offset = _rva_to_offset(info, thunk_rva)
        names: List[str] = []
        if thunk_offset is not None:
            width = 8 if info.is_64 else 4
            for thunk_index in range(4096):
                entry_offset = thunk_offset + thunk_index * width
                if entry_offset + width > len(raw):
                    break
                value = struct.unpack_from(
                    "<Q" if info.is_64 else "<I", raw, entry_offset
                )[0]
                if value == 0:
                    break
                ordinal_flag = 1 << 63 if info.is_64 else 1 << 31
                if value & ordinal_flag:
                    names.append("#%d" % (value & 0xFFFF))
                    continue
                hint_offset = _rva_to_offset(info, value)
                if hint_offset is None or hint_offset + 2 > len(raw):
                    break
                names.append(_cstring(raw, hint_offset + 2, 256))
        result[dll_name] = names
    return result


def _parse_exports(
    raw: bytes, info: PEInfo, directories: List[Tuple[int, int]]
) -> List[str]:
    if not directories or not directories[IMAGE_DIRECTORY_ENTRY_EXPORT][0]:
        return []
    export_rva, export_size = directories[IMAGE_DIRECTORY_ENTRY_EXPORT]
    offset = _rva_to_offset(info, export_rva)
    if offset is None or offset + 40 > len(raw):
        return []
    number_of_names = _u32(raw, offset + 24)
    address_of_names = _u32(raw, offset + 32)
    names_offset = _rva_to_offset(info, address_of_names)
    if names_offset is None:
        return []
    names: List[str] = []
    for index in range(min(number_of_names, 4096)):
        entry = names_offset + index * 4
        if entry + 4 > len(raw):
            break
        name_offset = _rva_to_offset(info, _u32(raw, entry))
        if name_offset is None:
            break
        names.append(_cstring(raw, name_offset, 256))
    return names


def _peb_access_offsets(data: bytes) -> List[int]:
    """Find x64 PEB reads emitted by MSVC and GCC/MinGW codegen."""
    offsets: List[int] = []
    index = 0
    while True:
        index = data.find(b"\x65\x48\x8b", index)
        if index < 0:
            break
        window = data[index : index + 12]
        if b"\x60\x00\x00\x00" in window:
            offsets.append(index)
        index += 3
    index = 0
    while True:
        index = data.find(b"\xb8\x60\x00\x00\x00\x65\x67\x48\x8b", index)
        if index < 0:
            break
        offsets.append(index)
        index += 6
    return offsets


def _hash_loop_candidates(data: bytes) -> List[int]:
    """Locate tight hash-style loops with arithmetic and a backward branch.

    A window is a candidate only when a backward branch closes a loop body
    that contains a byte load, at least one rotate/shift, and at least two
    arithmetic/bitwise transforms.  This is stricter than counting opcode
    bytes in an arbitrary 64-byte window; that naive version flagged most
    normal compiler loops.
    """
    candidates: List[int] = []
    length = len(data)
    for branch in range(2, length - 1):
        byte = data[branch]
        displacement = 0
        if 0x70 <= byte <= 0x7F:
            displacement = struct.unpack_from("<b", data, branch + 1)[0]
        elif byte == 0xE2:
            displacement = struct.unpack_from("<b", data, branch + 1)[0]
        elif byte in (0xE8, 0xE9) and branch + 5 <= length:
            displacement = struct.unpack_from("<i", data, branch + 1)[0]
        else:
            continue
        if displacement >= -2 or displacement < -96:
            continue
        start = max(0, branch + displacement)
        body = data[start:branch]
        if len(body) < 8:
            continue
        has_load = b"\x0f\xb6" in body or b"\x8a" in body
        has_rotate = any(
            value in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3)
            for value in body
        )
        transforms = sum(1 for value in body if value in TRANSFORM_BYTES)
        has_compare = any(value in body for value in (0x38, 0x39, 0x3A, 0x3B))
        has_compare = has_compare or b"\x83\xf8" in body or b"\x3d" in body
        has_mix = (
            b"\xc1\xc0\x05" in body
            or b"\xc1\xc8\x05" in body
            or b"\xc1\xd0\x05" in body
            or b"\xc1\xd8\x05" in body
            or b"\x69\xc0\x93\x01\x00\x01" in body
        )
        if has_load and has_rotate and has_mix and transforms >= 4 and has_compare:
            if not candidates or start - candidates[-1] > 48:
                candidates.append(start)
    return candidates


def _constant_hits(data: bytes) -> List[str]:
    hits: List[str] = []
    for value, name in HASH_CONSTANTS.items():
        needle = struct.pack("<I", value)
        if needle in data:
            hits.append(name)
    return hits


def static_features(info: PEInfo) -> Dict[str, Any]:
    """Derive detector features from one parsed PE."""
    executable = [section for section in info.sections if section.executable]
    code = b"".join(section.data for section in executable)
    hash_candidates: List[Tuple[str, int]] = []
    for section in executable:
        for offset in _hash_loop_candidates(section.data):
            hash_candidates.append((section.name, offset))
    peb_offsets = _peb_access_offsets(code)
    constants = _constant_hits(code)
    imported = set(info.imported_names)
    sensitive = sorted(imported & SENSITIVE_IMPORTS)
    cluster = sorted(imported & INJECTION_CLUSTER)
    rwx_sections = [section.name for section in info.sections if section.rwx]
    high_entropy = [
        section.name for section in info.sections if section.entropy >= 7.2
    ]
    return {
        "file": info.path,
        "file_size": info.file_size,
        "is_64": info.is_64,
        "machine": "x64" if info.machine == 0x8664 else hex(info.machine),
        "entry_point": "0x%x" % info.entry_point,
        "image_base": "0x%x" % info.image_base,
        "section_count": len(info.sections),
        "sections": [
            {
                "name": section.name,
                "virtual_address": "0x%x" % section.virtual_address,
                "virtual_size": section.virtual_size,
                "raw_size": section.raw_size,
                "characteristics": "0x%x" % section.characteristics,
                "entropy": round(section.entropy, 3),
                "executable": section.executable,
                "writable": section.writable,
            }
            for section in info.sections
        ],
        "import_dlls": sorted(info.imports),
        "import_count": info.import_count,
        "sensitive_imports": sensitive,
        "has_sensitive_imports": bool(sensitive),
        "injection_cluster": cluster,
        "exports": info.exports[:50],
        "rwx_sections": rwx_sections,
        "high_entropy_sections": high_entropy,
        "overlay_size": info.overlay_size,
        "signed": info.has_security_directory,
        "aslr": bool(info.dll_characteristics & DLL_ASLR),
        "dep": bool(info.dll_characteristics & DLL_DEP),
        "cfg": bool(info.dll_characteristics & DLL_CFG),
        "peb_access_offsets": ["0x%x" % offset for offset in peb_offsets[:20]],
        "peb_access": bool(peb_offsets),
        "hash_loop_candidates": [
            {"section": name, "offset": "0x%x" % offset}
            for name, offset in hash_candidates[:20]
        ],
        "hash_loop_count": len(hash_candidates),
        "hash_constants": constants,
        "parse_warnings": info.parse_warnings,
    }


def analyze_file(path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Parse a PE and return (features, evidence) with no alert logic."""
    info = parse_pe(path)
    features = static_features(info)
    evidence: List[Dict[str, Any]] = []

    if features["hash_loop_count"] or features["hash_constants"]:
        evidence.append(
            {
                "evidence_id": "ev-pe-hash-loop-%s"
                % Path(path).name,
                "area": "static",
                "detector": "hash_loop",
                "details": {
                    "file": path,
                    "hash_loop_count": features["hash_loop_count"],
                    "candidates": features["hash_loop_candidates"],
                    "hash_constants": features["hash_constants"],
                    "peb_access": features["peb_access"],
                },
                "weight": 2,
            }
        )

    dynamic = features["peb_access"] and (
        features["hash_loop_count"]
        or features["hash_constants"]
        or not features["has_sensitive_imports"]
    )
    if dynamic:
        observed = ["peb_module_walk"]
        if features["hash_loop_count"]:
            observed.append("hash_comparison")
        if features["hash_constants"]:
            observed.append("hash_constants")
        if not features["has_sensitive_imports"]:
            observed.append("sensitive_api_gap")
        evidence.append(
            {
                "evidence_id": "ev-pe-dynamic-resolve-%s"
                % Path(path).name,
                "area": "static",
                "detector": "dynamic_resolve",
                "details": {
                    "file": path,
                    "module": "peb+export_table",
                    "peb_access": True,
                    "export_traversal": True,
                    "name_iteration": True,
                    "hash_compare": bool(features["hash_loop_count"]),
                    "indirect_call": not features["has_sensitive_imports"],
                    "evidence": observed,
                    "peb_access_offsets": features["peb_access_offsets"],
                },
                "weight": 3,
            }
        )

    if (
        not features["has_sensitive_imports"]
        and (features["hash_loop_count"] or features["peb_access"])
        and features["import_count"] < 80
    ):
        evidence.append(
            {
                "evidence_id": "ev-pe-import-gap-%s" % Path(path).name,
                "area": "static_pe",
                "detector": "import_anomaly",
                "details": {
                    "file": path,
                    "reason": "sensitive_api_absence",
                    "import_count": features["import_count"],
                    "runtime_api_count": 0,
                    "sensitive_imports": [],
                    "note": "IAT lacks Nt*/injection APIs while dynamic "
                    "resolution indicators are present",
                },
                "weight": 2,
            }
        )

    cluster = features["injection_cluster"]
    if len(cluster) >= 4:
        evidence.append(
            {
                "evidence_id": "ev-pe-import-cluster-%s" % Path(path).name,
                "area": "static_pe",
                "detector": "sensitive_import_cluster",
                "details": {
                    "file": path,
                    "apis": cluster,
                    "cluster_size": len(cluster),
                    "note": "classic injection IAT cluster; supporting only",
                },
                "weight": 2,
            }
        )

    if features["rwx_sections"]:
        evidence.append(
            {
                "evidence_id": "ev-pe-rwx-%s" % Path(path).name,
                "area": "memory",
                "detector": "rwx_section",
                "details": {
                    "file": path,
                    "sections": features["rwx_sections"],
                    "memory_protection": "RWX",
                    "note": "static section flags; confirm at runtime",
                },
                "weight": 3,
            }
        )

    if (
        features["high_entropy_sections"]
        and not features["has_sensitive_imports"]
        and features["import_count"] < 10
    ):
        evidence.append(
            {
                "evidence_id": "ev-pe-packed-%s" % Path(path).name,
                "area": "static_pe",
                "detector": "packed",
                "details": {
                    "file": path,
                    "high_entropy_sections": features["high_entropy_sections"],
                    "import_count": features["import_count"],
                },
                "weight": 2,
            }
        )

    return features, evidence
