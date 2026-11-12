#!/usr/bin/env python3
"""Populate datasets/pe with local lab build artifacts (not committed).

The repository tracks source, telemetry and reports, not compiled binaries.
Run this after building the loader:

    cd Footless-loader && ./build.sh
    cd ../Footless-detector && python tools/sync_samples.py

Optional stress sample:
    ../Footless-loader/InjectionLab/bin/NT230_injector.exe
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "datasets" / "pe"
LOADER_DIST = ROOT.parent / "Footless-loader" / "dist"
INJECTION_DIST = ROOT.parent / "Footless-loader" / "InjectionLab" / "bin"

REQUIRED = (
    "footless_loader.exe",
    "footless_loader_seeded.exe",
    "footless_loader_module_api.exe",
    "footless_loader_quiet.exe",
    "footless_loader_seed_alt.exe",
    "benign_app.exe",
    "footless_target.exe",
    "footless_marker.dll",
)
OPTIONAL = ("NT230_injector.exe",)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    missing = []
    copied = []
    for name in REQUIRED:
        source = LOADER_DIST / name
        if not source.exists():
            missing.append(str(source))
            continue
        shutil.copy2(source, OUT / name)
        copied.append(name)
    for name in OPTIONAL:
        source = INJECTION_DIST / name
        if source.exists():
            shutil.copy2(source, OUT / name)
            copied.append(name)
        else:
            (OUT / name).unlink(missing_ok=True)
            print("note: optional stress sample missing: %s" % source)
    hashes = []
    for name in sorted(copied):
        path = OUT / name
        hashes.append("%s  %s" % (digest(path), name))
    (OUT / "SHA256.txt").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    print("copied %d samples to %s" % (len(copied), OUT))
    if missing:
        print("missing required artifacts:", file=sys.stderr)
        for item in missing:
            print("  " + item, file=sys.stderr)
        print("build the loader first: cd Footless-loader && ./build.sh", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
