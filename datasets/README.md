# Dataset

## Files

- `manifest.csv` — core benchmark, 22 rows (14 telemetry + 8 PE).
- `stress_manifest.csv` — 4-row stress set for documented limits.
- `telemetry/*.jsonl` — event records in the loader schema or Sysmon schema.
- `pe/*.exe`, `pe/*.dll` — benign lab binaries and loader variants. These are
  **not committed** (ignored); run `python tools/sync_samples.py` after
  building the loader to populate the directory.
- `pe/SHA256.txt` — generated hashes of the local PE samples (also ignored).
- `generate_telemetry.py` — deterministic generator for the telemetry files.

## Synthetic vs real

The JSONL files are **synthetic replays** of the loader event contract, not
Windows VM captures. They are generated deterministically so the detector and
evaluator can be re-run without a guest. They are not presented as measured
lab telemetry.

To use real data:

1. Run `../Footless-loader/docs/RUNBOOK.md` in the VM.
2. Copy `loader.jsonl` and/or Sysmon `telemetry.jsonl` from each run.
3. Create a manifest with `scenario_id,label,format,path,...` pointing at the
   real files (`format=jsonl`).
4. Run `python evaluate.py --manifest <your-manifest>`.
5. Keep the old reports and record which manifest produced the new numbers.

The PE samples are real build artifacts from MinGW-w64 and are parsed by the
detector without executing them. They are local-only because compiled binaries
do not belong in a source repository; `tools/sync_samples.py` reproduces the
exact set from `../Footless-loader/dist` and
`../Footless-loader/InjectionLab/bin`.

## Labels

| Label | Meaning |
|---|---|
| `benign` | no injection attempt; no alert expected |
| `malicious` | injection attempt / loader sample; alert expected |
| `excluded` | missing or unsupported row; not counted as true negative |

`P04_apc` is `malicious` even though the marker is not observed: queueing an
APC is an injection attempt.

## Provenance

| Item | Source |
|---|---|
| PE samples | `../Footless-loader/build.sh` (MinGW-w64 13.2), copied with SHA256 |
| `NT230_injector.exe` | `../Footless-loader/InjectionLab/build.ps1` equivalent cross-build |
| Telemetry | `generate_telemetry.py` |
| Reports | `evaluate.py`, `tools/ablation.py` |
