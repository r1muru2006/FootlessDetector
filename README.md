# Footless-detector (skeleton, U1)

Offline lab detector (stdlib-only Python, no network). U1 skeleton slice:
hash-loop static signal through the evidence engine to a correlated alert.

## Layout (GUIDE tree)

```text
main.py                 CLI / orchestration only (BR1.5, C3 envelope)
static/hash_loop.py     hash-loop detector (BR1.1, FR1, TC-DET-01)
runtime/                stub package for U3 (empty __init__ for now)
detection/evidence.py   evidence-shape contract C1/C2 (BR1.2, BR1.6)
detection/scoring.py    minimal scoring path (BR1.3, BR1.4)
tests/                  stdlib unittest suite (test_after per Testing Contract)
tests/fixtures/         deterministic synthetic fixtures (FR11)
```

## Usage

```sh
python main.py tests/fixtures/tc_det_01_hash_loop.json
python main.py tests/fixtures/skeleton_correlated.json
python -m unittest tests.test_static_hash_loop tests.test_detection_scoring tests.test_detection_cli
```

Stdout is one JSON document (`evidence`, `warnings`, `alert` or null,
`verdict`). Exit 0 on a clean run regardless of verdict, 2 on bad
target/usage, 1 on unexpected internal failure.

## Skeleton behavior

- One hash-loop function yields one evidence item and at most a
  below-threshold verdict: a single indicator alone never alerts (BR1.4).
- The correlated fixture chains stub evidence across static + runtime areas
  to demonstrate the score-6 alert path U2/U3 detectors will feed.
- Malformed inputs become structured warnings; the run continues (BR1.6).
