# Layer ablation

Generated: 2026-11-12T17:24:49Z UTC
Manifest: `datasets/manifest.csv`

| Configuration | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full | 13 | 0 | 9 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| static-only | 5 | 0 | 9 | 8 | 1.0000 | 0.3846 | 0.5556 | 0.0000 |
| runtime-only | 8 | 0 | 9 | 5 | 1.0000 | 0.6154 | 0.7619 | 0.0000 |
| no-graph | 13 | 0 | 9 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| no-static-pe | 8 | 0 | 9 | 5 | 1.0000 | 0.6154 | 0.7619 | 0.0000 |

## Per format

| Configuration | Format | TP | FP | TN | FN | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|
| full | jsonl | 8 | 0 | 6 | 0 | 1.0000 | 1.0000 |
| full | pe | 5 | 0 | 3 | 0 | 1.0000 | 1.0000 |
| static-only | jsonl | 0 | 0 | 6 | 8 | n/a | 0.0000 |
| static-only | pe | 5 | 0 | 3 | 0 | 1.0000 | 1.0000 |
| runtime-only | jsonl | 8 | 0 | 6 | 0 | 1.0000 | 1.0000 |
| runtime-only | pe | 0 | 0 | 3 | 5 | n/a | 0.0000 |
| no-graph | jsonl | 8 | 0 | 6 | 0 | 1.0000 | 1.0000 |
| no-graph | pe | 5 | 0 | 3 | 0 | 1.0000 | 1.0000 |
| no-static-pe | jsonl | 8 | 0 | 6 | 0 | 1.0000 | 1.0000 |
| no-static-pe | pe | 0 | 0 | 3 | 5 | n/a | 0.0000 |
