# Detector evaluation

Generated: 2026-11-12T17:24:49Z UTC
Manifest: `datasets/stress_manifest.csv`
Alert threshold: None

## Confusion matrix

| TP | FP | TN | FN | Evaluated | Excluded |
|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 1 | 1 | 4 | 0 |

## Metrics

| Metric | Value |
|---|---:|
| precision | 0.5000 |
| recall | 0.5000 |
| f1 | 0.5000 |
| fpr | 0.5000 |
| accuracy | 0.5000 |
| latency_ms_p50 | 0.300 ms |
| latency_ms_p95 | 16.727 ms |
| latency_ms_max | 16.727 ms |

## Per scenario

| Scenario | Label | Format | Alert | Verdict | Score | Evidence | Latency |
|---|---|---|---:|---|---:|---:|---:|
| X01_debugger_like | benign | jsonl | yes | alert | 17 | 11 | 0.386 ms |
| X02_benign_installer | benign | jsonl | no | suspicious | 3 | 3 | 0.161 ms |
| X03_injectionlab_injector | malicious | pe | no | clean | 2 | 1 | 16.727 ms |
| X04_injectionlab_runtime | malicious | jsonl | yes | alert | 17 | 11 | 0.300 ms |

## By format

- **jsonl**: P=0.5000 R=1.0000 F1=0.6667 FPR=0.5000 (n=3)
- **pe**: P=n/a R=0.0000 F1=n/a FPR=n/a (n=1)
