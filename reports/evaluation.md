# Detector evaluation

Generated: 2026-11-12T17:24:48Z UTC
Manifest: `datasets/manifest.csv`
Alert threshold: None

## Confusion matrix

| TP | FP | TN | FN | Evaluated | Excluded |
|---:|---:|---:|---:|---:|---:|
| 13 | 0 | 9 | 0 | 22 | 0 |

## Metrics

| Metric | Value |
|---|---:|
| precision | 1.0000 |
| recall | 1.0000 |
| f1 | 1.0000 |
| fpr | 0.0000 |
| accuracy | 1.0000 |
| latency_ms_p50 | 0.187 ms |
| latency_ms_p95 | 17.554 ms |
| latency_ms_max | 17.624 ms |

## Per scenario

| Scenario | Label | Format | Alert | Verdict | Score | Evidence | Latency |
|---|---|---|---:|---|---:|---:|---:|
| B01_target_only | benign | jsonl | no | clean | 1 | 1 | 0.145 ms |
| B02_self_dll | benign | jsonl | no | clean | 2 | 2 | 0.114 ms |
| B03_benign_app | benign | jsonl | no | clean | 2 | 2 | 0.098 ms |
| B04_loader_noise | benign | jsonl | no | clean | 1 | 1 | 0.071 ms |
| B05_jit_rwx | benign | jsonl | no | suspicious | 3 | 1 | 0.096 ms |
| B06_weak_query | benign | jsonl | no | clean | 2 | 2 | 0.074 ms |
| P01_crt | malicious | jsonl | yes | alert | 12 | 8 | 0.187 ms |
| P02_nt | malicious | jsonl | yes | alert | 12 | 8 | 0.154 ms |
| P03_stub | malicious | jsonl | yes | alert | 17 | 11 | 0.194 ms |
| P04_apc | malicious | jsonl | yes | alert | 14 | 10 | 0.191 ms |
| P05_section | malicious | jsonl | yes | alert | 17 | 11 | 0.190 ms |
| P06_quiet_stub | malicious | jsonl | yes | alert | 17 | 11 | 0.179 ms |
| P07_nt_image | malicious | jsonl | yes | alert | 8 | 5 | 0.113 ms |
| P08_sysmon_mixed | malicious | jsonl | yes | alert | 11 | 8 | 0.149 ms |
| S01_loader | malicious | pe | yes | alert | 7 | 3 | 16.752 ms |
| S02_loader_seeded | malicious | pe | yes | alert | 7 | 3 | 17.554 ms |
| S03_loader_module_api | malicious | pe | yes | alert | 7 | 3 | 17.624 ms |
| S04_loader_quiet | malicious | pe | yes | alert | 7 | 3 | 16.374 ms |
| S05_loader_seed_alt | malicious | pe | yes | alert | 7 | 3 | 16.479 ms |
| S06_benign_app | benign | pe | no | clean | 0 | 0 | 10.795 ms |
| S07_target | benign | pe | no | clean | 0 | 0 | 11.774 ms |
| S08_marker_dll | benign | pe | no | clean | 0 | 0 | 10.423 ms |

## By format

- **jsonl**: P=1.0000 R=1.0000 F1=1.0000 FPR=0.0000 (n=14)
- **pe**: P=1.0000 R=1.0000 F1=1.0000 FPR=0.0000 (n=8)
