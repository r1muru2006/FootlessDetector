# Evaluation

Mục tiêu: đo Precision/Recall/F1/FPR và latency trên một bộ scenario có nhãn,
tách core benchmark khỏi stress set, và chỉ ra giới hạn của phép đo.

## 1. Phương pháp

- Endpoint: **detector có alert hay không**, không phải marker đã chạy.
- Positive: injection attempt, kể cả APC queue chưa dispatch (P04).
- Negative: benign control.
- File thiếu hoặc label không hỗ trợ → `excluded`, không tính là TN.
- Mẫu số 0 → metric `null` (không báo 0 giả).
- Latency đo bằng `time.perf_counter()` quanh một lần `analyze_path`.

Công thức:

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2TP / (2TP + FP + FN)
FPR       = FP / (FP + TN)
Accuracy  = (TP + TN) / (TP + FP + TN + FN)
```

## 2. Core benchmark

22 scenario: 14 telemetry + 8 PE.

| TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 13 | 0 | 9 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |

Per format:

| Format | TP | FP | TN | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| jsonl | 8 | 0 | 6 | 0 | 1.0000 | 1.0000 |
| pe | 5 | 0 | 3 | 0 | 1.0000 | 1.0000 |

Latency:

| Metric | Giá trị |
|---|---:|
| p50 | 0.187 ms |
| p95 | 17.554 ms |
| max | 17.624 ms |

PE parsing chiếm phần lớn p95; JSONL < 1 ms. Số đo phụ thuộc máy (WSL2).

Chi tiết từng scenario: `reports/evaluation.md`.

## 3. Ablation theo layer

| Cấu hình | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| full | 13 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| static-only | 5 | 0 | 9 | 8 | 1.000 | 0.385 | 0.556 | 0.000 |
| runtime-only | 8 | 0 | 9 | 5 | 1.000 | 0.615 | 0.762 | 0.000 |
| no-graph | 13 | 0 | 9 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| no-static-pe | 8 | 0 | 9 | 5 | 1.000 | 0.615 | 0.762 | 0.000 |

Diễn giải:

1. Static-only bắt toàn bộ PE loader nhưng không thể bắt telemetry-only.
2. Runtime-only bắt toàn bộ telemetry nhưng không thể bắt PE-only.
3. Full cộng được hai tập.
4. `no-static-pe` mất `import_anomaly`; loader chỉ còn 2 evidence trong 1
   area, dừng ở suspicious. Điều này chứng minh yêu cầu ≥ 2 layer có tác
   dụng, không chỉ là trang trí.
5. `no-graph` không giảm recall trên bộ này; graph là lớp giải thích và
   redundancy. Báo cáo không tuyên bố graph làm tăng recall.

## 4. Stress set (giới hạn có chủ đích)

4 scenario:

| Scenario | Nhãn | Kết quả | Loại |
|---|---|---|---|
| X01 debugger hợp lệ | benign | alert | FP |
| X02 installer | benign | không alert | TN |
| X03 injector Win32 cổ điển (PE) | malicious | không alert | FN static |
| X04 X03 qua runtime | malicious | alert | TP |

| TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 1 | 1 | 0.500 | 0.500 | 0.500 | 0.500 |

Đây là kết quả **mong muốn** để thể hiện:

- Detection hành vi không phân biệt được debugger được phép và injector nếu
  không có allowlist/chữ ký.
- Static heuristic không bắt injector dùng IAT trực tiếp; cần runtime.
- Không dùng stress set để che core benchmark; hai bộ được báo cáo riêng.

## 5. So sánh biến thể

Năm PE loader (cùng source, khác hash/seed/strings) đều alert với score 7 và
cùng tập evidence `hash_loop + dynamic_resolve + import_anomaly`. Điều này
cho thấy detector bám cấu trúc, không bám một hash cụ thể.

Sáu method runtime:

| Method | Alert | Score | Layer chính |
|---|---:|---:|---|
| crt | yes | 12 | runtime + access + graph |
| nt | yes | 12 | runtime + access + graph |
| stub | yes | 17 | runtime + access + memory + graph |
| apc | yes | 14 | runtime + access + memory + graph |
| section | yes | 17 | runtime + access + memory + graph |
| nt-image | yes | 8 | runtime + access + graph |

P06 quiet (API label bị xóa) vẫn alert score 17 → không phụ thuộc chuỗi.
P04 APC không có remote thread vẫn alert nhờ memory + access + graph.

## 6. Độ tin cậy và giới hạn của phép đo

- **Dataset telemetry là synthetic replay** theo schema loader, không phải
  capture VM thật. Con số 1.000 trên core benchmark là kết quả trên bộ này;
  khi thay bằng capture thật, cần chạy lại và báo cáo lại.
- PE samples là binary thật do lab build, được parse thật; phần static có
  bằng chứng mạnh hơn phần telemetry.
- Bộ mẫu nhỏ (22 core, 4 stress); không đại diện cho phần mềm thực tế.
- Các run từ cùng binary/scenario có tương quan; không dùng để suy rộng.
- Latency phụ thuộc máy; PE ~10–17 ms trên môi trường tạo repo (WSL2).
- Không có ground truth từ Sysmon thật; EID mapping dựa trên schema chuẩn.

## 7. Tái lập

```sh
python datasets/generate_telemetry.py
python evaluate.py
python tools/ablation.py
python evaluate.py --manifest datasets/stress_manifest.csv \
  --out reports/stress_evaluation.json --markdown reports/stress_evaluation.md
python -m unittest discover
```

Kỳ vọng: 69 test pass; core 22 evaluated, 0 excluded; stress 4 evaluated.

Để dùng telemetry VM thật:

1. Chạy runbook trong `../Footless-loader/docs/RUNBOOK.md`.
2. Tạo manifest trỏ tới `loader.jsonl`/`telemetry.jsonl` thật.
3. Chạy `python evaluate.py --manifest <manifest>`.
4. Lưu kết quả mới, không ghi đè kết quả synthetic mà không ghi chú.

## 8. Kết luận

- Detector độc lập, đa lớp, giải thích được từng evidence.
- Core benchmark đạt P/R/F1 = 1.0, FPR = 0 trên bộ lab.
- Ablation chứng minh static và runtime bổ sung nhau.
- Stress set chỉ ra giới hạn thật: cần allowlist/chữ ký cho debugger và cần
  runtime cho injector IAT-visible.
- Điểm yếu lớn nhất của báo cáo là telemetry chưa phải capture VM; runbook
  và evaluator đã sẵn sàng để thay bằng dữ liệu thật.
