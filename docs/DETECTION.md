# Detection design

Tài liệu này giải thích từng feature, cách correlation và cách xử lý false
positive. Mã tương ứng nằm trong `detection/`, `static/`, `runtime/`.

## 1. Input routing

`detection/engine.py` nhận một trong các dạng:

| Dạng | Nhận biết | Xử lý |
|---|---|---|
| PE | `MZ` header hoặc `--format pe` | `detection/pe.py` |
| Evidence batch | dict có `evidence: [...]` hoặc item đủ 4 khóa | validate trực tiếp |
| Loader JSONL | `event` thuộc tập loader, có `run_id`/`tick_ms` | `runtime/telemetry.py` |
| Sysmon collector | `event_id`/`EventID` + `data`/`EventData` | map EID 7/8/10/25 |
| GUIDE event | có `api` + source/target | normalize rồi chạy detector |
| Region | có `protection` | RWX/RX |
| Stub summary | `function`/`loop`, `export_traversal`, `imports` | static detector tương ứng |
| Directory | path là thư mục | phân tích từng file rồi correlate một lần |

Malformed item → `warnings` có `input`, `detector`, `reason`; run tiếp tục.

## 2. Static PE features

### 2.1 Parser

`detection/pe.py` tự parse (không dùng `pefile`):

- DOS/NT headers, PE32/PE32+, sections, entropy, overlay.
- Import table: DLL, tên hàm, ordinal.
- Export table: tên export (dùng cho marker DLL/kiểm tra).
- Security directory, DLL characteristics (ASLR/DEP/CFG).
- Mọi đọc có kiểm tra biên; lỗi → `PEError` → warning.

### 2.2 `hash_loop`

Tìm vòng lặp hẹp có đủ:

1. một lệnh load byte (`0f b6` hoặc `8a`);
2. một rotate/shift (`c0/c1/d0..d3`);
3. một "mix" đặc trưng: `rol reg,5` (`c1 c? 05`) hoặc
   `imul eax,eax,0x01000193` (`69 c0 93 01 00 01`);
4. ít nhất 4 byte arithmetic/bitwise;
5. một compare (`38..3b`, `83 f8`, `3d`);
6. một backward branch (`7x` displacement âm, `e2`, `e8/e9` âm).

Đây là phiên bản chặt hơn nhiều so với "đếm opcode trong cửa sổ 64 byte".
Phiên bản lỏng từng báo 282–415 candidate trên cả binary benign; phiên bản
này báo 0 trên `benign_app.exe` và 5 trên loader.

Ngoài ra tìm hằng số: `0x01000193` (FNV prime), `0x811c9dc5` (FNV offset),
`0x9e3779b9` (golden ratio), `0xa5a5a5a5` (lab mix), `0xedb88320` (CRC32).

### 2.3 `dynamic_resolve`

Điều kiện:

```text
PEB access (gs:[0x60])
  AND (hash loop OR hash constants OR no sensitive import)
```

PEB access nhận cả:

- MSVC: `65 48 8b ... 60 00 00 00`;
- MinGW/GCC: `b8 60 00 00 00 65 67 48 8b` (`mov eax,0x60; mov rax,gs:[rax]`).

`export_table_traversal`/`name_iteration` được suy ra từ việc có hash loop +
PEB + đường resolve; details ghi rõ đây là suy luận cấu trúc, không phải
trace từng instruction.

### 2.4 `import_anomaly`

Hai trường hợp:

1. IAT rất nhỏ (≤ 5 import) nhưng runtime quan sát ≥ 10 API (stub detector).
2. **IAT không có API nhạy cảm** (`Nt*`, `CreateRemoteThread`,
   `WriteProcessMemory`, `VirtualAllocEx`, ...) trong khi code có PEB +
   hash loop/constants. Loader có 67 import CRT nhưng 0 API nhạy cảm, nên
   đây là gap có ý nghĩa, không phải "ít import".

### 2.5 Supporting features

- `sensitive_import_cluster`: ≥ 4 API injection cổ điển trong IAT; chỉ
  supporting (weight 2), không đủ alert.
- `rwx_section`: section có WRITE + EXECUTE; cảnh báo static, cần xác nhận
  runtime.
- `packed`: entropy ≥ 7.2 + IAT < 10; có thể là packer hoặc code hợp lệ.

## 3. Runtime normalization

`runtime/telemetry.py`:

- Loader: giữ context `source_target` (PID/tên/image) và gắn vào các event
  memory/thread phía sau. Mỗi `memory_protect`/`memory_map` tạo thêm một
  `memory_region` để chạy RWX/RX detector.
- Sysmon: EID 8 → `create_remote_thread`, EID 10 → `open_process` (decode
  `GrantedAccess`), EID 7 → `image_load`, EID 25 → `process_tampering`.
- Generic: điền `unknown` cho trường thiếu, giữ `timestamp` gốc.

Access mask decode map các bit `PROCESS_VM_*`, `PROCESS_CREATE_THREAD`,
`PROCESS_QUERY_INFORMATION`, `SYNCHRONIZE`; mask toàn quyền được mở thành
tập quyền mạnh.

## 4. Runtime detectors

| Detector | Điều kiện | Weight |
|---|---|---:|
| `api_chain` | event có timestamp/source/target/api/operation | 1 |
| `source_target` | source_pid != target_pid | 1 |
| `remote_thread` | source != target và operation là thread creation | 3 |
| `access` | requested rights giao với `{VM_OPERATION, VM_WRITE, VM_READ, CREATE_THREAD}` | 2 |
| `rwx` | protection = R+W+X | 3 |
| `rx_anomaly` | có X, không RWX, có prior write/alloc của process khác | 2 |
| `process_tampering` | Sysmon EID 25 | 3 |

`rx_anomaly` cố tình bỏ qua RX đơn thuần (image code bình thường) và bỏ qua
self-write. Nó liên kết theo `owner_pid` hoặc `base_address` với event
write/alloc trước đó.

## 5. Graph feature

`detection/graph.py` dựng đồ thị có hướng:

```text
node = (pid, name)
edge = (source_pid, target_pid) + set(operations) + count
```

Một edge bị coi là suspicious khi hội đủ:

```text
open/access  AND  (alloc|write|map|protect)  AND  (thread|apc|tamper)
```

Graph bỏ self-edge, bỏ PID không hợp lệ. Evidence `process_graph` chứa cả
`graph` (nodes/edges) để giải thích. Trong core benchmark graph không làm
tăng recall (vì các detector khác đã bắt), nhưng nó là lớp giải thích và
bắt các chuỗi mà từng event rời rạc.

## 6. Correlation `injection_behavior`

`detection/scoring.py` tìm trên **cùng một cặp PID** chuỗi có thứ tự:

```text
open  ->  allocate/write  ->  executable region
```

Executable region có thể là `rwx` hoặc `rx_anomaly`. Nếu đúng thứ tự, sinh
thêm evidence weight 2. Đây là "graph/chain feature" ở mức evidence, không
chỉ đếm event.

## 7. Scoring và tier

```text
score = sum(weight)
areas = distinct(area)
if len(evidence) == 1: at most suspicious
elif score >= 6 and len(areas) >= 2: alert
elif score >= 3: suspicious
else: clean
```

Ngưỡng 6 và yêu cầu 2 area là chủ ý: một indicator nặng (RWX weight 3)
không đủ; loader static có `static` + `static_pe` mới alert.

`--threshold` chỉ đổi ngưỡng alert, không đổi luật single-indicator.

## 8. False positive / false negative

### Đã xử lý

- same-process operations → không relation;
- bare RX / image-backed code → không anomaly;
- query-only access → không access evidence;
- image load đơn lẻ → không alert;
- một indicator → tối đa suspicious;
- allowlist theo tên process/file;
- PE benign (`benign_app`, target, marker DLL) → 0 evidence.

### Còn lại (stress set)

- Debugger/EDR hợp lệ thực hiện open+write+RX+thread → alert (X01).
- Injector cổ điển dùng IAT visible → static chỉ có cluster supporting,
  không alert; cần runtime (X03/X04).
- Packer/obfuscation có thể làm static heuristic sai; cần cập nhật rule.
- Sysmon thiếu EID 8/10 → coverage gap, không được coi là no_alert.

## 9. Error handling

- JSON lỗi → warning, exit 0.
- PE lỗi → warning, exit 0.
- Event thiếu trường → warning cho detector đó, các detector khác vẫn chạy.
- Không có event nhận dạng được → warning `no recognizable events`.
- Exit 2 chỉ cho target/usage; exit 1 cho lỗi nội bộ thật.

## 10. Vì sao stdlib-only

- Chạy offline trong VM, không tải model/dependency.
- Dễ audit: toàn bộ parser và rule đọc được.
- Không có supply-chain risk từ package lạ.
- Đổi lại: không có disassembler đầy đủ; heuristic byte-level có giới hạn
  và được ghi rõ.

## 11. Threat model và rủi ro triển khai

**Tài sản cần bảo vệ:** process của người dùng, credential trong memory,
tính toàn vẹn của endpoint.

**Kẻ tấn công giả định:** user-mode loader trên Windows x64, có quyền cùng
mức với target, có thể đổi hash algorithm/seed/thứ tự khóa và xóa chuỗi API.
Không giả định kernel exploit, signed driver, hay bypass EDR.

**Trust boundary:**

```text
PE file / telemetry  ->  detector (offline)
                            |
                            v
                     alert + evidence -> analyst / SIEM
```

Detector không tin input: mọi trường thiếu/không hợp lệ → warning; không
thực thi nội dung; không gọi network.

**Rủi ro triển khai:**

| Rủi ro | Giảm thiểu |
|---|---|
| False positive từ debugger/backup tool | allowlist theo chữ ký/đường dẫn; review evidence |
| False negative khi attacker dùng IAT trực tiếp | bật runtime layer (Sysmon EID 8/10) và correlation |
| Sensor thiếu event class | ghi coverage gap; không coi file rỗng là no_alert |
| PID reuse / clock skew | dùng ProcessGuid/time window trong triển khai thật |
| Alert flooding | threshold, dedupe, layer scoring, analyst triage |
| Evasion bằng obfuscation/packing | thêm entropy/packer rule và memory scan; hiện chỉ là heuristic |

**Khả năng tổng quát:** rule dựa trên cấu trúc PE (PEB/export/hash loop/IAT
gap) và quan hệ process, không dựa trên tên file/scenario. Vì vậy cùng rule
áp dụng cho loader khác nếu chúng dùng PEB + hash resolver. Với loader dùng
IAT trực tiếp, cần runtime layer (xem stress X03/X04).
