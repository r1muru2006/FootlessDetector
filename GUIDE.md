# GUIDE.md — Loader Detector

## 1. Mục tiêu

Xây dựng một detector để phát hiện các dấu hiệu thường gặp của loader sử dụng:

* Dynamic API Resolution / API Hashing
* NT API
* Process Injection

Detector gồm hai nhóm:

```text
Static Analysis
    ├── Hash loops
    ├── Dynamic resolution
    └── PE import anomaly

Runtime / Behavioral Analysis
    ├── API behavior
    ├── Source → Target relation
    ├── Remote thread
    ├── RWX / RX memory region
    └── Access rights
```

Mục tiêu của detector là **thu thập evidence và tạo alert**, không dựa vào một indicator duy nhất.

---

# 2. Kiến trúc

```text
                    ┌───────────────┐
                    │ Target Binary │
                    └───────┬───────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
       Static Analyzer              Runtime Monitor
              │                           │
      ┌───────┼────────┐        ┌─────────┼─────────┐
      ▼       ▼        ▼        ▼         ▼         ▼
   Hash    Dynamic    Import   API      Memory    Process
   Loop    Resolve    Anomaly  Behavior  Region    Relation
      │       │        │        │         │         │
      └───────┴────────┘        └─────────┴─────────┘
              │                           │
              └─────────────┬─────────────┘
                            ▼
                     Evidence Engine
                            │
                            ▼
                         Alert
```

---

# 3. Detector Structure

Project có thể giữ đơn giản:

```text
Detector/
│
├── main.py
│
├── static/
│   ├── hash_loop.py
│   ├── dynamic_resolve.py
│   └── import_anomaly.py
│
├── runtime/
│   ├── api_behavior.py
│   ├── process_relation.py
│   ├── memory_region.py
│   └── access_rights.py
│
├── detection/
│   ├── evidence.py
│   └── scoring.py
│
├── tests/
│   ├── test_static.py
│   └── test_runtime.py
│
└── README.md
```

---

# 4. Static Detection

## 4.1. Hash Loops

### Mục tiêu

Phát hiện code có đặc điểm:

```text
Read byte
    ↓
Transform / rotate / xor / add
    ↓
Update hash
    ↓
Loop
    ↓
Compare hash
```

Detector không cần xác định chính xác thuật toán hash.

Thay vào đó tìm các đặc điểm:

```text
Loop
 +
Byte/String traversal
 +
Repeated arithmetic/bitwise operations
 +
Comparison với constant
```

### Evidence

Ví dụ:

```text
Hash-loop candidate:
    function: 0x140001230
    loop:     0x14000128A
    operations:
        XOR
        ROL
        ADD
    comparison constants: 3
```

### Output

```text
HASH_LOOP_DETECTED
```

---

# 5. Dynamic Resolution

## 5.1. Mục tiêu

Phát hiện binary không sử dụng import trực tiếp để gọi API mà có hành vi:

```text
Module Base
     ↓
Export Table
     ↓
Export Name
     ↓
Hash / Compare
     ↓
Function Address
```

Các indicator cần kiểm tra:

```text
PEB access
Export Directory traversal
Export name iteration
Hash calculation
Function-address resolution
Indirect function call
```

### Evidence

```text
DYNAMIC_RESOLUTION_DETECTED

Module:
    ntdll.dll

Evidence:
    Export directory traversal
    API-name iteration
    Hash comparison
    Indirect call
```

---

# 6. PE Import Anomaly

## 6.1. Mục tiêu

Phân tích Import Table của PE.

Detector kiểm tra:

```text
Number of imports
Imported DLLs
Imported functions
Import density
Suspiciously small IAT
```

Ví dụ một binary có rất ít import nhưng runtime lại thực hiện nhiều API operation thì cần tạo evidence:

```text
Static imports:
    3 APIs

Observed runtime APIs:
    17 APIs
```

### Output

```text
PE_IMPORT_ANOMALY
```

Không nên coi import ít là malicious.

Đây chỉ là một **supporting indicator**.

---

# 7. Runtime API Behavior

## 7.1. Mục tiêu

Theo dõi chuỗi API operation thay vì chỉ kiểm tra một API riêng lẻ.

Ví dụ behavior chain:

```text
Open Process
      ↓
Allocate Memory
      ↓
Write Memory
      ↓
Change Protection
      ↓
Execution-related operation
```

Detector lưu event:

```text
timestamp
source_process
target_process
api
operation
result
```

Ví dụ:

```text
08:20:01
source=loader.exe
target=test.exe
api=NtOpenProcess
```

```text
08:20:01
source=loader.exe
target=test.exe
api=NtAllocateVirtualMemory
```

```text
08:20:01
source=loader.exe
target=test.exe
api=NtWriteVirtualMemory
```

Sau đó correlation engine ghép các event thành một behavior chain.

---

# 8. Source → Target Relation

## 8.1. Mục tiêu

Xác định process nào đang thao tác lên process nào.

Biểu diễn:

```text
Source Process
      │
      │ operation
      ▼
Target Process
```

Ví dụ:

```text
loader.exe
    │
    ├── OpenProcess
    ├── AllocateMemory
    └── WriteMemory
    │
    ▼
notepad.exe
```

Detector lưu:

```text
source_pid
source_name
target_pid
target_name
operation
timestamp
```

### Evidence

```text
SOURCE_TARGET_RELATION

Source:
    loader.exe (PID 4210)

Target:
    notepad.exe (PID 3312)

Operations:
    OpenProcess
    AllocateMemory
    WriteMemory
```

---

# 9. Remote Thread

## 9.1. Mục tiêu

Phát hiện trường hợp một process tạo thread trong process khác.

Logic:

```text
Source PID
     │
     │ Thread creation
     ▼
Target PID
```

Detector kiểm tra:

```text
source_pid != target_pid
```

và operation có liên quan tới remote thread creation.

### Output

```text
REMOTE_THREAD_DETECTED
```

Evidence:

```text
Source:
    loader.exe

Target:
    target.exe

Event:
    Remote thread creation
```

Remote thread chỉ là **một indicator**, không tự động đồng nghĩa với malicious activity.

---

# 10. RWX / RX Region

## 10.1. Mục tiêu

Theo dõi memory region của process.

Các thuộc tính cần lưu:

```text
base_address
size
protection
state
type
owner_process
```

Detector đặc biệt chú ý:

```text
RWX
```

và các executable region:

```text
RX
```

### RWX

```text
READ
WRITE
EXECUTE
```

Đánh dấu:

```text
RWX_REGION_DETECTED
```

### RX

RX tự nó không bất thường vì executable code hợp lệ thường tồn tại ở dạng RX.

Do đó cần xem thêm:

```text
region origin
region type
allocation event
writer process
execution event
```

Ví dụ:

```text
Private executable region
+
previously writable
+
written by another process
```

có giá trị detection cao hơn việc chỉ thấy một vùng RX.

---

# 11. Access Rights

## 11.1. Mục tiêu

Kiểm tra quyền mà source process yêu cầu đối với target process.

Detector ghi:

```text
source_pid
target_pid
requested_access
granted_access
```

Ví dụ:

```text
Source:
    loader.exe

Target:
    target.exe

Requested:
    PROCESS_VM_OPERATION
    PROCESS_VM_WRITE
    PROCESS_VM_READ
```

Detector có thể đánh dấu:

```text
PROCESS_ACCESS_ANOMALY
```

khi một process yêu cầu quyền thao tác mạnh lên process khác.

Không nên tạo alert chỉ dựa trên một access right; cần kết hợp với source-target relationship và các operation tiếp theo.

---

# 12. Evidence Correlation

Thay vì:

```text
1 indicator → 1 alert
```

nên sử dụng:

```text
Evidence
   │
   ├── Hash loop
   ├── Dynamic resolution
   ├── Import anomaly
   ├── Process access
   ├── Remote memory operation
   ├── Memory protection
   └── Source → Target relation
          │
          ▼
    Correlation Engine
          │
          ▼
        Alert
```

Ví dụ một execution chain:

```text
Dynamic API Resolution
        +
Low Import Count
        +
Open Target Process
        +
Remote Memory Operation
        +
Executable Memory
```

→ tạo một **correlated detection event**.

---

# 13. Event Format

Nên chuẩn hóa event thành JSON:

```json
{
    "timestamp": "...",
    "source_pid": 4210,
    "source_name": "loader.exe",
    "target_pid": 3312,
    "target_name": "target.exe",
    "event_type": "process_memory_operation",
    "operation": "write_memory",
    "access": "PROCESS_VM_WRITE",
    "memory_protection": "RX"
}
```

Static event:

```json
{
    "file": "loader.exe",
    "event_type": "dynamic_resolution",
    "module": "ntdll.dll",
    "evidence": [
        "export_table_traversal",
        "hash_comparison",
        "indirect_call"
    ]
}
```

---

# 14. Detection Pipeline

```text
                    PE FILE
                       │
                       ▼
              ┌─────────────────┐
              │ Static Analyzer │
              └────────┬────────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      Hash Loop   Dynamic API   Import Anomaly
          │            │            │
          └────────────┼────────────┘
                       │
                       ▼
                  Static Evidence


                   PROCESS
                       │
                       ▼
              ┌─────────────────┐
              │ Runtime Monitor │
              └────────┬────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
    API Events    Memory Events   Process Events
        │              │              │
        └──────────────┼──────────────┘
                       │
                       ▼
                  Runtime Evidence

                       │
                       ▼
              ┌─────────────────┐
              │   Correlation   │
              └────────┬────────┘
                       │
                       ▼
                     Alert
```

---

# 15. Test Cases

## TC-DET-01 — Hash Loop

**Input:**

Binary có một function duyệt qua chuỗi và thực hiện nhiều phép biến đổi lặp.

**Expected:**

```text
HASH_LOOP_DETECTED
```

---

## TC-DET-02 — Dynamic Resolution

**Input:**

Binary duyệt Export Table và resolve function address tại runtime.

**Expected:**

```text
DYNAMIC_RESOLUTION_DETECTED
```

---

## TC-DET-03 — Import Anomaly

**Input:**

PE có IAT rất nhỏ nhưng runtime tạo nhiều API events.

**Expected:**

```text
PE_IMPORT_ANOMALY
```

---

## TC-DET-04 — Source → Target

**Input:**

```text
Process A
    ↓
Process B
```

Process A thực hiện process-memory operation lên B.

**Expected:**

```text
SOURCE_TARGET_RELATION
```

---

## TC-DET-05 — Remote Thread

**Input:**

Một process tạo thread trong process khác.

**Expected:**

```text
REMOTE_THREAD_DETECTED
```

---

## TC-DET-06 — RWX Region

**Input:**

Process xuất hiện memory region có:

```text
READ + WRITE + EXECUTE
```

**Expected:**

```text
RWX_REGION_DETECTED
```

---

## TC-DET-07 — RX Region

**Input:**

Executable memory region được tạo hoặc thay đổi sau một memory-write event.

**Expected:**

```text
EXECUTABLE_MEMORY_ANOMALY
```

Detector không alert chỉ vì region có RX.

---

## TC-DET-08 — Access Rights

**Input:**

Process A yêu cầu quyền thao tác memory/process trên Process B.

**Expected:**

```text
PROCESS_ACCESS_EVENT
```

Nếu kết hợp với các event tiếp theo:

```text
Open Process
      ↓
Memory Operation
      ↓
Executable Region
```

thì correlation engine tạo:

```text
PROCESS_INJECTION_BEHAVIOR
```

---

# 16. Integration Test

Test đầy đủ detector:

```text
                    loader.exe
                         │
             ┌───────────┴───────────┐
             │                       │
             ▼                       ▼
       Static Analysis          Runtime Monitor
             │                       │
       ┌─────┼─────┐          ┌──────┼──────┐
       ▼     ▼     ▼          ▼      ▼      ▼
     Hash  Dynamic Import     API   Memory Process
     Loop  Resolve Anomaly   Event  Event  Event
       │     │     │          │      │      │
       └─────┴─────┘          └──────┴──────┘
              │                      │
              └──────────┬───────────┘
                         ▼
                    Correlation
                         │
                         ▼
                       Alert
```

Expected:

```text
[PASS] Hash loop detection
[PASS] Dynamic resolution detection
[PASS] PE import analysis
[PASS] API behavior monitoring
[PASS] Source-target tracking
[PASS] Remote thread detection
[PASS] RWX/RX region monitoring
[PASS] Access-right monitoring
[PASS] Evidence correlation
```

---

# 17. Definition of Done

### Static Detector

```text
Hash Loop Detection       ✓
Dynamic Resolution        ✓
PE Import Anomaly         ✓
```

### Runtime Detector

```text
API Behavior              ✓
Source → Target Relation  ✓
Remote Thread             ✓
RWX / RX Region           ✓
Access Rights             ✓
```

### Correlation

```text
Static Evidence
      +
Runtime Evidence
      ↓
Correlation
      ↓
Detection Alert
```

Detector chỉ được xem là hoàn thành khi có thể **ghi nhận evidence riêng lẻ và correlation được nhiều evidence thành một behavior chain**, thay vì alert dựa trên một dấu hiệu đơn lẻ.
