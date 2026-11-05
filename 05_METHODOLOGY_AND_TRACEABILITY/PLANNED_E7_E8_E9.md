# E7, E8, E9 — Thiết kế thí nghiệm mở rộng (trạng thái: PLANNED, chưa chạy, không có số liệu)

Lý do chưa chạy (2026-11-02): (1) Claude không có sudo; mọi thí nghiệm cần dừng follower, đổi `/etc/falco` hoặc nạp sensor eBPF mới. (2) Máy lab hiện **không ở trạng thái đóng băng**: `falcoctl-artifact-follow` đang active (hash rule vẫn `30a1a602…`, nhưng điều kiện preflight không đạt). (3) Không có VM dùng một lần có snapshot để chạy sensor thứ hai hoặc container unconfined. Những thí nghiệm dưới đây phải chạy trong điều kiện đó và được báo cáo dưới ID riêng, không gộp với E1–E5.

---

## E7 — Cross-tool comparison (Tetragon, Tracee)

### Nguồn đã kiểm tra (VERIFIED là tài liệu, không phải kết quả)
| Công cụ | Phiên bản mới nhất khi kiểm | Tài liệu đọc | Khả năng liên quan |
|---|---|---|---|
| Cilium Tetragon | v1.8.0 (tag), docs @ `31e646a5` (2026-10-30) | `docs/content/en/docs/policy-library/observability/_index.md`, `reference/grpc-api.md` | Sự kiện `process_exec` có `binary_properties.file` khi binary là memfd, file shm ẩn danh, hoặc **đã bị xoá**; `file.inode.links = 0` nghĩa là chỉ nằm trong bộ nhớ. Use case "Fileless Execution", "Execution of Deleted Binaries", "Shared Library Loading" trong policy library (cần bật Process Credentials). Mô hình: luồng sự kiện + TracingPolicy (kprobe/tracepoint/LSM) + lọc phía client; không có ruleset cảnh báo tương đương Falco theo mặc định. |
| Aqua Tracee | v0.24.1 (tag), docs @ `2f9dc40c` (2026-09-29) | `docs/docs/events/builtin/man/security/*.md` | Signature `fileless_execution` (TRC-105, T1620, dựa trên `sched_process_exec`), `ld_preload` (TRC-107: biến `LD_PRELOAD`/`LD_LIBRARY_PATH` và sửa `/etc/ld.so.preload`), `ptrace_code_injection` (TRC-103: chỉ `PTRACE_POKETEXT/POKEDATA`), `dropped_executable` (TRC-1022). |

### Khác biệt mô hình sự kiện cần ghi trước khi so sánh
- Falco: rule (điều kiện trên trường `proc.*`, `evt.*`, `fd.*`) → alert; `rule_matching: first` mặc định.
- Tracee: sự kiện thô + *signature* (Go/Rego) → finding; một sự kiện có thể sinh nhiều finding.
- Tetragon: sự kiện quan sát (`process_exec/exit`, `process_kprobe`) + policy; "phát hiện" phụ thuộc bộ lọc của người vận hành → phải chốt bộ lọc trước khi chạy.
- Không tương đương trực tiếp: T7 của lab chỉ attach/detach → TRC-103 theo định nghĩa sẽ **không** khớp (INFERRED); đó là khác biệt định nghĩa, không phải "bỏ lọt".

### Giao thức
1. VM riêng, cùng image Ubuntu 22.04/kernel 6.8, Docker 28.4.0/runc 1.3.3, snapshot trước mỗi công cụ.
2. **Mỗi lần chỉ một sensor** (Falco, rồi Tetragon, rồi Tracee) để tránh cạnh tranh tài nguyên/hook; Auditd giữ nguyên làm đối chứng.
3. Cùng harness `run_e1.sh` (11 kỹ thuật E1 + 7 biến thể E4 + DEV-T1r), REPS=5, cùng mạng `Internal=true`.
4. Chốt bằng văn bản trước khi chạy: với mỗi công cụ, sự kiện/signature nào được coi là *direct* cho kỹ thuật nào.
5. Lưu manifest phiên bản, policy/signature hash, log thô; parser riêng `parse_e7_<tool>.py`.

---

## E8 — Independent / unseen variant evaluation

Mục tiêu: đo rule v1 (và nếu có, `rules/candidate_rules_v2.yaml`) trên biến thể **không do tác giả rule thiết kế**.

| Nguồn | Test (ID ổn định) | Họ cơ chế | Ghi chú an toàn |
|---|---|---|---|
| Atomic Red Team (`redcanaryco/atomic-red-team` @ `d0cc590b`) | T1059.004 "Detecting pipe-to-shell" (`fca246a8`) | download-pipe | Cần mirror `pipe-to-shell.sh` lên `falco-lab-server` (mạng nội bộ), không tải từ Internet trong lúc đo |
| | T1059.004 "Command-Line Interface" (`d0c88567`, có biến thể `wget -O - \| bash`) | download-pipe | như trên |
| | T1059.004 "Obfuscated command line scripts" (`5bec4cc8`: `base64 -d \| /bin/bash`) | pipe-to-shell không có downloader | lành tính (`id`) |
| | T1059.004 "Environment variable scripts" (`bdaebd56`: `echo $ART \| /bin/sh`) | pipe-to-shell | lành tính |
| | T1059.006 "Execute Python via scripts" / "via Python executables" (`6c4d1dcb`, `0b44d79b`) | interpreter | kiểm nội dung trước khi chạy |
| | T1574.006 "Shared Library Injection via LD_PRELOAD" (`bc219ff7`), "via /etc/ld.so.preload" (`39cb0e67`) | LD_PRELOAD | `/etc/ld.so.preload` chỉ trong container dùng một lần; không trên host |
| falcosecurity/event-generator | `syscall.FilelessExecutionViaMemfdCreate`, `syscall.ExecutionFromDevShm`, `syscall.PtraceAttachedToProcess` | memfd, /dev/shm, ptrace | Do maintainer Falco viết để kích hoạt chính rule default → độc lập với tác giả lab nhưng **không** độc lập với rule default |
| Atomic Red Team T1620 | không có test Linux (kiểm 2026-11-02) | memfd | — |

Quy tắc: không dùng lại payload của lab đã đổi tên/tham số làm "độc lập". Ghi `class=independent_external` trong `report/tables/test_independence.csv` khi có dữ liệu.

---

## E9 — Container-ID proxy: Docker default vs unconfined AppArmor

### Cơ chế hiện tại (VERIFIED từ code)
`parse_e1.py`, hàm `audit_state`: `ctr = "subj=docker-default" in r["text"]`; kỹ thuật host (`T2-host`) yêu cầu `ctr == False`, mọi kỹ thuật khác yêu cầu `ctr == True`. Không có container ID thật: kernel 6.8.0-138 không có `/proc/self/audit_containerid` (references #15). Proxy này chỉ nói "tiến trình chạy dưới profile docker-default", không phân biệt container nào.

### Dự đoán (INFERRED từ code, chưa chạy)
Với `docker run --security-opt apparmor=unconfined` (không `--privileged`, không thêm capability), bản ghi audit mang `subj=unconfined` → parser coi là host → mọi kỹ thuật container sẽ thành Auditd `miss` dù telemetry có đủ. Falco không bị ảnh hưởng (container được xác định qua plugin container/cgroup).

### Giao thức và điều kiện an toàn
Chỉ chạy trong VM dùng một lần có snapshot, không dữ liệu/secret thật, không mount host filesystem, không `--privileged`, không thêm capability. Chạy T1, T3b, T4, T5 ở hai cấu hình (default, unconfined), REPS=5. Đề xuất sửa: thay proxy bằng `cgroup`/`pid namespace` (đối chiếu `ppid` với `containerd-shim`) hoặc dùng `auditctl` + `-F` theo cgroup nếu kernel hỗ trợ; đánh giá lại trên cả hai cấu hình.
