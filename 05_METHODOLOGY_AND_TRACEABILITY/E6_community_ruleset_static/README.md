# E6 — Community Ruleset Evaluation

| Phần | Trạng thái |
|---|---|
| Xác định nguồn, phiên bản, giấy phép | **VERIFIED** (2026-11-02) |
| Tương thích cú pháp với Falco 0.45.0 | **VERIFIED** — `falco -V` không cần sudo, 0 lỗi, 0 cảnh báo |
| Phân tích tĩnh: rule nào có thể chạm tới các họ cơ chế của lab | **VERIFIED** (đọc điều kiện; kết quả là *dự đoán*, không phải phát hiện) |
| Chạy E1/E4 với ruleset cộng đồng được nạp | **PLANNED** — chưa chạy; không có số liệu |

## 1. Nguồn (ghim theo tag, sao chép nguyên văn vào `upstream/`)

| File | Tag upstream | Commit tag | sha256 | Số rule |
|---|---|---|---|---|
| `falco-rules-5.2.0.yaml` | `falco-rules-5.2.0` | `80880bd5` | `30a1a602…b865b` (trùng `/etc/falco/falco_rules.yaml` và nhánh `main` @ `e7b066bf`, 2026-10-22) | 25 |
| `falco-incubating-rules-6.0.1.yaml` | `falco-incubating-rules-6.0.1` | `6cbb113d` | `47bf8704…be1ac` | 31 |
| `falco-sandbox-rules-6.2.0.yaml` | `falco-sandbox-rules-6.2.0` | `80880bd5` | `f05ad34f…3f33d3` | 39 |

Nguồn: https://github.com/falcosecurity/rules (tải qua `raw.githubusercontent.com/<tag>/rules/<file>`). Giấy phép **Apache-2.0** (`upstream/LICENSE.falcosecurity-rules`). Cả ba file khai báo `required_engine_version: 0.57.0`; Falco 0.45.0 có engine 0.65.0.

Falco Talon **không phải ruleset phát hiện**: đó là response engine nhận alert Falco và chạy hành động (terminate, label, …). Vì vậy Talon không được đưa vào E6. Không có ruleset bên thứ ba nào khác được tải hoặc đánh giá.

## 2. Kiểm tra tương thích (đã chạy)

```
falco -o json_output=true -V /etc/falco/falco_rules.yaml -V upstream/falco-incubating-rules-6.0.1.yaml \
      -V upstream/falco-sandbox-rules-6.2.0.yaml -V ../../rules/custom_rules.yaml
```
Kết quả 2026-11-02: cả bốn file `successful=true`, `schema_valid=true`, 0 errors, 0 warnings. Validate chỉ chứng minh nạp được cùng nhau, không chứng minh không trùng tên/macro theo ý đồ (tên rule custom đều có tiền tố `LAB`, không trùng upstream).

## 3. Phân tích tĩnh (`e6_static_scan.py` → `e6_static_candidates.csv`)

Script mở rộng macro/list theo tên rồi tìm dấu hiệu theo họ cơ chế; regex `interpreter` rất rộng (bắt mọi list có `python`), nên mỗi ứng viên được đọc tay. Kết luận đọc tay:

| Họ cơ chế | Rule cộng đồng (incubating/sandbox) có liên quan | Nhận định (INFERRED từ điều kiện, chưa chạy) |
|---|---|---|
| memfd | không có | Chỉ rule stable `Fileless execution via memfd_create` (đã có trong E1). Ngoại lệ #3444 không bị ruleset nào khác bù. |
| /dev/shm | `Create files below dev` (incubating) | Điều kiện `fd.directory = /dev` → file trong `/dev/shm/` có directory `/dev/shm`, **không khớp**. |
| /proc/self/fd exec | `Container Drift Detected (chmod)`, `(open+create)`, `Modify Container Entrypoint` (sandbox, đều `enabled: false`) | Là rule về **ghi/tạo** file, không về exec qua fd. `open+create` có thể bắn khi T3c tạo `/tmp/dropped_elf` có bit exec — sẽ là bắt *drop*, không bắt *exec qua fd* (misattrib), và cũng bắn trên build E2 (FP). |
| interpreter -c / stdin | không có | `Interpreted procs … network activity` (sandbox, tắt) nói về kết nối mạng, không về code inline. |
| download-pipe | `Launch Ingress Remote File Copy Tools in Container` (incubating) | Chỉ khớp `wget` hoặc `curl` có `-o/-O/--output/--remote-name`. Payload lab dùng `curl -fsS URL` (stdout) → **không khớp**. |
| LD_PRELOAD | `Potential Local Privilege Escalation via Environment Variables Misuse` | Macro `glibc_tunables_env` chỉ xét `GLIBC_TUNABLES` → **không khớp** LD_PRELOAD. |
| ptrace | không có thêm | Rule stable `PTRACE attached to process` đã có. |

**Dự đoán (cần E6 động để kiểm):** nạp incubating + sandbox (với mặc định `enabled`) không thêm phát hiện *direct* nào cho 19 biến thể của lab; có thể thêm alert misattrib/FP từ rule drift nếu bật thủ công.

## 4. Thiết kế E6 động (PLANNED — cần sudo, người dùng tự chạy)

Điều kiện tiên quyết: `sudo systemctl stop falcoctl-artifact-follow` (đang active ngày 2026-11-02), `sudo ./preflight.sh default` PASS, rule default vẫn `30a1a602…`.

1. Ruleset `community`: `rules.d/` chứa đúng hai file trong `upstream/` (sha256 như bảng trên), **không** có custom rule, `rule_matching: first` và một lần `all`.
2. Chạy cùng harness: `sudo REPS=5 ./run_e1.sh` (11 kỹ thuật E1) và `TECHS="e4_* dev_memfd_runcname"`. Đặt tên run `e6_community_<first|all>_<ts>`.
3. Parse bằng `parse_e1.py` với `RULESET=community`. Lưu ý: `parse_e1.py` hiện chỉ có map `DIRECT` cho `default`/`custom`; cần thêm map `community` **trước khi chạy** và ghi rõ trong manifest. Rule cộng đồng nào được coi là "direct" cho kỹ thuật nào phải được chốt bằng văn bản trước khi xem kết quả.
4. Chạy E2 (`run_e2.sh`) với cùng ruleset để đo FP.
5. Báo cáo riêng là E6; không gộp với E1–E5.

`ruleset.sh` hiện không có mode `community`; không sửa script đó trong đợt này vì nó thay đổi `/etc/falco` và restart dịch vụ.
