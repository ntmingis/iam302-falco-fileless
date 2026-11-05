# Phase 2 — Data and claim audit (2026-11-02)

## Đã chạy
| Kiểm tra | Lệnh | Kết quả |
|---|---|---|
| Unit test dự án | `python3 -m unittest discover -s tests -v` | 16/16 OK |
| Tái lập raw → parser → bảng | `bash final_evidence_report/verification/verify_pipeline.sh` | 46 SAME, 1 DIFF-EXPECTED (E5, CSV gốc vỡ cột do locale — đã biết), 0 DIFF chưa giải thích; giống hệt output 2026-10-29 |
| Claim → evidence | `python3 report/tools/build_revised_tables.py` | 29/29 claim khớp CSV (`report/tables/claim_evidence.csv`) |
| Wilson / rule of three | `tablestats.wilson` + tính tay | xem dưới |
| Hash rule đang nạp | `sha256sum /etc/falco/falco_rules.yaml` | `30a1a602…` (không đổi so với lúc thí nghiệm) |

## Các mục review (Mục II của yêu cầu) — đối chiếu
| # | Nhận định review | Kết quả đối chiếu |
|---|---|---|
| II.1 | E1 Nhóm A default: direct 1, misattrib 2, miss 3 | **VERIFIED** (C01–C03) |
| II.2 | E4: full custom 4/7 (T1b,T3d,T5c,T6b), full default 1/7, strict custom 2/5 | **VERIFIED** (C08–C12) |
| II.3 | Wilson CI của 20/35 và 10/25 khớp các khoảng trong Bảng 11 | **KHÔNG KHỚP — review nhầm, báo cáo đúng.** Bảng 11 tính Wilson trên *biến thể*: 4/7 → 0.25–0.84; 2/5 → 0.12–0.77. Wilson trên *lần chạy* là 20/35 → 0.41–0.72; 10/25 → 0.23–0.59 (C13–C16). Báo cáo chọn đơn vị biến thể vì 5 lần lặp của một biến thể cho kết quả xác định (luôn 5/5 hoặc 0/5), nên coi 35 lần là 35 mẫu độc lập sẽ thu hẹp khoảng một cách sai (pseudo-replication). Bản revised giữ khoảng theo biến thể và ghi chú khoảng theo lần chạy chỉ để đối chiếu. |
| II.4 | E5 n=5, min–max chồng lấn baseline, không kết luận overhead | **VERIFIED** (C23–C24: 9/9 ô có giám sát chồng lấn) |
| II.5 | Rule of three 0/10 → ≈0.3 | **VERIFIED** (C22). Ghi thêm: cận trên Clopper–Pearson một phía 95% chính xác là 0.259; Wilson hai phía 0.278. "≤ 0.3" là xấp xỉ bảo thủ. |
| II.6 | T1 và E4-T1b cùng execveat 322; loại T1b khỏi strict | **VERIFIED** (references #13; audit.log dòng 748 run e1_default_20261021_001604) |
| II.7 | Falco 0.45.0, runc 1.3.3, kernel 6.8, default + 6 custom, Docker, payload vô hại | **VERIFIED** (`versions.txt`, `falco --version` 2026-11-02, `rules/custom_rules.yaml` 6 rule) |

## Lỗi/thiếu sót phát hiện thêm
1. **Lỗi tra cứu trường Falco (ảnh hưởng diễn giải, không ảnh hưởng số liệu).** Báo cáo gốc ghi "Falco 0.45 không có `proc.stdin_type`" và dùng điều đó để giải thích E4-T4b/E4-T5b là không thể phát hiện bằng stdin. Falco 0.45.0 có `proc.stdin.type`/`proc.stdin.name` (dấu chấm). Đã đính chính trong bản revised và `docs/evasion_analysis.md`. Không sửa `rules/custom_rules.yaml` (file đóng băng, hash được tham chiếu).
2. **E4-T5c không hoàn toàn unseen.** `"| sh"` có trong `custom_rules.draft0.yaml` (2026-10-19). Đã có trong audit 2026-10-29; bản revised báo cả 2/5 (định nghĩa gốc, giữ nguyên) và 1/4 (độ nhạy).
3. **"Tổng quát hóa".** Mọi biến thể E4 đều cùng họ với kỹ thuật dùng viết rule; không có biến thể ngoài (external). Bản revised không dùng từ "generalization" cho 4/7 hay 2/5.
4. **Diễn đạt "11 kỹ thuật"** có thể khiến người đọc hiểu 11 mẫu độc lập. Thực tế: 7 họ cơ chế, 19 biến thể (11 E1 + 7 E4 + 1 DEV), trong đó chỉ 6 biến thể Nhóm A chạy được trong container Docker mặc định ở E1. Đã thêm bảng họ cơ chế.
5. **Định dạng số.** Bản gốc trộn dấu phẩy và dấu chấm thập phân ("0,1–0,2 ms", "0,72–1,0" bên cạnh "1.36 s"). Bản revised dùng dấu chấm thống nhất.
6. **Mã môn học.** Mọi file cục bộ (44 lần xuất hiện) dùng "IAM302"; không tìm thấy "IAM302t" ở đâu trên máy. Không đổi; đánh dấu cần chủ sở hữu xác nhận.

## Không thay đổi
Không số liệu thực nghiệm nào bị sửa. Không file trong `results/`, `analysis/`, `report/tables/` gốc nào bị sửa (chỉ thêm 3 CSV mới).
