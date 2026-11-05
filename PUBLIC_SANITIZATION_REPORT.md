# Public sanitization report — Group 8 public export

Built 2026-11-04 by `tools/build_public_export.py` from the verified release candidate `Group8_IAM302_Evidence_Package_RC3` (its `SHA256SUMS.txt` verified before copying; every source hash matched).

**ANONYMOUS REPOSITORY URL: NOT AVAILABLE — PUBLICATION PENDING** — nothing has been published.

## Scope (explicit allowlist)

112 files copied by allowlist (`config/public_export_allowlist.csv`, one documented reason per file) + 5 generated files. Categories:

| Category | Files |
|---|---|
| analysis-code | 2 |
| code | 21 |
| derived-table | 9 |
| e6-static | 8 |
| integrity-record | 4 |
| methodology | 16 |
| p1-evidence | 16 |
| raw-evidence | 16 |
| report | 3 |
| reproducibility | 3 |
| rules | 10 |
| status | 1 |
| verification-log | 3 |

**Excluded by design** (not in the allowlist): student names and IDs, member-level records, AI session logs and the AI interaction workbooks, private declarations and signatures, review checklists and private identity scans, internal backups, handoff / completion / changelog working files, the anonymization term list, packaging scripts whose detection lists contain identities, the unsent responsible-disclosure draft, credentials.

## Redaction applied (text files with transform = redact)

| What | Replaced with | Occurrences |
|---|---|---|
| build-machine host name (Falco `hostname` field, logs) | `lab-vm` | 265 |
| local home directory path | `/home/labuser` | 33 |
| local AI-session-store path | `[local AI session store]` | 3 |
| local user name in Falco `user.loginname` / `user_loginname` fields | `labuser` | 22 |

Redaction changes only identifying strings; no measurement, timestamp, rule, alert or count is altered. Redacted raw files therefore have a different SHA-256 from the private package; `PUBLIC_EXPORT_MANIFEST.csv` records both the source hash (as in the RC3 manifest) and the published hash for every file.

## Fail-closed checks (all passed for this build)

| Check | Result |
|---|---|
| Identity scan — member names (any spelling, diacritic-insensitive), name parts, student IDs (term list + ID pattern), user name, host name, home paths, handles, e-mail, machine-id, AI-session paths, institution terms | 0 findings in 117 files |
| Secret scan — cloud/API/GitHub/Slack tokens, private-key blocks, JWTs, URL credentials, password/token assignments, the known dummy lab DB password | 0 findings |
| Binary inspection — 2 binary files, each registered by SHA-256 in `config/public_export_binary_inspection.csv` with result PASS and re-checked automatically | PASS |
| Archive inspection — every member of every OOXML/ZIP container scanned (XML text + markup, media chunks, zip extra fields) | PASS |
| No `.git`, hidden files, symlinks or unlisted files; every allowlisted file present | PASS |
| Explicit exceptions (`config/public_export_exceptions.csv`, pinned to file SHA-256; never for names or student IDs) | 1 used: `05_METHODOLOGY_AND_TRACEABILITY/E6_community_ruleset_static/upstream/falco-rules-5.2.0.yaml` secret (generic_assignment) |
| Release archive `Group8_Public_Export.zip` — re-opened, 117 members, each re-scanned and byte-compared with the tree; normalised timestamps, no comment | PASS |

## Embedded metadata

| File | Metadata |
|---|---|
| `01_FINAL_REPORT/FINAL_REPORT_P0_REVISED.pdf` | Author: Group 8; Creator: Writer; Producer: LibreOffice 7.3; Title: Falco và Auditd phát hiện thực thi fileless trong container Docker (bản revised) |
| `01_FINAL_REPORT/FINAL_REPORT_P0_REVISED.docx` | creator: Group 8; title: Falco và Auditd phát hiện thực thi fileless trong container Docker (bản revised) |

Owner-approved identifiers that remain on purpose: the group identity **Group 8** (also *Nhóm 8*, *Group8* in file names) and the course code **IAM302** (owner instruction, 2026-11-04).

## Git metadata

The project is not a Git repository and this export contains no `.git` directory, so it carries no commit history or contributor metadata. If the owner later creates a repository from it, the first commit's author/committer name and e-mail are new metadata and must be set to a non-identifying value before pushing (anonymous.4open.science does not rewrite commit metadata of the source repository).

## Limits of this report

- Images were inspected visually once and are pinned by SHA-256; a changed image fails the build until re-inspected.
- Quasi-identifiers that are not names (writing style, the group number, the course code, dates) are not removed.
- A clean scan is necessary, not sufficient, for anonymity; the owner should review the export before any upload.


## RC4.1 additions (2026-11-05)

Excluded from the RC4 hand-off package:

- `OWNER_PUBLICATION_STEPS.md` — owner-only working instructions (local paths)
- `CHECKPOINT_STATUS.md` — internal progress log
- `CLEANUP_COMPLETE.md` — internal VM cleanup record
- `SLIDE_UPDATE_NOTES.md` — internal working note
- `RC4_HANDOFF_SUMMARY.md` — internal hand-off note (local paths); content covered by report §9
- `restore_points_log.md, restore_point_logs/` — VM restore-point internals (service states, local paths)
- `integrity/PRE_RC4_SHA256.txt, integrity/POST_RC4_SHA256.txt` — private file lists containing personal file names
- `report_output/` — superseded RC4 report and its checker (contains the identity block-list)
- `responsible_disclosure_draft_RC4.md` — unsent disclosure draft; release is the owner's decision
- `SHA256SUMS.txt` — refers to the private package; use PUBLIC_EXPORT_SHA256SUMS.txt

Redacted files (count per rule):

- `07_RC4_EXTENSIONS/prereg/PREREG_LEDGER.txt` — home path 6
- `07_RC4_EXTENSIONS/raw_excerpts/p1_branch_lines.jsonl` — host name 3
- `07_RC4_EXTENSIONS/runs/e7_run.attempt1.sh` — home path 1
- `07_RC4_EXTENSIONS/runs/e7_run.sh` — home path 1
- `07_RC4_EXTENSIONS/runs/e8_run.sh` — home path 1
- `07_RC4_EXTENSIONS/runs/e9_run.sh` — home path 1
- `07_RC4_EXTENSIONS/runs/fg_falco_harness.sh` — home path 1
- `07_RC4_EXTENSIONS/runs/p1_run.attempt1.sh` — home path 1
- `07_RC4_EXTENSIONS/runs/p1_run.sh` — home path 1

DOCX files were checked for comments, people and customXml parts (none) and metadata author = Group 8. The final scan below covers every file in this export.

Final identity scan (2026-11-05): 0 findings for host name, home path, logins, student-ID pattern, member names and local session paths (Vietnamese words 'xác minh'/'chứng minh' excluded).
