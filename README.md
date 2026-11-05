# Falco + Auditd fileless-execution detection in Docker — public research export (Group 8, IAM302)

**ANONYMOUS REPOSITORY URL: NOT AVAILABLE — PUBLICATION PENDING**

Public export of the Group 8 IAM302 research project *"Evaluating Falco and Auditd for Detecting Fileless Execution in
Docker Containers"* (Falco 0.45 modern eBPF + Auditd, Docker / runc, Ubuntu 22.04, kernel 6.8, benign payloads only).

> Group 8 collaboratively conducted the research, technical development, experimental preparation, evidence collection, analysis, and documentation activities described in this report.
>
> AI tools, particularly Claude Code and ChatGPT, were used as substantial development assistance throughout the Group 8 project. Their contributions included generating and refining technical scripts, detection rules, parsers, testing utilities, evidence-processing workflows, analytical materials, and documentation. AI-generated outputs were reviewed, evaluated, and revised under human direction. Research scope, experimental decisions, evidence interpretation, and final acceptance remained subject to human review and responsibility.

The extent of AI involvement is disclosed in report §14.

## Contents (183 files)

| Path | What |
|---|---|
| `01_FINAL_REPORT/` | Final report RC4.1, condensed paper, group AI declaration (PDF + DOCX), change log, `report_notes.md` |
| `02_P0_EVIDENCE/` | E1–E5 raw Falco alert streams of the canonical runs, run version records, derived tables, E4 reclassification script |
| `03_P1_EVIDENCE/` | DEV-T1r memfd-exception evidence: raw events, branch coverage, field semantics, read-only automation outputs |
| `05_METHODOLOGY_AND_TRACEABILITY/` | Claim → evidence mapping, reclassification, branch analyses, limitations, related work, E6 static scan, E7–E9 design |
| `06_REPRODUCIBILITY/` | Harness, parsers, analysis and validation scripts, rule files, environment, reproduction instructions, verification logs |
| `07_RC4_EXTENSIONS/` | RC4 follow-up (P1 branch tests, R4, E6-dynamic, E7 Tracee/Tetragon, E8 external variants, E9 AppArmor): pre-registrations, run scripts, scorers, tables |
| `RELEASE_STATUS.md` | Maturity of every milestone and experiment (VERIFIED / PARTIAL / NOT TESTED) |
| `PUBLIC_EXPORT_MANIFEST.csv` | Every file: source, source hash, published hash, transform, reason for publication |
| `PUBLIC_EXPORT_SHA256SUMS.txt` | `sha256sum -c PUBLIC_EXPORT_SHA256SUMS.txt` |
| `PUBLIC_SANITIZATION_REPORT.md` | What was removed or redacted and how it was checked |
| `REPOSITORY_PUBLICATION_STATUS.md` | Repository / anonymous-mirror status |

## Key results and limits (RC4.1)

Unit of analysis = variant, n = 5 deterministic repetitions, 95% Wilson intervals, one VM.

- **E4 strict-unseen (primary):** custom 1/4 [0.05, 0.70] vs default 0/4 [0.00, 0.49]; the earlier 2/5 figure is a
  labelled historical sensitivity row only.
- **E8 independent external variants (separate from E4):** custom v1 5/8 [0.31, 0.86] vs default 1/8 [0.02, 0.47].
- **DEV-T1r / memfd exception:** branches `proc.exepath` (memfd name) and `proc.exe` (argv[0], NT-B4) are verified
  bypasses (default rule 0 alerts in 5/5 runs each); `proc.name` non-match verified; the `proc.pname` positive case could
  not be built (NT-B2 INCONCLUSIVE). Candidate mitigation R4 is PARTIAL (legitimate runc memfd clone not reproducible).
- **E6 community rulesets:** 0/19 additional direct detections [0.00, 0.17]. **E7:** Tracee v0.23.2 7/9 modelled
  variants [0.45, 0.94]; Tetragon v1.7.1 base sensor only (no TracingPolicy) — no fileless indicator, not a head-to-head
  comparison. **E9:** under AppArmor unconfined the label-based Auditd container proxy attributes 0/5 variants, a
  PID/cgroup-lineage parser 5/5; PARTIAL because the default-profile control arm lost records (10/25 runs).
- Rules and lab variants share an author; only E8 is independent.

## Notes on the evidence

- Text evidence was redacted only for the lab machine's host name (`lab-vm`), its local home path (`/home/labuser`) and
  a local AI-session path. No measurement was changed. Published hashes therefore differ from the private originals for
  redacted files; both hashes are in `PUBLIC_EXPORT_MANIFEST.csv`. The `SHA256SUMS.txt` files *inside* evidence
  sub-folders are the original records and refer to the unredacted private files; verify this export with
  `PUBLIC_EXPORT_SHA256SUMS.txt`.
- Scripts expect the original project layout (see `06_REPRODUCIBILITY/reproduction_instructions.md`); privileged steps
  need `sudo` on an isolated lab VM. Payloads are benign test programs.
- Large raw Auditd logs, exploratory runs, AI interaction records and internal working documents are not included.
- The previous P0/RC3 report was replaced by RC4.1; the RC3 hand-off text above the results table is otherwise unchanged.
