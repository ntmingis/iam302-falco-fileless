# E4 independence reclassification (P0.1, 2026-11-03)

Status: **VERIFIED** (counts recomputed from raw logs; timeline from file metadata + Claude Code transcript `d5799203`).
Script: `report/tools/e4_reclassify.py` → `report/tables/e4_reclassified_{variants,subsets}.csv`, `report/tables/e4_sensitivity.csv`.
Historical tables (`e4_unseen_summary.csv`, `e4_coverage.csv`, `test_independence.csv`) are **not modified**; they remain the record of the 2026-10-22 / 2026-11-02 classification.

## 1. What changed

| | Historical (report 2026-10-22, revised 2026-11-02) | P0 (this document) |
|---|---|---|
| Primary strict-unseen set | E4-T3d, E4-T2b, E4-T4b, E4-T5b, **E4-T5c** | E4-T3d, E4-T2b, E4-T4b, E4-T5b |
| Strict custom (variant unit) | 2/5, 95% Wilson [0.12, 0.77] | **1/4, 95% Wilson [0.05, 0.70]** |
| Strict default | 0/5, [0.00, 0.43] | **0/4, [0.00, 0.49]** (one-sided exact 95% upper bound 0.53) |
| E4-T5c | strict (with a sensitivity note) | **related-unseen** |
| 2/5 | primary | kept only as a superseded sensitivity row |

Raw per-variant outcomes are **unchanged** (cross-check against `e4_unseen_summary.csv`: 0 mismatches). Only the grouping changed.

## 2. Evidence trail for E4-T5c

All times are local (UTC+7). Transcript = `[local AI session store]/d5799203-….jsonl` (line numbers split on `\n`).

| Time | Event | Evidence |
|---|---|---|
| 2026-10-19 14:53:11 | `~/Downloads/custom_rules.yaml` last modified. Header "Nhom 8 IAM302 (ban nhap E3)". Rule `LAB Download piped to shell in container` already contains `proc.pcmdline contains "\| sh"` / `"\|sh"` | `stat`; sha256 `69146033…26de` |
| 2026-10-20 23:45:44 | Claude Code copies it with `cp -p` to `rules/custom_rules.draft0.yaml` (this is why the copy's mtime says 10-19 while its birth time is 10-20 23:45) | transcript line 785; `stat %w`; identical sha256 |
| 2026-10-21 00:04:33 | AI notes (summarised reasoning) that `Execution from /dev/shm` uses `proc.exe` (argv[0]) and decides to keep an argv0 variant for E4, not for rule design | transcript line 979 |
| 2026-10-21 00:04:53 | AI writes `rules/custom_rules.yaml` v1-pre (4 rules); `\| sh` carried over from draft0 | transcript line 980; `custom_rules.v1pre.20261021_001017.yaml` |
| 2026-10-21 00:05:33 | AI dry-runs the seven E4 payloads, incl. `curl … \| sh`. Only payload stdout was read; **no Falco output was inspected** | transcript lines 999–1000 |
| 2026-10-21 00:06:04 | E4 functions added to `run_e1.sh` | transcript line 1011; `run_e1.sh.v3b.20261021_000605.bak` has no `e4_` |
| 2026-10-21 00:09:26 | prctl/name probe of the memfd exception (DEV) | transcript line 1176 |
| 2026-10-21 00:10:17 | Two rules **added** to v1: `LAB memfd exec masquerading as runc clone` and `LAB Shell reading script from downloader pipe in container`; v1 frozen (sha256 `8811248c…`) | transcript line 1183; `diff v1pre v1` |
| 2026-10-21 00:10:29 | DEV block added to `run_e1.sh` (anchored on the already-present E4 block) | transcript line 1196; `run_e1.sh` mtime |

Two independent reasons E4-T5c cannot be strict-unseen:

1. **Literal enumeration.** `| sh` is a literal alternative in the rule condition and was present in draft0 before E4 existed. The variant differs from T5 only by that string. The rule did not have to generalise; the case was written into it.
2. **Rule added after the variant was written.** `LAB Shell reading script from downloader pipe in container` (shell with empty args whose parent cmdline contains `curl `/`wget ` and `|`) was added at 00:10:17, about four minutes after the E4-T5c command text was written by the same author (the AI) in the same context. In the custom run, both rules fired on E4-T5c (`e4_reclassified_variants.csv`, `custom_alerts`). The transcript shows no Falco output for E4 being read before the freeze, so this is **contamination by design context, not by observed results**. It is still enough to exclude the variant.

**Correction to an earlier statement.** `docs/limitations.md` §3 and the revised report §5.1 say E4 independence is "guaranteed by chronology (rules frozen 00:10:17 before the E4 functions appear at 00:10:29)". That is inaccurate: 00:10:29 is the DEV block. The E4 functions were written at 00:06:04, before the last rule edit. The P0 report replaces that statement.

What the evidence does **not** show: who wrote `~/Downloads/custom_rules.yaml` on 2026-10-19 (no Git history, no transcript before 2026-10-20; the student stated on 2026-11-02 that the authorship cannot be established). File mtime is not used as proof of authorship, only as proof that the `| sh` text existed before E4 was designed. Origin: **PENDING HUMAN CONFIRMATION**.

## 3. Criteria and resulting classes

A held-out variant is **strict-unseen** only if all hold:

- (a) it was not executed or observed under Falco before the custom rules were frozen;
- (b) it is not syscall-equivalent to a known variant;
- (c) its distinguishing feature is not literally enumerated in any rule draft;
- (d) no rule was added or changed after the variant was written that matches it;
- (e) it belongs to Group A (fileless).

| Variant | Class | Default | Custom | Reason |
|---|---|---|---|---|
| T1–T7 (11 E1 variants) | known / in-sample | see E1 | see E3 | used in probe run for rule design |
| DEV-T1r | known / in-sample | miss 5/5 | direct 5/5 | used to write `LAB memfd exec masquerading as runc clone` |
| E4-T1b | related-unseen | direct | direct | fails (b): execveat (syscall 322) like T1; memfd name differs only |
| E4-T6b | related-unseen | miss | direct | fails (e): Group B; same `LD_PRELOAD` variable as T6 |
| E4-T5c | related-unseen | miss | direct | fails (c) and (d), section 2 |
| E4-T3d | strict-unseen | miss | direct | same `/proc/self/fd` family; argv0 + Python launcher differ |
| E4-T2b | strict-unseen (caveat) | miss | miss | conceived at 00:04:33 before freeze but never executed under Falco; custom rules have no /dev/shm clause; a miss either way |
| E4-T4b | strict-unseen | miss | miss | code via stdin |
| E4-T5b | strict-unseen | miss | miss | pipeline inside a script file |
| — | independent / external | NOT TESTED | NOT TESTED | no variant designed by anyone other than the rule author (E8 PLANNED) |

Note on E4-T1b vs T1: T1 uses `os.execve(fd)`, which CPython implements with `fexecve` → glibc `execveat(fd, "", …, AT_EMPTY_PATH)`. Audit shows syscall 322 for both (`results/e1_default_20261021_001604/audit.log`; see `docs/claim_audit.md` II.6). A syscall-equivalent variant is not counted as a separate mechanism.

## 4. Recomputed metrics (variant unit; run unit for reference only)

From `report/tables/e4_reclassified_subsets.csv`:

| Subset | Ruleset | k/n variants | 95% Wilson | runs (reference) |
|---|---|---|---|---|
| All E4 held-out (7) | default | 1/7 | [0.03, 0.51] | 5/35 |
| All E4 held-out (7) | custom | 4/7 | [0.25, 0.84] | 20/35 |
| Related-unseen (3) | default | 1/3 | [0.06, 0.79] | 5/15 |
| Related-unseen (3) | custom | 3/3 | [0.44, 1.00] | 15/15 |
| **Strict-unseen P0 (4)** | default | **0/4** | [0.00, 0.49] | 0/20 |
| **Strict-unseen P0 (4)** | custom | **1/4** | [0.05, 0.70] | 5/20 |
| Strict historical (5, superseded) | default | 0/5 | [0.00, 0.43] | 0/25 |
| Strict historical (5, superseded) | custom | 2/5 | [0.12, 0.77] | 10/25 |
| Independent / external | — | 0/0 | NOT TESTED | — |

Outcome categories within the strict P0 set (5 runs each): custom direct 1 variant (E4-T3d), misattributed 0, missed 3 (E4-T2b, E4-T4b, E4-T5b), blocked 0. Default: direct 0, misattributed 0, missed 4, blocked 0. Payload success 5/5 for every variant in both runs.

**Rule of three** is not used for E4: at n = 4 it gives 0.75, which is not informative. For default 0/4 we report the exact one-sided 95% upper bound 1 − 0.05^(1/4) = 0.53. The rule-of-three statement in the report concerns E2 (0/10 → ≈ 0.3) only and is unaffected.

### Sensitivity (`e4_sensitivity.csv`)

| Scenario | Custom | Default |
|---|---|---|
| Strict P0 (primary) | 1/4 [0.05, 0.70] | 0/4 [0.00, 0.49] |
| + E4-T5c (historical definition) | 2/5 [0.12, 0.77] | 0/5 [0.00, 0.43] |
| − E4-T2b (conceived before freeze) | 1/3 [0.06, 0.79] | 0/3 [0.00, 0.56] |
| − E4-T2b, + E4-T5c | 2/4 [0.15, 0.85] | 0/4 [0.00, 0.49] |

Every interval is wide and overlaps every other. The data cannot tell 1/4 from 2/5. The reclassification changes the claim we are entitled to make, not the evidence of a trend.

## 5. Limitations of this reclassification

- All variants, held-out or not, were written by the same author (the AI, under student direction) in the same session as the rules. "Strict-unseen" means *held out by the author*, not *independent*. Criterion (a) is supported by the transcript only for Falco output being read; the author's knowledge of the rules while writing variants cannot be ruled out, and for E4-T3d the v1 rule comment states explicitly that it was designed to be argv0-independent.
- Four variants in four families: the unit of inference is the variant, and n = 4 supports no rate estimate.
- The criteria were written after the results were known (2026-11-03). They are stated so that a reader can apply them differently. The sensitivity table shows what each choice gives.
- Draft0 authorship is unknown (section 2). The conclusion does not depend on who wrote it, only on the fact that the text existed before E4.
