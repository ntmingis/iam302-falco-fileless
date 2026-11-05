# DEV-T1r upstream exception analysis (P1.3, 2026-11-03)

Status: **VERIFIED** against the installed ruleset, upstream PR #268 and issue #3444 (read 2026-11-03). This is a **detection-rule coverage gap**, not a confirmed CVE or engine defect (classification in §4).

## 1. The exact exception, as installed

`/etc/falco/falco_rules.yaml` (sha256 `30a1a602…`, = tag `falco-rules-5.2.0`, = upstream `main` 2026-10-22, byte-for-byte), lines 1255-1263:

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

Used by `Fileless execution via memfd_create` (Critical) as `and not known_memfd_execution_processes`.

## 2. What false positive it was added for

- **Issue #3444** (falcosecurity/falco, opened 2025-01-10, closed 2025-02-21): on Bottlerocket with runc ≥ 1.1.15, the Critical rule fired on runc's own startup. runc clones itself into a memfd to mitigate CVE-2019-5736 (container breakout via overwriting the host runc binary). The reported alert fields: `process=5`, `proc_exepath=memfd:runc_cloned:/proc/self/exe`, `parent=runc`, `command=5 init`, `gparent=oci-add-hooks`, `exe_flags=EXE_WRITABLE|EXE_FROM_MEMFD`.
- Note the reported `proc.name` was a number (`5`), and `proc.pname` was `runc`.
- **PR #268** (merged 2025-02-17, commit 4633f29) changed the list from `items: []` to `items: [runc]` and replaced the single-line macro with the four-branch version above. So **three of the four branches (pname, exepath, exe) were added at once** by this PR; only the `proc.name` branch pre-existed (against an empty list).
- A reviewer (loresuso) noted on the PR that memfd execution often shows a numeric `proc.name` and suggested ancestor fields; the exepath/exe string branches were added because `proc.name`/`proc.pname` alone did not reliably match real runc.

## 3. Why DEV-T1r matches the exception scope — and why that is the gap

The memfd name and argv[0] are **chosen by the calling process** (`memfd_create(2)`: the name "is always prefixed with `memfd:` and serves only for debugging purposes"). Branches B3 and B4 compare `proc.exepath`/`proc.exe` to a **fixed attacker-choosable string**. DEV-T1r sets the memfd name to exactly `runc_cloned:/proc/self/exe`, so `proc.exepath` becomes `memfd:runc_cloned:/proc/self/exe` and branch B3 matches. The exception was intended to exempt *real runc*, but its B3/B4 branches exempt *anything that names its memfd like runc*.

The alert is missing **because of the exception (branch B3)**, not because of another condition: the base condition `proc.is_exe_from_memfd=true` is satisfied (the custom rule fires on the same event), and the only reason the default rule stays silent is that the macro is true. This is established from the custom run, which captured `proc.exepath = memfd:runc_cloned:/proc/self/exe` on the alerting event (`evidence/dev_t1r_branch_coverage/dev_t1r_event_fields.txt`).

`rule_matching` does not change this: the memfd rule is in the default file and is the only one keyed on `is_exe_from_memfd`; with `rule_matching: first` or `all`, a suppressed rule produces no alert either way. (The `rule_matching` issue in this project concerns custom rules being shadowed by default rules on the *same* event — not relevant here, since the default rule is the one suppressed.)

## 4. Classification (deliberately conservative)

| Candidate label | Applies? |
|---|---|
| Detection-rule coverage gap | **Yes** — the gap is in rule content (a macro), distributed in the ruleset |
| Exception overbreadth | **Yes** — the exemption is broader (any matching name) than its intent (real runc) |
| Event-model limitation | Partly — `proc.exepath` for a memfd reflects an attacker-chosen name; the engine exposes kernel-backed alternatives (`proc.pexepath`), so this is not a hard model limit |
| Engine-level defect | **No** — the engine evaluates the rule correctly |
| Incorrect attribution | **No** |

Falco's SECURITY.md (read 2026-11-03) treats "gaps in rule coverage and other detection-content improvements" as ordinary bugs, and reserves "silent detection bypass" (a vulnerability) for breaking the integrity of the *mechanism* (engine, driver, event handling), not the completeness of rule *content*. This finding is rule content. Because it silences a Critical rule without a trace, the draft recommends emailing the SECURITY channel first and letting maintainers classify. **Not** called a CVE.

A GitHub search on 2026-11-02 (falcosecurity/rules, falcosecurity/falco, terms "runc_cloned"/"memfd") found no public issue about spoofing this exception; that does not prove none was reported privately. Draft for maintainers: `docs/responsible_disclosure_draft.md` (unsent; the decision is the owner's).

## 5. Precise scope

- Affects every ruleset carrying this macro: from PR #268 (2025-02) through `main` 2026-10-22, including `falco-rules-5.2.0` which Falco 0.45.0 pins.
- Precondition: the attacker can already run code in the container/host (that is the premise of the fileless rule itself).
- Which branch is spoofable (updated 2026-11-03 with the field-semantics proof in `evidence/P1_DEV_T1r/field_semantics_evidence.md`):
  - **B3 (`proc.exepath`)** — VERIFIED spoofable; this is the branch DEV-T1r rides (captured exact-match value).
  - **B4 (`proc.exe` via argv[0])** — spoofable in principle: the probe run proves `proc.exe` = argv[0] on this VM, so argv[0] = `memfd:runc_cloned:/proc/self/exe` (any memfd name) would match B4. DEV-T1r does not use it; reachability test = NT-B4 (NOT TESTED).
  - **B1 (`proc.name`)** — not reachable by the memfd name: `proc.name` is always rendered `memfd:<name>` for an fd-exec, so it can never equal bare `runc`.
  - **B2 (`proc.pname`)** — needs a *live* parent whose comm is `runc` at the memfd execve; the real-runc FP had `parent=runc`, but DEV-T1r's runc parent has exited (parent=containerd-shim). Whether a runc-named parent can be kept alive (NT-B2) is NOT TESTED; a `prctl(PR_SET_NAME,"runc")` rename did not bypass.

## 6. Definitions of the candidate classifications (so the label is precise)

The §4 table uses these terms with these meanings:

- **Detection-rule coverage gap** — the detection *content* (a rule/macro/list shipped in the ruleset) does not cover a technique it is meant to, while the engine, driver and event model all work correctly. Fixed by editing rule content.
- **Overbroad exception** — a specific sub-case of a coverage gap where an *allow/exempt* clause added to suppress false positives is wider than its intent, so it also suppresses true positives. Here the runc exemption (intended for real runc) also exempts anything that *names itself* like runc.
- **Event-model limitation** — the engine cannot express a reliable condition because the needed information is not in the event model at all. Not the case here: kernel-backed alternatives (`proc.pexepath`, ancestor paths) exist and R4 uses them.
- **Incorrect process attribution** — Falco reports the wrong process/identity for an event (e.g. the overlayfs copy-up `procfd_link` artifact elsewhere in this project). Not the case here: the fields Falco reports are correct; the attacker simply chose values that satisfy the exempt string.
- **Engine-level defect** — the rule engine, driver or event handling evaluates a correct rule incorrectly, or drops/mis-delivers events. Not the case here: the engine evaluates the macro exactly as written.

**DEV-T1r is an *overbroad exception* (a form of detection-rule coverage gap).** It is explicitly **not** an engine defect, event-model limitation, incorrect attribution, or a confirmed CVE. Any disclosure uses that framing.

## 7. Direct DEV-event capture vs field-semantics evidence (2026-11-03 semantic audit)

The four exempt branches are not evidenced equally, and the distinction must be kept:

- **Directly captured in the DEV-T1r raw event** (`results/e1_custom_20261021_012554_dev/falco_events.json`, `output_fields`): `proc.exepath` (= `memfd:runc_cloned:/proc/self/exe` → **B3 matches, VERIFIED**) and `proc.pname` (= `containerd-shim` → **B2 non-match, VERIFIED**). The alerting rule templated only `proc.cmdline`, `proc.exepath`, `proc.pexepath`, `proc.pname`.
- **Not recorded in the DEV-T1r event**: `proc.name` and `proc.exe`. So **B1** (`proc.name`) is **INFERRED** — `proc.name` must not be read from the `proc.cmdline` first token; that is an inference, not the field — and **B4** (`proc.exe`) is **VERIFIED FIELD SEMANTICS; DEV-SPECIFIC VALUE INFERRED**, resting on the probe run (`results/e1_probe_20261020_235831_probe/…`, which *did* record `proc.exe`=argv0 for a memfd exec) plus the known payload, not on a captured DEV value.

Consequence for the headline: **B3 is the only branch confirmed to match by a directly captured DEV field**; the "sole suppressor" statement is sound as "sole *directly verified* matching branch", with B1/B4 non-matches inferred (closable by the DIAG-FIELDS capture in `evidence/dev_t1r_branch_coverage/sudo_commands.md §3A`). This does not change the finding (the default rule is silenced via the exception) or its classification; it only scopes the evidence grade per branch. The published final report already states this conservatively (`proc.exepath` VERIFIED; `proc.exe` INFERRED/NOT TESTED; `proc.pname` probe did not bypass), so **no report claim changes**.
