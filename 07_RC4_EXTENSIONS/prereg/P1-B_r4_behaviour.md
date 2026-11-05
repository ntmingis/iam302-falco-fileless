# Pre-registration — P1-B: R4 behavioural test

Status at registration: **NOT TESTED** (owner runs privileged steps). R4 syntax is VERIFIED only.

## Hypothesis
R4 (`rules/candidate_rules_v2.yaml`, `LAB2 memfd exec covered by runc exception without real runc parent`) fires on a
memfd exec that the default runc exception would exempt, unless the parent genuinely runs from a runc binary in
`lab_runc_paths`. It should fire on DEV-T1r (A), stay silent on the controls (B, D, E), and its behaviour on F/G must be
explained.

## Variants and n
Owner runbook: `evidence/dev_t1r_branch_coverage/sudo_commands.md` §D. Scenarios A, B, D, E, n = 5 each, under a bounded
temporary Falco instance loading installed default + `rules/custom_rules.yaml` (v1) + `rules/candidate_rules_v2.yaml`,
`rule_matching=all`, Method A. Benign payloads are those already defined in the runbook and `run_e1.sh`.
- **C** (legitimate runc memfd clone): **NOT REPRODUCIBLE** on this VM (runc 1.3.3 does not memfd-clone). Stays
  NOT TESTED. Never downgrade runc on the main VM; only attempt C in a separate disposable VM.
- **F** (empty/unreadable parent path) and **G** (real runc at an unlisted path): attempt only if constructible safely;
  otherwise BLOCKED with the reason.

## Outcome categories
Per scenario, score R4 and the default memfd rule in parallel: TP / TN / FP / FN per the expected-results table
(`evidence/P1_DEV_T1r/expected_results.md`). `blocked` and `misattrib` never count as `direct`.

## Expected outcome (design intent, not a result)
A → R4 fires (parent containerd-shim ∉ lab_runc_paths), default silent (exempt) → TP.
B → default fires, R4 silent → R4 correctly silent. D, E → both silent (`is_exe_from_memfd=false`) → TN.

## Decision rule
R4 is labelled a **validated mitigation** only if, in the measured run: A fires, the controls (B/D/E) stay silent, and
F/G behaviour is observed and explained. Otherwise R4 is **PARTIAL**. Because C — the central false-positive risk —
cannot be reproduced here, R4 cannot reach "validated" on this VM regardless of A/B/D/E; the best attainable state here
is PARTIAL, and that limitation is carried into `limitations_update.md`.
