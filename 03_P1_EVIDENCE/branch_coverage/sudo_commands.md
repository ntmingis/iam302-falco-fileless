# Level-3 privileged commands — for the owner to review and run (NOT executed by the assistant)

**Status of every test here: NOT TESTED.** Nothing in this file has been run. The assistant does not execute any of it. Run only in a disposable VM with a snapshot.

All payloads are benign: they create an in-memory copy of `/bin/echo`, run it so it prints a marker token, and exit — nothing written to disk, no network, no persistence. `sudo` prompts in your terminal; never put a password in a file or chat.

## Method policy (read before anything)
- **Method A (preferred): a bounded temporary `falco -M 90` instance** that loads rules via `-r` and **does not touch `/etc/falco`, does not restart any service, and does not change Auditd.** All tests below are designed for Method A.
- **Method B (fallback): install into `/etc/falco/rules.d` + restart `falco-modern-bpf`.** It is **DISABLED in this document and requires separate explicit approval**, because it modifies `/etc/falco` and restarts the sensor. Do **not** fall through to Method B automatically — in particular, if Method A's temporary instance fails to start (device busy / permission / driver attach failure), **STOP** and report; do not switch to Method B without approval.
- Concurrent modern-eBPF instances (a temp `falco` alongside the running `falco-modern-bpf`) are **not assumed to work** — section A verifies it, and if it fails you stop.

Conventions: `$TOK` is a per-run marker. `$RAW=evidence/P1_DEV_T1r/raw_logs`. Default-sensor Falco alerts (if you ever read the installed sensor) are in the journal: `journalctl -u falco-modern-bpf -o cat`.

---

## A. Read-only preflight (no changes to services, /etc/falco, or Auditd)

```bash
cd /home/labuser/lab/falco_lab_containers
RAW=evidence/P1_DEV_T1r/raw_logs
mkdir -p "$RAW"

# A1. RECORD service states (do NOT change them). Persist so restore (I) can compare.
{
  echo "falcoctl-artifact-follow=$(systemctl is-active falcoctl-artifact-follow 2>/dev/null)"
  echo "falco-modern-bpf=$(systemctl is-active falco-modern-bpf 2>/dev/null)"
  echo "recorded_at=$(date -Is)"
} | tee "$RAW/service_state_before.txt"
# NOTE: this file is the source of truth for section I. Method A never stops falcoctl-artifact-follow.

# A2. Versions / identity (record only)
falco --version | tee "$RAW/falco_version.txt"            # expect falco_version 0.45.0, engine 0.65.0, driver 11.0.0
readlink -f "$(which runc)"; runc --version | head -1      # expect /usr/bin/runc, runc 1.3.3 (in lab_runc_paths)
sha256sum /etc/falco/falco_rules.yaml | tee "$RAW/ruleset_hash_before.txt"
#   expect 30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b

# A3. Validate every rules file used below (no load, no sudo needed)
falco -V /etc/falco/falco_rules.yaml \
      -V evidence/P1_DEV_T1r/candidate_rules_copy/lab_diag_fields.yaml \
      -V rules/custom_rules.yaml \
      -V rules/candidate_rules_v2.yaml 2>&1 | tee "$RAW/validate.txt" | tail -1
#   expect a JSON line with all "successful":true, "schema_valid":true

# A4. Lab up + target container sanity (read-only checks)
sudo ./labctl.sh up
docker ps --format '{{.Names}}' | grep -q '^falco-lab-target$' && echo "target up" || echo "TARGET MISSING -> stop"
docker exec falco-lab-target test -x /usr/local/bin/python3 && echo "python3 present" \
  || echo "python3 MISSING at /usr/local/bin/python3 -> NT-B2 copy step must be adjusted (see C)"

# A5. Auditd execveat coverage (decides whether ausearch is usable as independent evidence)
sudo auditctl -l | grep -Ew 'execve|execveat' | tee "$RAW/auditd_execve_rules.txt" \
  || echo "NO execve/execveat audit rule loaded -> ausearch will likely be empty; rely on docker stdout + Falco DIAG instead"

# A6. VERIFY a concurrent temporary modern-eBPF instance can start AT ALL (3s smoke test).
#     If this fails, Method A is not available on this host -> STOP (do NOT go to Method B without approval).
sudo falco --modern-bpf -M 3 -o json_output=true -o stdout_output.enabled=true -o log_level=info \
  -r /etc/falco/falco_rules.yaml >"$RAW/smoke.json" 2>"$RAW/smoke.err" ; echo "smoke exit=$?"
if grep -qiE 'device.?busy|permission denied|unable to (load|open)|failed to (open|attach)|driver' "$RAW/smoke.err"; then
  echo "STOP: temporary modern-eBPF instance cannot attach concurrently. Do NOT proceed to Method B automatically; report this."
else
  echo "Method A available: concurrent temp instance started and exited cleanly."
fi
```
Expected: `target up`, `python3 present`, ruleset hash matches, validate all true, and A6 prints "Method A available". If A6 says STOP, do not run B–D.

---

## B. DIAG-FIELDS — directly capture all four branch fields (Method A)

Goal: record `proc.name`, `proc.exe`, `proc.exepath`, `proc.pname`, `proc.is_exe_from_memfd` for the live DEV-T1r memfd execve, so B1/B4 can move from inferred to directly captured. `rule_matching=all` ensures the diagnostic rule emits even when a detector also matches the same event.

```bash
cd /home/labuser/lab/falco_lab_containers; RAW=evidence/P1_DEV_T1r/raw_logs; mkdir -p "$RAW"
DIAG=evidence/P1_DEV_T1r/candidate_rules_copy/lab_diag_fields.yaml

# B1. start bounded temp instance (90s), capture PID + stderr
sudo falco --modern-bpf -M 90 -o json_output=true -o stdout_output.enabled=true -o rule_matching=all -o log_level=info \
  -r /etc/falco/falco_rules.yaml -r "$DIAG" >"$RAW/diag_fields_raw.json" 2>"$RAW/diag_fields_falco.err" &
FPID=$!
sleep 4
# B2. VERIFY it is actually running before sending the payload; scan stderr for driver failures
if ! kill -0 "$FPID" 2>/dev/null || grep -qiE 'device.?busy|permission denied|unable to (load|open)|failed to (open|attach)' "$RAW/diag_fields_falco.err"; then
  echo "STOP: temp Falco not running / driver error. See $RAW/diag_fields_falco.err. Do NOT run the payload; do NOT use Method B."
else
  # B3. run DEV-T1r once (prints TOK to docker stdout = independent proof it executed)
  TOK=DIAG_$(date +%s); echo "TOK=$TOK" | tee "$RAW/diag_fields_tok.txt"
  docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('runc_cloned:/proc/self/exe'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$TOK" \
    | tee "$RAW/diag_fields_payload_stdout.txt"
  # B4. wait for the -M window to end, capture exit status
  wait "$FPID"; echo "falco exit status: $?" | tee -a "$RAW/diag_fields_falco.err"
fi
```

```bash
# B5. classify each field as CAPTURED / EMPTY / ABSENT from the raw JSON (does NOT modify the JSON)
python3 -I - "$RAW/diag_fields_raw.json" <<'PY'
import json,sys
want=["proc.name","proc.exe","proc.exepath","proc.pname","proc.is_exe_from_memfd"]
rows=[]
for l in open(sys.argv[1],encoding="utf-8",errors="replace"):
    l=l.strip()
    if not l: continue
    try: e=json.loads(l)
    except Exception: continue
    if e.get("rule")!="LAB Diag memfd fields": continue
    o=e.get("output_fields",{}) or {}
    rows.append(o)
if not rows:
    print("NO DIAG EVENT CAPTURED -> payload may not have been observed; treat all branches as NOT TESTED"); sys.exit()
for o in rows:
    print("---")
    for k in want:
        if k not in o:          state="ABSENT (field not in event)"
        elif o[k] in (None,"<NA>"): state="ABSENT (null/<NA>)"
        elif o[k]=="":          state="EMPTY (present, empty string)"
        else:                   state=f"CAPTURED = {o[k]!r}"
        print(f"  {k}: {state}")
PY
```
**Expected (design intent, NOT TESTED):** one `LAB Diag memfd fields` event with `proc.is_exe_from_memfd=true`, `proc.exepath=memfd:runc_cloned:/proc/self/exe`, `proc.pname=containerd-shim`, `proc.name=memfd:runc_clon`, `proc.exe=x`. **Only fields that print `CAPTURED` may be cited as directly verified** — an `ABSENT`/`EMPTY` field stays inferred/NOT TESTED. Do not claim a field is verified if the event did not contain it.

---

## C. NT-B1 / NT-B2 / NT-B4 — isolated branches, observed with fields (Method A)

Each runs under a temp instance loading the default rules **and** the diag rule (`rule_matching=all`), so for every payload you see both (i) whether the default `Fileless execution via memfd_create` fired and (ii) the actual `proc.*` field values that decide the branch. **A missing alert alone is not evidence** — you must also see the DIAG event (proof the exec was observed) and the field values; if the deciding field is ABSENT/EMPTY or cannot be attributed to one branch, record the test **INCONCLUSIVE**.

```bash
cd /home/labuser/lab/falco_lab_containers; RAW=evidence/P1_DEV_T1r/raw_logs; mkdir -p "$RAW"
DIAG=evidence/P1_DEV_T1r/candidate_rules_copy/lab_diag_fields.yaml

run_nt(){   # $1=label  (payload is piped on stdin as a python -c body is inconvenient; use explicit blocks below)
  :; }

# start one 120s window for all three (or repeat per test)
sudo falco --modern-bpf -M 120 -o json_output=true -o stdout_output.enabled=true -o rule_matching=all -o log_level=info \
  -r /etc/falco/falco_rules.yaml -r "$DIAG" >"$RAW/branch_isolation_raw.json" 2>"$RAW/branch_isolation_falco.err" &
FPID=$!; sleep 4
if ! kill -0 "$FPID" 2>/dev/null || grep -qiE 'device.?busy|permission denied|failed to (open|attach)' "$RAW/branch_isolation_falco.err"; then
  echo "STOP: temp Falco not running. See $RAW/branch_isolation_falco.err. Do NOT run payloads; do NOT use Method B."
else
  # NT-B4: argv0 = exempt string, memfd name DIFFERENT (B3 cannot match) -> does proc.exe (B4) match?
  TOK=NTB4_$(date +%s); echo "$TOK" | tee -a "$RAW/branch_toks.txt"
  docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('not_runc_name'); os.write(fd,open('/bin/echo','rb').read())
os.execve(fd,['memfd:runc_cloned:/proc/self/exe',sys.argv[1]],{})" "$TOK" | tee -a "$RAW/branch_payload_stdout.txt"

  # NT-B1: memfd named 'runc' -> proc.name=memfd:runc (prefixed); B1 cannot be bare 'runc'
  TOK=NTB1_$(date +%s); echo "$TOK" | tee -a "$RAW/branch_toks.txt"
  docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('runc'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$TOK" | tee -a "$RAW/branch_payload_stdout.txt"

  # NT-B2: parent exec'd from a file named 'runc', stays alive as the parent; memfd name non-matching.
  # Precondition (A4): /usr/local/bin/python3 must exist; if MISSING, substitute "$(command -v python3)".
  PY=/usr/local/bin/python3
  docker exec falco-lab-target test -x "$PY" || PY=python3
  TOK=NTB2_$(date +%s); echo "$TOK (parent=$PY)" | tee -a "$RAW/branch_toks.txt"
  docker exec falco-lab-target bash -c 'cp "'"$PY"'" /tmp/runc 2>/dev/null; exec -a runc /tmp/runc -c "import os,sys
fd=os.memfd_create(\"benign_b2\"); os.write(fd,open(\"/bin/echo\",\"rb\").read()); os.execve(fd,[\"x\",sys.argv[1]],{})" "$0"' "$TOK" | tee -a "$RAW/branch_payload_stdout.txt"

  wait "$FPID"; echo "falco exit status: $?" | tee -a "$RAW/branch_isolation_falco.err"
fi
```

```bash
# Interpret: per TOK, pair the DIAG fields with whether the default memfd rule fired. INCONCLUSIVE if the deciding field is ABSENT/EMPTY.
python3 -I - "$RAW/branch_isolation_raw.json" <<'PY'
import json,sys
ev=[json.loads(l) for l in open(sys.argv[1],encoding="utf-8",errors="replace") if l.strip() and l.strip()[0]=="{"]
diag=[e for e in ev if e.get("rule")=="LAB Diag memfd fields"]
det =[e for e in ev if e.get("rule")=="Fileless execution via memfd_create"]
print("DIAG events:",len(diag),"| default-memfd alerts:",len(det))
for e in diag:
    o=e.get("output_fields",{}) or {}
    print("  DIAG", {k:o.get(k,"<absent>") for k in ("proc.name","proc.exe","proc.exepath","proc.pname","proc.is_exe_from_memfd")})
print("Rule: a branch 'matched' only if its deciding field has the exempt value AND the default rule was suppressed for that exec.")
print("If you cannot attribute suppression to exactly one field, record the test INCONCLUSIVE.")
PY
# Auditd cross-check only if A5 showed an execve/execveat rule; otherwise skip (ausearch would be empty):
if grep -q execve "$RAW/auditd_execve_rules.txt" 2>/dev/null; then
  sudo ausearch -sc execveat -ts recent | tee "$RAW/auditd_execveat.txt"
else echo "skip ausearch: no execve/execveat audit rule (A5)"; fi
```
**Expected (NOT TESTED):** NT-B4 argv0=exempt → B4 matches → default suppressed (and DIAG shows `proc.exe`=that string); NT-B1 `proc.name=memfd:runc` → B1 no → default fires; NT-B2 → suppressed only if DIAG shows `proc.pname=runc` at the memfd execve, else fires. Any case where the deciding field is ABSENT/EMPTY → **INCONCLUSIVE**.

---

## D. R4-A / R4-B / R4-D / R4-E — R4 behaviour (Method A)

```bash
cd /home/labuser/lab/falco_lab_containers; RAW=evidence/P1_DEV_T1r/raw_logs; mkdir -p "$RAW"
sudo falco --modern-bpf -M 120 -o json_output=true -o stdout_output.enabled=true -o rule_matching=all -o log_level=info \
  -r /etc/falco/falco_rules.yaml -r rules/custom_rules.yaml -r rules/candidate_rules_v2.yaml \
  >"$RAW/r4_scenarios_raw.json" 2>"$RAW/r4_falco.err" &
FPID=$!; sleep 4
if ! kill -0 "$FPID" 2>/dev/null || grep -qiE 'device.?busy|permission denied|failed to (open|attach)' "$RAW/r4_falco.err"; then
  echo "STOP: temp Falco not running. See $RAW/r4_falco.err. Do NOT run payloads; do NOT use Method B."
else
  TOK=R4A_$(date +%s); docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('runc_cloned:/proc/self/exe'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$TOK" | tee -a "$RAW/r4_payload_stdout.txt"   # A
  TOK=R4B_$(date +%s); docker exec falco-lab-target python3 -c "import os,sys
fd=os.memfd_create('falco_benign_memfd'); os.write(fd,open('/bin/echo','rb').read()); os.execve(fd,['x',sys.argv[1]],{})" "$TOK" | tee -a "$RAW/r4_payload_stdout.txt"           # B
  TOK=R4D_$(date +%s); docker exec falco-lab-target /bin/echo "$TOK" | tee -a "$RAW/r4_payload_stdout.txt"                                                                        # D
  TOK=R4E_$(date +%s); docker exec falco-lab-target bash -c 'cp /bin/echo /tmp/runc && exec -a runc /tmp/runc "$1"' _ "$TOK" | tee -a "$RAW/r4_payload_stdout.txt"                 # E
  wait "$FPID"; echo "falco exit status: $?" | tee -a "$RAW/r4_falco.err"
fi
```
**Expected (NOT TESTED):** A → `memfd exec hidden by runc exception` (R4 fires, TP). B → default `Fileless execution via memfd_create`, **no** R4 line. D, E → no R4 line (`is_exe_from_memfd` false). **Scenario C** (legitimate runc memfd clone — the key FP) is **NOT reproducible on this VM** (runc 1.3.3 does not self-clone via memfd) → stays NOT TESTED. **F/G** (empty parent path / real runc at unlisted path) are hard to force here; see `docs/r4_mitigation_evaluation.md`.

---

## E. Evidence collection (read-only; does not alter raw JSON)

```bash
cd /home/labuser/lab/falco_lab_containers; RAW=evidence/P1_DEV_T1r/raw_logs
ls -l "$RAW"
# key fields across all captured JSON:
python3 -I - "$RAW" <<'PY'
import json,glob,os,sys
base=sys.argv[1]
for p in sorted(glob.glob(os.path.join(base,"*_raw.json"))):
    print("==",p)
    for l in open(p,encoding="utf-8",errors="replace"):
        l=l.strip()
        if not l or l[0]!="{": continue
        try: e=json.loads(l)
        except Exception: continue
        o=e.get("output_fields",{}) or {}
        print("  ",e.get("rule"),{k:o.get(k) for k in ("proc.name","proc.exe","proc.exepath","proc.pname","proc.pexepath","proc.is_exe_from_memfd")})
PY
```

## F. SHA-256 verification (repeatable; excludes the manifest and directories; atomic rename)

```bash
cd /home/labuser/lab/falco_lab_containers/evidence/P1_DEV_T1r/raw_logs
find . -type f ! -name 'SHA256SUMS.txt' ! -name '.SHA256SUMS.tmp' -print0 | sort -z | xargs -0 sha256sum > .SHA256SUMS.tmp \
  && mv -f .SHA256SUMS.tmp SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt            # re-run any time; -type f excludes dirs, manifest + its temp excluded, idempotent
cd - >/dev/null
# refresh the parent evidence-set manifest (also excludes raw_logs, the manifest, and its temp):
cd /home/labuser/lab/falco_lab_containers/evidence/P1_DEV_T1r
find . -type f ! -path './raw_logs/*' ! -name 'SHA256SUMS.txt' ! -name '.SHA256SUMS.tmp' -print0 | sort -z | xargs -0 sha256sum > .SHA256SUMS.tmp \
  && mv -f .SHA256SUMS.tmp SHA256SUMS.txt
cd - >/dev/null
```

## G. Method A cleanup (safe; touches nothing in /etc/falco and no services)

The temp `falco -M` instances have already exited on their own. Method A changed no installed file and no service, so cleanup is only the benign temp file inside the container:

```bash
docker exec falco-lab-target rm -f /tmp/runc 2>/dev/null || true
```
Do **not** run `systemctl restart …`, `./labctl.sh down`, or `rm -rf /etc/falco/...` as part of Method A cleanup — none of those are needed, and the first two would change state you did not set here.

## H. Method B fallback — DISABLED (requires separate explicit approval)

> **Do not run this section without the owner's explicit approval for this specific action.** It modifies `/etc/falco` and restarts `falco-modern-bpf`. It is provided only so the steps are reviewable; it is intentionally fenced off and not part of the A→G flow. Use it only if Method A (temp instance) is unavailable **and** you have decided to accept a live-sensor change.

```bash
# (APPROVAL REQUIRED — do not execute otherwise)
# 1. Back up the exact files you will change:
#    TS=$(date +%Y%m%d_%H%M%S); BK=results/p1_r4_${TS}; mkdir -p "$BK/before"
#    sudo cp -a /etc/falco/rules.d "$BK/before/rules.d"        # only rules.d is changed below
# 2. Install the rule(s) you need, then restart:
#    sudo install -m0644 rules/custom_rules.yaml       /etc/falco/rules.d/lab_custom_rules.yaml
#    sudo install -m0644 rules/candidate_rules_v2.yaml /etc/falco/rules.d/lab_candidate_v2.yaml
#    sudo systemctl restart falco-modern-bpf
# 3. A restart RE-ENABLES falcoctl-artifact-follow. Return it to its RECORDED state (A1), e.g.:
#    want=$(grep -oP 'falcoctl-artifact-follow=\K\S+' evidence/P1_DEV_T1r/raw_logs/service_state_before.txt)
#    [ "$want" = active ] && sudo systemctl start falcoctl-artifact-follow || sudo systemctl stop falcoctl-artifact-follow
# 4. Method B rollback (restore ONLY what changed, then restart):
#    sudo rm -f /etc/falco/rules.d/lab_custom_rules.yaml /etc/falco/rules.d/lab_candidate_v2.yaml
#    sudo cp -a "$BK/before/rules.d/." /etc/falco/rules.d/      # restore originals if any were overwritten
#    sudo systemctl restart falco-modern-bpf
#    # then re-apply step 3 to restore the follower's recorded state
```

## I. Restore verification (confirm the host is back to its recorded state)

```bash
cd /home/labuser/lab/falco_lab_containers; RAW=evidence/P1_DEV_T1r/raw_logs
echo "--- ruleset hash (must be unchanged) ---"
sha256sum /etc/falco/falco_rules.yaml
grep . "$RAW/ruleset_hash_before.txt"
echo "--- service states: now vs recorded ---"
echo "now:      falcoctl-artifact-follow=$(systemctl is-active falcoctl-artifact-follow) falco-modern-bpf=$(systemctl is-active falco-modern-bpf)"
echo "recorded: $(grep -E 'falcoctl|falco-modern' "$RAW/service_state_before.txt" | tr '\n' ' ')"
echo "--- /etc/falco/rules.d unchanged under Method A? (should list no lab_* files added by this run) ---"
ls -l /etc/falco/rules.d
```
Pass criteria: ruleset hash equals the recorded value; `falcoctl-artifact-follow` and `falco-modern-bpf` match their recorded states; and (Method A) no `lab_*` file was added to `/etc/falco/rules.d`. If Method B was used, confirm its rollback (H.4) restored `rules.d` and the recorded service states.

---

After a real run: keep the raw JSON unchanged, run **F**, then write `docs/dev_t1r_level3_results.md` and flip the NOT TESTED rows in `docs/r4_mitigation_evaluation.md` §5 and `docs/dev_t1r_branch_coverage.md` to the measured outcome — citing only fields that printed `CAPTURED`.
