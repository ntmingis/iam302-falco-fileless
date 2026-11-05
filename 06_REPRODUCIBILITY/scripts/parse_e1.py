#!/usr/bin/env python3
"""parse_e1.py v4 - python3 parse_e1.py results/e1_<ruleset>_<time> [out_dir]
Payload (xac minh doc lap, dua vao exit_code + marker trong <tech>_<rep>.out + audit):
  ok      = exit 0 va co marker -> hanh vi muc tieu da xay ra
  blocked = exit != 0 va audit co exec THAT BAI (success=no) dung duong dan ky thuat (vd. EACCES do /dev/shm noexec)
  error   = con lai (khong du evidence) -> bao cao rieng, KHONG tinh la miss
Falco (chi xet khi payload=ok; neu khong thi falco = payload):
  direct    = alert dung rule cua ky thuat VA dung container mong doi (host-tech: alert chua token)
  misattrib = co alert trong cua so nhung khac rule/khac container
  miss      = payload chay thanh cong, khong co alert nao
Auditd (doc lap voi Falco): specific = key + exe/comm/path + success=yes + token trong argv (neu ky thuat co token)
  + dung pham vi (subj=docker-default cho container, unconfined cho host).
Nguon Falco: falco_events.json trong thu muc run (run_e1.sh v3) > /var/log/falco/events.json > falco_rx.log.
Do tre: e2e_ms_upper = luc NHAN alert (falco_rx, dong ho host) - start_ms (gom docker exec -> can tren);
        pipeline_ms = luc NHAN - evt time cua alert (do tre Falco tu syscall den file output).
Lech dong ho: Falco tinh evt.time tu moc boot lay luc khoi dong; neu dong ho host bi chinh (NTP step) sau do,
  moi evt.time lech mot hang so. skew = median(rx - evt); |skew| > 1000 ms -> hieu chinh evt.time theo skew,
  ghi canh bao vao parse_meta.txt va bo pipeline_ms (khong do duoc doc lap).
out_dir mac dinh = thu muc run."""
import csv, glob, json, os, re, statistics, sys
from collections import defaultdict
from datetime import datetime, timezone

RUN = sys.argv[1].rstrip("/")
OUT = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else RUN
FALCO, AUDIT = "/var/log/falco/events.json", "/var/log/audit/audit.log*"
# uu tien ban chup log do run_e1.sh v3 luu trong thu muc run
if os.path.exists(f"{RUN}/falco_events.json"): FALCO = f"{RUN}/falco_events.json"
if os.path.exists(f"{RUN}/audit.log"): AUDIT = f"{RUN}/audit.log"
RULESET, MATCHING = "default", "unknown"
try:
    for l in open(f"{RUN}/versions.txt"):
        if l.startswith("ruleset="): RULESET = l.split("=", 1)[1].strip()
        if l.startswith("rule_matching="): MATCHING = l.split("=", 1)[1].strip()
except OSError: pass

# id, nhom (A = fileless chinh, B = injection-related), container mong doi (None = host), ghi chu
TECH = {"memfd": ("T1", "A", "falco-lab-target", ""),
        "shm_host": ("T2-host", "A", None, "host context"),
        "shm_ctr": ("T2-ctr", "A", "falco-lab-target", "Docker default /dev/shm (noexec)"),
        "shm_ctr_exec": ("T2-ctr-exec", "A", "falco-lab-shmexec", "profile rieng: /dev/shm exec, KHONG phai Docker mac dinh"),
        "procfd_link": ("T3a", "A", "falco-lab-target", "bien the E4: link() gay copy-up /bin/echo"),
        "procfd_nolink": ("T3b", "A", "falco-lab-target", "bien the E4: exec fd cua binary goc"),
        "procfd_drop": ("T3c", "A", "falco-lab-target", "bien the E4: tha binary, xoa, exec fd"),
        "python": ("T4", "A", "falco-lab-target", ""),
        "curl": ("T5", "A", "falco-lab-client", ""),
        "preload": ("T6", "B", "falco-lab-target", ""),
        "ptrace": ("T7", "B", "falco-lab-target", ""),
        "dev_memfd_runcname": ("DEV-T1r", "A", "falco-lab-target", "DEV: memfd ten runc_cloned (bypass ngoai le #3444); da dung de thiet ke rule"),
        # E4 - bien the giu rieng, khong dung khi thiet ke custom rule
        "e4_memfd_execveat": ("E4-T1b", "A", "falco-lab-target", "execveat(AT_EMPTY_PATH) truc tiep qua ctypes"),
        "e4_procfd_argv0": ("E4-T3d", "A", "falco-lab-target", "Python os.execv(/proc/self/fd/N), argv0 gia"),
        "e4_shm_argv0": ("E4-T2b", "A", "falco-lab-shmexec", "profile /dev/shm exec, argv0 gia (exec -a kworker)"),
        "e4_python_stdin": ("E4-T4b", "A", "falco-lab-target", "code Python qua stdin (python3 -)"),
        "e4_curl_script": ("E4-T5b", "A", "falco-lab-client", "pipeline curl|bash nam trong file script"),
        "e4_curl_sh": ("E4-T5c", "A", "falco-lab-client", "curl | sh"),
        "e4_preload_env": ("E4-T6b", "B", "falco-lab-target", "LD_PRELOAD dat boi env trong container")}
DIRECT = {"memfd": ["Fileless execution via memfd_create"], "shm_host": ["/dev/shm"],
          "shm_ctr": ["/dev/shm"], "shm_ctr_exec": ["/dev/shm"], "ptrace": ["PTRACE"],
          "e4_memfd_execveat": ["Fileless execution via memfd_create"], "e4_shm_argv0": ["/dev/shm"],
          "dev_memfd_runcname": ["Fileless execution via memfd_create"]}
if RULESET == "custom":
    for t in ("procfd_link", "procfd_nolink", "procfd_drop", "e4_procfd_argv0"): DIRECT[t] = ["LAB Exec via proc fd"]
    for t in ("curl", "e4_curl_script", "e4_curl_sh"): DIRECT[t] = ["LAB Download piped", "LAB Shell reading"]
    for t in ("python", "e4_python_stdin"): DIRECT[t] = ["LAB Interpreter inline"]
    for t in ("preload", "e4_preload_env"): DIRECT[t] = ["LAB Process started with LD_PRELOAD"]
    DIRECT["dev_memfd_runcname"] = ["Fileless execution via memfd_create", "LAB memfd exec masquerading"]
AKEY = {"memfd": "fileless_memfd", "ptrace": "fileless_ptrace", "e4_memfd_execveat": "fileless_memfd", "dev_memfd_runcname": "fileless_memfd"}
APAT = {"python": r'exe="/usr/local/bin/python3"', "curl": r'exe="/usr/bin/curl"',
        "preload": r'exe="/usr/bin/echo"', "procfd_link": r'comm="3"', "procfd_nolink": r'comm="3"',
        "procfd_drop": r'comm="3"', "shm_host": r"/dev/shm/falco_shm_test", "shm_ctr": r"/dev/shm/falco_shm_test",
        "shm_ctr_exec": r"/dev/shm/falco_shm_test",
        "e4_procfd_argv0": r'comm="3"', "e4_shm_argv0": r"/dev/shm/falco_shm_test",
        "e4_python_stdin": r'exe="/usr/local/bin/python3"', "e4_curl_script": r'exe="/usr/bin/curl"',
        "e4_curl_sh": r'exe="/usr/bin/curl"', "e4_preload_env": r'exe="/usr/bin/echo"'}
# ky thuat ma token nam trong argv cua chinh tien trinh ky thuat (procfd_link/memfd/ptrace thi khong)
ATOK = {"python", "curl", "preload", "procfd_nolink", "procfd_drop", "shm_host", "shm_ctr", "shm_ctr_exec",
        "e4_procfd_argv0", "e4_shm_argv0", "e4_curl_script", "e4_curl_sh", "e4_preload_env"}
# marker trong stdout chung minh hanh vi muc tieu da chay ("{tok}" = token cua run)
MARK = {"procfd_link": "FALCO_PROC_FD_TEST", "curl": "BENIGN_PIPE_OK", "preload": "FALCO_LD_PRELOAD_TEST",
        "e4_curl_script": "BENIGN_PIPE_OK", "e4_curl_sh": "BENIGN_PIPE_OK", "e4_preload_env": "FALCO_LD_PRELOAD_TEST",
        "ptrace": "attach rc= 0 {tok}"}

def fts(s):
    b, _, f = s.rstrip("Z").partition(".")
    return int(datetime.fromisoformat(b).replace(tzinfo=timezone.utc).timestamp() * 1000) + int((f + "000")[:3])

def falco_lines():
    try: return open(FALCO, errors="replace"), FALCO
    except PermissionError:
        rx = f"{RUN}/falco_rx.log"
        print(f"[!] khong doc duoc {FALCO} -> dung {rx}", file=sys.stderr)
        return (l.partition("\t")[2] for l in open(rx, errors="replace")), rx

def load_falco():
    ev = []
    lines, src = falco_lines()
    for l in lines:
        try: j = json.loads(l)
        except ValueError: continue
        o = j.get("output_fields", {})
        ev.append({"ms": fts(j["time"]), "time": j["time"], "rule": j.get("rule", ""), "prio": j.get("priority", ""),
                   "cont": str(o.get("container.name", "")), "raw": l})
    return ev, src

def load_rx():
    rx = {}
    try:
        for l in open(f"{RUN}/falco_rx.log", errors="replace"):
            t, _, js = l.partition("\t")
            try: j = json.loads(js)
            except ValueError: continue
            rx.setdefault((j["time"], j.get("rule", "")), int(t))
    except OSError: pass
    return rx

A_RE = re.compile(r"msg=audit\((\d+)\.(\d+):(\d+)\)")
def load_audit():
    rec = defaultdict(lambda: {"ms": 0, "text": ""})
    for p in sorted(glob.glob(AUDIT)):
        for l in open(p, errors="replace"):
            m = A_RE.search(l)
            if m:
                r = rec[m.group(3)]; r["ms"] = int(m.group(1)) * 1000 + int(m.group(2)); r["text"] += l
    return list(rec.values())

ARG_RE = re.compile(r' a\d+=(?:"([^"]*)"|([0-9A-F]+))')
def argv(text):
    """argv tu ban ghi EXECVE (gia tri hex khi co dau cach/ky tu dac biet)."""
    out = []
    for l in text.splitlines():
        if "type=EXECVE" not in l: continue
        for q, h in ARG_RE.findall(l):
            out.append(bytes.fromhex(h).decode(errors="replace") if h else q)
    return " ".join(out)

def audit_state(t, tok, recs, s, e):
    key = AKEY.get(t, "fileless_exec"); pat = APAT.get(t)
    ok, failed = [], False
    for r in recs:
        if not (s - 1000 <= r["ms"] <= e) or f'key="{key}"' not in r["text"]: continue
        ctr = "subj=docker-default" in r["text"]
        if (t == "shm_host") == ctr: continue            # host-tech phai o host, con lai phai o container
        if pat and not re.search(pat, r["text"]): continue
        if "success=no" in r["text"]: failed = True; continue   # exec bi chan (vd. EACCES do noexec)
        if t in ATOK and tok not in argv(r["text"]): continue
        ok.append(ctr)
    return ("specific" if ok else "miss"), ("yes" if any(ok) else "no"), failed

def payload_state(t, tok, rc, rep, audit_failed):
    try: out = open(f"{RUN}/{t}_{rep}.out", errors="replace").read()
    except OSError: out = ""
    mark = MARK.get(t, "{tok}").format(tok=tok)
    if rc == 0 and mark in out: return "ok"
    if rc != 0 and audit_failed: return "blocked"
    return "error"

def falco_state(t, tok, evs, s, e):
    want = TECH[t][2]
    hit = [x for x in evs if s - 2000 <= x["ms"] <= e and
           ((tok in x["raw"]) if want is None else x["cont"].startswith("falco-lab-"))]
    rules = sorted({f'{x["rule"]}@{x["cont"]}' for x in hit})
    d = [x for x in hit if any(p in x["rule"] for p in DIRECT.get(t, [])) and (want is None or x["cont"] == want)]
    return ("direct" if d else "misattrib" if hit else "miss"), rules, d

SKEW_LIMIT = 1000
def clock_skew(fev, rx):
    d = sorted(rx[(x["time"], x["rule"])] - x["ms"] for x in fev if (x["time"], x["rule"]) in rx)
    return (statistics.median(d), len(d), (d[-1] - d[0]) if d else 0) if d else (0, 0, 0)

def pct(L, q): return L[min(len(L) - 1, int(q * len(L)))] if L else ""

def main():
    runs = list(csv.DictReader(open(f"{RUN}/runs.csv")))
    (fev, fsrc), aev, rx = load_falco(), load_audit(), load_rx()
    os.makedirs(OUT, exist_ok=True)
    skew, nsk, spread = clock_skew(fev, rx)
    skewed = abs(skew) > SKEW_LIMIT
    if skewed:
        for x in fev: x["ms"] += round(skew)
        print(f"[!] lech dong ho Falco/host = {skew:.0f} ms (n={nsk}, spread={spread} ms) -> da hieu chinh; bo pipeline_ms", file=sys.stderr)
    with open(f"{OUT}/parse_meta.txt", "w") as f:
        f.write(f"run={RUN}\nruleset={RULESET}\nrule_matching={MATCHING}\nfalco_src={fsrc}\naudit_src={AUDIT}\n"
                f"clock_skew_ms={skew:.0f}\nskew_samples={nsk}\nskew_spread_ms={spread}\nskew_corrected={skewed}\n")
    rows = []
    for r in runs:
        t, tok, s, e, rc = r["technique"], r["token"], int(r["start_ms"]), int(r["end_ms"]), int(r["exit_code"])
        tid, grp, _, _ = TECH[t]
        fs, rules, d = falco_state(t, tok, fev, s, e)
        au, actr, afail = audit_state(t, tok, aev, s, e)
        pl = payload_state(t, tok, rc, r["rep"], afail)
        if pl != "ok": fs = au = pl       # hanh vi khong xay ra / khong du evidence -> khong tinh miss/specific
        e2e = [rx[(x["time"], x["rule"])] - s for x in d if (x["time"], x["rule"]) in rx]
        pipe = [] if skewed else [rx[(x["time"], x["rule"])] - x["ms"] for x in d if (x["time"], x["rule"]) in rx]
        rows.append([tid, grp, t, r["rep"], tok, rc, pl, fs if pl == "ok" else pl, "|".join(rules), au, actr if pl == "ok" else "",
                     min(e2e) if e2e and pl == "ok" else "", min(pipe) if pipe and pl == "ok" else "", r["audit_lost_delta"]])
    hdr = ["tech_id", "group", "technique", "rep", "token", "exit", "payload", "falco", "falco_rules@container",
           "auditd", "auditd_container", "e2e_ms_upper", "pipeline_ms", "audit_lost"]
    with open(f"{OUT}/e1_detail.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(hdr); w.writerows(rows)
    by = defaultdict(list)
    for x in rows: by[x[2]].append(x)
    with open(f"{OUT}/e1_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tech_id", "group", "technique", "n", "payload_ok", "falco_direct", "falco_misattrib", "falco_miss",
                    "blocked", "error", "auditd_specific", "auditd_miss", "auditd_container", "e2e_p50", "e2e_p95",
                    "pipeline_p50", "pipeline_p95", "audit_lost_sum", "rules@container", "note"])
        for t, rs in by.items():
            cnt = lambda i, v: sum(x[i] == v for x in rs)
            E = sorted(x[11] for x in rs if x[11] != ""); P = sorted(x[12] for x in rs if x[12] != "")
            w.writerow([TECH[t][0], TECH[t][1], t, len(rs), cnt(6, "ok"), cnt(7, "direct"), cnt(7, "misattrib"), cnt(7, "miss"),
                        cnt(6, "blocked"), cnt(6, "error"), cnt(9, "specific"), cnt(9, "miss"), cnt(10, "yes"),
                        statistics.median(E) if E else "", pct(E, .95), statistics.median(P) if P else "", pct(P, .95),
                        sum(int(x[13] or 0) for x in rs),
                        "|".join(sorted({y for x in rs for y in x[8].split("|") if y})), TECH[t][3]])
    print(f"ruleset={RULESET} falco_src={fsrc} audit_src={AUDIT} -> {OUT}/e1_summary.csv")
    print(open(f"{OUT}/e1_summary.csv").read())

if __name__ == "__main__": main()
