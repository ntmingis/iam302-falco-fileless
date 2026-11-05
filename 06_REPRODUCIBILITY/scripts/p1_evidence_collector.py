#!/usr/bin/env python3
"""p1_evidence_collector.py — collect a P1 evidence snapshot from EXISTING files (no sudo, no live tests).

It records environment metadata, copies the raw Falco JSON that already exists, computes SHA-256 for every
artifact, and writes a run manifest under evidence/P1_DEV_T1r/automated_runs/<run_id>/. It is strictly a
COLLECTOR: it never runs sudo, never starts Falco, never executes a payload, and never modifies raw evidence.
Privileged test execution is a separate, human step (evidence/dev_t1r_branch_coverage/sudo_commands.md).

Usage:
    python3 tools/p1_evidence_collector.py                 # snapshot existing DEV-T1r raw evidence
    python3 tools/p1_evidence_collector.py --run-dir DIR   # also ingest a new raw run the owner produced
"""
import hashlib, json, os, platform, shutil, subprocess, sys, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
AUTO = os.path.join(ROOT, "evidence", "P1_DEV_T1r", "automated_runs")

# existing raw evidence this collector snapshots (read-only; never overwritten)
HISTORICAL = [
    "results/e1_default_20261021_005859_dev/falco_events.json",
    "results/e1_custom_20261021_012554_dev/falco_events.json",
    "results/e1_probe_20261020_235831_probe/falco_events.json",
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 16), b""):
            h.update(b)
    return h.hexdigest()


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception as e:
        return f"<unavailable: {e}>"


def anon_host():
    """Anonymized, stable hostname: no real name leaks into the manifest."""
    h = platform.node() or "unknown"
    return "host-" + hashlib.sha256(h.encode()).hexdigest()[:12]


def falco_version():
    out = run(["falco", "--version"])
    try:
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                return json.loads(ln)
    except Exception:
        pass
    return {"raw": out}


def ruleset_hash():
    p = "/etc/falco/falco_rules.yaml"
    try:
        return sha256(p) if os.path.exists(p) else "<not readable>"
    except Exception as e:
        return f"<error: {e}>"


def environment():
    fv = falco_version()
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "timestamp_utc": now.isoformat(),
        "timestamp_local": now.astimezone().isoformat(),
        "hostname_anonymized": anon_host(),
        "kernel": run(["uname", "-r"]),
        "falco_version": fv.get("falco_version", fv),
        "falco_engine": fv.get("engine_version_semver"),
        "falco_driver": fv.get("default_driver_version"),
        "active_driver": "modern_ebpf (falco-modern-bpf service; collector does not query the live service)",
        "docker_version": run(["docker", "--version"]),
        "runc_version": run(["runc", "--version"]).splitlines()[0] if run(["runc", "--version"]) else "<unavailable>",
        "runc_path": run(["readlink", "-f", shutil.which("runc") or "runc"]),
        "ruleset_hash_sha256": ruleset_hash(),
        "collector_privilege": "no sudo; read-only; no live Falco/Auditd interaction",
    }


def collect(run_dir=None):
    os.makedirs(AUTO, exist_ok=True)
    run_id = "p1auto_" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(AUTO, run_id)
    os.makedirs(os.path.join(dest, "raw"), exist_ok=True)

    artifacts = []
    sources = list(HISTORICAL)
    note = "snapshot of pre-existing historical DEV-T1r raw evidence; no new test was executed"
    if run_dir:
        # ingest a NEW raw run the owner produced (e.g. from sudo_commands.md). Copy, never move/alter the source.
        rd = run_dir if os.path.isabs(run_dir) else os.path.join(ROOT, run_dir)
        for f in sorted(os.listdir(rd)):
            fp = os.path.join(rd, f)
            if os.path.isfile(fp) and (f.endswith(".json") or f.endswith(".txt") or f.endswith(".log")):
                sources.append(os.path.relpath(fp, ROOT))
        note = f"snapshot of historical DEV-T1r raw + ingested owner-produced run {run_dir}"

    for rel in sources:
        src = os.path.join(ROOT, rel)
        exists = os.path.exists(src)
        rec = {"source": rel, "exists": exists,
               "bytes": os.path.getsize(src) if exists else 0,
               "source_sha256": sha256(src) if exists and os.path.getsize(src) else ("<empty>" if exists else None)}
        if exists:
            copy_name = rel.replace("/", "__")
            cp = os.path.join(dest, "raw", copy_name)
            shutil.copy2(src, cp)  # copy2 preserves mtime; source is never modified
            rec["collected_copy"] = os.path.relpath(cp, ROOT)
            rec["copy_sha256"] = sha256(cp) if os.path.getsize(cp) else "<empty>"
            rec["copy_matches_source"] = (rec.get("source_sha256") == rec.get("copy_sha256"))
        artifacts.append(rec)

    manifest = {
        "run_id": run_id,
        "note": note,
        "separation_of_duties": "collection only; privileged test execution is the owner's separate step (sudo_commands.md)",
        "environment": environment(),
        "artifacts": artifacts,
        "behavioural_tests_executed": [],         # none; this is collection, not execution
        "test_statuses": {t: "NOT TESTED" for t in
                          ["DIAG-FIELDS", "NT-B1", "NT-B2", "NT-B4", "R4-A", "R4-B", "R4-D", "R4-E"]} | {"R4-C": "NOT REPRODUCIBLE"},
    }
    mpath = os.path.join(dest, "run_manifest.json")
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=2, default=str)
    # SHA-256 over the collected copies + manifest (repeatable; excludes itself)
    sums = os.path.join(dest, "SHA256SUMS.txt")
    lines = []
    for base, _dirs, files in os.walk(dest):
        for fn in sorted(files):
            if fn == "SHA256SUMS.txt":
                continue
            fp = os.path.join(base, fn)
            lines.append(f"{sha256(fp)}  {os.path.relpath(fp, dest)}")
    with open(sums, "w") as f:
        f.write("\n".join(sorted(lines)) + "\n")
    print(f"run_id={run_id}")
    print(f"manifest={os.path.relpath(mpath, ROOT)}")
    print(f"artifacts collected: {sum(1 for a in artifacts if a['exists'])}/{len(artifacts)}")
    print(f"SHA256SUMS={os.path.relpath(sums, ROOT)}")
    return dest


def main():
    rd = None
    if "--run-dir" in sys.argv:
        rd = sys.argv[sys.argv.index("--run-dir") + 1]
    collect(rd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
