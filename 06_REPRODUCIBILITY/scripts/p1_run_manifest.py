#!/usr/bin/env python3
"""p1_run_manifest.py — (re)build a SHA-256 run manifest for a P1 evidence directory.

Repeatable and idempotent: excludes the manifest and its temp, excludes directories, writes a temp file and
atomically renames it. Also verifies an existing manifest. Does not touch raw evidence content.

Usage:
    python3 tools/p1_run_manifest.py build  <dir>    # write <dir>/SHA256SUMS.txt
    python3 tools/p1_run_manifest.py verify <dir>    # check files against <dir>/SHA256SUMS.txt
"""
import hashlib, os, sys

MAN = "SHA256SUMS.txt"
TMP = ".SHA256SUMS.tmp"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 16), b""):
            h.update(b)
    return h.hexdigest()


def iter_files(root):
    for base, _d, files in os.walk(root):
        for fn in sorted(files):
            if fn in (MAN, TMP):
                continue
            fp = os.path.join(base, fn)
            if os.path.isfile(fp):
                yield fp


def build(d):
    lines = [f"{sha256(fp)}  {os.path.relpath(fp, d)}" for fp in iter_files(d)]
    tmp = os.path.join(d, TMP)
    with open(tmp, "w") as f:
        f.write("\n".join(sorted(lines)) + "\n")
    os.replace(tmp, os.path.join(d, MAN))     # atomic rename
    print(f"wrote {os.path.join(d, MAN)} ({len(lines)} files)")
    return 0


def verify(d):
    man = os.path.join(d, MAN)
    if not os.path.exists(man):
        print(f"FAIL no manifest at {man}")
        return 1
    ok = True
    for ln in open(man):
        ln = ln.strip()
        if not ln:
            continue
        want, rel = ln.split("  ", 1)
        fp = os.path.join(d, rel)
        if not os.path.exists(fp):
            print(f"FAIL missing {rel}"); ok = False; continue
        if sha256(fp) != want:
            print(f"FAIL changed {rel}"); ok = False
    print("OK all files match" if ok else "FAIL manifest mismatch")
    return 0 if ok else 1


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("build", "verify"):
        print(__doc__); return 2
    d = sys.argv[2]
    d = d if os.path.isabs(d) else os.path.abspath(d)
    return build(d) if sys.argv[1] == "build" else verify(d)


if __name__ == "__main__":
    sys.exit(main())
