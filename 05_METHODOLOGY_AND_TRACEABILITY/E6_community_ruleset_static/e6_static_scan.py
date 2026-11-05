#!/usr/bin/env python3
"""e6_static_scan.py - E6 phan TINH: rule nao trong cac ruleset cong dong co the cham toi cac ho co che cua lab?
Chi doc YAML (khong chay Falco, khong chay payload). Voi moi rule: mo rong macro de quy (theo ten), roi tim cac dau hieu
(truong / chuoi) dac trung cho tung ho co che. Ket qua la ung vien de doc tay, KHONG phai ket qua phat hien.
  python3 experiments/E6_community_ruleset/e6_static_scan.py <rules.yaml>... > out.csv
Rule `enabled: false` duoc danh dau (Falco mac dinh khong nap)."""
import csv, re, sys
import yaml

SIG = {  # ho co che -> regex tren dieu kien da mo rong
    "memfd": r"is_exe_from_memfd|memfd",
    "/dev/shm": r"/dev/shm",
    "/proc/self/fd": r"/proc/self/fd|/proc/\*/fd|/dev/fd|evt\.arg\.filename",
    "interpreter": r"python|perl|ruby|node|interpreter|proc\.args .*-c|stdin",
    "download-pipe": r"curl|wget|downloader|pcmdline contains \"\|",
    "LD_PRELOAD": r"LD_PRELOAD|ld\.so\.preload|ld-linux|LD_LIBRARY_PATH",
    "ptrace": r"ptrace",
    "drop-exec (overlay)": r"is_exe_upper_layer|is_open_exec|EXE_UPPER_LAYER|is_exe_writable",
}

def load(paths):
    items, macros, lists = [], {}, {}
    for p in paths:
        for it in yaml.safe_load(open(p)) or []:
            it["_file"] = p.split("/")[-1]
            if "macro" in it: macros[it["macro"]] = it.get("condition", "")
            elif "list" in it: lists[it["list"]] = " ".join(map(str, it.get("items", [])))
            elif "rule" in it: items.append(it)
    return items, macros, lists

def expand(cond, macros, lists, depth=0, seen=None):
    seen = seen or set()
    if depth > 12: return cond
    out = cond
    for name in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cond):
        if name in seen: continue
        if name in macros:
            seen.add(name); out += " " + expand(macros[name], macros, lists, depth + 1, seen)
        elif name in lists:
            seen.add(name); out += " " + lists[name]
    return out

def main(paths):
    rules, macros, lists = load(paths)
    w = csv.writer(sys.stdout)
    w.writerow(["file", "rule", "enabled", "families_matched", "condition_head"])
    for r in rules:
        if "condition" not in r: continue          # override/append fragment
        full = expand(r["condition"], macros, lists)
        fams = [f for f, rx in SIG.items() if re.search(rx, full)]
        if not fams: continue
        w.writerow([r["_file"], r["rule"], r.get("enabled", True), "|".join(fams),
                    " ".join(r["condition"].split())[:160]])

if __name__ == "__main__":
    main(sys.argv[1:])
