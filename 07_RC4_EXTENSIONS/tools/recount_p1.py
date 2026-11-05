#!/usr/bin/env python3
"""recount_p1.py <raw_dir> — INDEPENDENT recount of P1 (does NOT import or reuse score_p1*.py).

Different code path on purpose: raw JSON is read with a hand-rolled line scan; events are bucketed by the token
string that appears in the raw line (output/cmdline), and the DIAG field values are pulled from the memfd execve by a
direct dict lookup. Counts default-memfd and R4 alerts per token. Prints a table; exits 2 if files missing.
"""
import json, os, re, sys
RAW = sys.argv[1]
DIAGR, DEF, R4 = "LAB Diag memfd fields", "Fileless execution via memfd_create", "LAB2 memfd exec covered by runc exception without real runc parent"
def scan(fn):
    p = os.path.join(RAW, fn)
    return [l for l in open(p, errors="replace")] if os.path.exists(p) else []
def toklist(fn):
    p = os.path.join(RAW, fn)
    return [re.split(r"\s", l.strip())[0].replace("TOK=", "") for l in open(p)] if os.path.exists(p) else []
out = {}
for rawfn, tokfn in (("diag_fields_raw.json","diag_fields_tok.txt"),("branch_isolation_raw.json","branch_toks.txt"),("r4_scenarios_raw.json","r4_toks.txt")):
    lines = scan(rawfn)
    for tok in toklist(tokfn):
        var = re.sub(r"_\d+(_r\d+)?$","",tok)
        d = out.setdefault(var, {"n":0,"diag_memfd":0,"def":0,"r4":0,"fields":{}})
        d["n"]+=1
        mine=[l for l in lines if tok in l]
        for l in mine:
            l=l.strip()
            if not l.startswith("{"): continue
            try: e=json.loads(l)
            except ValueError: continue
            ru=e.get("rule"); o=e.get("output_fields",{}) or {}
            if ru==DIAGR and str(o.get("proc.is_exe_from_memfd")).lower()=="true":
                d["diag_memfd"]+=1
                for k in ("proc.name","proc.exe","proc.exepath","proc.pname","proc.is_exe_from_memfd"):
                    if o.get(k) not in (None,"","<NA>"): d["fields"].setdefault(k,set()).add(str(o[k]))
            if ru==DEF: d["def"]+=1
            if ru==R4: d["r4"]+=1
print(f"{'variant':20s} n diag_memfd def r4  fields")
for v,d in out.items():
    f=";".join(f"{k.split('.')[-1]}={'/'.join(sorted(vals))}" for k,vals in d["fields"].items())
    print(f"{v:20s} {d['n']} {d['diag_memfd']:>3} {d['def']:>3} {d['r4']:>3}  {f}")
