"""tablestats.py - ham thong ke thuan cho build_tables.py (co test: tests/test_tablestats.py)."""
import math

def wilson(k, n, z=1.96):
    """Khoang Wilson 95% cho ti le k/n; n=0 -> (nan, nan)."""
    if n == 0: return float("nan"), float("nan")
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)

def coverage(rows, state_col, counts_col):
    """rows: dong e4_unseen_summary (dict). Tra ve (bien the direct, tong bien the, lan direct, tong lan).
    Bien the tinh 'direct' khi trang thai chiem uu the la direct; lan = so lan direct trong D/M/X/B/E."""
    nv = len(rows); kv = sum(1 for r in rows if r[state_col] == "direct")
    kr = sum(int(r[counts_col].split("/")[0]) for r in rows)
    nr = sum(sum(int(v) for v in r[counts_col].split("/")) for r in rows)
    return kv, nv, kr, nr
