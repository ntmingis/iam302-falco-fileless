"""rc4stats — Wilson 95% interval (same formula as tablestats.wilson) and one-sided 95% Clopper-Pearson upper bound for k=0."""
import math
def wilson(k, n, z=1.96):
    if n == 0: return float("nan"), float("nan")
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)
def cp_upper_k0(n, alpha=0.05):
    """one-sided (1-alpha) Clopper-Pearson upper bound when k=0: 1 - alpha**(1/n)."""
    return float("nan") if n == 0 else 1 - alpha ** (1.0 / n)
def fmt(k, n):
    lo, hi = wilson(k, n); s = f"{k}/{n} Wilson [{lo:.2f},{hi:.2f}]"
    if k == 0 and n: s += f"; CP1-sided95 upper {cp_upper_k0(n):.2f}"
    return s
