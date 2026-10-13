# -*- coding: utf-8 -*-
"""
06_kham_pha.py - Phan tich kham pha (KHONG phai gia thuyet dat truoc).
Khoang tin cay bootstrap cho chenh lech giua cong thuc (so mu 0.3) va CVSS
khi chi va 1% va 5% so lo hong, gop hai nam kiem thu 2024 va 2025.
Dung chung du lieu va ham voi 05_kiem_chung.py.
"""
import os, sys, json
import numpy as np
sys.argv = [sys.argv[0]]
HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "05_kiem_chung.py"), encoding="utf-8").read()
src = src.split("# ======================================================================= RQ3")[0]
exec(compile(src, "05_kiem_chung.py", "exec"))
g = np.random.default_rng(7); out = {}
log("\n" + "=" * 78); log("PHAN TICH KHAM PHA: VA IT, GOP 2024 VA 2025"); log("=" * 78)
for f in [0.01, 0.05]:
    for ref in ["CVSS", "EPSS"]:
        obs, boots = 0.0, np.zeros(NBOOT)
        data = {y: yearset(y) for y in TEST}
        for y, (c, e, t) in data.items():
            K = f * len(c); obs += exp_hits(c * e ** ALPHA0, t, K) - exp_hits(c if ref == "CVSS" else e, t, K)
        for b in range(NBOOT):
            for y, (c, e, t) in data.items():
                i = g.integers(0, len(c), len(c)); cc, ee, tt = c[i], e[i], t[i]; K = f * len(cc)
                boots[b] += exp_hits(cc * ee ** ALPHA0, tt, K) - exp_hits(cc if ref == "CVSS" else ee, tt, K)
        lo, hi = np.percentile(boots, [2.5, 97.5]); out[f"{f}_{ref}"] = dict(chenh=obs, ci=[lo, hi])
        log(f"  va {int(f*100)}%, cong thuc so voi {ref:<5}: {obs:+.1f} ca, khoang tin cay 95% [{lo:+.1f}, {hi:+.1f}]")
json.dump(out, open(os.path.join(OUT, "kham_pha.json"), "w"), indent=2, default=float)
open(os.path.join(OUT, "kham_pha.txt"), "w", encoding="utf-8").write("\n".join(lines))
