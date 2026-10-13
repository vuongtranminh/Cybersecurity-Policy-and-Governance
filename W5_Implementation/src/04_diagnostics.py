# -*- coding: utf-8 -*-
"""
04_diagnostics.py
Phan tich chan doan sau khi ket qua chinh cho thay gia thuyet khong duoc ung ho.
Muc dich: tim hieu VI SAO chi so khong hoat dong, va kiem tra xem con phat hien
nao con gia tri hay khong.
"""
import os, json
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "output")
lines = []
def log(s=""):
    print(s, flush=True); lines.append(str(s))

df = pd.read_csv(os.path.join(OUT, "features.csv"))
df["epss"] = df["epss"].fillna(0.0)
test = df[df["year"] == 2025].copy()

log("=" * 70); log("PHAN TICH CHAN DOAN"); log("=" * 70)

# 1. Vi sao thanh phan C lai mang dau am?
log("\n1. Ty le thuoc KEV theo do dai mo ta advisory")
log("-" * 70)
bins = [0, 30, 60, 100, 160, 10**6]
labels = ["duoi 30 tu", "30-60 tu", "60-100 tu", "100-160 tu", "tren 160 tu"]
test["nhom_do_dai"] = pd.cut(test["desc_words"], bins=bins, labels=labels, right=False)
g = test.groupby("nhom_do_dai", observed=True).agg(
    so_luong=("kev", "size"), thuoc_kev=("kev", "sum"))
g["ty_le_phan_tram"] = 100 * g["thuoc_kev"] / g["so_luong"]
log(g.to_string())
g.to_csv(os.path.join(OUT, "chan_doan_do_dai.csv"))

log("\n2. Ty le thuoc KEV theo tung muc diem cua tung tieu chi C")
log("-" * 70)
rows = []
for c in ["C1", "C2", "C3", "C4", "C5"]:
    for v in sorted(test[c].unique()):
        sub = test[test[c] == v]
        rows.append({"tieu_chi": c, "muc_diem": int(v), "so_luong": len(sub),
                     "thuoc_kev": int(sub["kev"].sum()),
                     "ty_le_phan_tram": 100 * sub["kev"].mean()})
t2 = pd.DataFrame(rows)
log(t2.to_string(index=False))
t2.to_csv(os.path.join(OUT, "chan_doan_tieu_chi_C.csv"), index=False)

log("\n3. Ty le thuoc KEV theo tier CWE (kiem tra thanh phan K)")
log("-" * 70)
g3 = test.groupby("K_tier").agg(so_luong=("kev", "size"), thuoc_kev=("kev", "sum"))
g3["ty_le_phan_tram"] = 100 * g3["thuoc_kev"] / g3["so_luong"]
log(g3.sort_values("ty_le_phan_tram", ascending=False).to_string())
g3.to_csv(os.path.join(OUT, "chan_doan_tier_cwe.csv"))

log("\n4. Vung bi chinh sach hien hanh bo sot: EPSS co bat duoc khong?")
log("-" * 70)
low = test[test["cvss"] < 8.0]
low_kev = low[low["kev"] == 1]
log(f"  Lo hong CVSS duoi 8.0 va da bi khai thac: {len(low_kev)}")
for thr in [0.1, 0.2, 0.5]:
    n = int((low_kev["epss"] >= thr).sum())
    log(f"    trong do co EPSS tu {thr}: {n} ({100*n/len(low_kev):.1f}%)")
log(f"  ROC-AUC trong dai CVSS duoi 8.0:")
for c in ["epss", "aeg_ei", "cvss", "Cn", "P", "E", "K"]:
    log(f"    {c:<7} {roc_auc_score(low['kev'], low[c]):.4f}")

log("\n5. Neu ket hop CVSS va EPSS thi bao phu duoc bao nhieu?")
log("-" * 70)
tot = int(test["kev"].sum())
r1 = int(((test["cvss"] >= 8.0)) .loc[test["kev"] == 1].sum())
r2 = int(((test["epss"] >= 0.1)).loc[test["kev"] == 1].sum())
r3 = int(((test["cvss"] >= 8.0) | (test["epss"] >= 0.1)).loc[test["kev"] == 1].sum())
n1 = int((test["cvss"] >= 8.0).sum())
n2 = int((test["epss"] >= 0.1).sum())
n3 = int(((test["cvss"] >= 8.0) | (test["epss"] >= 0.1)).sum())
log(f"  Quy tac CVSS tu 8.0        : bao phu {r1}/{tot} ({100*r1/tot:.1f}%), phai va {n1:,} lo hong")
log(f"  Quy tac EPSS tu 0.1        : bao phu {r2}/{tot} ({100*r2/tot:.1f}%), phai va {n2:,} lo hong")
log(f"  Ket hop hai quy tac        : bao phu {r3}/{tot} ({100*r3/tot:.1f}%), phai va {n3:,} lo hong")

log("\n6. So sanh chi phi: so lo hong phai va de bat duoc 80 phan tram so ca bi khai thac")
log("-" * 70)
for col, asc in [("cvss", False), ("epss", False), ("aeg_ei", False)]:
    d = test.sort_values(col, ascending=asc).reset_index(drop=True)
    cum = d["kev"].cumsum()
    idx = (cum >= 0.8 * tot).idxmax() if (cum >= 0.8 * tot).any() else None
    if idx is not None:
        log(f"  {col:<8}: can va {idx+1:,} lo hong ({100*(idx+1)/len(d):.1f}% toan bo)")
    else:
        log(f"  {col:<8}: khong dat duoc nguong 80 phan tram")

with open(os.path.join(OUT, "chan_doan.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
log("\nDa luu: output/chan_doan.txt va cac bang .csv")
