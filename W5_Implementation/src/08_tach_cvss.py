# -*- coding: utf-8 -*-
"""
08_tach_cvss.py
Tach diem CVSS v3.1 thanh hai nua theo dung cong thuc chinh thuc cua FIRST,
roi do xem nua nao thuc su mang thong tin du bao.

  Base Score = ham cua (Exploitability, Impact)
  Exploitability = 8.22 * AV * AC * PR * UI
  Impact         = tinh tu C, I, A va Scope

Muc dich: tra loi cau hoi "CVSS da co danh gia do de khai thac roi,
vay con thieu gi?"
"""
import os, re
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "output")
lines = []
def log(s=""):
    print(s, flush=True); lines.append(str(s))

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

def tach(vec):
    d = {}
    for part in str(vec).split("/"):
        if ":" in part:
            k, v = part.split(":", 1); d[k] = v
    try:
        scope_changed = d["S"] == "C"
        pr = (PR_C if scope_changed else PR_U)[d["PR"]]
        expl = 8.22 * AV[d["AV"]] * AC[d["AC"]] * pr * UI[d["UI"]]
        iss = 1 - (1 - CIA[d["C"]]) * (1 - CIA[d["I"]]) * (1 - CIA[d["A"]])
        if scope_changed:
            imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            imp = 6.42 * iss
        return expl, imp
    except Exception:
        return np.nan, np.nan

df = pd.read_csv(os.path.join(OUT, "features.csv"))
df["epss"] = df["epss"].fillna(0.0)
vals = df["cvss_vector"].map(tach)
df["cvss_exploitability"] = [v[0] for v in vals]
df["cvss_impact"] = [v[1] for v in vals]
df = df.dropna(subset=["cvss_exploitability", "cvss_impact"])

log("=" * 72)
log("TACH DIEM CVSS THANH HAI NUA")
log("=" * 72)
log(f"\nSo lo hong tach duoc: {len(df):,}")
log(f"Exploitability: tu {df['cvss_exploitability'].min():.2f} den "
    f"{df['cvss_exploitability'].max():.2f}")
log(f"Impact        : tu {df['cvss_impact'].min():.2f} den "
    f"{df['cvss_impact'].max():.2f}")

log("\n" + "-" * 72)
log("NUA NAO MANG THONG TIN DU BAO VIEC BI TAN CONG?")
log("-" * 72)
res = []
for name, col in [
    ("Base Score day du", "cvss"),
    ("Chi nua Exploitability", "cvss_exploitability"),
    ("Chi nua Impact", "cvss_impact"),
    ("EPSS (de doi chieu)", "epss"),
]:
    a = roc_auc_score(df["kev"], df[col])
    res.append({"chi_so": name, "roc_auc": a})
    log(f"  {name:<28} ROC-AUC = {a:.4f}")
pd.DataFrame(res).to_csv(os.path.join(OUT, "tach_cvss_auc.csv"), index=False)

log("\n" + "-" * 72)
log("TRONG DAI CVSS TU 8.0 TRO LEN, HAI NUA DONG GOP THE NAO?")
log("-" * 72)
band = df[df["cvss"] >= 8.0]
log(f"  So lo hong: {len(band):,}, bi tan cong: {int(band['kev'].sum())}")
for name, col in [("Base Score", "cvss"),
                  ("Exploitability", "cvss_exploitability"),
                  ("Impact", "cvss_impact"),
                  ("EPSS", "epss")]:
    log(f"  {name:<18} ROC-AUC = {roc_auc_score(band['kev'], band[col]):.4f}")

log("\n" + "-" * 72)
log("TY LE BI TAN CONG THEO TUNG TRUONG CUA NUA EXPLOITABILITY")
log("-" * 72)
def truong(vec, key):
    m = re.search(key + r":([A-Z])", str(vec))
    return m.group(1) if m else None
TEN = {
    "AV": ("Duong tan cong", {"N": "qua mang", "A": "ke can", "L": "cuc bo", "P": "vat ly"}),
    "AC": ("Do phuc tap", {"L": "thap", "H": "cao"}),
    "PR": ("Quyen can co", {"N": "khong can", "L": "quyen thap", "H": "quyen cao"}),
    "UI": ("Tuong tac nguoi dung", {"N": "khong can", "R": "co can"}),
}
for key, (ten, nhan) in TEN.items():
    df[key] = df["cvss_vector"].map(lambda v: truong(v, key))
    g = df.groupby(key).agg(so_luong=("kev", "size"), bi_tan_cong=("kev", "sum"))
    g["ty_le_phan_tram"] = 100 * g["bi_tan_cong"] / g["so_luong"]
    g.index = [nhan.get(i, i) for i in g.index]
    log(f"\n{ten}:")
    log(g.sort_values("ty_le_phan_tram", ascending=False).to_string())

log("\n" + "-" * 72)
log("CVSS CO CHI SO CHO MA KHAI THAC KHONG? CO, NHUNG KHONG AI CONG BO")
log("-" * 72)
log("CVSS v3.1 co nhom Temporal, trong do co Exploit Code Maturity.")
log("CVSS v4.0 doi ten thanh nhom Threat, cung co Exploit Maturity.")
log("Cac gia tri: Unproven, Proof-of-Concept, Functional, High.")
log("")
log("Kiem tra trong du lieu NVD da tai ve:")
import json
n_total = n_temporal = 0
with open(os.path.join(HERE, "..", "data", "nvd_raw.jsonl"), encoding="utf-8") as f:
    for line in f:
        n_total += 1
        if '"temporalScore"' in line or '"exploitCodeMaturity"' in line:
            n_temporal += 1
log(f"  Tong ban ghi NVD            : {n_total:,}")
log(f"  Co chi so Temporal hoac Threat: {n_temporal:,}")
log("")
log("Ket luan: chi so ma CVSS danh rieng cho viec do su ton tai cua ma khai thac")
log("ton tai tren giay nhung khong co trong du lieu cong khai ma ai cung dung.")

with open(os.path.join(OUT, "tach_cvss.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
log("\nDa luu: output/tach_cvss.txt")
