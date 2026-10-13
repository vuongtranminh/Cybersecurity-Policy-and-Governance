# -*- coding: utf-8 -*-
"""
07_y_tuong_goc.py
Kiem dinh dung y tuong goc cua nhom, da duoc phat bieu lai cho chinh xac:

  "Trong cung mot muc nghiem trong, lo hong nao DA CO MA TAN CONG CONG KHAI
   va THUOC LOP LOI PHO BIEN DE KHAI THAC thi phai va truoc."

Khac voi ban truoc o cho: khong dung do chi tiet cua advisory lam thanh phan
chinh. Chi dung hai yeu to ma nhom thuc su quan tam.

Thiet ke: GIU CO DINH muc nghiem trong (chi xet CVSS tu 8.0 tro len), roi hoi
trong dai do, hai yeu to kia co giup xep uu tien tot hon khong.
"""
import os
import numpy as np, pandas as pd
from sklearn.metrics import roc_auc_score, average_precision_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "output")
lines = []
def log(s=""):
    print(s, flush=True); lines.append(str(s))

df = pd.read_csv(os.path.join(OUT, "features.csv"))
df["epss"] = df["epss"].fillna(0.0)

log("=" * 72)
log("KIEM DINH Y TUONG GOC: trong cung muc nghiem trong, xep uu tien the nao")
log("=" * 72)

band = df[df["cvss"] >= 8.0].copy()
log(f"\nDai nghiem trong duoc xet: CVSS tu 8.0 tro len")
log(f"  So lo hong          : {len(band):,}")
log(f"  Da bi tan cong (KEV): {int(band['kev'].sum())} "
    f"({100*band['kev'].mean():.3f}%)")
log(f"  Day chinh la tap ma bai bao goc yeu cau va trong 48 gio.")

# ---------------------------------------------------- yeu to 1: ma cong khai
log("\n" + "-" * 72)
log("YEU TO 1. Da co ma tan cong cong khai hay chua")
log("-" * 72)
g = band.groupby("P").agg(so_luong=("kev", "size"), bi_tan_cong=("kev", "sum"))
g["ty_le_phan_tram"] = 100 * g["bi_tan_cong"] / g["so_luong"]
g.index = ["0.0 khong co gi", "0.5 chi co bai phan tich", "1.0 co ma chay duoc"]
log(g.to_string())
r0 = g.loc["0.0 khong co gi", "ty_le_phan_tram"]
r1 = g.loc["1.0 co ma chay duoc", "ty_le_phan_tram"]
log(f"\n  => Co ma chay duoc thi ty le bi tan cong cao gap {r1/r0:.1f} lan")

# ---------------------------------------------------- yeu to 2: lop loi
log("\n" + "-" * 72)
log("YEU TO 2. Lop lo hong, theo phan tier cua nhom")
log("-" * 72)
g2 = band.groupby("K_tier").agg(so_luong=("kev", "size"), bi_tan_cong=("kev", "sum"))
g2["ty_le_phan_tram"] = 100 * g2["bi_tan_cong"] / g2["so_luong"]
log(g2.sort_values("ty_le_phan_tram", ascending=False).to_string())

log("\n  Chi tiet theo tung ma CWE pho bien trong dai nay:")
cw = band.groupby("cwe").agg(so_luong=("kev", "size"), bi_tan_cong=("kev", "sum"))
cw = cw[cw["so_luong"] >= 150]
cw["ty_le_phan_tram"] = 100 * cw["bi_tan_cong"] / cw["so_luong"]
TEN = {"CWE-89": "tiem nhiem SQL", "CWE-79": "kich ban lien trang",
       "CWE-78": "tiem nhiem lenh he dieu hanh", "CWE-22": "vuot thu muc",
       "CWE-787": "ghi ngoai vung", "CWE-416": "dung sau khi giai phong",
       "CWE-125": "doc ngoai vung", "CWE-502": "giai tuan tu khong an toan",
       "CWE-918": "gia mao yeu cau phia may chu", "CWE-434": "tai len tep nguy hiem",
       "CWE-287": "xac thuc khong dung", "CWE-20": "kiem tra dau vao khong dung",
       "CWE-352": "gia mao yeu cau lien trang", "CWE-94": "tiem nhiem ma",
       "CWE-119": "loi gioi han bo nho", "CWE-190": "tran so nguyen",
       "CWE-862": "thieu kiem tra phan quyen", "CWE-863": "phan quyen sai",
       "CWE-269": "quan ly dac quyen sai", "CWE-306": "thieu xac thuc"}
cw["ten"] = [TEN.get(i, "") for i in cw.index]
log(cw.sort_values("ty_le_phan_tram", ascending=False).to_string())

# ---------------------------------------------------- so sanh cac quy tac
log("\n" + "-" * 72)
log("SO SANH CAC QUY TAC XEP UU TIEN, TRONG DAI CVSS TU 8.0 TRO LEN")
log("-" * 72)

band["y_tuong_goc"] = 0.6 * band["P"] + 0.4 * band["K"]
band["y_tuong_goc_cong_E"] = 0.45 * band["P"] + 0.30 * band["K"] + 0.25 * band["E"]
band["chi_P"] = band["P"]

rules = [
    ("CVSS trong dai (bai bao goc)", "cvss"),
    ("Chi dung ma cong khai (P)", "chi_P"),
    ("Y tuong goc: ma cong khai + lop loi", "y_tuong_goc"),
    ("Y tuong goc + kha nang tiep can", "y_tuong_goc_cong_E"),
    ("AEG-EI ban cu, co do chi tiet advisory", "aeg_ei"),
    ("EPSS (doi chung)", "epss"),
]
log(f"\n{'Quy tac':<42}{'ROC-AUC':>9}{'P@50':>8}{'P@100':>8}{'P@200':>8}")
res = []
for name, col in rules:
    auc = roc_auc_score(band["kev"], band[col])
    row = {"quy_tac": name, "roc_auc": auc}
    s = f"{name:<42}{auc:>9.4f}"
    for k in [50, 100, 200]:
        p = band.sort_values(col, ascending=False).head(k)["kev"].mean()
        row[f"p_at_{k}"] = p
        s += f"{p:>8.3f}"
    log(s); res.append(row)
pd.DataFrame(res).to_csv(os.path.join(OUT, "y_tuong_goc_so_sanh.csv"), index=False)

# ---------------------------------------------------- bang quyet dinh 2 chieu
log("\n" + "-" * 72)
log("BANG QUYET DINH: trong dai CVSS tu 8.0, chia theo ma cong khai va lop loi")
log("-" * 72)
band["co_ma"] = np.where(band["P"] >= 1.0, "co ma chay duoc", "chua co")
band["lop_loi"] = np.where(band["K"] >= 0.6, "lop de khai thac", "lop kho hon")
pv = band.pivot_table(index="co_ma", columns="lop_loi", values="kev",
                      aggfunc=["size", "sum", "mean"])
log("\nSo luong lo hong:")
log(pv["size"].to_string())
log("\nSo bi tan cong:")
log(pv["sum"].to_string())
log("\nTy le bi tan cong (phan tram):")
log((pv["mean"] * 100).round(3).to_string())

with open(os.path.join(OUT, "y_tuong_goc.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
log("\nDa luu: output/y_tuong_goc.txt")
