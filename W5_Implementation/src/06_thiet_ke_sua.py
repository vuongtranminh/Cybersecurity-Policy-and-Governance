# -*- coding: utf-8 -*-
"""
06_thiet_ke_sua.py
Chay lai phan tich theo ba thiet ke da sua, nham khac phuc loi thiet ke cua
ban phan tich ban dau.

LOI CUA BAN BAN DAU:
Gia thuyet noi ve do kho KY THUAT cua viec dung ma khai thac tu advisory.
Nhung bien ket qua duoc dung lai la viec lo hong CO BI TAN CONG ngoai doi hay
khong, von do quyet dinh CHON MUC TIEU cua ke tan cong. Hai khai niem khac nhau.
Hon nua quy mo nha cung cap tac dong len ca advisory lan kha nang bi nham toi,
nen moi tuong quan quan sat duoc deu bi nhieu.

BA THIET KE SUA:
  A. Doi bien ket qua sang "co ma khai thac cong khai xuat hien hay khong".
     Day la mot hanh vi ky thuat, phu thuoc do kho, dung voi gia thuyet hon.
  B. Chi xet trong nhom da bi tan cong, hoi ve TOC DO.
     Moi lo hong trong nhom nay deu du gia tri de bi nham toi, nen gia tri
     muc tieu khong con la bien gay nhieu.
  C. Chung minh su ton tai cua bien gay nhieu bang cach phan tang theo
     loai to chuc cong bo advisory.
"""
import os, re, json
import numpy as np, pandas as pd
from scipy import stats as sps
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
OUT = os.path.join(HERE, "..", "output")
lines = []
def log(s=""):
    print(s, flush=True); lines.append(str(s))

df = pd.read_csv(os.path.join(OUT, "features.csv"))
df["published_dt"] = pd.to_datetime(df["published"], errors="coerce")

log("=" * 72)
log("PHAN TICH THEO BA THIET KE DA SUA")
log("=" * 72)

# ===================================================== THIET KE A
log("\n" + "-" * 72)
log("THIET KE A. Bien ket qua moi: co ma khai thac cong khai xuat hien khong")
log("-" * 72)
log("Ly do doi: viec VIET RA ma khai thac la hanh vi ky thuat, phu thuoc do kho.")
log("Viec DEM DI TAN CONG la quyet dinh kinh doanh, phu thuoc gia tri muc tieu.")
log("Gia thuyet cua nhom noi ve cai thu nhat.\n")

edb = pd.read_csv("/tmp/edb.csv")
edb = edb[edb["codes"].notna()]
rows = []
for codes, dt in zip(edb["codes"].astype(str), edb["date_published"].astype(str)):
    for tok in codes.replace(";", " ").split():
        if tok.upper().startswith("CVE-"):
            rows.append((tok.upper(), dt[:10]))
e = (pd.DataFrame(rows, columns=["cve_id", "edb_date"])
       .groupby("cve_id")["edb_date"].min().reset_index())
df = df.merge(e, on="cve_id", how="left")
df["co_ma_khai_thac"] = df["edb_date"].notna().astype(int)

log(f"Tong lo hong phan tich        : {len(df):,}")
log(f"Co ma khai thac cong khai     : {int(df['co_ma_khai_thac'].sum()):,} "
    f"({100*df['co_ma_khai_thac'].mean():.2f}%)")
log(f"Da bi tan cong thuc te (KEV)  : {int(df['kev'].sum()):,} "
    f"({100*df['kev'].mean():.2f}%)")

log("\nSo sanh nang luc phan biet cua tung thanh phan, tren hai bien ket qua:")
log(f"{'Thanh phan':<10} {'voi KEV (ban cu)':>18} {'voi ma khai thac (moi)':>26}")
resA = []
for c in ["Cn", "C1", "C2", "C3", "C4", "C5", "K", "P", "E", "cvss"]:
    a1 = roc_auc_score(df["kev"], df[c])
    a2 = roc_auc_score(df["co_ma_khai_thac"], df[c])
    resA.append({"thanh_phan": c, "auc_kev": a1, "auc_ma_khai_thac": a2})
    log(f"{c:<10} {a1:>18.4f} {a2:>26.4f}")
pd.DataFrame(resA).to_csv(os.path.join(OUT, "sua_A_doi_bien_ket_qua.csv"), index=False)

log("\nTy le co ma khai thac cong khai, theo muc chi tiet ky thuat (tieu chi C2):")
g = df.groupby("C2").agg(so_luong=("co_ma_khai_thac", "size"),
                         co_ma=("co_ma_khai_thac", "sum"),
                         bi_tan_cong=("kev", "sum"))
g["ty_le_co_ma_phan_tram"] = 100 * g["co_ma"] / g["so_luong"]
g["ty_le_bi_tan_cong_phan_tram"] = 100 * g["bi_tan_cong"] / g["so_luong"]
log(g.to_string())
g.to_csv(os.path.join(OUT, "sua_A_theo_C2.csv"))

# ===================================================== THIET KE B
log("\n" + "-" * 72)
log("THIET KE B. Chi xet trong nhom da bi tan cong, hoi ve toc do")
log("-" * 72)
log("Moi lo hong trong nhom nay deu du gia tri de bi nham toi, nen gia tri muc")
log("tieu khong con gay nhieu. Cau hoi: advisory chi tiet hon thi bi dua vao")
log("danh muc nhanh hon khong?\n")

kev = pd.read_csv(os.path.join(DATA, "kev.csv"))
k = df[df["kev"] == 1].merge(kev[["cve_id", "date_added", "vendor"]], on="cve_id", how="left")
k["ngay_vao_kev"] = pd.to_datetime(k["date_added"], errors="coerce")
k["so_ngay"] = (k["ngay_vao_kev"] - k["published_dt"]).dt.days
k = k[(k["so_ngay"] >= 0) & (k["so_ngay"] <= 1095)]
log(f"So quan sat               : {len(k)}")
log(f"Trung vi so ngay          : {k['so_ngay'].median():.0f}")
log(f"Tu phan vi 25 va 75       : {k['so_ngay'].quantile(0.25):.0f} va "
    f"{k['so_ngay'].quantile(0.75):.0f}")

log("\nTuong quan Spearman giua tung thanh phan va so ngay cho toi khi vao danh muc:")
log("(he so AM nghia la diem cao hon thi bi dua vao danh muc NHANH hon, "
    "tuc ung ho gia thuyet)")
resB = []
for c in ["Cn", "C1", "C2", "C3", "C4", "C5", "K", "P", "E", "cvss", "epss"]:
    rho, p = sps.spearmanr(k[c], k["so_ngay"], nan_policy="omit")
    sig = "co y nghia" if p < 0.05 else "khong co y nghia"
    resB.append({"thanh_phan": c, "rho": rho, "p_value": p})
    log(f"  {c:<6} rho={rho:+.4f}  p={p:.4f}  {sig}")
pd.DataFrame(resB).to_csv(os.path.join(OUT, "sua_B_toc_do.csv"), index=False)

log("\nSo ngay trung vi theo muc diem C2, trong nhom da bi tan cong:")
gb = k.groupby("C2")["so_ngay"].agg(["size", "median"])
gb.columns = ["so_quan_sat", "trung_vi_so_ngay"]
log(gb.to_string())

# ===================================================== THIET KE C
log("\n" + "-" * 72)
log("THIET KE C. Chung minh su ton tai cua bien gay nhieu")
log("-" * 72)
log("Phan tang lo hong theo loai to chuc cong bo, suy ra tu ten mien cua cac")
log("tham chieu trong NVD.\n")

NHA_CUNG_CAP_LON = [
    "microsoft.com", "apple.com", "google.com", "chromium.org", "cisco.com",
    "adobe.com", "oracle.com", "ibm.com", "fortinet.com", "ivanti.com",
    "citrix.com", "vmware.com", "broadcom.com", "sap.com", "qualcomm.com",
    "samsung.com", "android.com", "redhat.com", "intel.com", "hp.com",
    "dell.com", "siemens.com", "se.com", "zoom.us", "atlassian.com",
    "paloaltonetworks.com", "juniper.net", "f5.com", "sonicwall.com",
    "trendmicro.com", "mozilla.org", "zyxel.com", "qnap.com", "synology.com",
    "sophos.com", "veeam.com", "progress.com", "jetbrains.com", "nvidia.com",
]
DU_AN_NHO = ["github.com", "gitlab.com", "huntr.dev", "patchstack.com",
             "wordfence.com", "wpscan.com", "sourceforge.net", "bitbucket.org"]

raw_refs = {}
with open(os.path.join(DATA, "nvd_raw.jsonl"), encoding="utf-8") as f:
    for line in f:
        try:
            r = json.loads(line)
        except Exception:
            continue
        raw_refs[r["id"]] = [x.get("url", "") for x in (r.get("refs") or [])]

def phan_loai(cid):
    urls = raw_refs.get(cid, [])
    joined = " ".join(urls).lower()
    if any(d in joined for d in NHA_CUNG_CAP_LON):
        return "nha cung cap lon"
    if any(d in joined for d in DU_AN_NHO):
        return "du an nho hoac nguon mo"
    return "khac"

df["loai_to_chuc"] = df["cve_id"].map(phan_loai)
g2 = df.groupby("loai_to_chuc").agg(
    so_luong=("kev", "size"),
    diem_C_trung_binh=("C_raw", "mean"),
    ty_le_C2_bang_2=("C2", lambda s: 100 * (s == 2).mean()),
    so_bi_tan_cong=("kev", "sum"))
g2["ty_le_bi_tan_cong_phan_tram"] = 100 * g2["so_bi_tan_cong"] / g2["so_luong"]
log(g2.to_string())
g2.to_csv(os.path.join(OUT, "sua_C_phan_tang.csv"))

log("\nNeu bien gay nhieu ton tai thi hai dieu sau phai cung dung:")
r1 = g2["diem_C_trung_binh"]
r2 = g2["ty_le_bi_tan_cong_phan_tram"]
log(f"  1. Diem C khac nhau ro ret giua cac tang: "
    f"{r1.min():.2f} den {r1.max():.2f}")
log(f"  2. Ty le bi tan cong khac nhau ro ret giua cac tang: "
    f"{r2.min():.3f}% den {r2.max():.3f}%")

log("\nQuan he giua C2 va viec bi tan cong, TRONG TUNG TANG rieng biet:")
log("(neu quan he nguoc bien mat khi xet trong tung tang thi no la do nhieu)")
for tang in df["loai_to_chuc"].unique():
    sub = df[df["loai_to_chuc"] == tang]
    if sub["kev"].sum() < 10:
        log(f"\n  {tang}: qua it quan sat duong, bo qua")
        continue
    auc = roc_auc_score(sub["kev"], sub["Cn"])
    log(f"\n  {tang} (n={len(sub):,}, so bi tan cong={int(sub['kev'].sum())}):")
    log(f"    ROC-AUC cua thanh phan C: {auc:.4f}")
    gg = sub.groupby("C2")["kev"].agg(["size", "mean"])
    gg.columns = ["so_luong", "ty_le"]
    gg["ty_le_phan_tram"] = 100 * gg["ty_le"]
    log(gg[["so_luong", "ty_le_phan_tram"]].to_string().replace("\n", "\n    "))

with open(os.path.join(OUT, "thiet_ke_sua.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
log("\nDa luu: output/thiet_ke_sua.txt va cac bang .csv")
