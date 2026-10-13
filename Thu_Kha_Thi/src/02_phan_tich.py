# -*- coding: utf-8 -*-
"""
02_phan_tich.py - Phan tich (Viec 2, 3, 4 cua de tai)

THIET KE CONG BANG VE THOI GIAN
  Mot phuong phap xep uu tien chi co gia tri neu no dung duoc TAI THOI DIEM
  phai ra quyet dinh va. Vi vay:
  - Lo hong nam 2025 duoc chia thanh 12 dot theo thang cong bo.
  - Thoi diem ra quyet dinh D = ngay cuoi cua thang cong bo.
  - Diem EPSS lay dung vao ngay D (du lieu lich su).
  - Lo hong da bi ghi nhan khai thac (vao KEV) truoc hoac dung ngay D bi loai,
    vi luc do khong con gi de du bao.
  - Ket qua can du bao: lo hong bi dua vao KEV trong vong 180 ngay sau ngay D.

Chay:  python3 02_phan_tich.py
"""
import os, io, json, gzip, glob
from datetime import date, timedelta
import numpy as np, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
OUT = os.path.join(HERE, "..", "output")
os.makedirs(OUT, exist_ok=True)
YEAR, FOLLOW, SEED, NBOOT = 2025, 180, 42, 2000
CSA_THRESHOLD = 8.0
rng = np.random.default_rng(SEED)
R = {}
lines = []
def log(s=""):
    print(s, flush=True); lines.append(str(s))

def wilson(k, n, z=1.96):
    p = k / n; d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d; h = z*np.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return 100*(c-h), 100*(c+h)

def load_epss(d):
    """Lay file EPSS dung ngay d, neu thieu thi lui toi da 4 ngay."""
    for back in range(5):
        dd = d - timedelta(days=back)
        p = os.path.join(DATA, f"epss_{dd.isoformat()}.csv.gz")
        if os.path.exists(p):
            df = pd.read_csv(io.StringIO(gzip.decompress(open(p, "rb").read()).decode()), comment="#")
            return dd, dict(zip(df["cve"].str.upper(), df["epss"].astype(float)))
    raise FileNotFoundError(f"khong co EPSS quanh ngay {d}")

def month_end(y, m):
    return (date(y + (m == 12), m % 12 + 1, 1) - timedelta(days=1))

# =================================================================== VIEC 1
log("=" * 74); log("VIEC 1. DU LIEU"); log("=" * 74)
recs = [json.loads(l) for l in open(os.path.join(DATA, f"nvd_{YEAR}.jsonl"), encoding="utf-8")]
nvd = pd.DataFrame(recs)
nvd = nvd[nvd["published"].str.startswith(str(YEAR))]
n_all = len(nvd)
n_rej = int((nvd["status"] == "Rejected").sum())
nvd = nvd[nvd["status"] != "Rejected"]
# Diem chinh: uu tien diem do NVD cham, neu khong co thi dung diem cua don vi cong bo (CNA).
# Diem doi chung: uu tien diem cua CNA, neu khong co thi dung diem cua NVD.
nvd["cvss3"] = nvd["cvss3_nvd"].fillna(nvd["cvss3_cna"])
nvd["cvss3_uu_tien_cna"] = nvd["cvss3_cna"].fillna(nvd["cvss3_nvd"])
n_v4only = int((nvd["cvss3"].isna() & nvd["cvss4"].notna()).sum())
n_none = int((nvd["cvss3"].isna() & nvd["cvss4"].isna()).sum())
nvd = nvd[nvd["cvss3"].notna()].copy()
nvd["id"] = nvd["id"].str.upper()
nvd["published"] = pd.to_datetime(nvd["published"])
log(f"Lo hong cong bo nam {YEAR}                 : {n_all:,}")
log(f"  loai: bi tu choi (Rejected)            : {n_rej:,}")
log(f"  loai: chi co CVSS 4.0, khong co 3.x     : {n_v4only:,}")
log(f"  loai: khong co diem CVSS nao            : {n_none:,}")
log(f"  con lai co diem CVSS 3.x               : {len(nvd):,}")
both = nvd["cvss3_nvd"].notna() & nvd["cvss3_cna"].notna()
log(f"    co diem do NVD cham                  : {int(nvd['cvss3_nvd'].notna().sum()):,}")
log(f"    co diem do don vi cong bo (CNA) cham : {int(nvd['cvss3_cna'].notna().sum()):,}")
log(f"    co ca hai diem                       : {int(both.sum()):,}, trong do NVD cham cao hon "
    f"{int((nvd.loc[both,'cvss3_nvd']>nvd.loc[both,'cvss3_cna']).sum()):,} truong hop, "
    f"chenh lech trung binh {float((nvd.loc[both,'cvss3_nvd']-nvd.loc[both,'cvss3_cna']).mean()):+.2f} diem")
R["nguon_diem"] = dict(co_nvd=int(nvd['cvss3_nvd'].notna().sum()), co_cna=int(nvd['cvss3_cna'].notna().sum()),
                       ca_hai=int(both.sum()),
                       nvd_cao_hon=int((nvd.loc[both,'cvss3_nvd']>nvd.loc[both,'cvss3_cna']).sum()),
                       chenh_tb=float((nvd.loc[both,'cvss3_nvd']-nvd.loc[both,'cvss3_cna']).mean()))
R["viec1"] = dict(tong=n_all, rejected=n_rej, chi_cvss4=n_v4only, khong_cvss=n_none,
                  co_cvss3=len(nvd))

kev = pd.DataFrame(json.load(open(os.path.join(DATA, "kev.json"))))
kev["cve_id"] = kev["cve_id"].str.upper()
kev["date_added"] = pd.to_datetime(kev["date_added"])
kev_date = dict(zip(kev["cve_id"], kev["date_added"]))

# thoi gian tu khi cong bo den khi bi ghi nhan khai thac (toan bo lo hong 2025 trong KEV)
k25 = nvd[nvd["id"].isin(kev_date)].copy()
k25["so_ngay"] = (k25["id"].map(kev_date) - k25["published"]).dt.days
bins = [(-10**6, 0, "Truoc hoac cung ngay cong bo"), (1, 7, "Tu 1 den 7 ngay"),
        (8, 30, "Tu 8 den 30 ngay"), (31, 180, "Tu 31 den 180 ngay"), (181, 10**6, "Sau 180 ngay")]
tg = [{"khoang": lab, "so_luong": int(((k25.so_ngay >= a) & (k25.so_ngay <= b)).sum())} for a, b, lab in bins]
tg = pd.DataFrame(tg); tg["ty_le_pct"] = 100 * tg["so_luong"] / len(k25)
tg.to_csv(os.path.join(OUT, "thoi_gian_bi_khai_thac.csv"), index=False)
log(f"\nLo hong cong bo nam {YEAR} va da vao KEV: {len(k25)}")
log(tg.to_string(index=False))
R["thoi_gian"] = tg.to_dict("records"); R["kev_2025"] = len(k25)

def build(offset_months=0):
    """Dung tap phan tich. offset_months=0: quyet dinh vao cuoi thang cong bo.
       offset_months=1: quyet dinh vao cuoi thang ke tiep (phan tich do nhay)."""
    parts = []
    for m in range(1, 13):
        y2, m2 = (YEAR, m + offset_months) if m + offset_months <= 12 else (YEAR + 1, m + offset_months - 12)
        D = month_end(y2, m2); Dts = pd.Timestamp(D)
        used, emap = load_epss(D)
        c = nvd[nvd["published"].dt.month == m].copy()
        c["epss"] = c["id"].map(emap)
        c["kev_date"] = c["id"].map(kev_date)
        c["da_kev_truoc"] = c["kev_date"].notna() & (c["kev_date"] <= Dts)
        c["y"] = (c["kev_date"].notna() & (c["kev_date"] > Dts) &
                  (c["kev_date"] <= Dts + pd.Timedelta(days=FOLLOW))).astype(int)
        c["ngay_quyet_dinh"] = D.isoformat(); c["ngay_epss"] = used.isoformat()
        parts.append(c)
    d = pd.concat(parts)
    info = dict(loai_da_kev=int(d["da_kev_truoc"].sum()), thieu_epss=int(d["epss"].isna().sum()))
    d = d[~d["da_kev_truoc"]].copy()
    d["epss"] = d["epss"].fillna(0.0)
    d["tie"] = rng.random(len(d))     # pha the hoa ngau nhien, co dinh seed
    return d, info

d, info = build(0)
cur = pd.read_csv(os.path.join(DATA, "epss_hien_tai.csv.gz"), comment="#")
d["epss_hien_tai"] = d["id"].map(dict(zip(cur["cve"].str.upper(), cur["epss"]))).fillna(0.0)
N, P = len(d), int(d["y"].sum())
log(f"\nTap phan tich (quyet dinh vao cuoi thang cong bo):")
log(f"  loai vi da vao KEV truoc thoi diem quyet dinh : {info['loai_da_kev']}")
log(f"  chua co diem EPSS luc quyet dinh (gan = 0)    : {info['thieu_epss']}")
log(f"  so lo hong phan tich                           : {N:,}")
log(f"  bi khai thac trong {FOLLOW} ngay sau quyet dinh    : {P} ({100*P/N:.3f}%)")
R["tap"] = dict(N=N, P=P, **info)
d.drop(columns=["tie"]).to_csv(os.path.join(OUT, "du_lieu_phan_tich.csv"), index=False)

def ranked(df, col):
    return df.sort_values([col, "tie"], ascending=[False, False])

def need_to_catch(df, col, frac, P_, reps=200):
    """So lo hong phai va (tu diem cao xuong) de bat duoc ty le frac so ca bi khai thac.
       Cac lo hong trung diem duoc sap xep ngau nhien; lap lai reps lan, lay trung vi."""
    need = int(np.ceil(frac * P_))
    sc, y = df[col].values, df["y"].values
    g = np.random.default_rng(SEED)
    out = []
    for _ in range(reps):
        order = np.lexsort((g.random(len(sc)), -sc))
        cum = np.cumsum(y[order])
        if cum[-1] < need: return None
        out.append(int(np.argmax(cum >= need) + 1))
    return int(np.median(out))

# =================================================================== VIEC 2
log("\n" + "=" * 74); log(f"VIEC 2. KIEM CHUNG KHUYEN NGHI CSA (CVSS tu {CSA_THRESHOLD})"); log("=" * 74)
csa_mask = d["cvss3"] >= CSA_THRESHOLD
W = int(csa_mask.sum()); hit = int(d.loc[csa_mask, "y"].sum()); miss = P - hit
lo, hi = wilson(miss, P)
log(f"So lo hong phai va theo quy tac CSA : {W:,} ({100*W/N:.1f}% tong so)")
log(f"Bat duoc                            : {hit}/{P}")
log(f"Bo sot                              : {miss}/{P} = {100*miss/P:.1f}%  "
    f"(khoang tin cay 95%: {lo:.1f}% den {hi:.1f}%)")
ms = d[(d["y"] == 1) & ~csa_mask]
b1 = int((ms["cvss3"] >= 7.0).sum()); b2 = int(((ms["cvss3"] >= 4.0) & (ms["cvss3"] < 7.0)).sum())
b3 = int((ms["cvss3"] < 4.0).sum())
log(f"Cac lo hong bi bo sot co diem CVSS  : tu 7.0 den 7.9: {b1};  tu 4.0 den 6.9: {b2};  duoi 4.0: {b3}")
alt = d["cvss3_uu_tien_cna"] >= CSA_THRESHOLD
Wa = int(alt.sum()); ha = int(d.loc[alt, "y"].sum()); la, hb = wilson(P - ha, P)
log(f"\nDo nhay theo nguon diem: neu uu tien diem cua don vi cong bo thay vi cua NVD:")
log(f"  phai va {Wa:,} ({100*Wa/N:.1f}%), bat duoc {ha}/{P}, bo sot {P-ha}/{P} = {100*(P-ha)/P:.1f}% "
    f"(khoang tin cay 95%: {la:.1f}% den {hb:.1f}%)")
R["viec2_cna"] = dict(phai_va=Wa, bat=ha, bo_sot=P-ha, ty_le_bo_sot=100*(P-ha)/P, ci_thap=la, ci_cao=hb)
R["viec2"] = dict(phai_va=W, ty_le_phai_va=100*W/N, bat=hit, bo_sot=miss, ty_le_bo_sot=100*miss/P,
                  ci_thap=lo, ci_cao=hi, bo_sot_7=b1, bo_sot_4_7=b2, bo_sot_duoi_4=b3)

# =================================================================== VIEC 3
log("\n" + "=" * 74); log("VIEC 3. SO SANH CVSS VA EPSS"); log("=" * 74)
methods = [("CVSS", "cvss3"), ("EPSS luc quyet dinh", "epss"),
           ("EPSS hien tai (nhin truoc dap an)", "epss_hien_tai")]
rows = []
for name, col in methods:
    r = {"phuong_phap": name}
    for f in [0.5, 0.8]:
        r[f"can_va_de_bat_{int(f*100)}pct"] = need_to_catch(d, col, f, P)
    r["can_va_de_bang_CSA"] = need_to_catch(d, col, hit / P, P)
    r["bat_khi_va_bang_CSA"] = int(ranked(d, col).head(W)["y"].sum())
    rows.append(r)
t3 = pd.DataFrame(rows); t3.to_csv(os.path.join(OUT, "viec3_so_sanh.csv"), index=False)
log(t3.to_string(index=False))

# khoang tin cay cho chenh lech so ca bat duoc khi cung khoi luong va
diffs = []
for _ in range(NBOOT):
    s = d.sample(len(d), replace=True, random_state=int(rng.integers(10**9)))
    w = int((s["cvss3"] >= CSA_THRESHOLD).sum())
    a = int(ranked(s, "cvss3").head(w)["y"].sum())
    b = int(ranked(s, "epss").head(w)["y"].sum())
    diffs.append(b - a)
dl, dh = np.percentile(diffs, [2.5, 97.5])
obs = t3.loc[1, "bat_khi_va_bang_CSA"] - t3.loc[0, "bat_khi_va_bang_CSA"]
log(f"\nCung va {W:,} lo hong: EPSS bat nhieu hon CVSS {obs:+d} ca "
    f"(khoang tin cay 95% bootstrap: {dl:+.0f} den {dh:+.0f})")
log("  Ket luan: " + ("khong co khac biet co y nghia thong ke" if dl <= 0 <= dh else "khac biet co y nghia thong ke"))
R["viec3"] = dict(bang=t3.to_dict("records"), chenh_lech=int(obs), ci=[float(dl), float(dh)])

# phan tich do nhay: quyet dinh muon hon 1 thang
d2, info2 = build(1)
P2 = int(d2["y"].sum()); W2 = int((d2["cvss3"] >= CSA_THRESHOLD).sum())
a2 = int(ranked(d2, "cvss3").head(W2)["y"].sum()); b2_ = int(ranked(d2, "epss").head(W2)["y"].sum())
n50c = need_to_catch(d2, "cvss3", 0.5, P2); n50e = need_to_catch(d2, "epss", 0.5, P2)
log(f"\nDo nhay: neu quyet dinh MUON HON 1 THANG (EPSS da co them 1 thang du lieu):")
log(f"  loai them vi da vao KEV: {info2['loai_da_kev']},  con {P2} ca bi khai thac de du bao")
log(f"  cung va {W2:,}: CVSS bat {a2}/{P2}, EPSS bat {b2_}/{P2}")
log(f"  de bat 50%: CVSS can {n50c:,}, EPSS can {n50e:,}")
R["do_nhay"] = dict(P=P2, loai=info2["loai_da_kev"], W=W2, cvss_bat=a2, epss_bat=b2_,
                    cvss_50=n50c, epss_50=n50e)

# =================================================================== VIEC 4
log("\n" + "=" * 74); log("VIEC 4. CAC QUY TAC KET HOP"); log("=" * 74)
rules = [("CVSS tu 8.0 (khuyen nghi CSA)", csa_mask)]
for t in [0.01, 0.05, 0.1]:
    rules.append((f"Chi EPSS tu {t}", d["epss"] >= t))
for t in [0.01, 0.05]:
    rules.append((f"CVSS tu 8.0 HOAC EPSS tu {t}", csa_mask | (d["epss"] >= t)))
for t in [0.01, 0.05]:
    rules.append((f"CVSS tu 7.0 VA EPSS tu {t}", (d["cvss3"] >= 7.0) & (d["epss"] >= t)))
out = []
for name, m in rules:
    n = int(m.sum()); h = int(d.loc[m, "y"].sum())
    out.append({"quy_tac": name, "phai_va": n, "bat_duoc": h, "ty_le_bat_pct": 100*h/P,
                "bat_tren_1000_ban_va": 1000*h/n if n else 0.0})
t4 = pd.DataFrame(out); t4.to_csv(os.path.join(OUT, "viec4_quy_tac.csv"), index=False)
log(t4.to_string(index=False, float_format=lambda x: f"{x:.1f}"))
R["viec4"] = t4.to_dict("records")

json.dump(R, open(os.path.join(OUT, "ket_qua.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2, default=float)
open(os.path.join(OUT, "ket_qua.txt"), "w", encoding="utf-8").write("\n".join(lines))
log("\nDa luu ket qua vao thu muc output/")
