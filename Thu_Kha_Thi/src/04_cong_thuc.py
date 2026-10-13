# -*- coding: utf-8 -*-
"""
04_cong_thuc.py - Kiem tra cong thuc Risk Score

  Risk = AC x ((KEV x CVSS) + (1 - KEV) x (CVSS x EPSS^0.3)) x 10

AC (muc quan trong tai san) khong co du lieu cong khai, nen coi AC = 1.

PHEP THU A - kha nang du bao (thiet ke cong bang nhu 02_phan_tich.py)
  Tap phan tich da loai moi lo hong vao KEV truoc ngay quyet dinh, nen KEV = 0
  voi moi lo hong, cong thuc rut ve CVSS x EPSS^0.3. So voi CVSS va EPSS,
  va thu nhieu so mu khac nhau.

PHEP THU B - kha nang phan ung
  Voi moi lo hong cong bo nam 2025 da vao KEV, lay ngay cuoi thang dau tien
  sau khi no vao KEV. Tai ngay do, cham diem toan bo lo hong 2025 da cong bo
  bang tung cach, roi xem lo hong vua vao KEV dung o vi tri nao.

Chay: python3 04_cong_thuc.py  (can chay 01 va 02 truoc)
"""
import os, io, json, gzip
from datetime import date, timedelta
import numpy as np, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
OUT = os.path.join(HERE, "..", "output")
SEED, NBOOT, REPS = 42, 2000, 200
lines = []
def log(s=""):
    print(s, flush=True); lines.append(str(s))

def risk(cvss, epss, kev, mu=0.3, ac=1.0):
    return ac * ((kev * cvss) + (1 - kev) * (cvss * np.power(epss, mu))) * 10

def ranks_needed(sc, y, frac, P, reps=REPS):
    g = np.random.default_rng(SEED); need = int(np.ceil(frac * P)); out = []
    for _ in range(reps):
        o = np.lexsort((g.random(len(sc)), -sc)); c = np.cumsum(y[o])
        out.append(int(np.argmax(c >= need) + 1))
    return int(np.median(out))

def caught_top(sc, y, k, reps=REPS):
    g = np.random.default_rng(SEED); out = []
    for _ in range(reps):
        o = np.lexsort((g.random(len(sc)), -sc)); out.append(int(y[o][:k].sum()))
    return int(np.median(out))

# ===================================================================== A
d = pd.read_csv(os.path.join(OUT, "du_lieu_phan_tich.csv"))
y = d["y"].values; P = int(y.sum()); W = int((d["cvss3"] >= 8.0).sum())
log("=" * 74); log("PHEP THU A. KHA NANG DU BAO (thiet ke cong bang)"); log("=" * 74)
log(f"{len(d):,} lo hong, {P} bi khai thac trong 180 ngay sau ngay quyet dinh.")
log(f"Lo hong da vao KEV truoc ngay quyet dinh da bi loai, nen KEV = 0 voi moi lo hong.\n")
methods = {
    "CVSS (quy tac CSA khi xep hang)": d["cvss3"].values,
    "EPSS luc quyet dinh": d["epss"].values,
    "Cong thuc Risk Score, so mu 0.3": risk(d["cvss3"].values, d["epss"].values, 0),
}
rows = []
log(f"{'Cach xep':<36}{'Vua '+format(W,','):>14}{'Top 500':>10}{'Bat 50%':>10}{'Bat 80%':>10}")
for name, sc in methods.items():
    r = dict(cach=name, bat_khi_vua_W=caught_top(sc, y, W), bat_top500=caught_top(sc, y, 500),
             can_va_50=ranks_needed(sc, y, .5, P), can_va_80=ranks_needed(sc, y, .8, P))
    rows.append(r)
    log(f"{name:<36}{r['bat_khi_vua_W']:>10}/{P}{r['bat_top500']:>7}/{P}{r['can_va_50']:>10,}{r['can_va_80']:>10,}")
pd.DataFrame(rows).to_csv(os.path.join(OUT, "cong_thuc_A.csv"), index=False)

rng = np.random.default_rng(SEED); diffs = []
cv, ep = d["cvss3"].values, d["epss"].values
for _ in range(NBOOT):
    i = rng.integers(0, len(d), len(d)); yy = y[i]; w = int((cv[i] >= 8).sum())
    a = yy[np.lexsort((rng.random(len(i)), -cv[i]))][:w].sum()
    b = yy[np.lexsort((rng.random(len(i)), -risk(cv[i], ep[i], 0)))][:w].sum()
    diffs.append(int(b - a))
lo, hi = np.percentile(diffs, [2.5, 97.5])
log(f"\nCung vua {W:,} lo hong: cong thuc bat nhieu hon CVSS "
    f"{rows[2]['bat_khi_vua_W'] - rows[0]['bat_khi_vua_W']:+d} ca, "
    f"khoang tin cay 95% bootstrap tu {lo:+.0f} den {hi:+.0f}")
log("  Ket luan: " + ("khong co khac biet co y nghia thong ke" if lo <= 0 <= hi
                      else "khac biet co y nghia thong ke"))

log("\nThu cac so mu khac nhau cho EPSS:")
log(f"{'So mu':<8}{'Vua '+format(W,','):>14}{'Top 500':>10}{'Bat 50%':>10}{'Bat 80%':>10}")
sens = []
for mu in [0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 1.0]:
    sc = risk(cv, ep, 0, mu)
    r = dict(so_mu=mu, bat_khi_vua_W=caught_top(sc, y, W), bat_top500=caught_top(sc, y, 500),
             can_va_50=ranks_needed(sc, y, .5, P), can_va_80=ranks_needed(sc, y, .8, P))
    sens.append(r)
    log(f"{mu:<8}{r['bat_khi_vua_W']:>10}/{P}{r['bat_top500']:>7}/{P}{r['can_va_50']:>10,}{r['can_va_80']:>10,}")
pd.DataFrame(sens).to_csv(os.path.join(OUT, "cong_thuc_so_mu.csv"), index=False)

# ===================================================================== B
log("\n" + "=" * 74); log("PHEP THU B. KHA NANG PHAN UNG KHI LO HONG VUA VAO KEV"); log("=" * 74)
nvd = pd.DataFrame([json.loads(l) for l in open(os.path.join(DATA, "nvd_2025.jsonl"), encoding="utf-8")])
nvd = nvd[(nvd["status"] != "Rejected") & nvd["published"].str.startswith("2025")].copy()
nvd["cvss"] = nvd["cvss3_nvd"].fillna(nvd["cvss3_cna"])
nvd = nvd.dropna(subset=["cvss"]); nvd["id"] = nvd["id"].str.upper()
nvd["pub"] = pd.to_datetime(nvd["published"])
kev = pd.DataFrame(json.load(open(os.path.join(DATA, "kev.json"))))
kev["cve_id"] = kev["cve_id"].str.upper(); kev["da"] = pd.to_datetime(kev["date_added"])
kd = dict(zip(kev["cve_id"], kev["da"]))
nvd["kev_date"] = nvd["id"].map(kd)

def month_end(y_, m_):
    return date(y_ + (m_ == 12), m_ % 12 + 1, 1) - timedelta(days=1)
def load_epss(D):
    for b in range(5):
        p = os.path.join(DATA, f"epss_{(D - timedelta(days=b)).isoformat()}.csv.gz")
        if os.path.exists(p):
            e = pd.read_csv(io.StringIO(gzip.decompress(open(p, "rb").read()).decode()), comment="#")
            return dict(zip(e["cve"].str.upper(), e["epss"].astype(float)))
    raise FileNotFoundError(D)

ends = [month_end(2025, m) for m in range(1, 13)] + [month_end(2026, 1)]
targets = nvd[nvd["kev_date"].notna()].copy()
def first_end(t):
    for D in ends:
        if pd.Timestamp(D) >= t: return D
    return None
targets["D"] = targets["kev_date"].map(first_end)
n_out = int(targets["D"].isna().sum()); targets = targets[targets["D"].notna()]
log(f"Lo hong cong bo nam 2025 da vao KEV: {len(targets) + n_out}, "
    f"phan tich duoc {len(targets)} (bo {n_out} vao KEV sau thang 1 nam 2026)")
log("Moi lo hong duoc xet tai ngay cuoi thang dau tien sau khi vao KEV.\n")

res = []
for D, grp in targets.groupby("D"):
    Dts = pd.Timestamp(D); emap = load_epss(D)
    pop = nvd[nvd["pub"] <= Dts].copy()
    pop["epss"] = pop["id"].map(emap).fillna(0.0)
    pop["kev"] = (pop["kev_date"].notna() & (pop["kev_date"] <= Dts)).astype(int)
    sc = {"CVSS": pop["cvss"].values,
          "CVSS x EPSS^0.3, khong co KEV": risk(pop["cvss"].values, pop["epss"].values, 0),
          "Cong thuc day du, co KEV": risk(pop["cvss"].values, pop["epss"].values, pop["kev"].values)}
    N = len(pop); idx = {c: i for i, c in enumerate(pop["id"].values)}
    for name, s in sc.items():
        rk = pd.Series(s).rank(ascending=False, method="average").values
        for cid in grp["id"]:
            res.append(dict(cach=name, cve=cid, ngay=D.isoformat(), N=N, hang=rk[idx[cid]],
                            phan_tram=100 * rk[idx[cid]] / N))
r = pd.DataFrame(res); r.to_csv(os.path.join(OUT, "cong_thuc_B_chi_tiet.csv"), index=False)
log(f"{'Cach cham diem':<34}{'Hang trung vi':>15}{'Top 1%':>10}{'Top 5%':>10}{'Top 25%':>10}")
summ = []
for name in ["CVSS", "CVSS x EPSS^0.3, khong co KEV", "Cong thuc day du, co KEV"]:
    x = r[r["cach"] == name]
    s = dict(cach=name, phan_tram_trung_vi=float(x["phan_tram"].median()),
             top1=100 * (x["phan_tram"] <= 1).mean(), top5=100 * (x["phan_tram"] <= 5).mean(),
             top25=100 * (x["phan_tram"] <= 25).mean())
    summ.append(s)
    log(f"{name:<34}{'top '+format(s['phan_tram_trung_vi'],'.2f')+'%':>15}"
        f"{s['top1']:>9.1f}%{s['top5']:>9.1f}%{s['top25']:>9.1f}%")
pd.DataFrame(summ).to_csv(os.path.join(OUT, "cong_thuc_B.csv"), index=False)
log("\n(Top 1% nghia la lo hong vua vao KEV nam trong 1% lo hong co diem cao nhat tai ngay do.)")

json.dump(dict(A=rows, A_ci=[float(lo), float(hi)], so_mu=sens, B=summ),
          open(os.path.join(OUT, "cong_thuc.json"), "w"), indent=2, default=float)
open(os.path.join(OUT, "cong_thuc.txt"), "w", encoding="utf-8").write("\n".join(lines))
