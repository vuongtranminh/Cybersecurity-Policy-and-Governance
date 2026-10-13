# -*- coding: utf-8 -*-
"""
05_kiem_chung.py - Kiem chung cong thuc uu tien va lo hong (tam bo he so tai san AC)

    Diem = CVSS x [KEV + (1 - KEV) x EPSS^alpha],   alpha = 0.3 theo cong thuc de xuat
    (he so x10 chi doi thang diem, khong doi thu tu nen bo qua)

KE HOACH DUOC CO DINH TRUOC KHI CHAY
  Du lieu  : lo hong cong bo nam 2023, 2024, 2025 (NVD), danh muc KEV, EPSS lich su cuoi moi thang.
  Thiet ke : moi thang la mot dot, ngay quyet dinh la cuoi thang cong bo, EPSS lay dung ngay do,
             loai lo hong da vao KEV truoc ngay quyet dinh, nhan la vao KEV trong 180 ngay sau.
  Theo thoi gian (walk-forward): nam kiem thu 2024 chon so mu tren 2023,
             nam kiem thu 2025 chon so mu tren 2023 va 2024.

  H1 (chinh) Cong thuc alpha = 0.3 bat duoc nhieu lo hong bi khai thac hon CVSS khi va cung so
             luong voi quy tac CSA (CVSS tu 8.0). Dat neu khoang tin cay 95% bootstrap cua chenh
             lech, gop hai nam kiem thu 2024 va 2025, nam hoan toan tren 0.
  H2         Trong mo phong van hanh hang thang voi cung ngan sach va, cong thuc day du (co KEV)
             co ty le "an toan trong 30 ngay" cao hon moi doi chung. An toan trong 30 ngay nghia
             la lo hong duoc va truoc khi bi khai thac, hoac cham nhat 30 ngay sau khi bi khai thac.
  RQ3        So mu chon tren du lieu cu co gan 0.3 khong, va co tot hon 0.3 tren nam kiem thu khong.
  RQ4        Thu tu giua cac phuong phap co giu nguyen qua tung nam khong.

Chay: python3 05_kiem_chung.py   (can tai du lieu: python3 01_thu_thap.py 2023 2024 2025)
"""
import os, io, re, json, gzip
from datetime import date, timedelta
import numpy as np, pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
OUT = os.path.join(HERE, "..", "output")
YEARS, TEST, FOLLOW = [2023, 2024, 2025], [2024, 2025], 180
ALPHA0, GRID = 0.3, [0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
FRACS = [0.01, 0.05, 0.10, 0.25]
SEED, NBOOT = 42, 1000
CSA_T, VMC_E, VMC_C = 8.0, 0.088, 7.0
BUDGETS = [0.10, 0.25, 0.50]          # ngan sach va ca nam, ty le so lo hong cong bo trong nam
rng = np.random.default_rng(SEED)
R, lines = {}, []
def log(s=""):
    print(s, flush=True); lines.append(str(s))

def month_end(y, m):
    return date(y + (m == 12), m % 12 + 1, 1) - timedelta(days=1)

_cache = {}
def load_epss(D):
    for b in range(5):
        p = os.path.join(DATA, f"epss_{(D - timedelta(days=b)).isoformat()}.csv.gz")
        if os.path.exists(p):
            if p not in _cache:
                raw = gzip.decompress(open(p, "rb").read()).decode()
                v = re.search(r"model_version:([^,\s]+)", raw[:200])
                e = pd.read_csv(io.StringIO(raw), comment="#")
                _cache[p] = (dict(zip(e["cve"].str.upper(), e["epss"].astype(float))),
                             v.group(1) if v else "khong ro")
            return _cache[p]
    raise FileNotFoundError(f"thieu EPSS ngay {D}")

def exp_hits(sc, y, K):
    """So ca bi khai thac ky vong trong K lo hong diem cao nhat, cac lo hong trung diem
       duoc xep ngau nhien (tinh chinh xac, khong can lap)."""
    K = int(K)
    if K <= 0: return 0.0
    if K >= len(sc): return float(y.sum())
    t = np.partition(sc, len(sc) - K)[len(sc) - K]
    above, at = sc > t, sc == t
    return float(y[above].sum() + (K - above.sum()) * y[at].sum() / at.sum())

def ndcg(sc, y, K, reps=20):
    g = np.random.default_rng(SEED); P = int(y.sum())
    disc = 1 / np.log2(np.arange(2, K + 2)); idcg = disc[:min(P, K)].sum(); out = []
    for _ in range(reps):
        o = np.lexsort((g.random(len(sc)), -sc)); out.append((y[o][:K] * disc).sum() / idcg)
    return float(np.mean(out))

# ======================================================================= du lieu
recs = []
for y in YEARS:
    recs += [json.loads(l) for l in open(os.path.join(DATA, f"nvd_{y}.jsonl"), encoding="utf-8")]
nvd = pd.DataFrame(recs)
nvd = nvd[nvd["status"] != "Rejected"].copy()
nvd["published"] = pd.to_datetime(nvd["published"]); nvd["year"] = nvd["published"].dt.year
nvd = nvd[nvd["year"].isin(YEARS)]
nvd["cvss"] = nvd["cvss3_nvd"].fillna(nvd["cvss3_cna"])
nvd = nvd.dropna(subset=["cvss"]).copy(); nvd["id"] = nvd["id"].str.upper()
kev = pd.DataFrame(json.load(open(os.path.join(DATA, "kev.json"))))
kd = dict(zip(kev["cve_id"].str.upper(), pd.to_datetime(kev["date_added"])))
nvd["kev_date"] = nvd["id"].map(kd)

parts, versions = [], {}
for y in YEARS:
    for m in range(1, 13):
        D = month_end(y, m); Dt = pd.Timestamp(D); emap, ver = load_epss(D)
        versions[D.isoformat()] = ver
        c = nvd[(nvd["year"] == y) & (nvd["published"].dt.month == m)].copy()
        c["epss"] = c["id"].map(emap).fillna(0.0)
        c["loai"] = c["kev_date"].notna() & (c["kev_date"] <= Dt)
        c["y"] = (c["kev_date"].notna() & (c["kev_date"] > Dt) &
                  (c["kev_date"] <= Dt + pd.Timedelta(days=FOLLOW))).astype(int)
        parts.append(c)
dd = pd.concat(parts)
d = dd[~dd["loai"]].copy()
log("=" * 78); log("DU LIEU"); log("=" * 78)
log(f"{'Nam':<6}{'Lo hong':>10}{'Loai vi da vao KEV':>21}{'Phan tich':>12}{'Bi khai thac sau':>18}")
R["du_lieu"] = {}
for y in YEARS:
    a, b = dd[dd["year"] == y], d[d["year"] == y]
    R["du_lieu"][y] = dict(tong=len(a), loai=int(a["loai"].sum()), N=len(b), P=int(b["y"].sum()))
    log(f"{y:<6}{len(a):>10,}{int(a['loai'].sum()):>21,}{len(b):>12,}{int(b['y'].sum()):>18}")
vs = sorted(set(versions.values())); log(f"\nPhien ban mo hinh EPSS xuat hien: {', '.join(vs)}")
R["epss_versions"] = versions

def yearset(y):
    s = d[d["year"] == y]; return s["cvss"].values, s["epss"].values, s["y"].values

# ======================================================================= RQ3: chon so mu
log("\n" + "=" * 78); log("RQ3. CHON SO MU TREN DU LIEU CU (walk-forward)"); log("=" * 78)
def crit(alpha, years):
    hits = P = 0
    for y in years:
        c, e, t = yearset(y)
        for f in FRACS: hits += exp_hits(c * e ** alpha, t, f * len(c))
        P += t.sum() * len(FRACS)
    return hits / P
chosen = {}
for ty in TEST:
    train = [y for y in YEARS if y < ty]
    scores = {a: crit(a, train) for a in GRID}
    best = max(scores, key=scores.get); chosen[ty] = best
    log(f"Kiem thu {ty}, chon tren {train}: " +
        ", ".join(f"{a}:{100*v:.1f}%" for a, v in scores.items()) + f"  ket qua: chon so mu {best}")
R["so_mu_chon"] = chosen

# ======================================================================= RQ1 / H1
log("\n" + "=" * 78); log("RQ1. KHA NANG DU BAO TREN NAM KIEM THU"); log("=" * 78)
def methods(y):
    c, e, t = yearset(y)
    return t, {"CVSS": c, "EPSS": e, "Cong thuc so mu 0.3": c * e ** ALPHA0,
               f"Cong thuc so mu chon ({chosen.get(y, ALPHA0)})": c * e ** chosen.get(y, ALPHA0)}
R["rq1"] = {}
for y in YEARS:
    t, M = methods(y); c, e, _ = yearset(y); N, P = len(t), int(t.sum())
    W_csa = int((c >= CSA_T).sum()); vmc = (e >= VMC_E) & (c >= VMC_C); W_vmc = int(vmc.sum())
    tag = "kiem thu" if y in TEST else "chi mo ta"
    log(f"\nNam {y} ({tag}): {N:,} lo hong, {P} bi khai thac sau ngay quyet dinh")
    log(f"  {'Phuong phap':<30}" + "".join(f"{'top '+str(int(f*100))+'%':>9}" for f in FRACS)
        + f"{'vua='+format(W_csa,','):>13}{'vua='+format(W_vmc,','):>11}{'NDCG@1%':>9}")
    rows = {}
    for name, sc in M.items():
        if y not in TEST and "chon" in name: continue
        r = {f: exp_hits(sc, t, f * N) for f in FRACS}
        r["W_csa"] = exp_hits(sc, t, W_csa); r["W_vmc"] = exp_hits(sc, t, W_vmc)
        r["ndcg1"] = ndcg(sc, t, int(0.01 * N)); rows[name] = r
        log(f"  {name:<30}" + "".join(f"{100*r[f]/P:>8.1f}%" for f in FRACS)
            + f"{r['W_csa']:>9.1f}/{P}{r['W_vmc']:>7.1f}/{P}{r['ndcg1']:>9.3f}")
    rows["Quy tac CSA"] = dict(W=W_csa, hits=int(t[c >= CSA_T].sum()))
    rows["Cay quyet dinh Shimizu (High)"] = dict(W=W_vmc, hits=int(t[vmc].sum()))
    log(f"  Quy tac CSA (CVSS tu 8.0): va {W_csa:,}, bat {rows['Quy tac CSA']['hits']}/{P}")
    log(f"  Cay Shimizu, nhanh High (EPSS tu 0.088 va CVSS tu 7.0): va {W_vmc:,}, "
        f"bat {rows['Cay quyet dinh Shimizu (High)']['hits']}/{P}")
    R["rq1"][y] = dict(N=N, P=P, W_csa=W_csa, W_vmc=W_vmc, ket_qua=rows)

log("\nH1: cong thuc so mu 0.3 so voi CVSS khi va bang quy tac CSA, gop 2024 va 2025")
def boot(compare_col):
    obs = 0.0; boots = np.zeros(NBOOT)
    data = {y: yearset(y) for y in TEST}
    for y, (c, e, t) in data.items():
        W = int((c >= CSA_T).sum()); ref = c if compare_col == "CVSS" else e
        obs += exp_hits(c * e ** ALPHA0, t, W) - exp_hits(ref, t, W)
    for b in range(NBOOT):
        tot = 0.0
        for y, (c, e, t) in data.items():
            i = rng.integers(0, len(c), len(c)); cc, ee, tt = c[i], e[i], t[i]
            W = int((cc >= CSA_T).sum()); ref = cc if compare_col == "CVSS" else ee
            tot += exp_hits(cc * ee ** ALPHA0, tt, W) - exp_hits(ref, tt, W)
        boots[b] = tot
    lo, hi = np.percentile(boots, [2.5, 97.5]); return obs, lo, hi
R["h1"] = {}
for ref in ["CVSS", "EPSS"]:
    obs, lo, hi = boot(ref)
    ok = lo > 0
    R["h1"][ref] = dict(chenh_lech=obs, ci=[lo, hi], dat=bool(ok))
    log(f"  so voi {ref:<5}: chenh lech {obs:+.1f} ca, khoang tin cay 95% [{lo:+.1f}, {hi:+.1f}]  "
        f"ket qua: {'DAT' if ok else 'CHUA DAT'}")

# ======================================================================= RQ2 / H2: mo phong van hanh
log("\n" + "=" * 78); log("RQ2. MO PHONG VAN HANH HANG THANG, CUNG NGAN SACH VA"); log("=" * 78)
SIM = ["CVSS", "EPSS", "Cong thuc bo KEV", "Cong thuc day du", "Cay Shimizu"]
def simulate(Y, method, frac, alpha=ALPHA0):
    pop = nvd[nvd["year"] == Y][["id", "published", "cvss", "kev_date"]].copy()
    points = [month_end(Y, m) for m in range(1, 13)] + [month_end(Y + 1, 1)]
    B = int(round(frac * len(pop) / len(points)))
    patched = pd.Series(pd.NaT, index=pop.index, dtype="datetime64[ns]")
    g = np.random.default_rng(SEED)
    for D in points:
        Dt = pd.Timestamp(D); emap, _ = load_epss(D)
        op = pop[(pop["published"] <= Dt) & patched.isna()]
        if op.empty: continue
        c = op["cvss"].values; e = op["id"].map(emap).fillna(0.0).values
        k = (op["kev_date"].notna() & (op["kev_date"] <= Dt)).values.astype(int)
        if method == "CVSS": s = c
        elif method == "EPSS": s = e
        elif method == "Cong thuc bo KEV": s = c * e ** alpha
        elif method == "Cong thuc day du": s = c * (k + (1 - k) * e ** alpha)
        else:
            tier = np.where(k == 1, np.where(c >= VMC_C, 3, 1),
                            np.where(e >= VMC_E, np.where(c >= VMC_C, 2, 1), 0))
            s = tier * 100 + c
        o = np.lexsort((g.random(len(s)), -s))[:B]
        patched.loc[op.index[o]] = Dt
    end = pd.Timestamp(points[-1])
    ex = pop[pop["kev_date"].notna() & (pop["kev_date"] <= end)]
    pt = patched.loc[ex.index]
    truoc = pt.notna() & (pt < ex["kev_date"])
    tre = (pt - ex["kev_date"]).dt.days
    an_toan_30 = truoc | (pt.notna() & (tre <= 30))
    sau = ex[~truoc]
    return dict(B=B, so_bi_khai_thac=len(ex), va_truoc=float(truoc.mean()),
                an_toan_30=float(an_toan_30.mean()),
                tre_trung_vi=float(tre[~truoc & pt.notna()].median()) if (~truoc & pt.notna()).any() else None,
                chua_va=float(pt.isna().mean()))
R["rq2"] = {}
for Y in TEST:
    R["rq2"][Y] = {}
    for frac in BUDGETS:
        R["rq2"][Y][frac] = {}
        log(f"\nNam {Y}, ngan sach va {int(frac*100)}% so lo hong trong nam:")
        log(f"  {'Cach chon':<20}{'Va truoc khi bi khai thac':>27}{'An toan trong 30 ngay':>24}"
            f"{'Tre trung vi':>14}{'Chua va':>10}")
        for mth in SIM:
            s = simulate(Y, mth, frac); R["rq2"][Y][frac][mth] = s
            log(f"  {mth:<20}{100*s['va_truoc']:>26.1f}%{100*s['an_toan_30']:>23.1f}%"
                f"{(str(int(s['tre_trung_vi']))+' ngay') if s['tre_trung_vi'] is not None else '-':>14}"
                f"{100*s['chua_va']:>9.1f}%")
        log(f"  (moi thang va {s['B']:,} lo hong; {s['so_bi_khai_thac']} lo hong bi khai thac trong ky)")
ok2 = all(R["rq2"][Y][0.25]["Cong thuc day du"]["an_toan_30"] >=
          max(R["rq2"][Y][0.25][m]["an_toan_30"] for m in SIM) for Y in TEST)
R["h2_dat"] = bool(ok2)
log(f"\nH2 (ngan sach 25%, ca hai nam kiem thu): {'DAT' if ok2 else 'CHUA DAT'}")

# ======================================================================= RQ4
log("\n" + "=" * 78); log("RQ4. DO ON DINH QUA CAC NAM (bat duoc khi va bang quy tac CSA)"); log("=" * 78)
for y in YEARS:
    r = R["rq1"][y]["ket_qua"]; P = R["rq1"][y]["P"]
    log(f"  {y}: CVSS {r['CVSS']['W_csa']:.1f}/{P}, EPSS {r['EPSS']['W_csa']:.1f}/{P}, "
        f"cong thuc 0.3 {r['Cong thuc so mu 0.3']['W_csa']:.1f}/{P}")

json.dump(R, open(os.path.join(OUT, "kiem_chung.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2, default=lambda o: float(o) if isinstance(o, (np.floating, np.integer)) else str(o))
open(os.path.join(OUT, "kiem_chung.txt"), "w", encoding="utf-8").write("\n".join(lines))
log("\nDa luu: output/kiem_chung.txt, output/kiem_chung.json")
