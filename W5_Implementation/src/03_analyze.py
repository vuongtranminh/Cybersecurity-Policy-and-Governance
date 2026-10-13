# -*- coding: utf-8 -*-
"""
03_analyze.py
Tra loi ba cau hoi nghien cuu da dat ra o bao cao tuan 3.

CH1: Dac trung van ban co gia tri du bao tang them so voi cac tin hieu da biet khong?
CH2: Xep uu tien theo AEG-EI co chinh xac hon quy tac nguong CVSS khong, hon bao nhieu?
CH3: Trong nhom CVSS duoi 8.0, bao nhieu phan tram da bi khai thac, AEG-EI co nhan dien duoc khong?

Chia du lieu theo thoi gian: huan luyen 2023-2024, kiem thu 2025.
"""
import os, json
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "output")
K_CAPACITY = 50          # nang luc xu ly gia dinh: 50 lo hong moi thang
RANDOM_STATE = 42

res = {}
lines = []
def log(s=""):
    print(s, flush=True); lines.append(str(s))


def precision_at_k(df, score_col, k, ascending=False):
    d = df.sort_values(score_col, ascending=ascending).head(k)
    return d["kev"].mean(), int(d["kev"].sum())


def main():
    df = pd.read_csv(os.path.join(OUT, "features.csv"))
    df = df.dropna(subset=["cvss", "aeg_ei"])
    df["epss"] = df["epss"].fillna(0.0)

    train = df[df["year"].isin([2023, 2024])].copy()
    test = df[df["year"] == 2025].copy()

    log("=" * 70)
    log("KET QUA PHAN TICH")
    log("=" * 70)
    log(f"Tap huan luyen (2023-2024): {len(train):,} lo hong, "
        f"{int(train['kev'].sum()):,} thuoc KEV ({100*train['kev'].mean():.2f}%)")
    log(f"Tap kiem thu  (2025)      : {len(test):,} lo hong, "
        f"{int(test['kev'].sum()):,} thuoc KEV ({100*test['kev'].mean():.2f}%)")
    res["n_train"] = len(train); res["n_test"] = len(test)
    res["kev_train"] = int(train["kev"].sum()); res["kev_test"] = int(test["kev"].sum())

    # ================================================================= CH1
    log("\n" + "-" * 70)
    log("CH1. Dac trung van ban co gia tri du bao tang them khong?")
    log("-" * 70)

    base_cols = ["cvss", "E"]                       # mo hinh nen
    ext_cols = ["cvss", "E", "C1", "C2", "C3", "C4", "C5", "K", "P"]   # mo hinh mo rong
    txt_only = ["C1", "C2", "C3", "C4", "C5"]

    def fit_eval(cols, name):
        sc = StandardScaler().fit(train[cols])
        m = LogisticRegression(max_iter=2000, class_weight="balanced",
                               random_state=RANDOM_STATE)
        m.fit(sc.transform(train[cols]), train["kev"])
        p = m.predict_proba(sc.transform(test[cols]))[:, 1]
        auc = roc_auc_score(test["kev"], p)
        ap = average_precision_score(test["kev"], p)
        log(f"  {name:<34} ROC-AUC={auc:.4f}  PR-AUC={ap:.4f}")
        return m, sc, p, auc, ap

    m_base, s_base, p_base, auc_base, ap_base = fit_eval(base_cols, "Mo hinh nen (CVSS + E)")
    m_ext, s_ext, p_ext, auc_ext, ap_ext = fit_eval(ext_cols, "Mo hinh mo rong (them C, K, P)")
    _, _, _, auc_txt, ap_txt = fit_eval(txt_only, "Chi rieng dac trung van ban C")

    log(f"\n  Muc tang ROC-AUC khi them dac trung: {auc_ext-auc_base:+.4f}")
    log(f"  Muc tang PR-AUC  khi them dac trung: {ap_ext-ap_base:+.4f}")
    res.update(auc_base=auc_base, auc_ext=auc_ext, ap_base=ap_base, ap_ext=ap_ext,
               auc_txt=auc_txt, ap_txt=ap_txt)

    log("\n  He so hoi quy cua mo hinh mo rong (da chuan hoa):")
    coefs = sorted(zip(ext_cols, m_ext.coef_[0]), key=lambda x: -abs(x[1]))
    for c, v in coefs:
        log(f"    {c:<6} {v:+.4f}")
    res["coefs"] = {c: float(v) for c, v in coefs}

    # bo trong so da hieu chinh cho bon thanh phan
    comp_cols = ["Cn", "K", "P", "E"]
    sc_c = StandardScaler().fit(train[comp_cols])
    m_c = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE)
    m_c.fit(sc_c.transform(train[comp_cols]), train["kev"])
    w = np.abs(m_c.coef_[0]); w = w / w.sum()
    log("\n  Bo trong so hieu chinh tu du lieu (so voi bo suy luan o tuan 2):")
    for c, wv, w0 in zip(comp_cols, w, [0.35, 0.25, 0.25, 0.15]):
        log(f"    {c:<4} hieu chinh={wv:.3f}   suy luan={w0:.2f}")
    res["weights_fitted"] = {c: float(x) for c, x in zip(comp_cols, w)}
    test["aeg_fitted"] = 100.0 * (test[comp_cols].values * w).sum(axis=1)

    # ================================================================= CH2
    log("\n" + "-" * 70)
    log("CH2. Xep uu tien theo AEG-EI co chinh xac hon nguong CVSS khong?")
    log("-" * 70)
    log(f"  Gia dinh nang luc xu ly: {K_CAPACITY} lo hong")

    rules = {
        "Quy tac nguong CVSS (bai bao goc)": "cvss",
        "Diem EPSS (doi chung)": "epss",
        "AEG-EI trong so suy luan": "aeg_ei",
        "AEG-EI trong so hieu chinh": "aeg_fitted",
    }
    tab = []
    for name, col in rules.items():
        pk, hit = precision_at_k(test, col, K_CAPACITY)
        tab.append({"quy_tac": name, "precision_at_k": pk, "so_bat_trung": hit,
                    "roc_auc": roc_auc_score(test["kev"], test[col]),
                    "pr_auc": average_precision_score(test["kev"], test[col])})
        log(f"  {name:<36} P@{K_CAPACITY}={pk:.3f} ({hit}/{K_CAPACITY})  "
            f"ROC-AUC={tab[-1]['roc_auc']:.4f}")
    dftab = pd.DataFrame(tab)
    dftab.to_csv(os.path.join(OUT, "ch2_so_sanh_quy_tac.csv"), index=False)

    base_p = dftab.loc[0, "precision_at_k"]
    best = dftab.iloc[2:]["precision_at_k"].max()
    delta = (best - base_p) * 100
    log(f"\n  Chenh lech so voi quy tac nguong CVSS: {delta:+.1f} diem phan tram")
    log(f"  Nguong da dat ra o tuan 3 la 10 diem phan tram -> "
        f"{'DAT' if delta >= 10 else 'CHUA DAT'}")
    res["p_at_k"] = {r["quy_tac"]: r["precision_at_k"] for r in tab}
    res["delta_pp"] = float(delta)
    res["k_capacity"] = K_CAPACITY

    log("\n  Kiem tra o nhieu muc nang luc khac nhau:")
    ks = []
    for k in [20, 50, 100, 200, 500]:
        a, _ = precision_at_k(test, "cvss", k)
        b, _ = precision_at_k(test, "aeg_ei", k)
        c, _ = precision_at_k(test, "aeg_fitted", k)
        d, _ = precision_at_k(test, "epss", k)
        ks.append({"k": k, "cvss": a, "epss": d, "aeg_suy_luan": b, "aeg_hieu_chinh": c})
        log(f"    k={k:<4} CVSS={a:.3f}  EPSS={d:.3f}  AEG(suy luan)={b:.3f}  AEG(hieu chinh)={c:.3f}")
    pd.DataFrame(ks).to_csv(os.path.join(OUT, "ch2_theo_nang_luc.csv"), index=False)
    res["p_at_k_sweep"] = ks

    # ================================================================= CH3
    log("\n" + "-" * 70)
    log("CH3. Nhom CVSS duoi 8.0 bi chinh sach hien hanh bo qua")
    log("-" * 70)
    low = test[test["cvss"] < 8.0]
    high = test[test["cvss"] >= 8.0]
    log(f"  Lo hong CVSS tu 8.0 tro len : {len(high):,}, thuoc KEV: {int(high['kev'].sum())}")
    log(f"  Lo hong CVSS duoi 8.0       : {len(low):,}, thuoc KEV: {int(low['kev'].sum())}")
    tot_kev = int(test["kev"].sum())
    miss = int(low["kev"].sum())
    share = 100.0 * miss / tot_kev if tot_kev else 0.0
    log(f"\n  => {miss}/{tot_kev} lo hong da bi khai thac nam NGOAI dien uu tien "
        f"cua bai bao goc, chiem {share:.1f}%")
    res["blind_spot_count"] = miss; res["blind_spot_total"] = tot_kev
    res["blind_spot_share"] = share

    if len(low) and miss:
        a = low[low["kev"] == 1]["aeg_ei"]; b = low[low["kev"] == 0]["aeg_ei"]
        log(f"\n  Trong dai CVSS duoi 8.0:")
        log(f"    AEG-EI trung binh cua nhom DA bi khai thac   : {a.mean():.2f}")
        log(f"    AEG-EI trung binh cua nhom CHUA bi khai thac : {b.mean():.2f}")
        log(f"    Chenh lech: {a.mean()-b.mean():+.2f} diem")
        pooled = np.sqrt((a.var(ddof=1) + b.var(ddof=1)) / 2) if len(a) > 1 else np.nan
        d = (a.mean() - b.mean()) / pooled if pooled and pooled > 0 else np.nan
        log(f"    He so anh huong Cohen d: {d:.3f}")
        res["blind_low_kev_mean"] = float(a.mean()); res["blind_low_nonkev_mean"] = float(b.mean())
        res["cohen_d"] = float(d) if d == d else None
        auc_low = roc_auc_score(low["kev"], low["aeg_ei"])
        auc_low_cvss = roc_auc_score(low["kev"], low["cvss"])
        log(f"    ROC-AUC cua AEG-EI trong dai nay: {auc_low:.4f} "
            f"(cua CVSS: {auc_low_cvss:.4f})")
        res["auc_low_band_aeg"] = auc_low; res["auc_low_band_cvss"] = auc_low_cvss

    # ================================================================= ablation
    log("\n" + "-" * 70)
    log("Phan tich dong gop cua tung thanh phan")
    log("-" * 70)
    full = {"Cn": 0.35, "K": 0.25, "P": 0.25, "E": 0.15}
    base_auc = roc_auc_score(test["kev"], test["aeg_ei"])
    log(f"  Chi so day du: ROC-AUC={base_auc:.4f}")
    abl = []
    for drop in full:
        rest = {k: v for k, v in full.items() if k != drop}
        tot = sum(rest.values())
        s = sum(test[k] * (v / tot) for k, v in rest.items()) * 100
        a = roc_auc_score(test["kev"], s)
        abl.append({"bo_thanh_phan": drop, "roc_auc": a, "thay_doi": a - base_auc})
        log(f"  Bo {drop:<3}: ROC-AUC={a:.4f}  ({a-base_auc:+.4f})")
    pd.DataFrame(abl).to_csv(os.path.join(OUT, "ablation.csv"), index=False)
    res["ablation"] = abl

    # ---- tung thanh phan rieng le
    log("\n  Nang luc phan biet cua tung thanh phan rieng le:")
    single = []
    for c in ["Cn", "K", "P", "E", "cvss", "epss"]:
        a = roc_auc_score(test["kev"], test[c])
        single.append({"thanh_phan": c, "roc_auc": a})
        log(f"    {c:<6} ROC-AUC={a:.4f}")
    pd.DataFrame(single).to_csv(os.path.join(OUT, "thanh_phan_rieng_le.csv"), index=False)
    res["single"] = single

    # ---- C5 rieng: gia thuyet ve patch diff
    log("\n  Kiem tra rieng gia thuyet ve muc cong khai cua ban va (C5):")
    for v in [0, 1, 2]:
        sub = test[test["C5"] == v]
        if len(sub):
            log(f"    C5={v}: {len(sub):,} lo hong, ty le thuoc KEV = {100*sub['kev'].mean():.3f}%")

    with open(os.path.join(OUT, "ket_qua.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2, default=float)
    with open(os.path.join(OUT, "ket_qua.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log("\nDa luu: output/ket_qua.json, output/ket_qua.txt va cac bang .csv")


if __name__ == "__main__":
    main()
