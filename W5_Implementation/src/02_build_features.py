# -*- coding: utf-8 -*-
"""
02_build_features.py
Tinh bon thanh phan cua chi so AEG-EI cho tung lo hong, gan nhan ground truth,
va xuat ra bang dac trung dung cho buoc phan tich.

AEG-EI = 100 * (0.35*Cn + 0.25*K + 0.25*P + 0.15*E)

LUU Y VE PHUONG PHAP:
Ban thiet ke o tuan 3 quy dinh ba tieu chi C2, C3, C4 duoc cham tay theo rubric.
Trong ban trien khai nay, ca nam tieu chi deu duoc cham tu dong bang luat tu khoa
va bieu thuc chinh quy, nham xu ly duoc toan bo tap du lieu hang tram nghin ban ghi.
Day la mot sai lech so voi thiet ke goc va duoc ghi nhan la mot gioi han.
"""
import json, os, re, csv, math
import pandas as pd
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
OUT = os.path.join(HERE, "..", "output")
os.makedirs(OUT, exist_ok=True)

# ---------------------------------------------------------------- thanh phan K
CWE_TIER = {}
for c in ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-918", "CWE-502", "CWE-94",
          "CWE-77", "CWE-91", "CWE-917", "CWE-74", "CWE-1336"]:
    CWE_TIER[c] = ("cao", 1.00)
for c in ["CWE-287", "CWE-862", "CWE-863", "CWE-434", "CWE-352", "CWE-306",
          "CWE-284", "CWE-269", "CWE-639", "CWE-798", "CWE-522", "CWE-640"]:
    CWE_TIER[c] = ("trung binh", 0.60)
for c in ["CWE-787", "CWE-125", "CWE-416", "CWE-120", "CWE-190", "CWE-122",
          "CWE-121", "CWE-476", "CWE-824", "CWE-191", "CWE-415", "CWE-680"]:
    CWE_TIER[c] = ("thap", 0.35)
for c in ["CWE-362", "CWE-367", "CWE-327", "CWE-330", "CWE-338", "CWE-326",
          "CWE-310", "CWE-335", "CWE-364", "CWE-366"]:
    CWE_TIER[c] = ("rat thap", 0.20)
K_DEFAULT = ("khong xac dinh", 0.45)   # cac CWE khac: gia tri trung gian

# ------------------------------------------------- bieu thuc cho thanh phan C
RE_FUNC = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\s*\(\s*\)")
RE_PATH = re.compile(r"[\w\-/\\]+\.(?:php|c|h|cpp|js|jsp|py|rb|aspx|asp|cgi|go|java|ts|sh|dll|so)\b", re.I)
RE_PARAM = re.compile(r"\b(?:parameter|param|argument|field|header|variable)\s+['\"`]?([A-Za-z_][\w\-]{1,})", re.I)
RE_ENDPOINT = re.compile(r"(?:/[\w\-.]+){2,}")
RE_MODULE = re.compile(r"\b(?:component|module|plugin|extension|library|package|function|endpoint|api)\b", re.I)

PRECOND = [r"\bauthenticated\b", r"\bunauthenticated\b", r"\brequires?\b", r"\bprivileg", r"\badmin",
           r"\bwhen\s+(?:the\s+)?\w+\s+is\s+(?:enabled|configured|set)", r"\bif\s+(?:the\s+)?\w+\s+is\s+enabled",
           r"\bprior to version\b", r"\bbefore version\b", r"\bin versions?\b", r"\bonly if\b",
           r"\bwith\s+(?:the\s+)?permission", r"\bmust\s+be\b", r"\bdefault configuration\b"]
MECHANISM = [r"does not (?:properly|correctly|adequately|sufficiently)", r"fails? to (?:properly|validate|check|sanitize|verify)",
             r"\bimproper(?:ly)?\b", r"\black of\b", r"\bmissing\b", r"\binsufficient", r"\bunsanitiz", r"\bunvalidated\b",
             r"buffer overflow", r"race condition", r"use[- ]after[- ]free", r"out[- ]of[- ]bounds",
             r"null pointer", r"integer (?:overflow|underflow)", r"injection", r"type confusion",
             r"double free", r"path traversal", r"deserializ", r"\boff[- ]by[- ]one\b", r"\buninitializ"]
RE_PRECOND = [re.compile(p, re.I) for p in PRECOND]
RE_MECH = [re.compile(p, re.I) for p in MECHANISM]
RE_COMMIT = re.compile(r"(commit|/commits?/|\.diff|\.patch|/pull/|changeset|/compare/)", re.I)
RE_CODEREPO = re.compile(r"(github\.com|gitlab\.com|bitbucket\.org|packetstorm|seclists|exploit-db|huntr\.dev)", re.I)


def score_C1(desc):
    n = len(desc.split())
    return 0 if n < 30 else (1 if n <= 80 else 2), n


def score_C2(desc):
    if RE_FUNC.search(desc) or RE_PARAM.search(desc) or RE_PATH.search(desc) or RE_ENDPOINT.search(desc):
        return 2
    if RE_MODULE.search(desc):
        return 1
    return 0


def score_C3(desc):
    k = sum(1 for r in RE_PRECOND if r.search(desc))
    return 0 if k == 0 else (1 if k == 1 else 2)


def score_C4(desc):
    k = sum(1 for r in RE_MECH if r.search(desc))
    return 0 if k == 0 else (1 if k == 1 else 2)


def score_C5(refs):
    has_patch_tag = any("Patch" in (r.get("tags") or []) for r in refs)
    has_commit = any(RE_COMMIT.search(r.get("url", "")) for r in refs)
    if has_commit and has_patch_tag:
        return 2
    if has_commit or has_patch_tag:
        return 1
    return 0


def score_K(cwes):
    best = None
    for c in cwes:
        t = CWE_TIER.get(c)
        if t and (best is None or t[1] > best[1]):
            best = t
    return best if best else K_DEFAULT


def score_P(refs, in_exploitdb):
    has_exploit_tag = any("Exploit" in (r.get("tags") or []) for r in refs)
    if in_exploitdb:
        return 1.0
    if has_exploit_tag and any(RE_CODEREPO.search(r.get("url", "")) for r in refs):
        return 1.0
    if has_exploit_tag:
        return 0.5
    return 0.0


AV = {"N": 1.0, "A": 0.6, "L": 0.3, "P": 0.0}
AC = {"L": 1.0, "H": 0.4}
PR = {"N": 1.0, "L": 0.5, "H": 0.2}
UI = {"N": 1.0, "R": 0.4}


def score_E(vector):
    if not vector:
        return None
    d = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            d[k] = v
    try:
        return (AV[d["AV"]] + AC[d["AC"]] + PR[d["PR"]] + UI[d["UI"]]) / 4.0
    except KeyError:
        return None


def main():
    kev = pd.read_csv(os.path.join(DATA, "kev.csv"))
    kev_set = set(kev["cve_id"].astype(str).str.upper())
    kev_date = dict(zip(kev["cve_id"].astype(str).str.upper(), kev["date_added"].astype(str)))

    edb = pd.read_csv(os.path.join(DATA, "exploitdb_cves.csv"))
    edb_set = set(edb["cve_id"].astype(str).str.upper())

    epss = pd.read_csv(os.path.join(DATA, "epss.csv"))
    epss_map = dict(zip(epss["cve_id"].astype(str).str.upper(), epss["epss"].astype(float)))

    rows = []
    excluded = {"trang thai khong hop le": 0, "thieu vector CVSS": 0, "thieu CWE xac dinh": 0, "thieu mo ta": 0}
    total_read = 0

    with open(os.path.join(DATA, "nvd_raw.jsonl"), encoding="utf-8") as f:
        for line in f:
            total_read += 1
            try:
                r = json.loads(line)
            except Exception:
                continue
            cid = (r.get("id") or "").upper()
            status = (r.get("status") or "")
            desc = r.get("desc") or ""
            cwes = r.get("cwes") or []
            vec = r.get("cvss_vector")
            score = r.get("cvss_score")

            # --- tieu chi loai tru (muc 3.2 cua bao cao tuan 3)
            if status in ("Rejected", "Awaiting Analysis", "Received", "Deferred"):
                excluded["trang thai khong hop le"] += 1; continue
            if not vec or score is None:
                excluded["thieu vector CVSS"] += 1; continue
            if not desc or desc.lower().startswith("rejected"):
                excluded["thieu mo ta"] += 1; continue
            real_cwes = [c for c in cwes if re.match(r"^CWE-\d+$", c)]
            if not real_cwes:
                excluded["thieu CWE xac dinh"] += 1; continue

            c1, nwords = score_C1(desc)
            c2 = score_C2(desc); c3 = score_C3(desc); c4 = score_C4(desc)
            c5 = score_C5(r.get("refs") or [])
            c_raw = c1 + c2 + c3 + c4 + c5
            k_tier, k_val = score_K(real_cwes)
            p_val = score_P(r.get("refs") or [], cid in edb_set)
            e_val = score_E(vec)
            if e_val is None:
                excluded["thieu vector CVSS"] += 1; continue

            cn = c_raw / 10.0
            aeg = 100.0 * (0.35 * cn + 0.25 * k_val + 0.25 * p_val + 0.15 * e_val)

            rows.append({
                "cve_id": cid,
                "published": (r.get("published") or "")[:10],
                "year": int((r.get("published") or "0000")[:4]) if (r.get("published") or "")[:4].isdigit() else None,
                "desc_words": nwords,
                "C1": c1, "C2": c2, "C3": c3, "C4": c4, "C5": c5, "C_raw": c_raw, "Cn": cn,
                "cwe": real_cwes[0], "K_tier": k_tier, "K": k_val,
                "P": p_val, "E": e_val,
                "cvss": float(score), "cvss_vector": vec,
                "epss": epss_map.get(cid, np.nan),
                "aeg_ei": aeg,
                "kev": 1 if cid in kev_set else 0,
                "kev_date": kev_date.get(cid, ""),
            })

    df = pd.DataFrame(rows)
    df = df[df["year"].between(2023, 2025)]
    df.to_csv(os.path.join(OUT, "features.csv"), index=False)

    print("=" * 62)
    print("THONG KE XAY DUNG DAC TRUNG")
    print("=" * 62)
    print(f"Ban ghi doc tu NVD          : {total_read:,}")
    for k, v in excluded.items():
        print(f"  loai do {k:<24}: {v:,}")
    print(f"Ban ghi dua vao phan tich   : {len(df):,}")
    print(f"  trong do thuoc KEV        : {int(df['kev'].sum()):,} "
          f"({100*df['kev'].mean():.2f}%)")
    print(f"  co diem EPSS              : {int(df['epss'].notna().sum()):,}")
    print("\nPhan bo theo nam:")
    print(df.groupby("year")["kev"].agg(["size", "sum"]).rename(
        columns={"size": "so_luong", "sum": "thuoc_KEV"}).to_string())
    print("\nPhan bo tier CWE:")
    print(df["K_tier"].value_counts().to_string())
    print(f"\nDa luu: output/features.csv")


if __name__ == "__main__":
    main()
