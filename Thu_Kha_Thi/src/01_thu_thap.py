# -*- coding: utf-8 -*-
"""
01_thu_thap.py - Thu thap du lieu (Viec 1 cua de tai)

Nguon (deu cong khai, mien phi):
  1. NVD (NIST)  : danh sach lo hong cong bo nam 2025 va diem CVSS
  2. CISA KEV    : danh sach lo hong DA BI KHAI THAC thuc te, kem ngay ghi nhan
  3. EPSS (FIRST): diem EPSS LICH SU vao cuoi moi thang nam 2025,
                   va diem EPSS hien tai (chi dung de minh hoa sai lech)

Chay:  python3 01_thu_thap.py
Thoi gian: khoang 5 den 10 phut, phan lon la do gioi han tan suat cua NVD.
Co the chay lai: du lieu da tai se duoc giu, chi tai phan con thieu.
"""
import os, sys, json, time, threading, urllib.request
from datetime import datetime, date, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
os.makedirs(DATA, exist_ok=True)
UA = "Nhom14-AcademicResearch/1.0 (course project; metadata only)"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_DAY = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"
EPSS_NOW = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

YEAR = 2025
WINDOW_DAYS = 115     # NVD cho phep toi da 120 ngay moi lan goi
PAGE = 2000           # toi da 2000 ban ghi moi trang
WORKERS = 5


class RateLimiter:
    """Khong co API key, NVD cho phep 5 lan goi trong 30 giay."""
    def __init__(self, n=5, per=30.0):
        self.n, self.per, self.t = n, per, []
        self.lock = threading.Lock()
    def wait(self):
        while True:
            with self.lock:
                now = time.time()
                self.t = [x for x in self.t if now - x < self.per]
                if len(self.t) < self.n:
                    self.t.append(now); return
                w = self.per - (now - self.t[0]) + 0.3
            time.sleep(max(w, 0.1))

limiter = RateLimiter()


def get(url, limited=False, retries=6, timeout=180):
    for a in range(retries):
        if limited:
            limiter.wait()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:
            print(f"    loi {type(e).__name__}, thu lai lan {a+1}", flush=True)
            time.sleep(8 * (a + 1))
    raise RuntimeError("khong tai duoc: " + url)


def pick(metric_list, kind):
    """Lay diem theo nguon: 'Primary' la diem do NVD cham,
       'Secondary' la diem do don vi cong bo lo hong (CNA) cham."""
    for m in (metric_list or []):
        if m.get("type") == kind:
            return m["cvssData"]
    return None


def slim(item):
    c = item.get("cve", {})
    met = c.get("metrics", {})
    v3 = (met.get("cvssMetricV31") or []) or (met.get("cvssMetricV30") or [])
    nvd, cna = pick(v3, "Primary"), pick(v3, "Secondary")
    v4 = pick(met.get("cvssMetricV40"), "Primary") or pick(met.get("cvssMetricV40"), "Secondary")
    return {
        "id": c.get("id"),
        "published": (c.get("published") or "")[:10],
        "status": c.get("vulnStatus"),
        "cvss3_nvd": nvd["baseScore"] if nvd else None,
        "cvss3_cna": cna["baseScore"] if cna else None,
        "cvss4": v4["baseScore"] if v4 else None,
    }


def fetch_nvd(YEAR):
    path = os.path.join(DATA, f"nvd_{YEAR}.jsonl")
    done = set()
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            try: done.add(json.loads(line)["id"])
            except Exception: pass
    print(f"[NVD] da co {len(done):,} ban ghi", flush=True)

    start, end = datetime(YEAR, 1, 1), datetime(YEAR, 12, 31, 23, 59, 59)
    tasks, cur = [], start
    while cur <= end:
        wend = min(cur + timedelta(days=WINDOW_DAYS), end)
        q = (f"pubStartDate={cur.strftime('%Y-%m-%dT%H:%M:%S.000')}"
             f"&pubEndDate={wend.strftime('%Y-%m-%dT%H:%M:%S.999')}")
        total = json.loads(get(f"{NVD_API}?{q}&resultsPerPage=1", limited=True))["totalResults"]
        print(f"[NVD] {cur.date()} den {wend.date()}: {total:,} ban ghi", flush=True)
        tasks += [(q, i) for i in range(0, total, PAGE)]
        cur = wend + timedelta(seconds=1)

    fout = open(path, "a", encoding="utf-8")
    lock = threading.Lock(); n_done = [0]

    def work(t):
        q, idx = t
        js = json.loads(get(f"{NVD_API}?{q}&resultsPerPage={PAGE}&startIndex={idx}", limited=True))
        recs = [slim(it) for it in js.get("vulnerabilities", [])]
        with lock:
            new = 0
            for r in recs:
                if r["id"] and r["id"] not in done:
                    fout.write(json.dumps(r) + "\n"); done.add(r["id"]); new += 1
            fout.flush(); n_done[0] += 1
            print(f"[NVD] trang {n_done[0]}/{len(tasks)}  moi={new}  tong={len(done):,}", flush=True)

    with ThreadPoolExecutor(WORKERS) as ex:
        for f in as_completed([ex.submit(work, t) for t in tasks]):
            f.result()
    fout.close()
    print(f"[NVD] xong: {len(done):,} ban ghi", flush=True)


def fetch_kev():
    js = json.loads(get(KEV_URL))
    rows = [{"cve_id": v["cveID"], "date_added": v["dateAdded"],
             "vendor": v.get("vendorProject", ""), "product": v.get("product", "")}
            for v in js["vulnerabilities"]]
    with open(os.path.join(DATA, "kev.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f)
    print(f"[KEV] {len(rows):,} lo hong da bi khai thac", flush=True)


def month_ends(YEAR):
    """Ngay cuoi cua 12 thang trong nam, cong them cuoi thang 1 nam sau."""
    out = []
    for m in range(1, 14):
        y, mm = (YEAR, m + 1) if m < 12 else (YEAR + 1, m - 11)
        out.append(date(y, mm, 1) - timedelta(days=1))
    return out


def fetch_epss(YEAR):
    for d in month_ends(YEAR):
        for back in range(5):          # neu ngay do thieu file thi lui toi da 4 ngay
            dd = d - timedelta(days=back)
            path = os.path.join(DATA, f"epss_{dd.isoformat()}.csv.gz")
            if os.path.exists(path):
                break
            try:
                open(path, "wb").write(get(EPSS_DAY.format(d=dd.isoformat()), retries=2))
                print(f"[EPSS] ngay {dd}", flush=True); break
            except Exception:
                if os.path.exists(path): os.remove(path)

def fetch_epss_now():
    path = os.path.join(DATA, "epss_hien_tai.csv.gz")
    open(path, "wb").write(get(EPSS_NOW))
    print("[EPSS] diem hien tai", flush=True)


if __name__ == "__main__":
    # Cach chay:  python3 01_thu_thap.py            (mac dinh nam 2025)
    #             python3 01_thu_thap.py 2023 2024 2025
    years = [int(a) for a in sys.argv[1:]] or [YEAR]
    fetch_kev()
    fetch_epss_now()
    for y in years:
        fetch_epss(y)
        fetch_nvd(y)
    print("XONG BUOC THU THAP", flush=True)
