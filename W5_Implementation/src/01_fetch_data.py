# -*- coding: utf-8 -*-
"""
01_fetch_data.py
Thu thap du lieu tho tu bon nguon cong khai, mien phi:
  1. NVD (NIST)        - mo ta advisory, CWE, vector CVSS, tham chieu
  2. CISA KEV          - danh muc lo hong da bi khai thac (nhan ground truth)
  3. EPSS (FIRST)      - diem xac suat khai thac (doi chung)
  4. Exploit-DB        - tinh trang ton tai ma minh chung (thanh phan P)

Khong sinh ma khai thac, khong tac dong toi bat ky he thong nao.
Chi doc sieu du lieu cong khai.
"""
import json, os, sys, time, gzip, csv, io, urllib.request, urllib.error
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
os.makedirs(DATA, exist_ok=True)

UA = "Nhom14-AcademicResearch/1.0 (course project; metadata only)"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

START = datetime(2023, 1, 1)
END = datetime(2025, 12, 31, 23, 59, 59)
WINDOW_DAYS = 115          # NVD gioi han toi da 120 ngay moi lan goi
PAGE = 2000                # so ban ghi toi da moi trang
SLEEP = 6.5                # khong co API key: 5 lan goi / 30 giay


def http_get(url, timeout=120, retries=5):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:
            wait = 10 * (attempt + 1)
            print(f"    loi {type(e).__name__}, thu lai sau {wait}s ({attempt+1}/{retries})", flush=True)
            time.sleep(wait)
    raise RuntimeError("khong tai duoc: " + url)


def slim(item):
    """Chi giu lai cac truong can dung, bo phan con lai de tiet kiem bo nho."""
    c = item.get("cve", {})
    desc = ""
    for d in c.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cwes = []
    for w in c.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                cwes.append(v)
    metrics = c.get("metrics", {})
    vec, score, sev = None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            m = metrics[key][0]["cvssData"]
            vec = m.get("vectorString"); score = m.get("baseScore"); sev = m.get("baseSeverity")
            break
    refs = [{"url": r.get("url", ""), "tags": r.get("tags", [])} for r in c.get("references", [])]
    return {
        "id": c.get("id"),
        "published": c.get("published"),
        "status": c.get("vulnStatus"),
        "desc": desc,
        "cwes": cwes,
        "cvss_vector": vec,
        "cvss_score": score,
        "cvss_severity": sev,
        "refs": refs,
    }


def fetch_nvd():
    out_path = os.path.join(DATA, "nvd_raw.jsonl")
    done = set()
    if os.path.exists(out_path):
        with open(out_path, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["id"])
                except Exception:
                    pass
        print(f"[NVD] da co san {len(done)} ban ghi, tiep tuc bo sung", flush=True)

    fout = open(out_path, "a", encoding="utf-8")
    cur = START
    total_new = 0
    while cur <= END:
        wend = min(cur + timedelta(days=WINDOW_DAYS), END)
        start_index = 0
        while True:
            url = (f"{NVD_API}?pubStartDate={cur.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                   f"&pubEndDate={wend.strftime('%Y-%m-%dT%H:%M:%S.999')}"
                   f"&resultsPerPage={PAGE}&startIndex={start_index}")
            raw = http_get(url)
            js = json.loads(raw)
            total = js.get("totalResults", 0)
            items = js.get("vulnerabilities", [])
            n = 0
            for it in items:
                rec = slim(it)
                if rec["id"] and rec["id"] not in done:
                    fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    done.add(rec["id"]); n += 1
            total_new += n
            fout.flush()
            print(f"[NVD] {cur.date()} .. {wend.date()}  "
                  f"index={start_index}/{total}  moi={n}  tong={len(done)}", flush=True)
            start_index += PAGE
            if start_index >= total or not items:
                break
            time.sleep(SLEEP)
        cur = wend + timedelta(seconds=1)
        time.sleep(SLEEP)
    fout.close()
    print(f"[NVD] hoan tat. Tong ban ghi: {len(done)} (moi: {total_new})", flush=True)


def fetch_kev():
    print("[KEV] dang tai ...", flush=True)
    raw = http_get(KEV_URL)
    js = json.loads(raw)
    items = js.get("vulnerabilities", [])
    path = os.path.join(DATA, "kev.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["cve_id", "date_added", "vendor", "product"])
        for it in items:
            w.writerow([it.get("cveID", ""), it.get("dateAdded", ""),
                        it.get("vendorProject", ""), it.get("product", "")])
    print(f"[KEV] {len(items)} lo hong da bi khai thac", flush=True)


def fetch_epss():
    print("[EPSS] dang tai ...", flush=True)
    raw = http_get(EPSS_URL)
    text = gzip.decompress(raw).decode("utf-8", errors="replace")
    path = os.path.join(DATA, "epss.csv")
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["cve_id", "epss", "percentile"])
        for line in text.splitlines():
            if line.startswith("#") or line.startswith("cve"):
                continue
            parts = line.split(",")
            if len(parts) >= 3:
                w.writerow([parts[0], parts[1], parts[2]]); n += 1
    print(f"[EPSS] {n} ban ghi", flush=True)


def fetch_exploitdb():
    print("[Exploit-DB] dang tai ...", flush=True)
    raw = http_get(EXPLOITDB_URL).decode("utf-8", errors="replace")
    rd = csv.DictReader(io.StringIO(raw))
    cves = set()
    for row in rd:
        codes = (row.get("codes") or "")
        for tok in codes.replace(";", " ").split():
            if tok.upper().startswith("CVE-"):
                cves.add(tok.upper())
    path = os.path.join(DATA, "exploitdb_cves.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["cve_id"])
        for c in sorted(cves):
            w.writerow([c])
    print(f"[Exploit-DB] {len(cves)} ma CVE co ma minh chung cong khai", flush=True)


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "kev"):        fetch_kev()
    if which in ("all", "epss"):       fetch_epss()
    if which in ("all", "exploitdb"):  fetch_exploitdb()
    if which in ("all", "nvd"):        fetch_nvd()
    print("XONG", flush=True)
