# -*- coding: utf-8 -*-
"""
01b_fetch_nvd_parallel.py
Ban song song cua buoc thu thap NVD.

Ly do: moi lan goi tra ve 2000 ban ghi va mat khoang 50 giay de tai,
trong khi gioi han tan suat cua NVD la 5 lan goi moi 30 giay.
Goi tuan tu chi dung khoang 12 phan tram han muc cho phep.
Ban nay dung nhieu luong co bo dieu tiet tan suat, ton trong dung gioi han.
"""
import json, os, time, threading, urllib.request
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
UA = "Nhom14-AcademicResearch/1.0 (course project; metadata only)"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
START, END = datetime(2023, 1, 1), datetime(2025, 12, 31, 23, 59, 59)
WINDOW_DAYS, PAGE, WORKERS = 115, 2000, 5

# --- bo dieu tiet: toi da 5 lan goi trong moi cua so 30 giay
class RateLimiter:
    def __init__(self, n, per):
        self.n, self.per, self.calls = n, per, []
        self.lock = threading.Lock()
    def acquire(self):
        while True:
            with self.lock:
                now = time.time()
                self.calls = [t for t in self.calls if now - t < self.per]
                if len(self.calls) < self.n:
                    self.calls.append(now); return
                wait = self.per - (now - self.calls[0]) + 0.3
            time.sleep(max(wait, 0.1))

limiter = RateLimiter(5, 30.0)
write_lock = threading.Lock()
import importlib.util
spec = importlib.util.spec_from_file_location("f1", os.path.join(HERE, "01_fetch_data.py"))
f1 = importlib.util.module_from_spec(spec); spec.loader.exec_module(f1)
slim = f1.slim


def get(url, retries=6):
    for a in range(retries):
        limiter.acquire()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read())
        except Exception as e:
            print(f"    loi {type(e).__name__} lan {a+1}, cho {8*(a+1)}s", flush=True)
            time.sleep(8 * (a + 1))
    raise RuntimeError("that bai: " + url)


def build_tasks():
    tasks, cur = [], START
    while cur <= END:
        wend = min(cur + timedelta(days=WINDOW_DAYS), END)
        js = get(f"{NVD_API}?pubStartDate={cur.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                 f"&pubEndDate={wend.strftime('%Y-%m-%dT%H:%M:%S.999')}&resultsPerPage=1")
        total = js.get("totalResults", 0)
        print(f"[cua so] {cur.date()} .. {wend.date()} : {total:,} ban ghi", flush=True)
        for idx in range(0, total, PAGE):
            tasks.append((cur, wend, idx, total))
        cur = wend + timedelta(seconds=1)
    return tasks


def main():
    out_path = os.path.join(DATA, "nvd_raw.jsonl")
    done = set()
    if os.path.exists(out_path):
        with open(out_path, encoding="utf-8") as f:
            for line in f:
                try: done.add(json.loads(line)["id"])
                except Exception: pass
    print(f"da co san {len(done):,} ban ghi", flush=True)

    tasks = build_tasks()
    print(f"tong so lan goi can thuc hien: {len(tasks)}", flush=True)
    fout = open(out_path, "a", encoding="utf-8")
    counter = {"n": 0}

    def work(t):
        s, e, idx, total = t
        js = get(f"{NVD_API}?pubStartDate={s.strftime('%Y-%m-%dT%H:%M:%S.000')}"
                 f"&pubEndDate={e.strftime('%Y-%m-%dT%H:%M:%S.999')}"
                 f"&resultsPerPage={PAGE}&startIndex={idx}")
        recs = [slim(it) for it in js.get("vulnerabilities", [])]
        n = 0
        with write_lock:
            for r in recs:
                if r["id"] and r["id"] not in done:
                    fout.write(json.dumps(r, ensure_ascii=False) + "\n")
                    done.add(r["id"]); n += 1
            fout.flush(); counter["n"] += 1
            print(f"[{counter['n']}/{len(tasks)}] {s.date()} idx={idx} "
                  f"moi={n} tong={len(done):,}", flush=True)
        return n

    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(work, t) for t in tasks]
        for f in as_completed(futs):
            try: f.result()
            except Exception as e: print("  loi tac vu:", e, flush=True)
    fout.close()
    print(f"HOAN TAT. Tong ban ghi: {len(done):,}", flush=True)


if __name__ == "__main__":
    main()
