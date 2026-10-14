# -*- coding: utf-8 -*-
"""07_bieu_do_kiem_chung.py - Ve bieu do cho phan kiem chung cong thuc."""
import os, sys, json
import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
sys.argv = [sys.argv[0]]
HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "05_kiem_chung.py"), encoding="utf-8").read()
exec(compile(src.split("# ======================================================================= RQ3")[0], "05", "exec"))
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                     "axes.spines.top": False, "axes.spines.right": False})
R = json.load(open(os.path.join(OUT, "kiem_chung.json"), encoding="utf-8"))

fr = np.unique(np.concatenate([np.logspace(-3, 0, 60), [0.01, 0.05, 0.1, 0.25]]))
fig, ax = plt.subplots(figsize=(7.4, 4.4))
for lab, fn, st in [("CVSS", lambda c, e: c, "-"), ("EPSS", lambda c, e: e, "--"),
                    ("Công thức, số mũ 0,3", lambda c, e: c * e ** 0.3, "-")]:
    ys = []
    for f in fr:
        h = P = 0
        for y in TEST:
            c, e, t = yearset(y); h += exp_hits(fn(c, e), t, f * len(c)); P += t.sum()
        ys.append(100 * h / P)
    ax.plot(100 * fr, ys, st, lw=2.2 if "Công" in lab else 1.6, label=lab)
# Chon ngau nhien: va x% bat duoc x%. Truc hoanh la logarit nen phai ve nhieu diem, khong noi thang hai dau
xs = np.logspace(-1, 2, 200)
ax.plot(xs, xs, color="gray", lw=0.8, label="Chọn ngẫu nhiên")
ax.set_xscale("log"); ax.grid(alpha=0.25)
ax.set_xlabel("Tỷ lệ lỗ hổng được vá (%), thang logarit")
ax.set_ylabel("Tỷ lệ lỗ hổng bị khai thác về sau được vá (%)")
ax.set_title("Hình 3. Khả năng dự báo, gộp hai năm kiểm thử 2024 và 2025")
ax.legend(frameon=False, loc="upper left")
fig.tight_layout(); fig.savefig(os.path.join(OUT, "hinh3_kiem_chung_du_bao.png"), dpi=170)

SIM = ["CVSS", "EPSS", "Cong thuc bo KEV", "Cong thuc day du", "Cay Shimizu"]
TEN = ["CVSS", "EPSS", "Công thức\nbỏ KEV", "Công thức\nđầy đủ", "Cây quyết định\nShimizu"]
fig, axes = plt.subplots(1, 2, figsize=(9.6, 3.9), sharey=True)
for ax, key, title in [(axes[0], "va_truoc", "Vá trước khi bị khai thác"),
                       (axes[1], "an_toan_30", "An toàn trong 30 ngày")]:
    x = np.arange(len(SIM)); w = 0.38
    for j, Y in enumerate(["2024", "2025"]):
        v = [100 * R["rq2"][Y]["0.25"][m][key] for m in SIM]
        b = ax.bar(x + (j - 0.5) * w, v, w, label=f"Năm {Y}", color=["#888", "#333"][j])
        for xi, vi in zip(x + (j - 0.5) * w, v): ax.text(xi, vi + 1, f"{vi:.0f}", ha="center", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels(TEN, fontsize=8.5); ax.set_title(title)
    ax.grid(alpha=0.25, axis="y"); ax.set_ylim(0, 110)
axes[0].set_ylabel("Tỷ lệ lỗ hổng bị khai thác (%)"); axes[0].legend(frameon=False, loc="upper left")
fig.suptitle("Hình 4. Mô phỏng vận hành hằng tháng, ngân sách vá 25% số lỗ hổng trong năm", y=1.0)
fig.tight_layout(); fig.savefig(os.path.join(OUT, "hinh4_mo_phong.png"), dpi=170, bbox_inches="tight")
print("Da ve hinh3_kiem_chung_du_bao.png, hinh4_mo_phong.png")
