# -*- coding: utf-8 -*-
"""03_bieu_do.py - Ve bieu do tu ket qua cua 02_phan_tich.py"""
import os, json
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "output")
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                     "axes.spines.top": False, "axes.spines.right": False})
d = pd.read_csv(os.path.join(OUT, "du_lieu_phan_tich.csv"))
R = json.load(open(os.path.join(OUT, "ket_qua.json"), encoding="utf-8"))
P = int(d["y"].sum()); W = R["viec2"]["phai_va"]
rng = np.random.default_rng(42); d["tie"] = rng.random(len(d))

fig, ax = plt.subplots(figsize=(7.4, 4.4))
for col, lab, st in [("cvss3", "CVSS", "-"), ("epss", "EPSS tại thời điểm quyết định", "--"),
                     ("epss_hien_tai", "EPSS hiện tại (nhìn trước đáp án)", ":")]:
    s = d.sort_values([col, "tie"], ascending=False)
    ax.plot(np.arange(1, len(s) + 1), 100 * s["y"].cumsum() / P, st, lw=1.8, label=lab)
ax.plot([1, len(d)], [0, 100], color="gray", lw=0.8, label="Chọn ngẫu nhiên")
ax.axvline(W, color="black", lw=0.8, ls="-.")
ax.text(W * 1.08, 6, f"Quy tắc CSA\n({W:,} lỗ hổng)", fontsize=8.5)
ax.set_xscale("log"); ax.grid(alpha=0.25)
ax.set_xlabel("Số lỗ hổng phải vá (thang logarit)")
ax.set_ylabel("Tỷ lệ lỗ hổng bị khai thác được vá kịp (%)")
ax.set_title("Hình 1. Mức bao phủ theo khối lượng vá, lỗ hổng năm 2025")
ax.legend(frameon=False, fontsize=8.5, loc="upper left")
fig.tight_layout(); fig.savefig(os.path.join(OUT, "hinh1_bao_phu.png"), dpi=170)

tg = pd.DataFrame(R["thoi_gian"])
fig, ax = plt.subplots(figsize=(7.4, 3.6))
ax.bar(range(len(tg)), tg["ty_le_pct"], color="#444", width=0.6)
for i, v in enumerate(tg["ty_le_pct"]):
    ax.text(i, v + 0.8, f"{v:.1f}%", ha="center", fontsize=9)
ax.set_xticks(range(len(tg)))
ax.set_xticklabels(["Trước hoặc\ncùng ngày công bố", "1 đến 7 ngày", "8 đến 30 ngày",
                    "31 đến 180 ngày", "Sau 180 ngày"], fontsize=8.5)
ax.set_ylim(0, 30)
ax.set_ylabel("Tỷ lệ (%)"); ax.grid(alpha=0.25, axis="y")
ax.set_title(f"Hình 2. Thời gian từ khi công bố tới khi bị ghi nhận khai thác ({R['kev_2025']} lỗ hổng)")
fig.tight_layout(); fig.savefig(os.path.join(OUT, "hinh2_thoi_gian.png"), dpi=170)
print("Da ve: hinh1_bao_phu.png, hinh2_thoi_gian.png")
