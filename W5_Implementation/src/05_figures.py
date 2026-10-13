# -*- coding: utf-8 -*-
"""05_figures.py - sinh bieu do cho bao cao."""
import os
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "output")
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                     "axes.spines.top": False, "axes.spines.right": False})

df = pd.read_csv(os.path.join(OUT, "features.csv"))
df["epss"] = df["epss"].fillna(0.0)
test = df[df["year"] == 2025].copy()
tot = int(test["kev"].sum())

# ---- Hinh 1: duong cong bao phu theo so lo hong phai va
fig, ax = plt.subplots(figsize=(7.2, 4.2))
for col, lab, st in [("epss", "EPSS", "-"), ("cvss", "CVSS", "--"), ("aeg_ei", "AEG-EI", ":")]:
    d = test.sort_values(col, ascending=False).reset_index(drop=True)
    cum = d["kev"].cumsum() / tot * 100
    ax.plot(np.arange(1, len(d) + 1), cum, st, label=lab, linewidth=1.8)
ax.plot([1, len(test)], [0, 100], color="gray", linewidth=0.8, label="Chon ngau nhien")
ax.set_xscale("log")
ax.set_xlabel("So lo hong phai va (thang logarit)")
ax.set_ylabel("Ty le lo hong da bi khai thac duoc bao phu (%)")
ax.set_title("Hinh 1. Bao phu so voi chi phi va loi, du lieu kiem thu nam 2025")
ax.legend(frameon=False); ax.grid(alpha=0.25)
fig.tight_layout(); fig.savefig(os.path.join(OUT, "hinh1_bao_phu.png"), dpi=170)

# ---- Hinh 2: ty le KEV theo muc diem C2 va do dai mo ta
fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.6))
d2 = test.groupby("C2")["kev"].mean() * 100
axes[0].bar([0, 1, 2], d2.reindex([0, 1, 2]).values, color="#444", width=0.6)
axes[0].set_xticks([0, 1, 2])
axes[0].set_xticklabels(["0\nkhong neu", "1\nneu module", "2\nneu ham/tham so"])
axes[0].set_ylabel("Ty le thuoc KEV (%)")
axes[0].set_title("Muc chi tiet ky thuat (tieu chi C2)")
bins = [0, 30, 60, 100, 160, 10**6]
labs = ["<30", "30-60", "60-100", "100-160", ">160"]
test["b"] = pd.cut(test["desc_words"], bins=bins, labels=labs, right=False)
d3 = test.groupby("b", observed=True)["kev"].mean() * 100
axes[1].bar(range(len(d3)), d3.values, color="#444", width=0.6)
axes[1].set_xticks(range(len(d3))); axes[1].set_xticklabels(d3.index.astype(str))
axes[1].set_xlabel("So tu trong mo ta advisory")
axes[1].set_title("Do dai mo ta")
for a in axes: a.grid(alpha=0.25, axis="y")
fig.suptitle("Hinh 2. Quan he giua do giau thong tin cua advisory va ty le bi khai thac", y=1.02)
fig.tight_layout(); fig.savefig(os.path.join(OUT, "hinh2_dac_trung_C.png"), dpi=170, bbox_inches="tight")

print("Da sinh: hinh1_bao_phu.png, hinh2_dac_trung_C.png")
