#!/usr/bin/env bash
# Chay toan bo: thu thap, phan tich, ve bieu do.
# Yeu cau: python3, pandas, numpy, matplotlib
set -e
cd "$(dirname "$0")"
python3 01_thu_thap.py 2023 2024 2025
python3 02_phan_tich.py
python3 03_bieu_do.py
python3 04_cong_thuc.py
python3 05_kiem_chung.py
python3 06_kham_pha.py
python3 07_bieu_do_kiem_chung.py
