#!/usr/bin/env bash
# Chay toan bo quy trinh tu dau den cuoi.
# Yeu cau: python3 kem pandas, numpy, scikit-learn
set -e
cd "$(dirname "$0")"
echo "=== Buoc 1: thu thap du lieu ==="
python3 01_fetch_data.py kev
python3 01_fetch_data.py epss
python3 01_fetch_data.py exploitdb
python3 01b_fetch_nvd_parallel.py
echo "=== Buoc 2: tinh dac trung ==="
python3 02_build_features.py
echo "=== Buoc 3: phan tich ==="
python3 03_analyze.py
echo "=== XONG. Ket qua nam trong thu muc output/ ==="
