# Kiem chung uu tien va lo hong theo CVSS so voi EPSS, du lieu nam 2025

## Cau truc

    src/01_thu_thap.py   Viec 1: tai du lieu NVD 2025, CISA KEV, EPSS lich su va EPSS hien tai
    src/02_phan_tich.py  Viec 2, 3, 4: kiem chung khuyen nghi CSA, so sanh CVSS va EPSS, quy tac ket hop
    src/03_bieu_do.py    Ve Hinh 1 va Hinh 2
    src/run_all.sh       Chay toan bo
    data/                Du lieu tho da tai
    output/              Ket qua: ket_qua.txt, ket_qua.json, cac bang .csv, hinh .png
    BaoCao_KiemChung_CVSS_EPSS.docx   Bao cao day du

## Cach chay

    pip install pandas numpy matplotlib
    bash src/run_all.sh

Buoc thu thap mat khoang 5 den 10 phut do gioi han tan suat cua NVD.

## Nguyen tac quan trong

Diem EPSS duoc lay DUNG vao thoi diem ra quyet dinh va (du lieu lich su),
khong dung diem hien tai. Diem hien tai da phan anh viec lo hong bi khai thac,
nen dung no se cho ket qua sai lech.
