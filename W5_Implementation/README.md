# AEG-EI - Ma nguon va du lieu

Trien khai thuc nghiem cho de tai: do luong muc do de bi vu khi hoa tu dong bang
mo hinh ngon ngu lon cua lo hong cong bo, va ung dung trong chinh sach uu tien va loi.

## Cau truc

    src/01_fetch_data.py            thu thap KEV, EPSS, Exploit-DB va NVD (tuan tu)
    src/01b_fetch_nvd_parallel.py   ban song song cua buoc thu thap NVD
    src/02_build_features.py        tinh bon thanh phan C, K, P, E va chi so AEG-EI
    src/03_analyze.py               tra loi ba cau hoi nghien cuu
    src/run_all.sh                  chay toan bo quy trinh
    data/                           du lieu tho da tai ve
    output/                         bang dac trung va ket qua phan tich

## Nguon du lieu

| Nguon | Dung de |
|---|---|
| NVD (NIST) | mo ta advisory, CWE, vector CVSS, tham chieu |
| CISA KEV | nhan ground truth: lo hong da bi khai thac thuc te |
| EPSS (FIRST) | doi chung |
| Exploit-DB | tinh trang ton tai ma minh chung cong khai |

Tat ca deu cong khai va mien phi.

## Rang buoc dao duc

Nghien cuu nay chi doc sieu du lieu cong khai. Khong sinh ma khai thac,
khong thu nghiem khai thac tren bat ky he thong nao, khong dung mo hinh
ngon ngu lon de tao noi dung mang tinh tan cong.
