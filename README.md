# Chính sách và Quản trị an ninh mạng - Nhóm 14

Đề tài: kiểm chứng khuyến nghị "vá trong 48 giờ các lỗ hổng CVSS từ 8,0 trên hệ thống phơi ra Internet" trong bài báo *Automated Exploit Generation: LLMs Cross the Threshold* của CSA (02/04/2026), và đề xuất công thức ưu tiên vá lỗ hổng kết hợp CVSS, EPSS, KEV và mức quan trọng của tài sản.

Ý tưởng chi tiết: [Thu_Kha_Thi/Y_TUONG.md](Thu_Kha_Thi/Y_TUONG.md)

## Công thức đề xuất

```
S = AC × CVSS × [KEV + (1 - KEV) × EPSS^0,3] × 10
```

- AC: mức quan trọng của tài sản (0 đến 1)
- CVSS: mức nghiêm trọng (0 đến 10)
- KEV: 1 nếu lỗ hổng đã có trong danh mục KEV của CISA, ngược lại 0
- EPSS: xác suất bị khai thác trong 30 ngày tới (0 đến 1)
- S: điểm ưu tiên (0 đến 100)

## Cấu trúc

| Thư mục, tệp | Nội dung |
|---|---|
| `Thu_Kha_Thi/notebooks/thong_ke_nguong_cvss_8.ipynb` | Thống kê ngưỡng CVSS 8,0 so với KEV, phân bổ theo EPSS |
| `Thu_Kha_Thi/notebooks/kiem_chung_cong_thuc_S.ipynb` | Kiểm chứng công thức S tại ba ngày đánh giá trong quá khứ |
| `Thu_Kha_Thi/notebooks/so_sanh_truoc_khi_vao_kev.ipynb` | So sánh điểm S trước khi vào KEV và khi vào KEV |
| `Thu_Kha_Thi/notebooks/kev_cvss_theo_nam.ipynb` | Lỗ hổng KEV theo năm và điểm CVSS |
| `Thu_Kha_Thi/notebooks/ket_qua*/` | Bảng (CSV, Excel), hình và số liệu do các notebook sinh ra |
| `Thu_Kha_Thi/src/` | Bộ script kiểm chứng CVSS và EPSS (chạy bằng `run_all.sh`) |
| `Thu_Kha_Thi/output/` | Kết quả của bộ script trong `src/` |
| `Thu_Kha_Thi/cong_thuc_risk_score.tex` | Công thức viết bằng LaTeX |
| `ReportLatexType1/bao_cao.tex` | Báo cáo theo mẫu Springer LNCS (một cột, 15 trang), tiếng Việt |
| `ReportLatexType2/IEEE-conference-template-062824/bao_cao_ieee.tex` | Báo cáo theo mẫu IEEE conference (hai cột, 6 trang), tiếng Việt |
| `ReportLatexType1/`, `ReportLatexType2/` (các tệp còn lại) | Mẫu gốc của Springer và IEEE |
| `tools/latex/Dockerfile` | Môi trường biên dịch LaTeX cho hai bản báo cáo |
| `SrcPaper/` | Bài báo gốc của CSA (PDF, không đưa lên git) |
| `W5_Implementation/src/` | Mã của hướng tiếp cận ban đầu (đã thay bằng hướng hiện tại) |
| `tools/latex_live_preview.py` | Công cụ tự biên dịch và xem trước tệp LaTeX |

## Cách chạy

Trên Google Colab: tải notebook lên, chọn *Runtime*, sau đó *Run all*. Notebook tự tải dữ liệu vào thư mục `du_lieu_nvd` và lưu kết quả vào thư mục `ket_qua*`.

Trên máy:

```bash
pip install pandas numpy matplotlib openpyxl jupyter
jupyter notebook Thu_Kha_Thi/notebooks
```

Lần đầu chạy cần tải khoảng 300 MB dữ liệu NVD. Notebook so sánh trước khi vào KEV gọi API EPSS cho khoảng 400 ngày, mất khoảng 25 phút.

## Biên dịch báo cáo

Cần Docker. Lần đầu build môi trường (image khoảng 3,3 GB):

```bash
docker build -t nhom14-latex tools/latex
```

Sau đó biên dịch từng bản (chạy tại thư mục gốc của repo):

```bash
docker run --rm -v "$PWD:/work" -w /work/ReportLatexType1 nhom14-latex latexmk -xelatex bao_cao.tex
docker run --rm -v "$PWD:/work" -w /work/ReportLatexType2/IEEE-conference-template-062824 nhom14-latex latexmk -xelatex bao_cao_ieee.tex
```

Trên Git Bash của Windows, thêm `MSYS_NO_PATHCONV=1` vào đầu lệnh `docker run`.

## Nguồn dữ liệu

- NVD (NIST): điểm CVSS, tệp dữ liệu theo năm định dạng JSON 2.0
- CISA KEV: danh mục lỗ hổng đã bị khai thác, lấy từ kho `cisagov/kev-data` trên GitHub
- FIRST EPSS: điểm EPSS theo ngày, qua API `api.first.org` và tệp điểm hằng ngày

Dữ liệu thô không được đưa lên repo, chạy lại code để tải.

## Phạm vi đạo đức

Đề tài chỉ dùng dữ liệu mô tả lỗ hổng công khai. Không tạo mã khai thác, không quét hay tấn công bất kỳ hệ thống nào.
