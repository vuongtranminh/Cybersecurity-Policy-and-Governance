# Ý tưởng đề tài: ưu tiên vá lỗ hổng bằng cách kết hợp CVSS, EPSS, KEV và mức quan trọng của tài sản

Nhóm 14, học phần Chính sách và Quản trị an ninh mạng.

## 1. Xuất phát điểm

Bài báo "Automated Exploit Generation: LLMs Cross the Threshold" của CSA (02/04/2026) khuyến nghị vá trong 48 giờ mọi lỗ hổng có điểm CVSS từ 8,0 trở lên. Nhóm đặt câu hỏi: nếu chỉ dựa vào điểm CVSS thì việc ưu tiên vá có đúng không?

## 2. Vấn đề khi chỉ dùng một nguồn thông tin

**Chỉ dùng CVSS.** CVSS đo mức nghiêm trọng của lỗ hổng, không đo việc lỗ hổng có đang bị khai thác hay không. Vì vậy:

- Nhiều lỗ hổng CVSS cao nhưng trên thực tế khó khai thác hoặc chưa ai khai thác, vẫn phải tập trung vá. Trong 66.722 lỗ hổng CVSS từ 8,0, có 65.845 / 66.722 = 98,69% chưa ghi nhận bị khai thác. Trung bình phải vá 76,1 lỗ hổng mới trúng 1 lỗ hổng thực sự bị khai thác.
- Nhiều lỗ hổng CVSS dưới 8,0 đã bị khai thác nhưng bị bỏ qua: 693 / 1.570 = 44,14% lỗ hổng trong danh mục KEV.

**Chỉ dùng EPSS.** EPSS cho biết khả năng bị khai thác trong 30 ngày tới và phân biệt tốt hơn CVSS. Nhưng phần lớn lỗ hổng có điểm EPSS rất thấp, điểm phân bố không đều, và EPSS không cho biết hậu quả nặng hay nhẹ.

**Chỉ dùng KEV.** KEV là danh sách lỗ hổng đã được xác nhận bị khai thác. Nếu chỉ vá theo KEV thì:

- Không ưu tiên được gì trước khi việc khai thác xảy ra.
- Có những lỗ hổng trong KEV nhưng CVSS thấp, hậu quả nhẹ, vẫn bị đưa lên vá ngay, dẫn đến dư thừa.

## 3. Ý tưởng: kết hợp cả ba nguồn và thêm mức quan trọng của tài sản

```
S = AC × CVSS × [KEV + (1 - KEV) × EPSS^0,3] × 10
```

| Thành phần | Giá trị | Ý nghĩa |
|---|---|---|
| AC | 0 đến 1 | Mức quan trọng của tài sản chứa lỗ hổng, do tổ chức tự xác định |
| CVSS | 0 đến 10 | Mức nghiêm trọng kỹ thuật của lỗ hổng |
| KEV | 0 hoặc 1 | Bằng 1 nếu lỗ hổng đã có trong KEV tại thời điểm đánh giá |
| EPSS | 0 đến 1 | Xác suất bị khai thác trong 30 ngày tới |
| S | 0 đến 100 | Điểm ưu tiên xử lý, càng cao càng phải vá sớm |

Thang điểm: CVSS dùng thang 0 đến 10 và nhân 10 thì S nằm trong khoảng 0 đến 100. Nếu chuẩn hóa CVSS về 0 đến 1 thì nhân 100.

**Logic của công thức:**

- **Lỗ hổng đã có trong KEV** (KEV = 1): S = AC × CVSS × 10. Lỗ hổng đã bị khai thác nên không cần dự đoán nữa, chỉ cần nhân với mức nghiêm trọng và mức quan trọng của tài sản là biết có đáng vá ngay hay không.
- **Lỗ hổng chưa có trong KEV** (KEV = 0): S = AC × CVSS × EPSS^0,3 × 10. Đây là phần cần dự đoán: mức nghiêm trọng được điều chỉnh theo khả năng bị khai thác. Số mũ 0,3 nén điểm EPSS để EPSS không lấn át CVSS.
- **Hệ số AC**: cùng một lỗ hổng, nằm trên máy chủ thanh toán thì phải vá trước khi nằm trên máy thử nghiệm.

Công thức này gần với cây quyết định VMC của Shimizu và Hashimoto (IEEE Access, 2026): xét KEV trước, sau đó EPSS, sau đó CVSS. Điểm khác là công thức cho ra một điểm liên tục từ 0 đến 100 thay vì 4 nhóm, và có thêm mức quan trọng của tài sản.

## 4. Cách chứng minh

1. **Tạm bỏ AC** (coi AC = 1), vì không có dữ liệu công khai về tài sản.
2. **Phần đã có trong KEV không cần chứng minh**, vì đã bị khai thác.
3. **Chứng minh phần chưa có trong KEV**: chọn một ngày trong quá khứ, chấm điểm S chỉ bằng thông tin có tại ngày đó, chia thành các mức 10 điểm. Đếm số lỗ hổng trong mỗi mức và số lỗ hổng thực sự vào KEV trong 12 tháng sau. Nếu mức điểm cao chứa nhiều lỗ hổng sắp bị khai thác hơn, công thức dự đoán được.
4. **So sánh với quy tắc của CSA** khi cùng khối lượng vá: cách nào bắt được nhiều lỗ hổng sắp bị khai thác hơn.
5. **So sánh trên cùng thang điểm**: điểm S của một lỗ hổng ngay trước khi vào KEV so với điểm của nó khi đã vào KEV.
6. Khi phần không có AC đã được chứng minh tốt, **nhân thêm hệ số AC** để có công thức hoàn chỉnh.

## 5. Kết quả kiểm chứng

**Đã chứng minh được:**

- Khi chỉ vá 1% hoặc 5% số lỗ hổng, công thức bắt được nhiều gấp 2,7 đến 8,9 lần so với xếp theo CVSS, ổn định ở cả ba ngày đánh giá (31/12/2023, 31/12/2024, 30/06/2025).
- Điểm càng cao thì tỷ lệ vào KEV càng cao. Ngày 30/06/2025, các mức từ 70 điểm có tỷ lệ vào KEV gấp khoảng 27 đến 30 lần trung bình.
- Ngay trước khi vào KEV, mức S từ 70 chứa lỗ hổng sắp bị khai thác nhiều gấp khoảng 13 lần chọn ngẫu nhiên. Quy tắc CSA chỉ gấp khoảng 2,3 lần.
- Thành phần KEV là bắt buộc: 226 / 836 = 27,03% lỗ hổng KEV là lỗ hổng zero-day, vừa công bố đã bị khai thác, không thể chấm điểm trước.

**Chưa chứng minh được:**

- Công thức không dự đoán tốt hơn EPSS dùng riêng. Thừa số CVSS có vai trò thêm mức nghiêm trọng, không làm dự đoán chính xác hơn.
- Khi vá bằng khối lượng của quy tắc CSA, công thức hơn CVSS ở hai trong ba ngày, chưa ổn định.
- Điểm trước khi vào KEV thường thấp hơn nhiều điểm khi vào KEV (trung vị tỷ số 0,19), vì EPSS chủ yếu tăng sau khi việc khai thác đã được biết đến.
- Hệ số AC chưa kiểm chứng được vì không có dữ liệu tài sản.

## 6. Kết luận ý tưởng

Không nguồn thông tin nào dùng riêng là đủ. Công thức kết hợp là cách sắp thứ tự ưu tiên tốt hơn rõ rệt so với quy tắc vá theo ngưỡng CVSS 8,0 khi nguồn lực vá có hạn:

- EPSS giúp chọn lỗ hổng có khả năng bị khai thác.
- KEV đưa ngay lỗ hổng đã bị khai thác lên đầu.
- CVSS và AC đưa mức nghiêm trọng và tầm quan trọng của tài sản vào thứ tự ưu tiên.

## 7. Tài liệu và mã nguồn

| Tệp | Nội dung |
|---|---|
| `BaoCao_ThongKe_NguongCVSS8.docx` | Báo cáo thống kê, nhận xét và kiểm chứng công thức |
| `notebooks/thong_ke_nguong_cvss_8.ipynb` | Thống kê ngưỡng CVSS 8,0 và phân bổ theo EPSS |
| `notebooks/kiem_chung_cong_thuc_S.ipynb` | Kiểm chứng công thức tại ba ngày đánh giá |
| `notebooks/so_sanh_truoc_khi_vao_kev.ipynb` | So sánh điểm trước khi vào KEV và khi vào KEV |
| `cong_thuc_risk_score.tex` | Công thức viết bằng LaTeX |

Các notebook đều chạy được trên Google Colab: tải lên, chọn Runtime, sau đó Run all.

Nguồn dữ liệu: NVD (điểm CVSS), danh mục KEV của CISA, điểm EPSS của FIRST. Đề tài chỉ dùng dữ liệu mô tả lỗ hổng, không tạo mã khai thác, không tấn công hệ thống nào.
