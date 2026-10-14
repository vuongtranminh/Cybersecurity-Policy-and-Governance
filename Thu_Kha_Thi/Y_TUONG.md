# Ý tưởng đề tài: ưu tiên vá lỗ hổng bằng cách kết hợp CVSS, EPSS, KEV và mức quan trọng của tài sản

Nhóm 14, học phần Chính sách và Quản trị an ninh mạng.

## 1. Xuất phát điểm

Bài báo "Automated Exploit Generation: LLMs Cross the Threshold" của CSA (02/04/2026) khuyến nghị vá trong 48 giờ các lỗ hổng có điểm CVSS từ 8,0 trở lên ảnh hưởng tới hệ thống phơi ra Internet. Dữ liệu công khai không cho biết lỗ hổng nằm trên hệ thống nào, nên phần kiểm chứng áp ngưỡng 8,0 cho mọi lỗ hổng. Nhóm đặt câu hỏi: nếu chỉ dựa vào điểm CVSS thì việc ưu tiên vá có đúng không?

## 2. Vấn đề khi chỉ dùng một nguồn thông tin

**Chỉ dùng CVSS.** CVSS đo mức nghiêm trọng của lỗ hổng, không đo việc lỗ hổng có đang bị khai thác hay không. Vì vậy:

- Nhiều lỗ hổng CVSS cao nhưng trên thực tế khó khai thác hoặc chưa ai khai thác, vẫn phải tập trung vá. Trong 66.722 lỗ hổng CVSS từ 8,0, có 65.845 / 66.722 = 98,69% chưa ghi nhận bị khai thác. Trung bình phải vá 76,1 lỗ hổng mới trúng 1 lỗ hổng thực sự bị khai thác.
- Nhiều lỗ hổng CVSS dưới 8,0 đã bị khai thác nhưng bị bỏ qua: 693 / 1.570 = 44,14% lỗ hổng trong danh mục KEV.

**Chỉ dùng EPSS.** EPSS cho biết khả năng bị khai thác trong 30 ngày tới và phân biệt tốt hơn CVSS. Nhưng phần lớn lỗ hổng có điểm EPSS rất thấp, điểm phân bố không đều, và EPSS không cho biết hậu quả nặng hay nhẹ.

**Chỉ dùng KEV.** KEV là danh sách lỗ hổng đã được xác nhận bị khai thác. KEV chỉ chiếm khoảng 0,65% số lỗ hổng, nên vá ngay toàn bộ KEV không tốn nhiều. Vấn đề là nếu chỉ vá theo KEV thì:

- Không ưu tiên được gì trước khi việc khai thác xảy ra.
- CISA chỉ thêm lỗ hổng sau khi đã có bằng chứng bị khai thác, nên KEV luôn đến muộn hơn kẻ tấn công.

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
- **Hệ số AC**: cùng một lỗ hổng, nằm trên máy chủ thanh toán thì phải vá trước khi nằm trên máy thử nghiệm. AC ở đây là mức quan trọng của tài sản, không liên quan tới chỉ số Attack Complexity của CVSS.
- **Quy tắc KEV**: ở nhánh KEV, S = AC × CVSS × 10, nên lỗ hổng đã bị khai thác nhưng CVSS thấp (ví dụ 6,5) chỉ được 65 điểm, dưới ngưỡng vá khẩn cấp 70. Ngày 30/06/2025, 160 / 1.371 = 11,67% lỗ hổng trong KEV rơi vào trường hợp này. Vì vậy chính sách đi kèm quy tắc: **mọi lỗ hổng đã có trong KEV luôn thuộc nhóm vá khẩn cấp**, giống Chỉ thị BOD 22-01 của CISA; S dùng để sắp thứ tự trong nhóm và cho các lỗ hổng chưa có trong KEV.

Vì nâng lên lũy thừa dương không đổi thứ tự, xếp theo S ở nhánh chưa KEV tương đương xếp theo EPSS × CVSS^3,33: một lỗ hổng CVSS 10 chỉ cần EPSS bằng khoảng 1/10 của một lỗ hổng CVSS 5 để có cùng thứ hạng.

Nghiên cứu gần nhất là Vulnerability Management Chaining (VMC) của Shimizu và Hashimoto (IEEE Access, vol. 14, 2026): một khung hai bước, lọc theo mối đe dọa (có trong KEV hoặc EPSS từ 0,088) rồi lọc theo mức nghiêm trọng (CVSS từ 7,0). Điểm khác là công thức cho ra một điểm liên tục từ 0 đến 100, xử lý KEV bằng quy tắc riêng và có thêm mức quan trọng của tài sản.

## 4. Cách chứng minh

1. **Tạm bỏ AC** (coi AC = 1), vì không có dữ liệu công khai về tài sản.
2. **Phần đã có trong KEV không cần chứng minh**, vì đã bị khai thác.
3. **Chứng minh phần chưa có trong KEV**: chọn một ngày trong quá khứ, chấm điểm S chỉ bằng thông tin có tại ngày đó, chia thành các mức 10 điểm. Đếm số lỗ hổng trong mỗi mức và số lỗ hổng thực sự vào KEV trong 12 tháng sau. Nếu mức điểm cao chứa nhiều lỗ hổng sắp bị khai thác hơn, công thức dự đoán được.
4. **So sánh với quy tắc của CSA** khi cùng khối lượng vá: cách nào bắt được nhiều lỗ hổng sắp bị khai thác hơn.
5. **Điểm trước khi được CISA xác nhận**: điểm S của một lỗ hổng ngay trước khi vào KEV. CISA chỉ thêm lỗ hổng sau khi có bằng chứng bị khai thác, nên đây là phát hiện trước khi CISA xác nhận, chưa phải dự báo trước khi bị khai thác.
6. **Đọc khuyến nghị CSA sát hơn** (`do_nhay_quy_tac_csa.ipynb`): ngưỡng trên 8,0; chỉ lỗ hổng khai thác được qua mạng (AV:N); thêm điều kiện có PoC công khai.
7. **Lặp lại ở nhiều ngày đánh giá và nhiều số mũ** (`kiem_chung_S_nhieu_ngay.ipynb`): 11 ngày cuối quý, 3 ngày có cửa sổ theo dõi không chồng nhau, số mũ từ 0,1 đến 1,0.
8. Khi phần không có AC đã được chứng minh tốt, **nhân thêm hệ số AC** để có công thức hoàn chỉnh.

## 5. Kết quả kiểm chứng

**Đã chứng minh được:**

- Kết luận vá thừa đúng với mọi cách đọc khuyến nghị CSA: chỉ 1,3–1,5% lỗ hổng trong nhóm phải vá bị khai thác. Tỷ lệ bỏ sót thì phụ thuộc cách đọc: 44,14% theo cách đọc đơn giản nhất, 20,73% khi chỉ xét lỗ hổng khai thác qua mạng (AV:N) và thêm điều kiện có PoC công khai.
- Ngưỡng S từ 70 ổn định qua 11 ngày cuối quý (31/03/2023 đến 30/09/2025): chỉ chiếm 0,78–1,40% số lỗ hổng chưa có trong KEV nhưng hiệu suất gấp 15,9–34,2 lần chọn ngẫu nhiên, trong khi quy tắc CSA chỉ 1,7–2,3 lần ở mọi cách đọc.
- Khi chỉ vá 1% hoặc 5% số lỗ hổng, công thức bắt được nhiều gấp 2,7 đến 8,9 lần so với xếp theo CVSS ở ba ngày đánh giá cũ, và không kém CVSS ở cả 11 ngày, kể cả ba ngày có cửa sổ theo dõi không chồng nhau.
- Điểm càng cao thì tỷ lệ vào KEV càng cao. Ngày 30/06/2025, các mức từ 70 điểm có tỷ lệ vào KEV gấp khoảng 27 đến 30 lần trung bình.
- Thành phần KEV là bắt buộc: 226 / 836 = 27,03% lỗ hổng KEV là lỗ hổng zero-day, vừa công bố đã bị khai thác, không thể chấm điểm trước. Trong mô phỏng vá hằng tháng, công thức có KEV an toàn trong 30 ngày 100% ở cả hai năm.
- Kết luận không phụ thuộc số mũ 0,3: mọi số mũ từ 0,2 đến 1,0 cho kết quả gần như nhau.

**Chưa chứng minh được hoặc là hạn chế:**

- So với EPSS dùng riêng, công thức gần như ngang ở hầu hết các mức. Công thức chỉ hơn rõ khi vá nhiều lỗ hổng mới công bố (thực nghiệm 4: hơn 15,2 ca, khoảng tin cậy 95% từ 5,2 đến 26,7); trên tập lỗ hổng tồn đọng, hai cách gần như ngang nhau.
- Khi vá bằng khối lượng của quy tắc CSA, công thức hơn CVSS chưa có ý nghĩa thống kê (H1: hơn 6,0 ca, khoảng tin cậy từ −2,0 đến 15,0).
- Công thức gần như không cảnh báo trước được lỗ hổng mới công bố: trong số lỗ hổng công bố tối đa 30 ngày trước khi vào KEV, trung vị EPSS một ngày trước khi vào KEV chỉ 0,0009 và chỉ 4,46% có S từ 70. Điểm cao một ngày trước khi vào KEV chủ yếu thuộc về lỗ hổng cũ (63% đã công bố hơn 1 năm).
- PoC công khai là tín hiệu có giá trị mà công thức chưa dùng: năm 2024, quy tắc CSA có thêm điều kiện PoC bắt được nhiều hơn công thức ở cùng khối lượng vá.
- Hệ số AC chưa kiểm chứng được vì không có dữ liệu tài sản.

## 6. Kết luận ý tưởng

Không nguồn thông tin nào dùng riêng là đủ. Công thức kết hợp là cách sắp thứ tự ưu tiên tốt hơn rõ rệt so với quy tắc vá theo ngưỡng CVSS 8,0 khi nguồn lực vá có hạn:

- EPSS giúp chọn lỗ hổng có khả năng bị khai thác.
- Quy tắc KEV đưa mọi lỗ hổng đã bị khai thác vào nhóm vá khẩn cấp.
- CVSS và AC đưa mức nghiêm trọng và tầm quan trọng của tài sản vào thứ tự ưu tiên; thừa số CVSS còn giúp sắp thứ tự khi phải vá nhiều.

Giới hạn lớn nhất: công thức gần như không cảnh báo trước được lỗ hổng mới công bố, đúng nhóm mà CSA lo ngại nhất. Với nhóm này, chính sách vẫn phải dựa vào quy tắc KEV, cảnh báo của nhà cung cấp và tình báo mối đe dọa.

## 7. Tài liệu và mã nguồn

| Tệp | Nội dung |
|---|---|
| `BaoCao_ThongKe_NguongCVSS8.docx` | Báo cáo thống kê, nhận xét và kiểm chứng công thức |
| `notebooks/thong_ke_nguong_cvss_8.ipynb` | Thống kê ngưỡng CVSS 8,0 và phân bổ theo EPSS |
| `notebooks/kiem_chung_cong_thuc_S.ipynb` | Kiểm chứng công thức tại ba ngày đánh giá |
| `notebooks/so_sanh_truoc_khi_vao_kev.ipynb` | So sánh điểm trước khi vào KEV và khi vào KEV |
| `notebooks/phan_tich_bo_sung.ipynb` | Phân tích bổ sung từ kết quả đã có: theo khối lượng vá, theo tuổi lỗ hổng, nhóm vá khẩn cấp có quy tắc KEV |
| `notebooks/do_nhay_quy_tac_csa.ipynb` | Độ nhạy của quy tắc CSA theo năm cách đọc |
| `notebooks/kiem_chung_S_nhieu_ngay.ipynb` | Kiểm chứng tại 11 ngày đánh giá và quét số mũ |
| `cong_thuc_risk_score.tex` | Công thức viết bằng LaTeX |
| `../ReportLatexType1/bao_cao.tex`, `../ReportLatexType2/.../bao_cao_ieee.tex` | Báo cáo theo mẫu Springer LNCS và IEEE |

Các notebook đều chạy được trên Google Colab: tải lên, chọn Runtime, sau đó Run all.

Nguồn dữ liệu: NVD (điểm CVSS), danh mục KEV của CISA, điểm EPSS của FIRST. Đề tài chỉ dùng dữ liệu mô tả lỗ hổng, không tạo mã khai thác, không tấn công hệ thống nào.
