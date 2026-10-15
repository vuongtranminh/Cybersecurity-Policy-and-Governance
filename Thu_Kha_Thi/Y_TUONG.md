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
- **Quy tắc KEV**: ở nhánh KEV, S = AC × CVSS × 10, nên lỗ hổng đã bị khai thác nhưng CVSS thấp (ví dụ 6,5) chỉ được 65 điểm, dưới ngưỡng vá khẩn cấp 70. Ngày 30/06/2025, 160 / 1.371 = 11,67% lỗ hổng trong KEV rơi vào trường hợp này. Vì vậy chính sách đi kèm quy tắc: **mọi lỗ hổng đã có trong KEV luôn thuộc nhóm vá khẩn cấp**, phù hợp với Chỉ thị BOD 26-04 của CISA (10/06/2026, thay thế BOD 22-01), theo đó lỗ hổng trong KEV có hạn vá 3 hoặc 14 ngày; S dùng để sắp thứ tự trong nhóm và cho các lỗ hổng chưa có trong KEV.

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
8. **Tình huống điển hình** (`tinh_huong_dien_hinh.ipynb`): chọn theo tiêu chí cố định các lỗ hổng mà công thức bắt trước còn quy tắc CSA bỏ qua, các lỗ hổng quy tắc CSA vá thừa, và các trường hợp công thức không bắt được.
9. Khi phần không có AC đã được chứng minh tốt, **nhân thêm hệ số AC** để có công thức hoàn chỉnh.

## 5. Kết quả kiểm chứng

**Đã chứng minh được:**

- Kết luận vá thừa đúng với mọi cách đọc khuyến nghị CSA: chỉ 1,3% đến 1,5% lỗ hổng trong nhóm phải vá bị khai thác. Tỷ lệ bỏ sót thì phụ thuộc cách đọc: 44,14% theo cách đọc đơn giản nhất, 20,73% khi chỉ xét lỗ hổng khai thác qua mạng (AV:N) và thêm điều kiện có PoC công khai.
- Ngưỡng S từ 70 ổn định qua 11 ngày cuối quý (31/03/2023 đến 30/09/2025): chỉ chiếm 0,78% đến 1,40% số lỗ hổng chưa có trong KEV nhưng hiệu suất gấp 15,9 đến 34,2 lần chọn ngẫu nhiên, trong khi quy tắc CSA chỉ 1,7 đến 2,3 lần ở mọi cách đọc.
- Khi chỉ vá 1% hoặc 5% số lỗ hổng, công thức bắt được nhiều gấp 2,7 đến 8,9 lần so với xếp theo CVSS ở ba ngày đánh giá cũ, và không kém CVSS ở cả 11 ngày, kể cả ba ngày có cửa sổ theo dõi không chồng nhau.
- Điểm càng cao thì tỷ lệ vào KEV càng cao. Ngày 30/06/2025, các mức từ 70 điểm có tỷ lệ vào KEV gấp khoảng 27 đến 30 lần trung bình.
- Thành phần KEV là bắt buộc: 227 / 836 = 27,15% lỗ hổng KEV là lỗ hổng zero-day, vừa công bố đã bị khai thác, không thể chấm điểm trước. Trong mô phỏng vá hằng tháng, công thức có KEV an toàn trong 30 ngày 100% ở cả hai năm.
- Kết luận không phụ thuộc số mũ 0,3: mọi số mũ từ 0,2 đến 1,0 cho kết quả gần như nhau.

**Chưa chứng minh được hoặc là hạn chế:**

- So với EPSS dùng riêng, công thức gần như ngang ở hầu hết các mức. Công thức chỉ hơn rõ khi vá nhiều lỗ hổng mới công bố (thực nghiệm 4: hơn 15,2 ca, khoảng tin cậy 95% từ 5,2 đến 26,7); trên tập lỗ hổng tồn đọng, hai cách gần như ngang nhau.
- Khi vá bằng khối lượng của quy tắc CSA, công thức hơn CVSS chưa có ý nghĩa thống kê (H1: hơn 6,0 ca, khoảng tin cậy từ âm 2,0 đến 15,0).
- Công thức gần như không cảnh báo trước được lỗ hổng mới công bố: trong số lỗ hổng công bố tối đa 30 ngày trước khi vào KEV, trung vị EPSS một ngày trước khi vào KEV chỉ 0,0009 và chỉ 4,46% có S từ 70. Điểm cao một ngày trước khi vào KEV chủ yếu thuộc về lỗ hổng cũ (63% đã công bố hơn 1 năm).
- PoC công khai là tín hiệu có giá trị mà công thức chưa dùng, nhưng chỉ với lỗ hổng tồn đọng: năm 2024, quy tắc CSA có thêm điều kiện PoC bắt được nhiều hơn công thức ở cùng khối lượng vá. Với lỗ hổng mới công bố thì không: tại cuối tháng công bố chỉ 3 / 116 lỗ hổng sắp bị khai thác đã có PoC trên Exploit-DB.
- Đã thử ba cách bổ sung tín hiệu sớm cho lỗ hổng mới công bố (PoC, lịch sử nhà cung cấp, cờ "Exploited" của Microsoft) theo thiết kế của thực nghiệm 4; không cách nào cải thiện có ý nghĩa thống kê khi đã loại rò rỉ dữ liệu (báo cáo, mục "Các cải tiến đã thử nhưng không hiệu quả"). Khi chỉ dùng điểm CVSS có tại ngày quyết định (điểm của CNA), lợi thế của công thức so với CVSS khi vá 5% giảm từ 18,2 xuống 5,3 ca và không còn ý nghĩa thống kê.
- Hệ số AC chưa kiểm chứng được vì không có dữ liệu tài sản.

## 6. Tình huống điển hình: CVSS nói thấp, thực tế nói cao

Phần này trình bày các tình huống cụ thể theo kiểu "case in point" (ví dụ minh họa thực tế), lấy từ dữ liệu của nhóm (`notebooks/tinh_huong_dien_hinh.ipynb`, kết quả trong `notebooks/ket_qua_tinh_huong/`). Để tránh chọn ví dụ có lợi, các tình huống được chọn theo **tiêu chí cố định đặt trước**, và báo cáo cả số trường hợp không đạt:

- **Công thức bắt trước, quy tắc CSA bỏ qua:** lỗ hổng vào KEV từ 01/04/2023, có CVSS dưới 8,0 (quy tắc CSA không bao giờ ưu tiên), và có S từ 50 trở lên 30 ngày trước khi vào KEV. Ngày 30/06/2025, chỉ 6.868 / 209.623 = 3,28% lỗ hổng chưa có trong KEV đạt S từ 50.
- **Ba tình huống vẽ lịch sử điểm theo tháng**, chọn theo quy tắc: CVSS thấp nhất, báo trước lâu nhất, thời gian từ công bố đến khi vào KEV ngắn nhất.
- **Quy tắc CSA vá thừa:** lỗ hổng CVSS từ 9,0 chưa có trong KEV tại ngày 30/06/2025.
- **Trường hợp công thức không bắt được**, gồm ví dụ CVE-2025-13956 do CrowdSec công bố.

### 6.1. Tình huống 1: CVSS nói 5,3, công thức nói 52 (CVE-2021-26086, Atlassian Jira)

- Lỗ hổng Jira Server and Data Center, công bố 16/08/2021, CVSS 5,3 (mức trung bình).
- Quy tắc CSA: không bao giờ ưu tiên lỗ hổng này.
- Công thức S: điểm tăng dần theo EPSS, từ 11 (09/2021) lên 45 (03/2022). S đạt 50 lần đầu vào 03/2023 (đúng tháng EPSS đổi mô hình), sau đó có 5 tháng rơi lại dưới 50; chuỗi liên tục từ 50 bắt đầu khoảng 8 tháng trước khi vào KEV.
- CISA đưa vào KEV ngày 12/11/2024. Ba mươi ngày trước đó, EPSS đã là 0,8549 và S = 50,6.
- Kết quả: công thức đưa lỗ hổng vào nhóm ưu tiên cao (S từ 50) khoảng 8 đến 19 tháng trước khi CISA xác nhận, tùy tính từ chuỗi liên tục hay từ lần đầu. Quy tắc CVSS để nó nằm trong danh sách tồn đọng suốt thời gian đó.
- Giới hạn: với CVSS 5,3, S tối đa chỉ 53, nên lỗ hổng này không bao giờ vào nhóm vá khẩn cấp (S từ 70) trước khi vào KEV. Quy tắc KEV mới đưa nó vào nhóm khẩn cấp.

### 6.2. Tình huống 2: từ 7 lên 62 điểm trong hai tháng (CVE-2023-32315, Ignite Realtime Openfire)

| Ngày | Điểm S | Quy tắc CSA (CVSS 7,5) |
|---|---|---|
| 31/05/2023 (vừa công bố ngày 26/05/2023) | 7 | Không ưu tiên |
| 30/06/2023 | 34 | Không ưu tiên |
| 31/07/2023 | 62 | Không ưu tiên |
| 24/08/2023: vào KEV | 75 (CVSS × 10) | Không ưu tiên |

Đây là dạng "chuyển pha": lỗ hổng chuyển nhanh từ bình thường sang bị khai thác. Công thức tính lại điểm hằng ngày theo EPSS nên nhận ra thay đổi gần một tháng trước khi CISA xác nhận, dù điểm 62 mới ở mức ưu tiên cao, chưa tới ngưỡng vá khẩn cấp 70. Khi lỗ hổng vào KEV, thành phần KEV đẩy điểm lên mức cao nhất của nó. Điểm CVSS vẫn là 7,5 như ngày công bố.

### 6.3. Tình huống 3: CISA xác nhận muộn hơn 4 năm (CVE-2015-5477, ISC BIND)

- Lỗ hổng BIND, công bố 29/07/2015, CVSS 7,5.
- Công thức S: điểm ở mức khoảng 73 liên tục từ 02/2022, nằm trong khoảng 1,3% lỗ hổng có điểm cao nhất.
- CISA đưa vào KEV ngày 08/10/2026, tức công thức báo trước khoảng 55 tháng.
- Quy tắc CSA: không ưu tiên ở bất kỳ thời điểm nào.

Hình minh họa ba tình huống: `notebooks/ket_qua_tinh_huong/hinh1_lich_su_diem.png`.

### 6.4. Tổng hợp theo tiêu chí

Lỗ hổng vào KEV từ 01/04/2023 có CVSS dưới 8,0: 328 lỗ hổng, quy tắc CSA bỏ qua toàn bộ.

| Hạng mục | Số lượng |
|---|---|
| Có điểm EPSS 30 ngày trước khi vào KEV | 156 / 328 = 47,56% |
| S từ 50 trở lên 30 ngày trước khi vào KEV (công thức bắt trước) | 24 / 156 = 15,38% (tính trên cả 328: 24 / 328 = 7,32%) |
| S từ 70 trở lên 30 ngày trước khi vào KEV (ngưỡng vá khẩn cấp) | 14 / 156 = 8,97% (tính trên cả 328: 14 / 328 = 4,27%) |
| Trong 24 lỗ hổng bắt trước, báo trước từ 12 tháng trở lên, tính từ lần đầu S từ 50 | 18 / 24 = 75,00% (trung vị 19,4 tháng) |
| Như trên, tính từ đầu chuỗi tháng liên tục có S từ 50 đến khi vào KEV | 15 / 24 = 62,50% (trung vị 14,3 tháng) |
| S dưới 30, 30 ngày trước khi vào KEV (công thức không bắt trước) | 119 / 156 = 76,28% |

Hai cách tính thời gian báo trước khác nhau ở 5 lỗ hổng mà điểm rơi lại dưới 50 sau lần đầu vượt ngưỡng (CVE-2021-22555, CVE-2020-9715, CVE-2021-26086, CVE-2021-41277, CVE-2022-43769). Cách tính liên tục sát hơn với việc tổ chức thực sự giữ lỗ hổng trong nhóm ưu tiên.

Cột "Ngày gần nhất trở lại S từ 50" là ngày cuối tháng bắt đầu chuỗi tháng liên tục có S từ 50 kéo dài tới khi vào KEV; cột "Báo trước liên tục" tính từ ngày này:

```
Báo trước          = (Ngày vào KEV - ngày cuối tháng đầu tiên S từ 50) / 30,44
Báo trước liên tục = (Ngày vào KEV - ngày gần nhất trở lại S từ 50) / 30,44
```

Với 19 lỗ hổng điểm không rơi dưới 50 sau lần đầu, ngày này trùng với tháng đầu tiên S từ 50. Ví dụ CVE-2021-41277: S đạt 50 lần đầu ngày 31/03/2023, rơi xuống 31,9 đến 39,3 từ 09/2023 đến 01/2024, trở lại 74,0 ngày 29/02/2024 và giữ tới khi vào KEV ngày 12/11/2024, nên báo trước liên tục là 257 / 30,44 = 8 tháng thay vì 592 / 30,44 = 19 tháng.

Danh sách đầy đủ 24 lỗ hổng công thức bắt trước (sắp theo S 30 ngày trước khi vào KEV):

| STT | Mã CVE | Sản phẩm | CVSS | Ngày công bố | Ngày vào KEV | EPSS 30 ngày trước | S 30 ngày trước | S khi vào KEV | Tháng đầu tiên S từ 50 | Báo trước (tháng) | Ngày gần nhất trở lại S từ 50 | Báo trước liên tục (tháng) | Mã độc tống tiền |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2016-6415 | Cisco IOS, IOS XR, and IOS XE | 7,5 | 19/09/2016 | 19/05/2023 | 0,9727 | 74,4 | 75,0 | 02/2022 | 15 | 28/02/2022 | 15 | Chưa rõ |
| 2 | CVE-2016-9079 | Mozilla Firefox, Firefox ESR, and Thunderbird | 7,5 | 11/06/2018 | 22/06/2023 | 0,9719 | 74,4 | 75,0 | 02/2022 | 16 | 28/02/2022 | 16 | Chưa rõ |
| 3 | CVE-2020-17519 | Apache Flink | 7,5 | 05/01/2021 | 23/05/2024 | 0,9708 | 74,3 | 75,0 | 05/2021 | 36 | 31/05/2021 | 36 | Chưa rõ |
| 4 | CVE-2021-41277 | Metabase Metabase | 7,5 | 17/11/2021 | 12/11/2024 | 0,9515 | 73,9 | 75,0 | 03/2023 | 19 | 29/02/2024 | 8 | Chưa rõ |
| 5 | CVE-2021-43798 | Grafana Labs Grafana | 7,5 | 07/12/2021 | 09/10/2025 | 0,9434 | 73,7 | 75,0 | 12/2021 | 45 | 31/12/2021 | 45 | Chưa rõ |
| 6 | CVE-2019-5418 | Rails Ruby on Rails | 7,5 | 27/03/2019 | 07/07/2025 | 0,9423 | 73,7 | 75,0 | 05/2021 | 49 | 31/05/2021 | 49 | Chưa rõ |
| 7 | CVE-2020-25078 | D-Link DCS-2530L and DCS-2670L Devices | 7,5 | 02/09/2020 | 05/08/2025 | 0,9403 | 73,6 | 75,0 | 03/2023 | 28 | 31/03/2023 | 28 | Chưa rõ |
| 8 | CVE-2021-22555 | Linux Kernel | 7,8 | 07/07/2021 | 06/10/2025 | 0,8242 | 73,6 | 78,0 | 10/2021 | 47 | 31/03/2025 | 6 | Chưa rõ |
| 9 | CVE-2017-3506 | Oracle WebLogic Server | 7,4 | 24/04/2017 | 03/06/2024 | 0,9688 | 73,3 | 74,0 | 02/2022 | 27 | 28/02/2022 | 27 | Chưa rõ |
| 10 | CVE-2019-9621 | Synacor Zimbra Collaboration Suite (ZCS) | 7,5 | 30/04/2019 | 07/07/2025 | 0,9181 | 73,1 | 75,0 | 05/2021 | 49 | 31/05/2021 | 49 | Chưa rõ |
| 11 | CVE-2015-5477 | ISC BIND | 7,5 | 29/07/2015 | 08/10/2026 | 0,9128 | 73,0 | 75,0 | 02/2022 | 55 | 28/02/2022 | 55 | Chưa rõ |
| 12 | CVE-2021-22054 | Omnissa Workspace One UEM | 7,5 | 17/12/2021 | 09/03/2026 | 0,8893 | 72,4 | 75,0 | 03/2023 | 35 | 31/03/2023 | 35 | Chưa rõ |
| 13 | CVE-2024-21182 | Oracle WebLogic Server | 7,5 | 16/07/2024 | 01/06/2026 | 0,8767 | 72,1 | 75,0 | 03/2025 | 14 | 31/03/2025 | 14 | Chưa rõ |
| 14 | CVE-2024-27199 | JetBrains TeamCity | 7,3 | 04/03/2024 | 20/04/2026 | 0,9449 | 71,8 | 73,0 | 03/2025 | 13 | 31/03/2025 | 13 | Có |
| 15 | CVE-2021-21311 | Adminer Adminer | 7,2 | 11/02/2021 | 29/09/2025 | 0,8753 | 69,2 | 72,0 | 03/2025 | 6 | 31/03/2025 | 6 | Chưa rõ |
| 16 | CVE-2020-9715 | Adobe Acrobat | 7,8 | 19/08/2020 | 13/04/2026 | 0,5621 | 65,6 | 78,0 | 01/2022 | 50 | 31/05/2023 | 34 | Chưa rõ |
| 17 | CVE-2023-32315 | Ignite Realtime Openfire | 7,5 | 26/05/2023 | 24/08/2023 | 0,5255 | 61,8 | 75,0 | 07/2023 | 1 | 31/07/2023 | 1 | Chưa rõ |
| 18 | CVE-2018-9276 | Paessler PRTG Network Monitor | 7,2 | 02/07/2018 | 04/02/2025 | 0,5241 | 59,3 | 72,0 | 02/2022 | 35 | 28/02/2022 | 35 | Chưa rõ |
| 19 | CVE-2023-27351 | PaperCut NG/MF | 7,5 | 20/04/2023 | 20/04/2026 | 0,4475 | 58,9 | 75,0 | 12/2025 | 4 | 31/12/2025 | 4 | Có |
| 20 | CVE-2022-43769 | Hitachi Vantara Pentaho Business Analytics (BA) Server | 7,2 | 03/04/2023 | 03/03/2025 | 0,3560 | 52,8 | 72,0 | 08/2023 | 18 | 31/12/2023 | 14 | Chưa rõ |
| 21 | CVE-2023-24955 | Microsoft SharePoint Server | 7,2 | 09/05/2023 | 26/03/2024 | 0,3361 | 51,9 | 72,0 | 09/2023 | 6 | 30/09/2023 | 6 | Có |
| 22 | CVE-2021-39935 | GitLab Community and Enterprise Editions | 7,5 | 13/12/2021 | 03/02/2026 | 0,2825 | 51,3 | 75,0 | 04/2025 | 9 | 30/04/2025 | 9 | Chưa rõ |
| 23 | CVE-2021-26086 | Atlassian Jira Server and Data Center | 5,3 | 16/08/2021 | 12/11/2024 | 0,8549 | 50,6 | 53,0 | 03/2023 | 19 | 29/02/2024 | 8 | Chưa rõ |
| 24 | CVE-2023-0386 | Linux Kernel | 7,8 | 22/03/2023 | 17/06/2025 | 0,2318 | 50,3 | 78,0 | 05/2025 | 1 | 31/05/2025 | 1 | Chưa rõ |

### 6.5. Chiều ngược lại: CVSS nói 9,8, thực tế không có gì

Ngày 30/06/2025 có 30.308 lỗ hổng CVSS từ 9,0 chưa có trong KEV. Quy tắc CSA bắt vá tất cả trong 48 giờ, nhưng trong 12 tháng sau chỉ 25 / 30.308 = 0,082% lỗ hổng vào KEV.

| Nhóm theo công thức | Số lỗ hổng CVSS từ 9,0 | Vào KEV trong 12 tháng | So với tổng số vào KEV |
|---|---|---|---|
| S dưới 30 | 22.245 / 30.308 = 73,40% | 7 / 22.245 = 0,031% | 7 / 25 = 28,00% |
| S từ 30 đến dưới 50 | 4.622 / 30.308 = 15,25% | 1 / 4.622 = 0,022% | 1 / 25 = 4,00% |
| S từ 50 đến dưới 70 | 1.562 / 30.308 = 5,15% | 4 / 1.562 = 0,256% | 4 / 25 = 16,00% |
| S từ 70 trở lên | 1.879 / 30.308 = 6,20% | 13 / 1.879 = 0,692% | 13 / 25 = 52,00% |
| Tổng (quy tắc CSA vá tất cả) | 30.308 | 25 / 30.308 = 0,082% | 25 |

- Bảng chỉ xét lỗ hổng CVSS từ 9,0, một phần trong nhóm CVSS từ 8,0 mà quy tắc CSA bắt vá.
- Công thức hạ ưu tiên 73,40% số lỗ hổng mà quy tắc CSA bắt vá gấp. Cái giá là nhóm bị hạ này vẫn chứa 7 / 25 = 28,00% số lỗ hổng sau đó bị khai thác.
- Nhóm S từ 70 chỉ bằng 6,20% khối lượng nhưng chứa 52,00% số lỗ hổng thực sự bị khai thác. Tỷ lệ bị khai thác của nhóm này (0,692%) gấp khoảng 22 lần nhóm S dưới 30 (0,031%).

Ba ví dụ chọn ngẫu nhiên (hạt giống cố định) trong nhóm S dưới 30 và chưa vào KEV:

| Mã CVE | CVSS | EPSS ngày 30/06/2025 | S | Vào KEV đến nay |
|---|---|---|---|---|
| CVE-2022-28512 | 9,8 | 0,00250 | 16,2 | Không |
| CVE-2018-17796 | 9,8 | 0,00264 | 16,5 | Không |
| CVE-2023-2659 | 9,8 | 0,00056 | 10,4 | Không |

### 6.6. Trường hợp công thức không bắt được

**CVE-2025-13956 (LearnPress, plugin WordPress, CVSS 5,3).** Theo CrowdSec, lỗ hổng bị khai thác từ tháng 4/2026 và trở thành chiến dịch tấn công có chủ đích vào tháng 6/2026 (168 địa chỉ IP tấn công, điểm CrowdSec 9/10). Dữ liệu của nhóm:

- Lỗ hổng chưa có trong KEV. NVD ghi ngày công bố là 16/12/2025, khác với "tháng 3/2025" trong bài viết của CrowdSec.

| Ngày | EPSS | Điểm S | Quy tắc CSA |
|---|---|---|---|
| 31/12/2025 | 0,00061 | 5,8 | Không ưu tiên |
| 31/01/2026 | 0,00067 | 5,9 | Không ưu tiên |
| 28/02/2026 | 0,04112 | 20,3 | Không ưu tiên |
| 31/03/2026 | 0,04606 | 21,1 | Không ưu tiên |
| 30/04/2026 | 0,06054 | 22,9 | Không ưu tiên |
| 31/05/2026 | 0,03572 | 19,5 | Không ưu tiên |
| 30/06/2026 | 0,00917 | 13,0 | Không ưu tiên |
| 31/07/2026 | 0,00917 | 13,0 | Không ưu tiên |
| 31/08/2026 | 0,00906 | 12,9 | Không ưu tiên |
| 30/09/2026 | 0,00892 | 12,9 | Không ưu tiên |

Điểm S tăng gần 4 lần khi lỗ hổng bắt đầu bị khai thác, nhưng cao nhất chỉ khoảng 23, chưa vào nhóm ưu tiên, rồi giảm lại khi EPSS giảm. Ở tình huống này, dữ liệu theo dõi tấn công trực tiếp (như của CrowdSec) nhanh hơn EPSS. Không phải nguồn cảnh báo nào cũng vậy: với cờ "Exploited" của Microsoft, 85 / 108 lần Microsoft báo cùng ngày với CISA KEV, và đưa cờ này vào công thức chỉ bắt thêm 1 đến 2 lỗ hổng mới công bố (báo cáo, mục "Các cải tiến đã thử nhưng không hiệu quả").

**Lỗ hổng zero-day.** 227 / 836 = 27,15% lỗ hổng vào KEV từ 01/04/2023 không có điểm EPSS một ngày trước khi vào KEV, vì được công bố và đưa vào KEV gần như cùng lúc. Với nhóm này chỉ thành phần KEV xử lý được.

### 6.7. Lưu ý khi dùng các tình huống

1. **"Báo trước" là báo trước khi CISA xác nhận, chưa chắc là trước khi bị khai thác.** Nhiều lỗ hổng như Jira, BIND đã bị khai thác từ lâu, chỉ là KEV ghi nhận muộn. Kết luận đúng: công thức dùng tín hiệu khai thác sớm hơn KEV, còn quy tắc CVSS không dùng tín hiệu khai thác nào.
2. **Một nửa số lần vượt ngưỡng trùng với lúc EPSS đổi mô hình.** Trong 24 lỗ hổng bắt trước, 12 lỗ hổng đạt S từ 50 lần đầu đúng tháng EPSS đổi mô hình (02/2022, 03/2023, 03/2025), 4 lỗ hổng đạt ngay tháng đầu có điểm (3 lỗ hổng ở 05/2021, tháng đầu của chuỗi dữ liệu, nên thời gian báo trước chỉ là cận dưới), và chỉ 8 lỗ hổng có điểm tăng dần theo EPSS giữa hai lần đổi mô hình. Điểm tại các thời điểm đó vẫn là điểm có thật mà tổ chức nhận được vào lúc đó, nhưng thời gian báo trước dài chủ yếu phản ánh việc mô hình EPSS mới chấm lại lỗ hổng cũ, không phải công thức phát hiện sớm.
3. **Ngưỡng 50 dùng ở đây thấp hơn ngưỡng vá khẩn cấp 70.** Chỉ 14 / 24 lỗ hổng bắt trước đạt S từ 70; lỗ hổng có CVSS dưới 7,0 (như Jira, CVSS 5,3) không bao giờ đạt 70 nếu chưa vào KEV.
4. **Tình huống minh họa không thay cho kiểm chứng thống kê ở mục 5.** Công thức chỉ bắt trước được 24 / 156 = 15,38% lỗ hổng KEV có CVSS thấp và có điểm EPSS (24 / 328 = 7,32% nếu tính cả lỗ hổng chưa có điểm); 76,28% vẫn có S dưới 30 trước khi vào KEV.

## 7. Kết luận ý tưởng

Không nguồn thông tin nào dùng riêng là đủ. Công thức kết hợp là cách sắp thứ tự ưu tiên tốt hơn rõ rệt so với quy tắc vá theo ngưỡng CVSS 8,0 khi nguồn lực vá có hạn:

- EPSS giúp chọn lỗ hổng có khả năng bị khai thác.
- Quy tắc KEV đưa mọi lỗ hổng đã bị khai thác vào nhóm vá khẩn cấp.
- CVSS và AC đưa mức nghiêm trọng và tầm quan trọng của tài sản vào thứ tự ưu tiên; thừa số CVSS còn giúp sắp thứ tự khi phải vá nhiều.

Giới hạn lớn nhất: công thức gần như không cảnh báo trước được lỗ hổng mới công bố, đúng nhóm mà CSA lo ngại nhất. Với nhóm này, chính sách vẫn phải dựa vào quy tắc KEV, cảnh báo của nhà cung cấp và tình báo mối đe dọa.

## 8. Mở rộng: khung đánh giá rủi ro tích hợp 5D theo BOD 26-04 (chưa kiểm chứng)

Phần này mở rộng công thức ở mục 3 bằng hai biến của Chỉ thị BOD 26-04 của CISA (10/06/2026): khả năng tự động hóa khai thác (Exploit Automation) và mức phơi ra Internet (Publicly Exposed). Khung tích hợp năm nguồn: CVSS, EPSS, CISA KEV, khả năng tự động hóa khai thác và mức phơi ra Internet, cùng hệ số mức quan trọng của tài sản.

### 8.1. Công thức tổng quát

Điểm rủi ro tổng hợp S nằm trên thang 0 đến 100, tính bằng một phương trình gồm các bộ lọc nhị phân lồng nhau:

```
S = AC × CVSS × [ KEV × PE + (1 - KEV) × ( EA × PE + (1 - EA) × EPSS^0,3 ) ] × 10
```

Dạng LaTeX:

```latex
S = \text{AC} \times \text{CVSS} \times \left[ K_{\text{KEV}} \times \text{PE} + (1 - K_{\text{KEV}}) \times \Big( \text{EA} \times \text{PE} + (1 - \text{EA}) \times \text{EPSS}^{0.3} \Big) \right] \times 10
```

### 8.2. Ý nghĩa và cách quy đổi các biến đầu vào

Các trường dữ liệu dạng nhãn được số hóa theo quy tắc sau:

| Biến | Định nghĩa | Giá trị quy đổi | Nguồn dữ liệu |
|---|---|---|---|
| AC (Asset Criticality) | Tầm quan trọng của máy chủ chứa lỗ hổng đối với hoạt động của tổ chức | 1,0: hệ thống lõi, cơ sở dữ liệu khách hàng, cổng Internet. 0,8: máy chủ nội bộ, Active Directory. 0,5: máy trạm nhân viên, môi trường staging. 0,2: thiết bị thử nghiệm, máy in | Tổ chức tự cấu hình trong CMDB hoặc hệ thống gắn nhãn tài sản |
| CVSS | Mức nghiêm trọng kỹ thuật của lỗ hổng | Giữ nguyên điểm gốc từ 0,0 đến 10,0 | NVD hoặc công cụ quét lỗ hổng |
| KEV | Lỗ hổng đã bị khai thác trong thực tế hay chưa | 1: có trong danh mục KEV. 0: không có | Danh mục CISA KEV |
| EA (Exploit Automation) | Khả năng kẻ tấn công dùng công cụ hoặc AI tự động hóa khai thác trên diện rộng (biến Automatable của BOD 26-04) | 1: CISA gán nhãn Automatable là Yes. 0: CISA gán nhãn Automatable là No | Chương trình Vulnrichment của CISA (kho `cisagov/vulnrichment` trên GitHub) |
| PE (Publicly Exposed) | Thiết bị chứa lỗ hổng có truy cập được trực tiếp từ Internet công cộng không (biến Publicly Exposed của BOD 26-04) | 1: phơi ra Internet công cộng. 0: nằm trong mạng nội bộ | Tổ chức tự xác định bằng công cụ quản lý bề mặt tấn công bên ngoài (EASM) hoặc cấu hình tường lửa |
| EPSS | Xác suất lỗ hổng bị khai thác trong thực tế trong 30 ngày tới | Giữ nguyên xác suất gốc từ 0,0000 đến 1,0000 | FIRST EPSS |

### 8.3. Logic vận hành của công thức

Phần trong ngoặc vuông đóng vai trò bộ lọc mối đe dọa. Nhờ các biến chỉ nhận giá trị 0 hoặc 1, công thức tự rẽ nhánh mà không cần câu lệnh điều kiện.

**Nhánh 1: KEV × PE (lỗ hổng đã có trong KEV)**

- Logic bảo mật: lỗ hổng đang bị khai thác thực tế (KEV = 1) trở thành mối nguy cao nhất khi tài sản phơi ra Internet (PE = 1). Nếu tài sản nằm trong mạng nội bộ (PE = 0), kẻ tấn công từ Internet không tiếp cận trực tiếp được.
- Khi PE = 1: KEV × PE = 1, phần sau chứa (1 - KEV) = 0 bị triệt tiêu, ngoặc vuông bằng 1. Khi đó S = AC × CVSS × 10, là mức cao nhất mà lỗ hổng đó có thể đạt, thuộc nhóm vá khẩn cấp theo BOD 26-04.
- Khi PE = 0: KEV × PE = 0, nhánh KEV không còn tạo mức khẩn cấp. Lỗ hổng được hạ mức xử lý, nhường nguồn lực cho lỗ hổng khác.

**Nhánh 2: EA × PE (chưa có trong KEV nhưng tự động hóa được)**

Khi KEV = 0, vế đầu bằng 0 và vế sau được xét: EA × PE + (1 - EA) × EPSS^0,3.

- Logic bảo mật: lỗ hổng tự động hóa được (EA = 1, tức công cụ hoặc AI có thể tự quét và tấn công trọn chuỗi) chỉ gây tấn công hàng loạt khi tài sản phơi ra Internet (PE = 1). Nếu tài sản nằm trong mạng nội bộ, công cụ quét tự động của kẻ tấn công không nhìn thấy nó.
- Khi EA = 1 và PE = 1: cụm này bằng 1, phần chứa (1 - EA) = 0 nên EPSS bị bỏ qua. Ngoặc vuông bằng 1, điểm lên mức cao nhất vì lỗ hổng có thể bị quét và tấn công tự động trên diện rộng bất cứ lúc nào.
- Khi EA = 1 và PE = 0: cụm này bằng 0, nguy cơ tấn công tự động hàng loạt coi như bị chặn.

**Nhánh 3: (1 - EA) × EPSS^0,3 (không tự động hóa được)**

Khi KEV = 0 và EA = 0, điểm phụ thuộc EPSS như công thức ở mục 3.

**Vì sao PE không nhân với phần chứa EPSS**

- EPSS là xác suất do mô hình học máy tính trên dữ liệu tấn công toàn cầu, bao gồm cả các con đường không đi trực tiếp từ Internet như thư lừa đảo, mối đe dọa nội bộ, hoặc đi qua VPN.
- Nếu nhân PE với cả phần EPSS, lỗ hổng trong mạng nội bộ (PE = 0) sẽ có điểm EPSS bị xóa về 0. Điều này nguy hiểm, vì kẻ tấn công vẫn có thể vào mạng nội bộ bằng cách lừa nhân viên bấm đường link, rồi từ máy nhân viên tấn công sang lỗ hổng này.
- Vì vậy PE chỉ đi kèm KEV và EA, còn EPSS được giữ nguyên khi EA = 0. Lỗ hổng không tự động hóa được vẫn có điểm tăng dần theo xác suất EPSS, kể cả khi nằm trong mạng nội bộ.

**Ý nghĩa số mũ 0,3**

Phân phối điểm EPSS lệch rất mạnh về phía giá trị nhỏ, đa số lỗ hổng có EPSS dưới 0,01. Số mũ 0,3 kéo các giá trị nhỏ lên mức hợp lý (ví dụ 0,01^0,3 khoảng 0,25), để lỗ hổng nghiêm trọng về kỹ thuật mà mô hình dự báo có nguy cơ vẫn giữ mức cảnh báo vừa phải. Kết quả kiểm chứng ở mục 5 cho thấy thứ tự xếp hạng gần như không đổi với các số mũ từ 0,2 đến 1,0.

### 8.4. Ứng dụng trên công cụ

Công thức trên Excel hoặc Google Sheets (dòng 2; B2 = CVSS, C2 = EPSS, D2 = KEV, E2 = EA, F2 = PE, G2 = AC):

```
=G2 * B2 * (D2 * F2 + (1 - D2) * (E2 * F2 + (1 - E2) * (C2 ^ 0.3))) * 10
```

Hàm Python:

```python
def calculate_integrated_risk(cvss, epss, kev, ea, pe, ac):
    """
    Tinh diem rui ro tich hop 5D dua tren CISA BOD 26-04
    """
    # Bo loc moi de doa
    threat_filter = (kev * pe) + (1 - kev) * ((ea * pe) + (1 - ea) * (epss ** 0.3))

    # Diem rui ro tong hop (0 den 100)
    risk_score = ac * cvss * threat_filter * 10
    return round(risk_score, 2)
```

### 8.5. Các điểm cần xem xét trước khi dùng

Khung 5D chưa được kiểm chứng bằng dữ liệu. Khi đối chiếu logic, có một số điểm cần cân nhắc:

1. **Lỗ hổng KEV trong mạng nội bộ bị về 0 điểm.** Khi KEV = 1 và PE = 0, ngoặc vuông bằng 0 nên S = 0, thấp hơn mọi lỗ hổng chưa bị khai thác có EPSS lớn hơn 0. Điều này khác BOD 26-04: theo các bản tóm tắt chỉ thị, lỗ hổng KEV chiếm toàn quyền hệ thống có hạn 3 ngày bất kể có phơi ra Internet hay không, và phần lớn lỗ hổng KEV khác có hạn 14 ngày. Điều này cũng mâu thuẫn với lập luận ở mục 8.3 rằng kẻ tấn công vẫn vào được mạng nội bộ qua thư lừa đảo; các nhóm mã độc tống tiền thường dùng chính lỗ hổng KEV để lan trong mạng nội bộ.
2. **Lỗ hổng tự động hóa được trong mạng nội bộ cũng về 0.** Khi KEV = 0, EA = 1, PE = 0, S = 0. Cùng lỗ hổng đó nếu EA = 0 thì vẫn có điểm theo EPSS. Ví dụ CVSS 9,8, EPSS 0,5, nằm trong mạng nội bộ: EA = 0 cho S = 79,6, còn EA = 1 cho S = 0. Nghĩa là tự động hóa được lại làm điểm giảm, trái với ý nghĩa của biến.
3. **Điểm tối đa và hạn 72 giờ.** Nhánh KEV và PE cho S = AC × CVSS × 10, chỉ bằng 100 khi CVSS = 10 và AC = 1. Theo BOD 26-04, hạn 3 ngày gắn với lỗ hổng KEV chiếm toàn quyền hệ thống (Technical Impact là Total) và một số tổ hợp rủi ro cao, không phải mọi lỗ hổng KEV phơi ra Internet.
4. **Thiếu biến thứ tư của BOD 26-04 là Technical Impact** (chiếm toàn quyền hay một phần). CVSS chỉ thay thế được một phần.
5. **AC và PE trùng nhau một phần.** Mức AC = 1,0 có "cổng Internet", trong khi PE đã đo việc phơi ra Internet, nên một tài sản có thể bị tính hai lần. Nên để AC chỉ đo tầm quan trọng nghiệp vụ.
6. **Thiếu dữ liệu EA.** Vulnrichment chỉ phủ khoảng 45,8% số CVE, chủ yếu từ năm 2024. Cần quy tắc cho trường hợp thiếu, ví dụ coi EA = 0 để quay về dùng EPSS.
7. **Phạm vi đã kiểm chứng.** Khi PE = 1 và EA = 0, khung 5D trùng với công thức ở mục 3, nên kết quả ở mục 5 và mục 6 chỉ áp dụng cho trường hợp này. Biến PE không có trong dữ liệu công khai nên không kiểm chứng được; biến EA có thể kiểm chứng một phần bằng dữ liệu Vulnrichment.

**Phương án sửa đề xuất** (giữ ý tưởng: chỉ tổ hợp tự động hóa được và phơi ra Internet mới được đẩy lên mức cao nhất, còn lại quay về EPSS; KEV luôn ở mức cao nhất như BOD 26-04):

```
S = AC × CVSS × [ KEV + (1 - KEV) × ( EA × PE + (1 - EA × PE) × EPSS^0,3 ) ] × 10
```

- KEV = 1: S = AC × CVSS × 10 bất kể PE. Mức phơi ra Internet nên dùng để chọn hạn vá (3 hay 14 ngày) thay vì đưa điểm về 0.
- KEV = 0, EA = 1, PE = 1: ngoặc vuông bằng 1, điểm lên mức cao nhất.
- Các trường hợp còn lại: điểm theo EPSS^0,3, nên lỗ hổng nội bộ không bao giờ bị về 0 chỉ vì nằm trong mạng nội bộ.
- Điểm không bao giờ giảm khi KEV, EA, PE hoặc EPSS tăng.

```python
def calculate_integrated_risk_v2(cvss, epss, kev, ea, pe, ac):
    tu_dong_va_phoi = ea * pe
    threat_filter = kev + (1 - kev) * (tu_dong_va_phoi + (1 - tu_dong_va_phoi) * (epss ** 0.3))
    return round(ac * cvss * threat_filter * 10, 2)
```

## 9. Thang điểm S và khuyến nghị xử lý

Thang điểm dựa trên kết quả kiểm chứng ngày 30/06/2025: 209.623 lỗ hổng chưa có trong KEV, theo dõi 12 tháng sau có 91 lỗ hổng vào KEV, tỷ lệ trung bình 0,043%. Hạn vá bám theo các bậc 3, 14, 60 ngày của BOD 26-04.

### 9.1. Thang điểm S và ý nghĩa

| Mức điểm S | Phân loại | Ý nghĩa | Hạn vá khuyến nghị |
|---|---|---|---|
| Không xét điểm: KEV = 1 và PE = 1 | **Khẩn cấp, đã bị khai thác** | Lỗ hổng đã bị khai thác thực tế và tài sản tiếp cận được từ Internet. | **3 ngày**, kèm kiểm tra dấu hiệu xâm nhập |
| Không xét điểm: KEV = 0, EA = 1, PE = 1 | **Khẩn cấp, tự động hóa được** | Chưa có bằng chứng khai thác, nhưng có thể bị quét và tấn công tự động trên diện rộng, và tài sản phơi ra Internet. | **3 ngày** |
| 70 đến 100 | **Nghiêm trọng** | Khả năng bị khai thác rất cao so với mặt bằng. Cần CVSS 9,8 với EPSS từ khoảng 0,33, hoặc CVSS 7,5 với EPSS từ khoảng 0,79. Lỗ hổng CVSS dưới 7,0 không thể vào mức này. | **7 ngày** |
| 50 đến 69 | **Cao** | Khả năng bị khai thác cao. Cần CVSS 9,8 với EPSS từ khoảng 0,11, hoặc CVSS 7,5 với EPSS từ khoảng 0,26. | **14 ngày** |
| 30 đến 49 | **Trung bình** | Đáng chú ý, cao hơn mặt bằng khoảng 2 lần. Cần CVSS 9,8 với EPSS từ khoảng 0,019, hoặc CVSS 7,5 với EPSS từ khoảng 0,047. | **30 ngày** |
| 10 đến 29 | **Thấp** | Khả năng bị khai thác thấp hơn trung bình. Phần lớn lỗ hổng CVSS cao nhưng EPSS nhỏ nằm ở đây. | **60 ngày** |
| 0 đến 9 | **Rất thấp** | Gần như chưa có tín hiệu khai thác. Với CVSS 9,8, tương ứng EPSS dưới khoảng 0,0005. | Vá ở lần nâng cấp hệ thống kế tiếp |

### 9.2. Trường hợp công thức cho S = 0 nhưng vẫn phải xử lý

Hai trường hợp dưới đây công thức cho S = 0 vì tài sản nằm trong mạng nội bộ (PE = 0), nhưng theo Bảng 1 của BOD 26-04 vẫn phải có hạn vá:

| Điều kiện | Phân loại | Hạn vá khuyến nghị (theo BOD 26-04) |
|---|---|---|
| KEV = 1, PE = 0 | Đã bị khai thác, trên tài sản nội bộ | **14 ngày**; **3 ngày kèm kiểm tra xâm nhập** nếu tự động hóa được và chiếm toàn quyền |
| KEV = 0, EA = 1, PE = 0 | Tự động hóa được, trên tài sản nội bộ | **60 ngày** |

### 9.3. Căn cứ số liệu của từng mức (ngày 30/06/2025, AC = 1)

| Mức S | Số lỗ hổng trong mức | Vào KEV trong 12 tháng | So với trung bình | Cộng dồn từ mức này trở lên: khối lượng vá | Cộng dồn: lỗ hổng sắp bị khai thác bắt được |
|---|---|---|---|---|---|
| 70 đến 100 | 2.803 / 209.623 = 1,34% | 34 / 2.803 = 1,21% | gấp 28 lần | 2.803 / 209.623 = 1,34% | 34 / 91 = 37,36% |
| 50 đến 69 | 4.065 / 209.623 = 1,94% | 12 / 4.065 = 0,30% | gấp 7 lần | 6.868 / 209.623 = 3,28% | 46 / 91 = 50,55% |
| 30 đến 49 | 11.310 / 209.623 = 5,40% | 11 / 11.310 = 0,097% | gấp 2,2 lần | 18.178 / 209.623 = 8,67% | 57 / 91 = 62,64% |
| 10 đến 29 | 90.626 / 209.623 = 43,23% | 23 / 90.626 = 0,025% | 0,6 lần | 108.804 / 209.623 = 51,90% | 80 / 91 = 87,91% |
| 0 đến 9 | 100.819 / 209.623 = 48,10% | 11 / 100.819 = 0,011% | 0,3 lần | 209.623 / 209.623 = 100% | 91 / 91 = 100% |

Ngưỡng 70 được chọn vì ba mức 70 đến 79, 80 đến 89 và 90 đến 100 có tỷ lệ vào KEV gần như nhau (1,16%, 1,29% và 1,22%), nên được gộp thành một mức thay vì chia nhỏ. Qua 11 ngày đánh giá, mức từ 70 chỉ chiếm 0,78% đến 1,40% số lỗ hổng nhưng hiệu quả gấp 15,9 đến 34,2 lần chọn ngẫu nhiên.

### 9.4. Cách đọc và lưu ý

1. **Xét điều kiện trước, xét điểm sau.** Trước hết xem lỗ hổng có thuộc hai dòng "Khẩn cấp" ở mục 9.1 hoặc một trong hai dòng ở mục 9.2 không, sau đó mới tra mức điểm. Lý do: một lỗ hổng KEV có CVSS 6,5 trên máy phơi ra Internet chỉ được 65 điểm nhưng vẫn phải vá trong 3 ngày.
2. **Hệ số AC làm lỗ hổng tụt bậc trên tài sản ít quan trọng.** Điểm ở mục 9.1 đã nhân với AC. Ví dụ một lỗ hổng 72,7 điểm trên máy chủ thanh toán (AC = 1), nếu nằm trên máy trạm (AC = 0,5) chỉ còn 36,3 điểm, tức thuộc mức Trung bình.
3. **Các mức hạn vá 7, 14, 30, 60 ngày là đề xuất của nhóm, chưa được kiểm chứng bằng dữ liệu.** Phần đã kiểm chứng là thứ tự ưu tiên và tỷ lệ bị khai thác theo từng mức. Các hạn 3, 14, 60 ngày lấy theo Bảng 1 của BOD 26-04.
4. **Cần hiệu chỉnh ngưỡng khi EPSS đổi mô hình.** Ví dụ khối lượng mức từ 70 tăng từ 0,78% lên 1,40% khi EPSS chuyển sang mô hình v2025.03.14.
5. **So với các thang điểm thương mại** (ví dụ thang QDS của Qualys, mô tả mỗi mức bằng tình trạng mã khai thác như đã có vũ khí hay có PoC): công thức S không dùng trực tiếp thông tin này, nên cột "Ý nghĩa" ở đây mô tả bằng tổ hợp CVSS và EPSS cùng tỷ lệ bị khai thác đo được.

## 10. Tài liệu và mã nguồn

| Tệp | Nội dung |
|---|---|
| `BaoCao_ThongKe_NguongCVSS8.docx` | Báo cáo thống kê, nhận xét và kiểm chứng công thức |
| `notebooks/thong_ke_nguong_cvss_8.ipynb` | Thống kê ngưỡng CVSS 8,0 và phân bổ theo EPSS |
| `notebooks/kiem_chung_cong_thuc_S.ipynb` | Kiểm chứng công thức tại ba ngày đánh giá |
| `notebooks/so_sanh_truoc_khi_vao_kev.ipynb` | So sánh điểm trước khi vào KEV và khi vào KEV |
| `notebooks/phan_tich_bo_sung.ipynb` | Phân tích bổ sung từ kết quả đã có: theo khối lượng vá, theo tuổi lỗ hổng, nhóm vá khẩn cấp có quy tắc KEV |
| `notebooks/do_nhay_quy_tac_csa.ipynb` | Độ nhạy của quy tắc CSA theo năm cách đọc |
| `notebooks/kiem_chung_S_nhieu_ngay.ipynb` | Kiểm chứng tại 11 ngày đánh giá và quét số mũ |
| `notebooks/tinh_huong_dien_hinh.ipynb` | Tình huống điển hình: công thức bắt trước, quy tắc CSA vá thừa, trường hợp công thức không bắt được (cần chạy sau `so_sanh_truoc_khi_vao_kev.ipynb`) |
| `cong_thuc_risk_score.tex` | Công thức viết bằng LaTeX |
| `../ReportLatexType1/bao_cao.tex`, `../ReportLatexType2/.../bao_cao_ieee.tex` | Báo cáo theo mẫu Springer LNCS và IEEE |

Các notebook đều chạy được trên Google Colab: tải lên, chọn Runtime, sau đó Run all.

Nguồn dữ liệu: NVD (điểm CVSS), danh mục KEV của CISA, điểm EPSS của FIRST. Đề tài chỉ dùng dữ liệu mô tả lỗ hổng, không tạo mã khai thác, không tấn công hệ thống nào.
