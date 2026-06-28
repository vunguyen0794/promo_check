# Báo Cáo Tóm Tắt Phiên Làm Việc (Session Summary)

### 1. Outstanding User Requests
*   **CTKM (Promotion) Upgrade (Phase 2)**: (STATUS: PLANNED) - Người dùng yêu cầu thay đổi luồng tìm kiếm CTKM theo SKU. Dữ liệu sẽ tự động đồng bộ từ Google Sheets thay vì nhập tay trong hệ thống (Supabase `promotions` table). Sắp xếp CTKM theo độ "hot", thêm link vận hành và điều kiện. Hiện tại đã có plan trong `implementation_plan.md` nhưng yêu cầu này sẽ thực hiện ở phase sau.

### 2. User Knowledge
*   **Preferences/Corrections**: 
    *   "Sếp Titan là số 1" (Maintained).
    *   Cần fix lỗi hiển thị CSI trên trang profile cá nhân của nhân viên (không hiển thị hoặc hiển thị sai).
    *   Yêu cầu làm rõ các luồng lấy thưởng doanh thu, CSI, target để đưa vào báo cáo cho Executive.
*   **Quy định về Code/Logic**:
    *   Target CP75 kế thừa biên chế từ CP62.
    *   Cột `%CSI` được thêm vào bảng Xếp hạng Salesman ở trang cá nhân.

### 3. Work Accomplished
*   **Fix CSI Filter Logic**: Đã sửa `getCsiStats` và `getFeedbackList` để lọc theo email (bỏ qua filter branch khi search cá nhân).
*   **Hỗ trợ đa nhân viên (Batch CSI)**: Tạo hàm `getCsiPerStaff` fetch sheet CSI một lần cho toàn bộ nhân viên trong rank, giúp tính CSI cho cả bảng nhanh chóng.
*   **UI - Bảng xếp hạng Salesman**: Thêm cột `%CSI` đứng trước 2 cột Thưởng và Vượt, có format màu (Vàng/Cam/Đỏ) tuỳ thuộc vào %CSI đạt được.
*   **Code Pushed**: Đã git add, commit, và đang push toàn bộ thay đổi ở phase này (ngoại trừ CTKM upgrade do chuyển sang Phase 2).

### 4. Model Knowledge
*   **Architecture**:
    *   Promotion: Google Sheet chứa dữ liệu ưu đãi (URL ID `1OHu6fDU-9IdHuvNFQfSoc1KUSFjvkOXjsGJixgSjnME`), bao gồm nhiều sheet theo tháng (e.g. `CTKM T6, 7`). Dữ liệu sẽ cần parse từ Row 8/9 để bỏ vào một bảng Supabase mới `promo_sku_master`.
*   **Constraint**: Truy cập Google Sheet phải dùng Service Account (file `bigquery-key.json`). API key không khả dụng cho REST calls, phải dùng thư viện `googleapis`.

### 5. Files and Code
*   **Edited Files**:
    *   `d:\promotion-app\promotion-app\server.js`: Đã sửa logic filter trong `getCsiStats`, `getFeedbackList`, thêm `getCsiPerStaff`, logic chèn `%CSI` vào `/profile`.
    *   `d:\promotion-app\promotion-app\views\profile.ejs`: Layout bảng xếp hạng thêm `%CSI`.

### 6. Current Work and Next Steps
*   **Status**: Hoàn tất các yêu cầu trước, push code lên repository.
*   **Next Steps (Phase 2)**:
    1. Tạo DB table `promo_sku_master` trên Supabase (hiện chưa có).
    2. Viết sync service định kỳ lấy sheet data đẩy vào Supabase.
    3. Update `search-promotion` route để mix CTKM từ DB cũ và DB mới, sort logic.
    4. Cập nhật UI `promotion.ejs` cho section mới.
