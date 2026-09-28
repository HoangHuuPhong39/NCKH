# Kịch Bản Trình Diễn Báo Cáo Bảo Vệ (Thesis Defense Demo Script)

Tài liệu này cung cấp kịch bản chi tiết từng phút (3-Minute Screencast Script) để bạn quay video/GIF hoặc trình diễn trực tiếp (Live Demo) trước Hội đồng Đánh giá Nghiên cứu Khoa học.

---

##  1. Công Cụ Khuyến Nghị Để Quay Màn Hình
- **OBS Studio (Khuyến nghị cho Video MP4 Full HD):** Miễn phí, không watermark, quay độ phân giải 1080p/60fps.
- **ShareX / LICEcap (Khuyến nghị cho GIF nén đưa vào Slide/README):** Xuất file `.gif` dung lượng nhẹ, tự động tối ưu hóa bảng màu.

---

##  2. Kịch Bản Chi Tiết 3 Phút (3-Minute Defense Demo)

###  [00:00 - 00:30] — Khởi Động & Giới Thiệu Giao Diện Web SOC
- **Thao tác:**
  1. Mở terminal, chạy lệnh khởi động máy chủ:
     ```bash
     python web/app.py
     ```
  2. Mở trình duyệt tại `http://localhost:5000`.
- **Lời thuyết trình (Talking Points):**
  > *"Kính thưa Hội đồng, đây là giao diện Web Dashboard của Bộ công cụ AI Security Scanner. Hệ thống được thiết kế theo phong cách Security Operations Center (SOC) hiện đại, tích hợp giám sát thời gian thực qua Server-Sent Events (SSE). Bảng điều khiển gồm thanh trạng thái kết nối tới máy chủ suy luận Ollama, danh sách các Attack Modules chuẩn hóa theo OWASP Top 10 for LLMs 2025 và MITRE ATLAS."*

###  [00:30 - 01:15] — Thực Thi Quét Module Jailbreak (Real-time Scan)
- **Thao tác:**
  1. Nhấp chọn module **Jailbreak / Safety Bypass (LLM01)**.
  2. Xem danh sách payload và nhấn nút **▶ Run Module** (hoặc dùng tính năng chỉnh sửa payload trực tiếp).
  3. Quan sát **Thanh tiến độ (%)** tăng dần và **Terminal Streaming** hiển thị kết quả từng mili-giây.
- **Lời thuyết trình (Talking Points):**
  > *"Em tiến hành quét module Jailbreak. Hệ thống sử dụng cơ chế xử lý không đồng bộ (Asynchronous Worker). Khi mỗi payload được gửi tới mô hình LLaMA-3, phản hồi lập tức đi qua cơ chế phát hiện hai lớp: Tier-1 Pattern Matcher lọc nhanh và Tier-2 LLM-as-Judge đánh giá ngữ nghĩa. Điểm rủi ro CVSS-like được tính toán tự động từ 0.0 đến 10.0."*

###  [01:15 - 02:00] — Khảo Sát Bảng Lỗ Hổng & Drill-down Modal
- **Thao tác:**
  1. Chuyển sang tab ** Findings**.
  2. Nhấp vào một lỗ hổng phát hiện (dòng màu đỏ Critical / High) để mở **Drill-down Modal**.
  3. Trình chiếu: Toàn văn Payload, Phản hồi của AI, Điểm rủi ro, Chỉ số kỹ thuật OWASP/MITRE, và **Khuyến nghị khắc phục (Remediation Guidance)**.
  4. Trình diễn nút **Sao chép Payload** và **Sao chép Phản hồi**.
  5. Thử nghiệm **Bộ lọc Lịch chọn ngày** (chọn dropdown ngày hoặc mở lịch đồ họa).
- **Lời thuyết trình (Talking Points):**
  > *"Tại bảng phát hiện lỗ hổng, nhà phân tích có thể lọc nhanh theo mức độ nghiêm trọng hoặc mốc ngày quét. Khi nhấp vào chi tiết, hệ thống cung cấp đầy đủ thông tin truy nguyên: bằng chứng tấn công, phản hồi thực tế và hướng dẫn khắc phục cụ thể cho đội ngũ kỹ sư hệ thống theo chuẩn OWASP."*

###  [02:00 - 02:40] — Báo Cáo Thống Kê & Xuất File (Report Export)
- **Thao tác:**
  1. Chuyển sang tab ** Dashboard**: Chỉ vào biểu đồ tròn **Phân bổ theo Severity** và biểu đồ cột **Findings theo Module**.
  2. Chuyển sang tab ** Báo Cáo**: Nhấn ** Tạo HTML Report** và nhấn **⬇ Tải HTML** / ** Xuất JSON**.
  3. Mở file `report.html` vừa tải về trên trình duyệt.
- **Lời thuyết trình (Talking Points):**
  > *"Hệ thống tổng hợp dữ liệu trực quan bằng biểu đồ Chart.js và cung cấp công cụ xuất báo cáo kiểm thử tự động định dạng HTML và JSON chuẩn, sẵn sàng tích hợp vào hệ thống SIEM/SOAR hoặc gửi cho các bên kiểm toán độc lập."*

###  [02:40 - 03:00] — Kết Luận & Cổng API Docs (Swagger)
- **Thao tác:**
  1. Nhấp nút ** API Docs** trên thanh điều hướng để mở trang `http://localhost:5000/docs`.
  2. Thao tác nút chuyển đổi ** Giao diện Sáng /  Giao diện Tối**.
- **Lời thuyết trình (Talking Points):**
  > *"Cuối cùng, hệ thống cung cấp chuẩn giao tiếp RESTful API OpenAPI 3.0 với giao diện tương tác Swagger UI có 2 chế độ sáng/tối độ tương phản cao, phục vụ tự động hóa DevSecOps trong quy trình phát triển phần mềm an toàn."*
