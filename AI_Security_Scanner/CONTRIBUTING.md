# Hướng Dẫn Đóng Góp Phát Triển (Contribution Guidelines)

Cảm ơn bạn đã quan tâm đến việc đóng góp vào dự án **AI Security Scanner**! Tài liệu này cung cấp các nguyên tắc, tiêu chuẩn mã nguồn và quy trình để gửi mã nguồn (Pull Requests) hoặc báo cáo lỗi (Issues).

---

## 1. Nguyên Tắc Ứng Xử (Code of Conduct)
- Tôn trọng và hỗ trợ các thành viên trong nhóm nghiên cứu.
- Các mô-đun tấn công và payload chỉ được sử dụng cho mục đích nghiên cứu học thuật, kiểm thử an toàn nội bộ (Red-Teaming) và phòng thủ (Defense). Nghiêm cấm sử dụng cho các hành vi tấn công trái phép.

---

## 2. Thiết Lập Môi Trường Phát Triển (Development Setup)

### 2.1 Yêu cầu tiên quyết
- Python 3.10, 3.11, hoặc 3.12
- Git
- Ollama (hoặc OpenAI API Key) để chạy thử nghiệm các mô hình LLM

### 2.2 Các bước cài đặt
```bash
# 1. Clone kho lưu trữ
git clone https://github.com/your-org/AI_Security_Scanner.git
cd AI_Security_Scanner

# 2. Tạo môi trường ảo
python -m venv venv
source venv/bin/activate  # Trên Windows: .\venv\Scripts\activate

# 3. Cài đặt các thư viện phát triển và kiểm thử
pip install -r requirements.txt
pip install pre-commit black flake8 mypy

# 4. Kích hoạt Git Pre-commit Hooks
pre-commit install
```

---

## 3. Quy Chuẩn Mã Nguồn (Coding Standards)

- **Định dạng code:** Sử dụng `black` với độ dài dòng tối đa 120 ký tự (`--line-length=120`).
- **Kiểm tra cú pháp (Linting):** Tuân thủ tiêu chuẩn PEP 8 thông qua `flake8`.
- **Kiểm tra kiểu dữ liệu (Typing):** Khuyến khích sử dụng Type Hints (`typing`) và kiểm tra bằng `mypy`.
- **Đóng gói Modules:** Khi bổ sung một Attack Module mới vào `modules/exploits/`:
  - Kế thừa cấu trúc danh sách `payloads = [{"name": ..., "payload": ..., "category": ..., "owasp": ..., "mitre": ...}]`.
  - Cập nhật ánh xạ phân loại trong `core/risk_scorer.py` và `core/owasp_mapper.py`.
  - Đăng ký metadata hiển thị trong `MODULES_METADATA` tại `main.py` và `web/app.py`.
  - Bổ sung ca kiểm thử trong `tests/unit/test_pattern_detector.py`.

---

## 4. Kiểm Thử & Kiểm Định (Testing)

Trước khi gửi Pull Request, bắt buộc phải chạy toàn bộ bộ kiểm thử:
```bash
# Chạy toàn bộ unit tests và integration tests
pytest tests/ -v

# Chạy kiểm thử kèm báo cáo độ phủ (Coverage Report)
pytest tests/ --cov=core --cov=modules --cov=web --cov-report=term
```
*Tất cả 100% tests phải vượt qua (PASSED).*

---

## 5. Quy Trình Gửi Pull Request (PR Workflow)

1. **Tạo nhánh tính năng:**
   ```bash
   git checkout -b feature/ten-tinh-nang-moi
   # hoặc:
   git checkout -b fix/ten-loi-can-sua
   ```
2. **Commit mã nguồn:** Tuân thủ quy chuẩn Conventional Commits:
   - `feat: thêm module kiểm thử Indirect RAG Injection`
   - `fix: sửa lỗi tính điểm CVSS khi payload quá ngắn`
   - `docs: bổ sung hướng dẫn cấu hình TLS`
   - `test: thêm kiểm thử cho Circuit Breaker`
3. **Đẩy mã nguồn và tạo PR:**
   - Đảm bảo GitHub Actions CI Pipeline hoàn thành với trạng thái xanh (`Success`).
   - Mô tả rõ ràng mục đích thay đổi và đính kèm kết quả chạy thực nghiệm.
