# Cẩm Nang Xử Lý Sự Cố (Troubleshooting & FAQ)

Tài liệu này tổng hợp các sự cố thường gặp trong quá trình cài đặt, vận hành và kiểm thử hệ thống **AI Security Scanner**, cùng với các bước chẩn đoán và giải pháp khắc phục chi tiết.

---

## 1. Sự Cố Kết Nối Tới Mô Hình LLM Target

### 1.1 Lỗi: `[-] Connection error (Ollama): Connection refused`
- **Nguyên nhân:**
  1. Dịch vụ Ollama chưa được khởi động trên máy chủ đích.
  2. Ollama chỉ lắng nghe trên `127.0.0.1` nên không thể truy cập từ bên ngoài hoặc từ Docker container.
- **Cách khắc phục:**
  - Kiểm tra trạng thái Ollama:
    ```bash
    curl http://localhost:11434/api/tags
    ```
  - Nếu chạy trên Linux / macOS, bật cho phép truy cập từ mọi địa chỉ mạng bằng biến môi trường:
    ```bash
    export OLLAMA_HOST=0.0.0.0:11434
    ollama serve
    ```
  - Nếu scanner chạy trong Docker và Ollama chạy trên máy host: đổi `SCANNER_TARGET_URL` thành:
    - Trên Windows / macOS: `http://host.docker.internal:11434`
    - Trên Linux: `http://172.17.0.1:11434`

### 1.2 Lỗi: `[-] Request timed out after 60s (Ollama)`
- **Nguyên nhân:** Mô hình quá lớn (ví dụ LLaMA-3 70B hoặc chạy trên CPU không có GPU hỗ trợ), dẫn đến thời gian sinh token vượt quá ngưỡng timeout mặc định.
- **Cách khắc phục:**
  - Tăng thời gian timeout trong `config.yaml`:
    ```yaml
    scanner:
      timeout: 180  # Tăng lên 180 giây
    ```
  - Hoặc điều chỉnh trên giao diện Web Dashboard tại mục **Cài Đặt** $\rightarrow$ **Timeout** $\rightarrow$ Lưu cài đặt.

---

## 2. Sự Cố Circuit Breaker

### 2.1 Cảnh báo: `[-] Circuit breaker open: Circuit breaker is OPEN. Target server is failing`
- **Nguyên nhân:** Hệ thống phát hiện target LLM server bị lỗi liên tiếp (mặc định 5 lần) do sập mạng hoặc crash tiến trình. Cơ chế Circuit Breaker được kích hoạt để ngắt gọi tiếp tục, tránh gây treo luồng quét.
- **Cách khắc phục:**
  - Kiểm tra lại xem LLM server có đang hoạt động hay không.
  - Sau khi LLM server phục hồi, mạch sẽ tự động chuyển sang `HALF_OPEN` sau 30 giây và khôi phục về `CLOSED` bình thường ngay sau request thành công đầu tiên.
  - Có thể điều chỉnh ngưỡng trong `config.yaml`:
    ```yaml
    scanner:
      circuit_breaker:
        failure_threshold: 10
        recovery_timeout: 15
    ```

---

## 3. Sự Cố Database SQLite

### 3.1 Lỗi: `sqlite3.OperationalError: database is locked`
- **Nguyên nhân:** Nhiều luồng truy cập ghi đồng thời vào file `scanner.db` khi đang dùng chế độ rollback journal cũ.
- **Cách khắc phục:**
  - Hệ thống đã tích hợp chế độ **WAL (Write-Ahead Logging)** tự động. Nếu vẫn gặp sự cố trên môi trường mạng NFS/SMB, hãy chuyển database về ổ đĩa cục bộ:
    ```bash
    sqlite3 scanner.db "PRAGMA journal_mode=WAL;"
    ```

---

## 4. Sự Cố Web Dashboard & Streaming (SSE)

### 4.1 Terminal trên Web Dashboard không nhảy chữ theo thời gian thực (SSE bị đơ)
- **Nguyên nhân:**
  1. Khi triển khai qua Nginx reverse proxy, proxy buffering đang bật khiến Nginx gom dữ liệu thay vì gửi ngay lập tức.
  2. Các phần mềm diệt virus hoặc tường lửa trên máy trạm chặn kết nối HTTP chunked streaming.
- **Cách khắc phục:**
  - Đảm bảo trong cấu hình Nginx có các chỉ thị sau tại block `location /`:
    ```nginx
    proxy_buffering off;
    proxy_cache off;
    proxy_set_header X-Accel-Buffering no;
    ```

### 4.2 Giao diện chọn ngày không hiển thị lịch
- **Giải pháp:**
  - Nhấp vào nút **[🗓️ Mở lịch]** để mở lưới lịch đồ họa chọn ngày.
  - Hoặc chọn ngày trong danh sách xổ xuống **[📅 Chọn ngày]**.
  - Nhấp nút **[Hôm nay]** để lọc nhanh các phiên quét trong ngày hiện tại.

---

## 5. Sự Cố Redis Caching

### 5.1 Cảnh báo: `Redis unavailable (...), falling back to In-Memory cache`
- **Giải thích:** Đây là tính năng dự phòng an toàn (Graceful Degradation). Khi không cài đặt Redis hoặc chưa bật server Redis, hệ thống sẽ tự động chuyển sang bộ nhớ đệm RAM (In-Memory LRU Cache) mà không ảnh hưởng tới bất kỳ tính năng nào của hệ thống.
- **Cách khắc phục (nếu muốn dùng Redis thật):**
  - Khởi động Redis service: `docker run -d -p 6379:6379 redis:alpine`
  - Đặt biến môi trường: `export ENABLE_REDIS=true` và `export REDIS_URL=redis://localhost:6379/0`.

---

## 6. Truy Cập API Documentation (Swagger / OpenAPI)

- Tài liệu tương tác Swagger UI: `http://localhost:5000/docs` hoặc `http://localhost:5000/swagger`
- Chuẩn đặc tả thô JSON: `http://localhost:5000/api/openapi.json`
- Metrics giám sát Prometheus: `http://localhost:5000/metrics`
