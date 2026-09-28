# Hướng Dẫn Triển Khai Hệ Thống (Deployment Guide)

> 💡 **Tài liệu đầy đủ và cập nhật mới nhất đã được chuyển tới [DEPLOYMENT.md](file:///d:/TTCS/NCKH/AI_Security_Scanner/docs/DEPLOYMENT.md).**

Vui lòng xem file [`docs/DEPLOYMENT.md`](file:///d:/TTCS/NCKH/AI_Security_Scanner/docs/DEPLOYMENT.md) để xem hướng dẫn chi tiết về:
- Triển khai Gunicorn WSGI Server đa luồng
- Thiết lập chứng chỉ HTTPS / SSL (Let's Encrypt & Self-signed cert script)
- Cấu hình Nginx Reverse Proxy với SSE buffering off
- Tích hợp giám sát Prometheus (`/metrics`) và Grafana
- Cấu hình cụm Redis Caching
- Quản lý dịch vụ tự khởi động Systemd
- Đóng gói và chạy bằng Docker & Docker Compose
