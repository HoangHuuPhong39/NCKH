# -*- coding: utf-8 -*-
"""
web/openapi.py - Clean High-Contrast Cybersecurity OpenAPI 3.0 & Swagger UI
"""

SWAGGER_UI_HTML = """<!DOCTYPE html>
<html lang="vi" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Documentation · AI Security Scanner v2.0</title>
  <link rel="stylesheet" href="/static/swagger-ui.css" />
  <link rel="icon" type="image/jpeg" href="/static/logo.jpg">

  <style>
    /* ══════════════════════════════════════════════════
       THEME VARIABLES - SYNCHRONIZED WITH MAIN APP
       ══════════════════════════════════════════════════ */
    :root[data-theme="dark"] {
      --bg-base: #090d16;
      --bg-surface: #101726;
      --bg-card: #131c2e;
      --bg-inner: #0c121e;
      --border-color: #334155;
      --border-focus: #475569;
      --text-heading: #f8fafc;
      --text-body: #cbd5e1;
      --text-muted: #94a3b8;
      --text-subtle: #64748b;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --nav-bg: #090d16;
      --code-bg: #070a10;
      --input-bg: #0a0f1a;
    }

    :root[data-theme="light"] {
      --bg-base: #f8fafc;
      --bg-surface: #ffffff;
      --bg-card: #ffffff;
      --bg-inner: #f8fafc;
      --border-color: #cbd5e1;
      --border-focus: #94a3b8;
      --text-heading: #0f172a;
      --text-body: #334155;
      --text-muted: #64748b;
      --text-subtle: #94a3b8;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --nav-bg: #f8fafc;
      --code-bg: #0f172a;
      --input-bg: #ffffff;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 0;
      background-color: var(--bg-base);
      color: var(--text-body);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      line-height: 1.5;
      font-size: 14.5px;
      -webkit-font-smoothing: antialiased;
    }

    /* ══════════════════════════════════════════════════
       TOPBAR NAVIGATION
       ══════════════════════════════════════════════════ */
    .docs-nav {
      position: sticky;
      top: 0;
      z-index: 1000;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      height: 64px;
      background-color: var(--nav-bg);
      border-bottom: 1px solid var(--border-color);
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
    }
    .brand-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text-heading);
    }
    .brand-pill {
      font-size: 11px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      background-color: var(--bg-inner);
      color: var(--text-muted);
      border: 1px solid var(--border-color);
      font-family: "JetBrains Mono", Consolas, monospace;
    }
    .nav-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .nav-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 16px;
      font-size: 13px;
      font-weight: 600;
      border-radius: 6px;
      text-decoration: none;
      transition: background-color 0.12s, border-color 0.12s, color 0.12s;
      cursor: pointer;
      border: 1px solid transparent;
      font-family: inherit;
    }
    .nav-btn-primary {
      background-color: var(--accent);
      color: #ffffff !important;
      border-color: var(--accent);
    }
    .nav-btn-primary:hover {
      background-color: var(--accent-hover);
    }
    .nav-btn-outline {
      background-color: transparent;
      color: var(--text-body);
      border-color: var(--border-color);
    }
    .nav-btn-outline:hover {
      background-color: var(--bg-inner);
      border-color: var(--border-focus);
    }

    /* ══════════════════════════════════════════════════
       HERO OVERVIEW CARD
       ══════════════════════════════════════════════════ */
    .docs-hero {
      max-width: 1300px;
      margin: 32px auto 0 auto;
      padding: 0 20px;
    }
    .hero-card {
      background-color: transparent;
      border-bottom: 1px solid var(--border-color);
      padding: 0 0 24px 0;
      margin-bottom: 24px;
    }
    .hero-title {
      font-size: 22px;
      font-weight: 700;
      color: var(--text-heading);
      margin: 0 0 12px 0;
    }
    .hero-desc {
      font-size: 14.5px;
      color: var(--text-muted);
      margin: 0;
      max-width: 900px;
      line-height: 1.6;
    }
    .hero-badges {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 20px;
    }
    .hero-badge {
      font-size: 12px;
      font-weight: 600;
      padding: 4px 12px;
      border-radius: 6px;
      background-color: var(--bg-surface);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
    }

    /* ══════════════════════════════════════════════════
       SWAGGER UI SOLID OVERRIDES
       ══════════════════════════════════════════════════ */
    .swagger-ui {
      max-width: 1300px !important;
      margin: 0 auto !important;
      padding: 0 20px 80px 20px !important;
      font-family: inherit !important;
    }

    .swagger-ui .topbar { display: none !important; }
    .swagger-ui .information-container { display: none !important; }

    .swagger-ui .scheme-container {
      background-color: transparent !important;
      border: none !important;
      border-bottom: 1px solid var(--border-color) !important;
      border-radius: 0 !important;
      padding: 0 0 24px 0 !important;
      margin-bottom: 32px !important;
      box-shadow: none !important;
    }
    .swagger-ui .servers-title {
      color: var(--text-heading) !important;
      font-size: 14px !important;
      font-weight: 700 !important;
      margin-bottom: 8px !important;
    }
    .swagger-ui .servers select {
      background-color: var(--input-bg) !important;
      color: var(--text-body) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: 6px !important;
      padding: 8px 16px !important;
      font-size: 13.5px !important;
      font-family: "JetBrains Mono", Consolas, monospace !important;
    }

    .swagger-ui .filter .operation-filter-input {
      background-color: var(--input-bg) !important;
      color: var(--text-heading) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: 6px !important;
      padding: 10px 16px !important;
      font-size: 14px !important;
      margin: 0 0 24px 0 !important;
      box-shadow: none !important;
    }
    .swagger-ui .filter .operation-filter-input:focus {
      border-color: var(--accent) !important;
    }

    .swagger-ui .opblock-tag {
      color: var(--text-heading) !important;
      font-size: 18px !important;
      font-weight: 700 !important;
      border-bottom: 1px solid var(--border-color) !important;
      padding: 16px 0 !important;
      margin-bottom: 16px !important;
    }
    .swagger-ui .opblock-tag small {
      color: var(--text-muted) !important;
      font-size: 13.5px !important;
      font-weight: 400 !important;
    }

    /* Operation Blocks - Flat Solid Borders */
    .swagger-ui .opblock {
      background-color: var(--bg-card) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: 8px !important;
      margin-bottom: 12px !important;
      box-shadow: none !important;
      overflow: hidden;
    }

    .swagger-ui .opblock .opblock-summary {
      padding: 10px 16px !important;
      border-bottom: 1px solid transparent !important;
    }
    .swagger-ui .opblock.is-open .opblock-summary {
      border-bottom-color: var(--border-color) !important;
    }

    .swagger-ui .opblock .opblock-summary-method {
      border-radius: 6px !important;
      font-size: 12px !important;
      font-weight: 800 !important;
      padding: 6px 12px !important;
      min-width: 80px !important;
      text-align: center !important;
      font-family: "JetBrains Mono", Consolas, monospace !important;
    }

    /* Solid Method Badges */
    .swagger-ui .opblock.opblock-get .opblock-summary-method {
      background-color: #2563eb !important;
      color: #ffffff !important;
    }
    .swagger-ui .opblock.opblock-post .opblock-summary-method {
      background-color: #16a34a !important;
      color: #ffffff !important;
    }
    .swagger-ui .opblock.opblock-delete .opblock-summary-method {
      background-color: #dc2626 !important;
      color: #ffffff !important;
    }
    .swagger-ui .opblock.opblock-put .opblock-summary-method {
      background-color: #d97706 !important;
      color: #ffffff !important;
    }

    .swagger-ui .opblock .opblock-summary-path a span {
      color: var(--text-heading) !important;
      font-size: 14px !important;
      font-family: "JetBrains Mono", Consolas, monospace !important;
      font-weight: 600 !important;
    }

    .swagger-ui .opblock .opblock-summary-description {
      color: var(--text-muted) !important;
      font-size: 13.5px !important;
    }

    /* Text Color Fixes for Markdown and inner elements */
    .swagger-ui .markdown p,
    .swagger-ui .markdown li,
    .swagger-ui .opblock-description-wrapper p,
    .swagger-ui .responses-inner h4,
    .swagger-ui .responses-inner h5,
    .swagger-ui .response-col_status,
    .swagger-ui .response-col_description,
    .swagger-ui .response-col_links,
    .swagger-ui .parameter__in,
    .swagger-ui .opblock-body p,
    .swagger-ui table thead tr td,
    .swagger-ui table tbody tr td {
      color: var(--text-body) !important;
    }

    .swagger-ui .opblock-body {
      background-color: var(--bg-surface) !important;
      padding: 20px !important;
    }

    .swagger-ui .opblock-section-header {
      background-color: transparent !important;
      border-bottom: 1px solid var(--border-color) !important;
      padding: 12px 0 !important;
      margin-bottom: 16px !important;
    }
    .swagger-ui .opblock-section-header h4 {
      color: var(--text-heading) !important;
      font-size: 14px !important;
      font-weight: 700 !important;
    }

    .swagger-ui table thead tr th {
      color: var(--text-muted) !important;
      font-size: 12px !important;
      font-weight: 700 !important;
      text-transform: uppercase !important;
      border-bottom: 1px solid var(--border-color) !important;
      padding: 12px 8px !important;
    }
    .swagger-ui table tbody tr td {
      color: var(--text-body) !important;
      font-size: 13.5px !important;
      border-bottom: 1px solid var(--border-color) !important;
      padding: 12px 8px !important;
    }

    .swagger-ui .parameter__name {
      color: var(--text-heading) !important;
      font-weight: 700 !important;
      font-family: "JetBrains Mono", Consolas, monospace !important;
      font-size: 13px !important;
    }
    .swagger-ui .parameter__type {
      color: var(--accent) !important;
      font-size: 12px !important;
      font-family: "JetBrains Mono", Consolas, monospace !important;
    }

    /* Buttons inside Swagger UI */
    .swagger-ui .btn {
      border-radius: 6px !important;
      font-size: 13px !important;
      font-weight: 600 !important;
      padding: 8px 16px !important;
      border: 1px solid var(--border-color) !important;
      background-color: var(--bg-card) !important;
      color: var(--text-body) !important;
      box-shadow: none !important;
    }
    .swagger-ui .btn.execute {
      background-color: var(--accent) !important;
      color: #ffffff !important;
      border-color: var(--accent) !important;
    }
    .swagger-ui .btn.cancel {
      background-color: transparent !important;
      color: #dc2626 !important;
      border-color: #dc2626 !important;
    }

    /* Code & JSON Output */
    .swagger-ui .highlight-code,
    .swagger-ui pre {
      background-color: var(--code-bg) !important;
      border: 1px solid var(--border-color) !important;
      border-radius: 8px !important;
      color: #38bdf8 !important;
      font-family: "JetBrains Mono", Consolas, monospace !important;
      font-size: 13px !important;
      padding: 16px !important;
    }
    .swagger-ui pre code {
      color: #e2e8f0 !important;
      font-family: "JetBrains Mono", Consolas, monospace !important;
    }

    .swagger-ui svg {
      fill: var(--text-muted) !important;
    }
  </style>
</head>
<body>

  <!-- Top Navigation Bar -->
  <nav class="docs-nav">
    <a href="/" class="nav-brand">
      <div>
        <span class="brand-title">AI Security Scanner</span>
        <span class="brand-pill">API v2.0</span>
      </div>
    </a>
    <div class="nav-actions">
      <button class="nav-btn nav-btn-outline" id="theme-btn" onclick="toggleTheme()" title="Switch Light/Dark Theme">
        <span id="theme-text">Theme: Light</span>
      </button>
      <a href="/" class="nav-btn nav-btn-primary">
        Back to Dashboard
      </a>
      <a href="/api/openapi.json" target="_blank" class="nav-btn nav-btn-outline">
        OpenAPI JSON Spec
      </a>
      <a href="/api/health" target="_blank" class="nav-btn nav-btn-outline">
        Health Check
      </a>
    </div>
  </nav>

  <!-- Hero Overview Card -->
  <header class="docs-hero">
    <div class="hero-card">
      <div class="hero-title">REST API Specification & Testing Console</div>
      <p class="hero-desc">
        Comprehensive OpenAPI 3.0 specification and interactive testing console for the AI Security Scanner framework.
        Directly benchmarkable against OWASP Top 10 for LLM Applications 2025 and MITRE ATLAS Matrix.
      </p>
      <div class="hero-badges">
        <span class="hero-badge">OWASP LLM 2025</span>
        <span class="hero-badge">MITRE ATLAS Matrix</span>
        <span class="hero-badge">Bearer JWT Auth</span>
        <span class="hero-badge">Prometheus Metrics</span>
        <span class="hero-badge">Server-Sent Events</span>
      </div>
    </div>
  </header>

  <!-- Swagger UI Mount Point -->
  <div id="swagger-ui"></div>

  <script src="/static/swagger-ui-bundle.js"></script>
  <script>
    function initTheme() {
      const savedTheme = localStorage.getItem('ai_scanner_theme') || 'dark';
      applyTheme(savedTheme);
    }

    function applyTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('ai_scanner_theme', theme);
      const text = document.getElementById('theme-text');
      if (text) {
        text.textContent = theme === 'dark' ? 'Theme: Light' : 'Theme: Dark';
      }
    }

    function toggleTheme() {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      applyTheme(next);
    }

    window.onload = function() {
      initTheme();
      window.ui = SwaggerUIBundle({
        url: "/api/openapi.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout",
        defaultModelsExpandDepth: -1,
        docExpansion: "list",
        filter: true,
        showExtensions: true,
        showCommonExtensions: true
      });
    };
  </script>
</body>
</html>
"""

def get_openapi_spec() -> dict:
    """Returns the complete OpenAPI 3.0 specification dictionary."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "AI Security Scanner REST API",
            "description": "Production-grade RESTful API for AI Red-Teaming, Automated Vulnerability Assessment, and OWASP Top 10 for LLMs 2025 Auditing.",
            "version": "2.0.0",
            "contact": {
                "name": "AI Security Research Lab",
                "url": "https://github.com/your-org/AI_Security_Scanner"
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        },
        "servers": [
            {"url": "http://localhost:5000", "description": "Local development server"}
        ],
        "tags": [
            {"name": "System & Health", "description": "Kiểm tra sức khỏe hệ thống, giám sát metrics và observability"},
            {"name": "Scanning & Exploitation", "description": "Khởi chạy, theo dõi tiến độ thời gian thực (SSE) và hủy phiên quét"},
            {"name": "Findings & Analytics", "description": "Truy vấn danh sách lỗ hổng phát hiện, thống kê rủi ro CVSS và lịch sử quét"},
            {"name": "Authentication & Config", "description": "Xác thực JWT Token, quản lý API Key và cấu hình mục tiêu"}
        ],
        "paths": {
            "/api/health": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Kiểm tra tình trạng sức khỏe hệ thống (Health Check)",
                    "description": "Kiểm tra trạng thái kết nối SQLite Database, tiến trình worker nền và phiên bản hệ thống.",
                    "responses": {
                        "200": {
                            "description": "Hệ thống hoạt động bình thường (healthy) hoặc suy giảm (degraded)",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "status": "healthy",
                                        "database": "connected",
                                        "scanner_running": False,
                                        "active_module": None,
                                        "timestamp": "2026-09-25T21:15:00",
                                        "version": "2.0.0"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/metrics": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Số liệu thống kê hoạt động định dạng JSON",
                    "description": "Cung cấp tổng số lượt scan, số phát hiện phân bổ theo severity và thời gian uptime.",
                    "responses": {
                        "200": {"description": "Dữ liệu JSON thống kê vận hành"}
                    }
                }
            },
            "/metrics": {
                "get": {
                    "tags": ["System & Health"],
                    "summary": "Endpoint Prometheus Exporter Scraping",
                    "description": "Xuất dữ liệu định dạng chuẩn Prometheus (text/plain) phục vụ cào metrics bởi Prometheus Server và hiển thị trên Grafana.",
                    "responses": {
                        "200": {
                            "description": "Dữ liệu text/plain Prometheus format",
                            "content": {"text/plain": {}}
                        }
                    }
                }
            },
            "/api/auth/login": {
                "post": {
                    "tags": ["Authentication & Config"],
                    "summary": "Đăng nhập và cấp phát Bearer JWT Token",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "api_key": {"type": "string", "example": "ai-scanner-admin-secret-token"},
                                        "username": {"type": "string", "example": "admin"},
                                        "password": {"type": "string", "example": "ai-scanner-admin-secret-token"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Đăng nhập thành công, trả về JWT bearer token có hiệu lực 24h"},
                        "401": {"description": "Thông tin xác thực không chính xác"}
                    }
                }
            },
            "/api/modules": {
                "get": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Danh sách tất cả Attack Modules đã nạp",
                    "description": "Trả về thông tin chi tiết các module tấn công (OWASP 2025, MITRE ATLAS, số lượng payload, mức độ nghiêm trọng).",
                    "responses": {
                        "200": {"description": "Từ điển metadata của 8 exploit modules + 1 auxiliary module"}
                    }
                }
            },
            "/api/scan/run": {
                "post": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Khởi chạy quét một Attack Module cụ thể",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["module", "target_url", "target_model"],
                                    "properties": {
                                        "module": {"type": "string", "example": "jailbreak", "description": "Tên module (jailbreak, prompt_injection, rag_security, excessive_agency, ...)"},
                                        "target_url": {"type": "string", "example": "http://localhost:11434", "description": "URL endpoint LLM mục tiêu"},
                                        "target_model": {"type": "string", "example": "llama3", "description": "Tên mô hình AI"},
                                        "timeout": {"type": "integer", "example": 60, "description": "Thời gian timeout (giây)"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Khởi động phiên scan thành công"},
                        "400": {"description": "Dữ liệu đầu vào không hợp lệ (URL scheme sai, module không tồn tại)"},
                        "409": {"description": "Đang có một phiên quét khác chạy dở"}
                    }
                }
            },
            "/api/scan/run-all": {
                "post": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Khởi chạy chuỗi quét toàn diện tất cả các Modules",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "modules": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "example": ["prompt_injection", "jailbreak", "rag_security", "excessive_agency"]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Chuỗi quét đa modules đã bắt đầu"}
                    }
                }
            },
            "/api/scan/cancel": {
                "post": {
                    "tags": ["Scanning & Exploitation"],
                    "summary": "Hủy tức thời phiên quét đang thực hiện",
                    "responses": {
                        "200": {"description": "Lệnh dừng đã được gửi tới worker thread"}
                    }
                }
            },
            "/api/findings": {
                "get": {
                    "tags": ["Findings & Analytics"],
                    "summary": "Truy vấn danh sách lỗ hổng và bộ lọc ngày",
                    "parameters": [
                        {"name": "severity", "in": "query", "schema": {"type": "string"}, "description": "Lọc theo severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"},
                        {"name": "module", "in": "query", "schema": {"type": "string"}, "description": "Lọc theo module ID"},
                        {"name": "date", "in": "query", "schema": {"type": "string"}, "description": "Lọc theo ngày (YYYY-MM-DD)"},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 100}}
                    ],
                    "responses": {
                        "200": {"description": "Danh sách findings chi tiết và danh sách ngày có dữ liệu"}
                    }
                }
            },
            "/api/scans": {
                "get": {
                    "tags": ["Findings & Analytics"],
                    "summary": "Truy vấn lịch sử các phiên quét",
                    "parameters": [
                        {"name": "date", "in": "query", "schema": {"type": "string"}, "description": "Lọc theo ngày (YYYY-MM-DD)"},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}}
                    ],
                    "responses": {
                        "200": {"description": "Danh sách các phiên scan đã thực hiện"}
                    }
                }
            }
        }
    }
