"""
AI Security Scanner - Web Dashboard Backend
Modular Flask REST API with Blueprints and Multi-Subscriber SSE Streaming.
"""

import hmac
import json
import os
import queue
import sys
import threading
import time
import uuid
from datetime import datetime

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, Response, jsonify, render_template, request
from flask_cors import CORS

from core.config import cfg
from core.db import get_findings, get_stats, init_db, start_scan
from core.governance import log_audit_event
from core.llm_client import SimpleLLMClient
from core.logger import logger
from modules.registry import MODULES_METADATA, get_modules_metadata
from web.routes.governance import governance_bp
from web.routes.reports import reports_bp
from web.routes.sast_oss import sast_oss_bp
from web.security import (
    add_security_headers,
    generate_token,
    is_request_authenticated,
    rate_limit,
    require_auth,
    validate_config_request,
    validate_custom_payloads,
    validate_scan_request,
)
from web.services import scan_manager
from web.services.scan_manager import (
    SERVER_START_TIME,
    ScanBroadcaster,
    _launch_multi_module_scan,
    _parse_int_arg,
    app_config,
    cancel_event,
    risk_scorer,
    scan_lock,
    scan_queue,
    scan_status,
    scan_worker,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload cap
app.secret_key = cfg.get("web.jwt_secret_key")
_cors_origins = cfg.get("web.cors_origins", [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "https://localhost:5000",
    "https://127.0.0.1:5000",
])
CORS(app, origins=_cors_origins)

# Ensure SQLite schema/indexes exist under WSGI servers (Gunicorn) as well as direct runs
init_db()

# Register modular Blueprints
app.register_blueprint(reports_bp)
app.register_blueprint(sast_oss_bp)
app.register_blueprint(governance_bp)


@app.after_request
def apply_security_headers(response):
    return add_security_headers(response)


# ─────────────────────────────────────────────
# Routes: Pages
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/docs")
@app.route("/swagger")
def swagger_ui():
    """Interactive Swagger UI API Documentation."""
    from web.openapi import SWAGGER_UI_HTML
    return Response(SWAGGER_UI_HTML, mimetype="text/html")


@app.route("/api/openapi.json", methods=["GET"])
def api_openapi_json():
    """Returns OpenAPI 3.0 specification JSON."""
    from web.openapi import get_openapi_spec
    return jsonify(get_openapi_spec())


# ─────────────────────────────────────────────
# Routes: API
# ─────────────────────────────────────────────
@app.route("/api/modules", methods=["GET"])
def api_modules():
    return jsonify({"modules": get_modules_metadata(dynamic_counts=True)})


@app.route("/api/modules/<module_name>/payloads", methods=["GET"])
def api_module_payloads(module_name):
    """Lấy danh sách payloads chi tiết của module để chỉnh sửa tương tác."""
    if module_name not in MODULES_METADATA:
        return jsonify({"error": f"Module {module_name} không tồn tại"}), 404
    try:
        if module_name == "port_scan":
            return jsonify({"module": module_name, "payloads": [], "count": 0})

        from modules.registry import load_module
        mod_obj = load_module(module_name)

        if mod_obj:
            payloads = getattr(mod_obj, "payloads", [])
            return jsonify({"module": module_name, "payloads": payloads, "count": len(payloads)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"module": module_name, "payloads": []})


# ─────────────────────────────────────────────
# Observability & Health Endpoints
# ─────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check for system components (DB, worker, config)."""
    db_ok = True
    try:
        from core.db import _get_conn
        conn = _get_conn()
        conn.execute("SELECT 1")
        conn.close()
    except Exception as exc:
        db_ok = False
        logger.error("Health check DB failure: %s", exc)

    return jsonify({
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "error",
        "scanner_running": scan_status["running"],
        "active_module": scan_status.get("current_module"),
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
    })


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    """Operational metrics for monitoring dashboards."""
    stats = get_stats()
    uptime = round(time.time() - SERVER_START_TIME, 2)
    return jsonify({
        "total_scans": len(stats.get("recent_scans", [])),
        "total_findings": stats.get("total_findings", 0),
        "by_severity": stats.get("by_severity", {}),
        "scanner_active": scan_status["running"],
        "uptime_seconds": uptime,
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/metrics", methods=["GET"])
@require_auth
def prometheus_metrics():
    """Prometheus metrics endpoint for scraping by Prometheus server."""
    stats = get_stats()
    by_sev = stats.get("by_severity", {})
    uptime = round(time.time() - SERVER_START_TIME, 2)
    total_findings = stats.get("total_findings", 0)
    total_scans = len(stats.get("recent_scans", []))
    is_active = 1 if scan_status["running"] else 0

    lines = [
        "# HELP ai_scanner_up Indicates if the AI security scanner service is running",
        "# TYPE ai_scanner_up gauge",
        "ai_scanner_up 1",
        "",
        "# HELP ai_scanner_uptime_seconds Total service uptime in seconds",
        "# TYPE ai_scanner_uptime_seconds gauge",
        f"ai_scanner_uptime_seconds {uptime}",
        "",
        "# HELP ai_scanner_active_scans Gauge of currently active running scan jobs",
        "# TYPE ai_scanner_active_scans gauge",
        f"ai_scanner_active_scans {is_active}",
        "",
        "# HELP ai_scanner_scans_total Total number of scans completed",
        "# TYPE ai_scanner_scans_total counter",
        f"ai_scanner_scans_total {total_scans}",
        "",
        "# HELP ai_scanner_findings_total Total findings discovered partitioned by severity",
        "# TYPE ai_scanner_findings_total counter",
        f'ai_scanner_findings_total{{severity="CRITICAL"}} {by_sev.get("CRITICAL", 0)}',
        f'ai_scanner_findings_total{{severity="HIGH"}} {by_sev.get("HIGH", 0)}',
        f'ai_scanner_findings_total{{severity="MEDIUM"}} {by_sev.get("MEDIUM", 0)}',
        f'ai_scanner_findings_total{{severity="LOW"}} {by_sev.get("LOW", 0)}',
        f'ai_scanner_findings_total{{severity="INFO"}} {by_sev.get("INFO", 0)}',
        "",
        "# HELP ai_scanner_all_findings_total Total findings discovered across all categories",
        "# TYPE ai_scanner_all_findings_total counter",
        f"ai_scanner_all_findings_total {total_findings}",
        "",
    ]
    return Response("\n".join(lines), mimetype="text/plain; version=0.0.4; charset=utf-8")


# ─────────────────────────────────────────────
# Auth Endpoint
# ─────────────────────────────────────────────
@app.route("/api/auth/status", methods=["GET"])
def api_auth_status():
    """Return whether auth is enforced and whether the current caller is authenticated."""
    req_auth = bool(cfg.get("web.require_auth", False))
    if not req_auth:
        return jsonify({"require_auth": False, "authenticated": True, "user": "local_dev"})
    authed, user = is_request_authenticated()
    return jsonify({"require_auth": True, "authenticated": authed, "user": user})


@app.route("/api/auth/login", methods=["POST"])
@rate_limit(limit=10, window=60)
def api_auth_login():
    """Issue JWT token upon valid credential / API key submission."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid payload", "message": "Expected JSON object."}), 400
    admin_key = str(cfg.get("web.admin_api_key", "") or "").strip()
    if not admin_key:
        return jsonify({"error": "Server auth misconfigured", "message": "Admin API key is not configured."}), 503

    api_key = data.get("api_key")
    username = data.get("username")
    password = data.get("password")

    is_valid = False
    if isinstance(api_key, str) and api_key and hmac.compare_digest(api_key, admin_key):
        is_valid = True
    elif username == "admin" and isinstance(password, str) and password and hmac.compare_digest(password, admin_key):
        is_valid = True

    if is_valid:
        expires_sec = int(cfg.get("web.jwt_access_token_expires_minutes", 1440)) * 60
        token = generate_token(identity="admin", expires_in_seconds=expires_sec)
        return jsonify({
            "success": True,
            "token": token,
            "token_type": "Bearer",
            "expires_in": expires_sec,
        })
    return jsonify({"error": "Invalid credentials", "message": "Incorrect username/password or API key."}), 401


@app.route("/api/taxonomy", methods=["GET"])
def api_taxonomy():
    tax_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "taxonomy.json")
    if os.path.exists(tax_path):
        with open(tax_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if "categories" in data and "taxonomy" not in data:
                data["taxonomy"] = {c.get("id", f"CAT_{i}"): c for i, c in enumerate(data["categories"])}
            return jsonify(data)
    return jsonify({"categories": [], "taxonomy": {}})


def mask_api_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "••••••••"
    return f"{key[:3]}••••••••{key[-4:]}"


@app.route("/api/config", methods=["GET"])
@require_auth
def api_get_config():
    cfg_copy = dict(app_config)
    cfg_copy["api_key"] = mask_api_key(cfg_copy.get("api_key", ""))
    cfg_copy["has_api_key"] = bool(app_config.get("api_key"))
    return jsonify(cfg_copy)


@app.route("/api/config", methods=["POST"])
@require_auth
def api_set_config():
    data = request.get_json(silent=True) or {}
    is_valid, err_msg = validate_config_request(data)
    if not is_valid:
        return jsonify({"error": "Invalid configuration", "message": err_msg}), 400

    for key in ["target_url", "target_model", "timeout"]:
        if key in data:
            app_config[key] = data[key]

    if "api_key" in data and isinstance(data["api_key"], str):
        new_key = data["api_key"]
        if new_key and "••••" not in new_key:
            app_config["api_key"] = new_key
        elif new_key == "":
            app_config["api_key"] = ""

    cfg_copy = dict(app_config)
    cfg_copy["api_key"] = mask_api_key(cfg_copy.get("api_key", ""))
    cfg_copy["has_api_key"] = bool(app_config.get("api_key"))
    return jsonify({"success": True, "config": cfg_copy})




@app.route("/api/scan/run", methods=["POST"])
@require_auth
@rate_limit(limit=30, window=60)
def api_scan_run():
    data = request.get_json(silent=True) or {}
    is_valid, err_msg = validate_scan_request(data)
    if not is_valid:
        if err_msg and "scope" in err_msg.lower():
            log_audit_event(
                "SCOPE_BLOCKED",
                target_url=str(data.get("target_url", "")),
                outcome="DENIED",
                details={"reason": err_msg},
            )
        return jsonify({"error": "Validation Error", "message": err_msg}), 400

    if data.get("custom_payloads"):
        cp_ok, cp_err = validate_custom_payloads(data["custom_payloads"])
        if not cp_ok:
            return jsonify({"error": "Validation Error", "message": cp_err}), 400

    if isinstance(data.get("modules"), list) and len(data.get("modules")) > 1:
        return _launch_multi_module_scan(data)

    with scan_lock:
        if scan_status["running"]:
            return jsonify({"error": "Một scan đang chạy. Nhấn 'Hủy Scan' nếu muốn dừng lại."}), 409

        cancel_event.clear()
        current_token = str(uuid.uuid4())
        scan_manager.set_active_scan_token(current_token)
        scan_status["running"] = True

    module_name = data.get("module")
    if not module_name and data.get("modules"):
        mods = data.get("modules")
        if isinstance(mods, list) and len(mods) > 0:
            module_name = mods[0]

    if not module_name or module_name not in MODULES_METADATA:
        with scan_lock:
            scan_status["running"] = False
            scan_manager.set_active_scan_token(None)
        return jsonify({"error": f"Module không hợp lệ: {module_name}"}), 400

    config = {**app_config, **{k: v for k, v in data.items() if k in app_config}}
    if data.get("custom_payloads"):
        config["custom_payloads"] = data["custom_payloads"]
    if "adaptive_mode" in data:
        config["adaptive_mode"] = bool(data["adaptive_mode"])

    scan_queue.clear_backlog()
    scan_id = start_scan(config["target_url"], config["target_model"])
    thread = threading.Thread(
        target=scan_worker,
        args=(module_name, config, scan_id, False, None, current_token),
        daemon=True,
    )
    thread.start()

    return jsonify({"success": True, "scan_id": scan_id, "module": module_name, "scan_token": current_token})


@app.route("/api/scan/run-all", methods=["POST"])
@require_auth
@rate_limit(limit=10, window=60)
def api_scan_run_all():
    """Chạy tất cả modules lần lượt trong một thread (có kiểm tra SSRF & RoE)."""
    data = request.get_json(silent=True) or {}
    return _launch_multi_module_scan(data)


@app.route("/api/scan/cancel", methods=["POST"])
@require_auth
def api_scan_cancel():
    """Hủy phiên scan đang chạy (cả đơn module và run-all)."""
    with scan_lock:
        if not scan_status["running"]:
            return jsonify({"success": False, "message": "Không có phiên scan nào đang chạy."})

        cancel_event.set()
        token = scan_manager.get_active_scan_token()
        scan_manager.set_active_scan_token(None)
        scan_status["running"] = False
        mod = scan_status.get("current_module") or "hiện tại"

    scan_queue.put({
        "type": "cancelled",
        "data": {"message": f"Scan module '{mod}' đã bị hủy bởi người dùng."},
        "token": token,
        "ts": datetime.now().isoformat()
    })
    return jsonify({"success": True, "message": "Đã gửi lệnh dừng scan."})


@app.route("/api/scan/status", methods=["GET"])
@require_auth
def api_scan_status():
    return jsonify(scan_status)


@app.route("/api/scan/stream")
@require_auth
def api_scan_stream():
    """Server-Sent Events endpoint - multi-subscriber fan-out stream."""
    requested_token = (request.args.get("scan_token") or "").strip() or None
    current_token = requested_token or scan_manager.get_active_scan_token()
    sub_queue = scan_queue.subscribe(replay_token=current_token)

    def generate():
        try:
            yield 'data: {"type": "connected", "message": "SSE Connected"}\n\n'
            while True:
                try:
                    msg = sub_queue.get(timeout=25)
                    msg_token = msg.get("token")
                    expected = requested_token or scan_manager.get_active_scan_token() or current_token
                    if msg_token and expected and msg_token != expected:
                        continue
                    yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
                    if msg.get("type") in ("done", "all_done", "error", "cancelled"):
                        break
                except queue.Empty:
                    yield 'data: {"type": "heartbeat"}\n\n'
        finally:
            scan_queue.unsubscribe(sub_queue)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )




@app.route("/api/connection/test", methods=["POST"])
@require_auth
def api_test_connection():
    data = request.get_json(silent=True) or {}
    url = data.get("url", app_config["target_url"])
    valid_url, url_err = validate_config_request({"target_url": str(url)})
    if not valid_url:
        return jsonify({"success": False, "connected": False, "error": "Validation Error", "message": url_err}), 400
    model = data.get("model", app_config["target_model"])
    api_key = data.get("api_key", app_config.get("api_key", ""))
    if api_key and "••••" in api_key:
        api_key = app_config.get("api_key", "")

    client = SimpleLLMClient(api_url=url, model_name=model, timeout=10, api_key=api_key)
    
    t0 = time.monotonic()
    ok, msg = client.test_connection()
    latency_ms = max(1, int((time.monotonic() - t0) * 1000))

    models = getattr(client, "discovered_models", []) or client.list_models()
    resolved = client.resolve_model_name()

    # Kiểm tra tính khả dụng thực tế của mô hình trên target
    if ok and not client._is_openai_compatible():
        if isinstance(models, list) and len(models) == 0:
            ok = False
            msg = "Ollama đang chạy nhưng chưa phát hiện mô hình nào được cài đặt (ollama list rỗng). Vui lòng chạy 'ollama pull <model>'."
        elif isinstance(models, list) and len(models) > 0 and resolved not in models:
            ok = False
            msg = f"Mô hình '{model}' chưa được cài đặt trên Ollama. Các mô hình hiện có: {', '.join(models)}"

    if ok:
        app_config["target_url"] = url
        app_config["target_model"] = resolved

    return jsonify({
        "success": ok,
        "connected": ok,
        "latency_ms": latency_ms,
        "model": resolved,
        "message": msg,
        "models": models,
        "resolved_model": resolved,
    })
# ─────────────────────────────────────────────
# Advanced NCKH Endpoints: Threat Model, Replay, Benchmark & OSS


# ─────────────────────────────────────────────
# Init & Run
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    web_host = cfg.get("web.host", "127.0.0.1")
    web_port = int(cfg.get("web.port", 5000))
    web_debug = bool(cfg.get("web.debug", False))
    print("\n" + "="*60)
    print("  🔐 AI Security Scanner - Web Dashboard")
    print(f"  📡 http://{web_host}:{web_port}")
    print("="*60 + "\n")
    app.run(host=web_host, port=web_port, debug=web_debug, threaded=True)
