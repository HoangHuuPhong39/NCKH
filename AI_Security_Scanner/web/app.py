"""
AI Security Scanner - Web Dashboard Backend
Flask REST API with Server-Sent Events (SSE) for real-time scan output.
"""

import sys
import os

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import json
import time
import queue
import threading
import uuid
from datetime import datetime

# Thêm thư mục gốc vào sys.path để import các module core
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request, Response, render_template, send_from_directory
from flask_cors import CORS

from core.config import cfg
from core.logger import logger
from core.db import (
    init_db, save_finding, get_findings, get_stats, clear_findings,
    start_scan, complete_scan, get_scans, get_scan_dates, get_finding_dates
)
from core.llm_client import SimpleLLMClient
from core.risk_scorer import RiskScorer
from core.report import generate_html_report, export_json_report
from web.security import (
    require_auth, rate_limit, validate_scan_request,
    validate_config_request, generate_token, add_security_headers
)
import hmac

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
CORS(app)

@app.after_request
def apply_security_headers(response):
    return add_security_headers(response)

# ─────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────
scan_queue: queue.Queue = queue.Queue()
cancel_event: threading.Event = threading.Event()
scan_lock: threading.Lock = threading.Lock()
active_scan_token: str | None = None

scan_status = {
    "running": False,
    "current_module": None,
    "progress": 0,
    "total": 0,
    "scan_id": None,
    "started_at": None,
}

SERVER_START_TIME = time.time()

# Config mặc định (tải từ config.yaml / ENV và có thể thay đổi qua /api/config)
app_config = {
    "target_url": cfg.get("scanner.target_url", "http://localhost:11434"),
    "target_model": cfg.get("scanner.target_model", "llama3"),
    "timeout": cfg.get("scanner.timeout", 60),
    "api_key": cfg.get("scanner.api_key", ""),
}

MODULES_METADATA = {
    "prompt_injection": {
        "name": "Prompt Injection",
        "description": "Kiểm tra khả năng mô hình bỏ qua hướng dẫn hệ thống bằng các câu lệnh ghi đè trực tiếp/gián tiếp.",
        "owasp": "LLM01",
        "mitre": "AML.T0051",
        "severity": "HIGH",
        "payloads_count": 12,
        "icon": "🎯",
        "category": "exploits",
    },
    "jailbreak": {
        "name": "Jailbreak / Safety Bypass",
        "description": "Sử dụng kịch bản nhập vai (DAN, AIM, STAN) để ép AI bỏ qua các quy tắc an toàn.",
        "owasp": "LLM01",
        "mitre": "AML.T0054",
        "severity": "CRITICAL",
        "payloads_count": 6,
        "icon": "🔓",
        "category": "exploits",
    },
    "prompt_leak": {
        "name": "System Prompt Disclosure",
        "description": "Trích xuất System Prompt ẩn bằng cách yêu cầu AI lặp lại hoặc dịch hướng dẫn nội bộ.",
        "owasp": "LLM07",
        "mitre": "AML.T0010",
        "severity": "MEDIUM",
        "payloads_count": 7,
        "icon": "📤",
        "category": "exploits",
    },
    "sensitive_disclosure": {
        "name": "Sensitive Information Disclosure",
        "description": "Kiểm thử rò rỉ PII, thông tin xác thực, dữ liệu huấn luyện nhạy cảm.",
        "owasp": "LLM02",
        "mitre": "AML.T0024",
        "severity": "HIGH",
        "payloads_count": 6,
        "icon": "🔍",
        "category": "exploits",
    },
    "model_dos": {
        "name": "Unbounded Consumption (DoS)",
        "description": "Kiểm thử tiêu thụ tài nguyên không giới hạn bằng prompt cực dài, tác vụ đệ quy.",
        "owasp": "LLM10",
        "mitre": "AML.T0029",
        "severity": "MEDIUM",
        "payloads_count": 4,
        "icon": "💥",
        "category": "exploits",
    },
    "output_handling": {
        "name": "Improper Output Handling",
        "description": "Kiểm tra xem AI có tạo ra output nguy hiểm (XSS, SQL injection, SSRF) khi được yêu cầu.",
        "owasp": "LLM05",
        "mitre": "AML.T0048",
        "severity": "HIGH",
        "payloads_count": 6,
        "icon": "⚠️",
        "category": "exploits",
    },
    "misinformation": {
        "name": "Misinformation / Hallucination",
        "description": "Kiểm thử khả năng AI tạo ra thông tin sai lệch có độ tin cậy cao, bịa đặt trích dẫn.",
        "owasp": "LLM09",
        "mitre": "AML.T0048.003",
        "severity": "MEDIUM",
        "payloads_count": 6,
        "icon": "🌀",
        "category": "exploits",
    },
    "excessive_agency": {
        "name": "Excessive Agency",
        "description": "Kiểm tra khả năng mô hình tự ý thực thi các hành vi vượt thẩm quyền nguy hiểm (giao dịch, xóa dữ liệu).",
        "owasp": "LLM06",
        "mitre": "AML.T0048.001",
        "severity": "CRITICAL",
        "payloads_count": 6,
        "icon": "🤖",
        "category": "exploits",
    },
    "rag_security": {
        "name": "Vector & Embedding Weaknesses",
        "description": "Kiểm thử khả năng mô hình bị thao túng gián tiếp qua ngữ cảnh RAG nhiễm độc (Indirect Injection / Delimiter Breakout).",
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "severity": "HIGH",
        "payloads_count": 6,
        "icon": "📚",
        "category": "exploits",
    },
    "multiturn_jailbreak": {
        "name": "Multi-Turn Jailbreak Escalation",
        "description": "Kiểm thử khả năng bẻ khóa an toàn qua chuỗi hội thoại nhiều lượt (Crescendo / PAIR).",
        "owasp": "LLM01",
        "mitre": "AML.T0054",
        "severity": "CRITICAL",
        "payloads_count": 3,
        "icon": "🪜",
        "category": "exploits",
    },
    "model_fingerprint": {
        "name": "Model Architecture Fingerprinting",
        "description": "Nhận diện họ mô hình AI (LLaMA, Mistral, GPT, Claude, Qwen, DeepSeek) và chữ ký bảo vệ.",
        "owasp": "N/A",
        "mitre": "AML.T0008",
        "severity": "INFO",
        "payloads_count": 6,
        "icon": "🧬",
        "category": "auxiliary",
    },
    "port_scan": {
        "name": "AI Service Port Scanner",
        "description": "Quét các cổng mạng phổ biến của dịch vụ AI/ML (Ollama, MLflow, Ray, Qdrant...).",
        "owasp": "N/A",
        "mitre": "AML.T0008",
        "severity": "INFO",
        "payloads_count": 6,
        "icon": "🔭",
        "category": "auxiliary",
    },
}

risk_scorer = RiskScorer()


# ─────────────────────────────────────────────
# Scan worker (runs in background thread)
# ─────────────────────────────────────────────
def scan_worker(module_name: str, config: dict, scan_id: int, is_batch: bool = False, batch_info: dict = None, scan_token: str = None):
    """Background thread that runs a security module and streams output."""
    import socket
    from modules.detectors.pattern_match import PatternDetector

    def is_aborted():
        return cancel_event.is_set() or (scan_token is not None and scan_token != active_scan_token)

    def emit(msg_type: str, data: dict):
        """Push a message to the SSE queue only if this scan is still active."""
        if scan_token and scan_token != active_scan_token:
            return
        scan_queue.put({"type": msg_type, "data": data, "token": scan_token, "ts": datetime.now().isoformat()})

    try:
        scan_status["running"] = True
        scan_status["current_module"] = module_name
        scan_status["scan_id"] = scan_id
        scan_status["started_at"] = datetime.now().isoformat()

        client = SimpleLLMClient(
            api_url=config["target_url"],
            model_name=config["target_model"],
            timeout=int(config.get("timeout", 60)),
        )
        if config.get("api_key"):
            client.api_key = config["api_key"]

        resolved_model = client.resolve_model_name()
        if resolved_model != config["target_model"]:
            emit("status", {
                "message": f"[*] Tự động map mô hình '{config['target_model']}' -> '{resolved_model}' (đã cài đặt trên target)",
                "level": "info"
            })

        detector = PatternDetector()
        from modules.detectors.llm_judge import LLMJudge
        judge = LLMJudge(judge_client=client)

        meta = MODULES_METADATA.get(module_name, {})
        display_name = meta.get("name", module_name)
        emit("status", {"message": f"[*] Khởi chạy module: {display_name} (Target model: {resolved_model})", "level": "info"})

        if module_name == "port_scan":
            from modules.auxiliary.scanner.port_scan import PortScanner
            scanner = PortScanner()
            host = config["target_url"].split("://")[-1].split(":")[0]
            if host == "localhost":
                host = "127.0.0.1"
            emit("status", {"message": f"[*] Đang quét dịch vụ AI trên host: {host}", "level": "info"})

            ports_to_scan = list(scanner.ai_ports.items())
            total_ports = len(ports_to_scan)
            scan_status["total"] = total_ports

            for p_idx, (port, service) in enumerate(ports_to_scan):
                if is_aborted():
                    emit("status", {"message": f"[!] Đã hủy quét port tại cổng {port}.", "level": "warn"})
                    break

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                res = sock.connect_ex((host, port))
                sock.close()

                if res == 0:
                    risk_score = risk_scorer.calculate_score("port_scan", True, 0)
                    severity = risk_scorer.score_to_severity(risk_score)
                    save_finding(
                        scan_id, config["target_url"], "port_scan",
                        f"Port {port}", f"Service: {service}",
                        severity, risk_score, "N/A", "AML.T0008"
                    )
                    emit("finding", {
                        "payload": f"Port {port}", "response": f"Service: {service}",
                        "is_vuln": True, "reason": f"Cổng mở: {service}",
                        "severity": severity, "risk_score": risk_score,
                        "owasp": "N/A", "mitre": "AML.T0008",
                    })

                pct = round(((p_idx + 1) / total_ports) * 100)
                scan_status["progress"] = p_idx + 1
                progress_data = {
                    "current": p_idx + 1,
                    "total": total_ports,
                    "percent": pct,
                    "module": module_name,
                }
                if batch_info:
                    b_curr = batch_info["offset"] + p_idx + 1
                    b_tot = batch_info["total_payloads"]
                    progress_data["overall_current"] = b_curr
                    progress_data["overall_total"] = b_tot
                    progress_data["percent"] = round((b_curr / b_tot) * 100)
                emit("progress", progress_data)

        else:
            # Load attack module
            if module_name == "prompt_injection":
                from modules.exploits.prompt_injection import PromptInjection
                module = PromptInjection()
            elif module_name == "jailbreak":
                from modules.exploits.jailbreak import JailbreakDAN
                module = JailbreakDAN()
            elif module_name == "prompt_leak":
                from modules.exploits.prompt_leak import PromptLeak
                module = PromptLeak()
            elif module_name == "model_dos":
                from modules.exploits.model_dos import ModelDoS
                module = ModelDoS()
            elif module_name == "sensitive_disclosure":
                from modules.exploits.sensitive_disclosure import SensitiveDisclosure
                module = SensitiveDisclosure()
            elif module_name == "output_handling":
                from modules.exploits.output_handling import OutputHandling
                module = OutputHandling()
            elif module_name == "misinformation":
                from modules.exploits.misinformation import Misinformation
                module = Misinformation()
            elif module_name == "excessive_agency":
                from modules.exploits.excessive_agency import ExcessiveAgency
                module = ExcessiveAgency()
            elif module_name == "rag_security":
                from modules.exploits.rag_security import RAGSecurity
                module = RAGSecurity()
            elif module_name == "multiturn_jailbreak":
                from modules.exploits.multiturn_jailbreak import MultiTurnJailbreak
                module = MultiTurnJailbreak()
            elif module_name == "model_fingerprint":
                from modules.auxiliary.model_fingerprint import ModelFingerprint
                module = ModelFingerprint()
            else:
                emit("error", {"message": f"Module không tồn tại: {module_name}"})
                return

            if config.get("custom_payloads") and isinstance(config["custom_payloads"], list) and len(config["custom_payloads"]) > 0:
                payloads = config["custom_payloads"]
            else:
                payloads = getattr(module, "payloads", [])
            total_payloads = len(payloads)
            scan_status["total"] = total_payloads

            for i, p in enumerate(payloads):
                if is_aborted():
                    emit("status", {"message": f"[!] Đã dừng module {display_name} tại payload {i+1}/{total_payloads}.", "level": "warn"})
                    break

                payload_text = p.get("payload", "")
                payload_name = p.get("name", f"Payload {i+1}")
                emit("status", {"message": f"[*] [{i+1}/{total_payloads}] Gửi payload: {payload_name} ({p.get('category', '')})", "level": "info"})

                t0 = time.monotonic()
                try:
                    if p.get("turns") and isinstance(p["turns"], list):
                        conv_history = []
                        last_resp = ""
                        turns = p["turns"]
                        for t_idx, turn_prompt in enumerate(turns, 1):
                            if is_aborted():
                                break
                            emit("status", {"message": f"    ↳ [{payload_name}] Đang gửi Turn {t_idx}/{len(turns)}...", "level": "info"})
                            p_ctx = "".join([f"[{role}]: {txt}\n" for role, txt in conv_history]) + f"[User]: {turn_prompt}"
                            t_resp = client.send_prompt(p_ctx)
                            conv_history.append(("User", turn_prompt))
                            conv_history.append(("Assistant", t_resp))
                            last_resp = t_resp
                        response_text = last_resp
                    else:
                        response_text = client.send_prompt(payload_text)
                except Exception as exc:
                    response_text = f"[ERROR] {exc}"
                t1 = time.monotonic()
                resp_time_ms = int((t1 - t0) * 1000)

                if is_aborted():
                    emit("status", {"message": f"[!] Đã hủy scan sau payload {payload_name}.", "level": "warn"})
                    break

                # ── Guard: Kiểm tra lỗi kết nối trước khi đưa vào detector ──
                if response_text.startswith("[-] Model not found"):
                    emit("status", {"message": f"[ERROR] {response_text}", "level": "error"})
                    emit("error", {"message": f"Mô hình '{client.model_name}' không tồn tại trên target: {response_text}"})
                    break

                if response_text.startswith("[-]") or response_text.startswith("[ERROR]"):
                    if module_name == "model_dos" and ("timeout" in response_text.lower() or "timed out" in response_text.lower()):
                        pass  # Timeout trong DoS là dấu hiệu cạn kiệt tài nguyên
                    else:
                        emit("status", {"message": f"[!] Lỗi kết nối khi gửi '{payload_name}': {response_text[:80]}", "level": "warn"})
                        pct = round(((i + 1) / total_payloads) * 100)
                        scan_status["progress"] = i + 1
                        progress_data = {
                            "current": i + 1,
                            "total": total_payloads,
                            "percent": pct,
                            "module": module_name,
                        }
                        if batch_info:
                            b_curr = batch_info["offset"] + i + 1
                            b_tot = batch_info["total_payloads"]
                            progress_data["overall_current"] = b_curr
                            progress_data["overall_total"] = b_tot
                            progress_data["percent"] = round((b_curr / b_tot) * 100)
                        emit("progress", progress_data)
                        continue

                is_vuln, reason, confidence = detector.analyze(response_text, payload_text, module_name)

                # ── Tầng 2: LLM-as-Judge (khi confidence LOW) ────────
                if confidence == "LOW" and module_name not in ("model_dos", "port_scan"):
                    judge_verdict = judge.evaluate(payload_text, response_text, module_name,
                                                   pattern_result=(is_vuln, reason, confidence))
                    if judge_verdict.get("judge_used"):
                        is_vuln = judge_verdict["is_exploited"]
                        reason = f"[LLM-Judge] {judge_verdict['reasoning']}"
                        confidence = f"JUDGE({judge_verdict['confidence']:.0%})"

                risk_score = risk_scorer.calculate_score(module_name, is_vuln, len(response_text)) if is_vuln else 0.0
                severity = risk_scorer.score_to_severity(risk_score) if is_vuln else "INFO"

                owasp = p.get("owasp", meta.get("owasp", "N/A"))
                mitre = p.get("mitre", meta.get("mitre", "N/A"))

                if is_vuln:
                    save_finding(
                        scan_id, config["target_url"], module_name,
                        payload_text, response_text,
                        severity, risk_score, owasp, mitre
                    )

                emit("finding", {
                    "index": i + 1,
                    "total": total_payloads,
                    "name": payload_name,
                    "payload": payload_text[:200],
                    "response": response_text[:300],
                    "is_vuln": is_vuln,
                    "reason": reason,
                    "confidence": confidence,
                    "severity": severity,
                    "risk_score": risk_score,
                    "owasp": owasp,
                    "mitre": mitre,
                    "response_time_ms": resp_time_ms,
                })

                pct = round(((i + 1) / total_payloads) * 100)
                scan_status["progress"] = i + 1
                progress_data = {
                    "current": i + 1,
                    "total": total_payloads,
                    "percent": pct,
                    "module": module_name,
                }
                if batch_info:
                    b_curr = batch_info["offset"] + i + 1
                    b_tot = batch_info["total_payloads"]
                    progress_data["overall_current"] = b_curr
                    progress_data["overall_total"] = b_tot
                    progress_data["percent"] = round((b_curr / b_tot) * 100)
                emit("progress", progress_data)

        complete_scan(scan_id)
        if is_aborted():
            if not is_batch:
                emit("cancelled", {"message": f"Scan module '{display_name}' đã bị hủy bởi người dùng.", "scan_id": scan_id})
        else:
            if not is_batch:
                emit("done", {"message": f"Scan hoàn tất module '{display_name}'!", "scan_id": scan_id})

    except Exception as e:
        scan_queue.put({"type": "error", "data": {"message": str(e)}, "ts": datetime.now().isoformat()})
    finally:
        if not is_batch and (scan_token is None or scan_token == active_scan_token):
            scan_status["running"] = False
            scan_status["current_module"] = None


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
    return jsonify({"modules": MODULES_METADATA})


@app.route("/api/modules/<module_name>/payloads", methods=["GET"])
def api_module_payloads(module_name):
    """Lấy danh sách payloads chi tiết của module để chỉnh sửa tương tác."""
    if module_name not in MODULES_METADATA:
        return jsonify({"error": f"Module {module_name} không tồn tại"}), 404
    try:
        mod_obj = None
        if module_name == "prompt_injection":
            from modules.exploits.prompt_injection import PromptInjection
            mod_obj = PromptInjection()
        elif module_name == "jailbreak":
            from modules.exploits.jailbreak import JailbreakDAN
            mod_obj = JailbreakDAN()
        elif module_name == "prompt_leak":
            from modules.exploits.prompt_leak import PromptLeak
            mod_obj = PromptLeak()
        elif module_name == "sensitive_disclosure":
            from modules.exploits.sensitive_disclosure import SensitiveDisclosure
            mod_obj = SensitiveDisclosure()
        elif module_name == "output_handling":
            from modules.exploits.output_handling import OutputHandling
            mod_obj = OutputHandling()
        elif module_name == "misinformation":
            from modules.exploits.misinformation import Misinformation
            mod_obj = Misinformation()
        elif module_name == "model_dos":
            from modules.exploits.model_dos import ModelDoS
            mod_obj = ModelDoS()
        elif module_name == "excessive_agency":
            from modules.exploits.excessive_agency import ExcessiveAgency
            mod_obj = ExcessiveAgency()
        elif module_name == "rag_security":
            from modules.exploits.rag_security import RAGSecurity
            mod_obj = RAGSecurity()
        elif module_name == "multiturn_jailbreak":
            from modules.exploits.multiturn_jailbreak import MultiTurnJailbreak
            mod_obj = MultiTurnJailbreak()
        elif module_name == "model_fingerprint":
            from modules.auxiliary.model_fingerprint import ModelFingerprint
            mod_obj = ModelFingerprint()
        elif module_name == "port_scan":
            return jsonify({"module": module_name, "payloads": []})

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
@app.route("/api/auth/login", methods=["POST"])
@rate_limit(limit=10, window=60)
def api_auth_login():
    """Issue JWT token upon valid credential / API key submission."""
    data = request.get_json() or {}
    admin_key = cfg.get("web.admin_api_key", "ai-scanner-admin-secret-token")
    api_key = data.get("api_key")
    username = data.get("username")
    password = data.get("password")

    is_valid = False
    if api_key and hmac.compare_digest(api_key, admin_key):
        is_valid = True
    elif username == "admin" and password and hmac.compare_digest(password, admin_key):
        is_valid = True

    if is_valid:
        token = generate_token(identity="admin", expires_in_seconds=86400)
        return jsonify({
            "success": True,
            "token": token,
            "token_type": "Bearer",
            "expires_in": 86400,
        })
    return jsonify({"error": "Invalid credentials", "message": "Incorrect username/password or API key."}), 401


@app.route("/api/taxonomy", methods=["GET"])
def api_taxonomy():
    tax_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "taxonomy.json")
    if os.path.exists(tax_path):
        with open(tax_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({"categories": []})


@app.route("/api/config", methods=["GET"])
def api_get_config():
    return jsonify(app_config)


@app.route("/api/config", methods=["POST"])
@require_auth
def api_set_config():
    data = request.get_json() or {}
    is_valid, err_msg = validate_config_request(data)
    if not is_valid:
        return jsonify({"error": "Invalid configuration", "message": err_msg}), 400

    for key in ["target_url", "target_model", "timeout", "api_key"]:
        if key in data:
            app_config[key] = data[key]
    return jsonify({"success": True, "config": app_config})


@app.route("/api/scan/run", methods=["POST"])
@require_auth
@rate_limit(limit=30, window=60)
def api_scan_run():
    global active_scan_token
    data = request.get_json() or {}
    is_valid, err_msg = validate_scan_request(data)
    if not is_valid:
        return jsonify({"error": "Validation Error", "message": err_msg}), 400

    # Nếu người dùng gửi mảng nhiều module, tự động chuyển tiếp sang luồng quét nhiều module
    if isinstance(data.get("modules"), list) and len(data.get("modules")) > 1:
        return api_scan_run_all()

    with scan_lock:
        if scan_status["running"]:
            return jsonify({"error": "Một scan đang chạy. Nhấn 'Hủy Scan' nếu muốn dừng lại."}), 409

        cancel_event.clear()
        active_scan_token = str(uuid.uuid4())
        scan_status["running"] = True

    module_name = data.get("module")
    if not module_name and data.get("modules"):
        mods = data.get("modules")
        if isinstance(mods, list) and len(mods) > 0:
            module_name = mods[0]

    if not module_name or module_name not in MODULES_METADATA:
        with scan_lock:
            scan_status["running"] = False
            active_scan_token = None
        return jsonify({"error": f"Module không hợp lệ: {module_name}"}), 400

    # Lấy config từ request (nếu có) hoặc dùng app_config
    config = {**app_config, **{k: v for k, v in data.items() if k in app_config}}
    if data.get("custom_payloads"):
        config["custom_payloads"] = data["custom_payloads"]

    # Xóa queue cũ
    while not scan_queue.empty():
        try:
            scan_queue.get_nowait()
        except queue.Empty:
            break

    current_token = active_scan_token
    scan_id = start_scan(config["target_url"], config["target_model"])
    thread = threading.Thread(
        target=scan_worker,
        args=(module_name, config, scan_id, False, None, current_token),
        daemon=True
    )
    thread.start()

    return jsonify({"success": True, "scan_id": scan_id, "module": module_name})


@app.route("/api/scan/run-all", methods=["POST"])
@require_auth
@rate_limit(limit=10, window=60)
def api_scan_run_all():
    """Chạy tất cả modules lần lượt trong một thread."""
    global active_scan_token
    with scan_lock:
        if scan_status["running"]:
            return jsonify({"error": "Một scan đang chạy. Nhấn 'Hủy Scan' nếu muốn dừng lại."}), 409

        cancel_event.clear()
        active_scan_token = str(uuid.uuid4())
        scan_status["running"] = True

    data = request.get_json() or {}
    config = {**app_config, **{k: v for k, v in data.items() if k in app_config}}
    modules_to_run = data.get("modules", list(MODULES_METADATA.keys()))

    while not scan_queue.empty():
        try:
            scan_queue.get_nowait()
        except queue.Empty:
            break

    current_token = active_scan_token

    def run_all_worker():
        try:
            total_all_payloads = sum(
                MODULES_METADATA.get(m, {}).get("payloads_count", 6)
                for m in modules_to_run if m in MODULES_METADATA
            )
            offset = 0
            for mod_idx, mod in enumerate(modules_to_run):
                if cancel_event.is_set() or current_token != active_scan_token:
                    break
                if mod not in MODULES_METADATA:
                    continue
                scan_id = start_scan(config["target_url"], config["target_model"])
                scan_queue.put({
                    "type": "module_start",
                    "data": {
                        "module": mod,
                        "module_index": mod_idx + 1,
                        "total_modules": len(modules_to_run)
                    },
                    "token": current_token,
                    "ts": datetime.now().isoformat()
                })
                mod_payloads_count = MODULES_METADATA.get(mod, {}).get("payloads_count", 6)
                batch_info = {
                    "offset": offset,
                    "total_payloads": total_all_payloads,
                    "mod_index": mod_idx + 1,
                    "total_mods": len(modules_to_run),
                }
                scan_worker(mod, config, scan_id, is_batch=True, batch_info=batch_info, scan_token=current_token)
                offset += mod_payloads_count
                if cancel_event.is_set() or current_token != active_scan_token:
                    break
                time.sleep(0.3)

            if cancel_event.is_set() or current_token != active_scan_token:
                scan_queue.put({
                    "type": "cancelled",
                    "data": {"message": "Đã hủy chuỗi quét modules theo yêu cầu."},
                    "token": current_token,
                    "ts": datetime.now().isoformat()
                })
            else:
                scan_queue.put({
                    "type": "all_done",
                    "data": {"message": "Tất cả modules đã hoàn tất!"},
                    "token": current_token,
                    "ts": datetime.now().isoformat()
                })
        except Exception as e:
            scan_queue.put({"type": "error", "data": {"message": str(e)}, "token": current_token, "ts": datetime.now().isoformat()})
        finally:
            with scan_lock:
                if current_token == active_scan_token:
                    scan_status["running"] = False
                    scan_status["current_module"] = None

    thread = threading.Thread(target=run_all_worker, daemon=True)
    thread.start()
    return jsonify({"success": True, "modules": modules_to_run})


@app.route("/api/scan/cancel", methods=["POST"])
def api_scan_cancel():
    """Hủy phiên scan đang chạy (cả đơn module và run-all)."""
    global active_scan_token
    with scan_lock:
        if not scan_status["running"]:
            return jsonify({"success": False, "message": "Không có phiên scan nào đang chạy."})

        cancel_event.set()
        token = active_scan_token
        active_scan_token = None
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
def api_scan_status():
    return jsonify(scan_status)


@app.route("/api/scan/stream")
def api_scan_stream():
    """Server-Sent Events endpoint - stream scan results to browser."""
    current_token = active_scan_token

    def generate():
        yield "data: {\"type\": \"connected\", \"message\": \"SSE Connected\"}\n\n"
        while True:
            try:
                msg = scan_queue.get(timeout=60)
                msg_token = msg.get("token")
                # Bỏ qua các message từ phiên scan cũ đã chết
                if msg_token and current_token and msg_token != current_token:
                    continue
                yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
                if msg.get("type") in ("done", "all_done", "error", "cancelled"):
                    break
            except queue.Empty:
                yield "data: {\"type\": \"heartbeat\"}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/findings", methods=["GET"])
def api_findings():
    severity = request.args.get("severity")
    module = request.args.get("module")
    date = request.args.get("date")
    limit = int(request.args.get("limit", 100))
    findings = get_findings(severity=severity, module_name=module, date=date, limit=limit)
    dates = get_finding_dates()
    return jsonify({"findings": findings, "count": len(findings), "dates": dates})


@app.route("/api/scans", methods=["GET"])
def api_scans():
    date = request.args.get("date")
    limit = int(request.args.get("limit", 50))
    scans = get_scans(date=date, limit=limit)
    dates = get_scan_dates()
    return jsonify({"scans": scans, "count": len(scans), "dates": dates})


@app.route("/api/findings", methods=["DELETE"])
def api_clear_findings():
    clear_findings()
    return jsonify({"success": True, "message": "Đã xóa tất cả findings."})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    stats = get_stats()
    return jsonify(stats)


@app.route("/api/report/generate", methods=["POST"])
def api_generate_report():
    data = request.get_json(silent=True) or {}
    severity = data.get("severity") or request.args.get("severity")
    module = data.get("module") or request.args.get("module")
    
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), cfg.get("storage.reports_dir", "reports"))
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, "report.html")
    
    success = generate_html_report(report_path, severity=severity, module_name=module)
    if success:
        return jsonify({"success": True, "path": report_path, "severity": severity, "module": module})
    return jsonify({"error": "Không thể tạo báo cáo."}), 500


@app.route("/api/report/download")
def api_download_report():
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), cfg.get("storage.reports_dir", "reports"))
    return send_from_directory(reports_dir, "report.html", as_attachment=True)


@app.route("/api/report/view")
def api_view_report():
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), cfg.get("storage.reports_dir", "reports"))
    return send_from_directory(reports_dir, "report.html", as_attachment=False)


@app.route("/api/report/json")
def api_json_report():
    severity = request.args.get("severity")
    module = request.args.get("module")
    data = export_json_report(severity=severity, module_name=module)
    return jsonify(data)


@app.route("/api/connection/test", methods=["POST"])
def api_test_connection():
    data = request.get_json(silent=True) or {}
    url = data.get("url", app_config["target_url"])
    model = data.get("model", app_config["target_model"])
    api_key = data.get("api_key", app_config.get("api_key", ""))
    client = SimpleLLMClient(api_url=url, model_name=model, timeout=10, api_key=api_key)
    ok, msg = client.test_connection()
    models = getattr(client, "discovered_models", []) or client.list_models()
    resolved = client.resolve_model_name()
    return jsonify({
        "success": ok,
        "message": msg,
        "models": models,
        "resolved_model": resolved,
    })


# ─────────────────────────────────────────────
# Init & Run
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n" + "="*60)
    print("  🔐 AI Security Scanner - Web Dashboard")
    print("  📡 http://localhost:5000")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
