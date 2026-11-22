# -*- coding: utf-8 -*-
"""
web/services/scan_manager.py - Scan State, SSE Broadcaster, Worker & Multi-Module Launcher
"""

from __future__ import annotations

import os
import queue
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List

from flask import jsonify, request

from core.config import cfg
from core.db import complete_scan, save_finding, start_scan
from core.governance import CampaignBudget, log_audit_event
from core.llm_client import SimpleLLMClient
from core.logger import logger
from core.risk_scorer import RiskScorer
from modules.registry import MODULES_METADATA, get_modules_metadata
from web.security import validate_custom_payloads, validate_scan_request

def _parse_int_arg(name: str, default: int, min_val: int = 1, max_val: int = 1000) -> int:
    raw = request.args.get(name, None)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        val = int(raw)
    except (ValueError, TypeError):
        return default
    return max(min_val, min(val, max_val))


class ScanBroadcaster:
    """Thread-safe multi-subscriber SSE broadcaster with bounded buffer."""

    def __init__(self, max_subscribers: int = 32, max_queue_size: int = 500) -> None:
        self._lock = threading.Lock()
        self._subscribers: list[queue.Queue] = []
        self._backlog: list[dict] = []
        self._max_subscribers = max_subscribers
        self._max_queue_size = max_queue_size

    def subscribe(self, replay_token: str | None = None) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self._max_queue_size)
        with self._lock:
            if len(self._subscribers) >= self._max_subscribers:
                self._subscribers.pop(0)
            if replay_token:
                for item in self._backlog:
                    if item.get("token") == replay_token:
                        try:
                            q.put_nowait(item)
                        except queue.Full:
                            break
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def put(self, item: dict) -> None:
        with self._lock:
            self._backlog.append(item)
            if len(self._backlog) > 250:
                self._backlog = self._backlog[-250:]
            for q in list(self._subscribers):
                try:
                    q.put_nowait(item)
                except queue.Full:
                    try:
                        q.get_nowait()
                        q.put_nowait(item)
                    except Exception:
                        pass

    def clear_backlog(self) -> None:
        with self._lock:
            self._backlog.clear()

    def empty(self) -> bool:
        return True

    def get_nowait(self):
        raise queue.Empty()



# ─────────────────────────────────────────────
# Shared Runtime State
# ─────────────────────────────────────────────
scan_queue = ScanBroadcaster()
cancel_event: threading.Event = threading.Event()
scan_lock: threading.Lock = threading.Lock()
active_scan_token: str | None = None

scan_status: Dict[str, Any] = {
    "running": False,
    "current_module": None,
    "progress": 0,
    "total": 0,
    "scan_id": None,
    "started_at": None,
}

SERVER_START_TIME = time.time()

app_config: Dict[str, Any] = {
    "target_url": cfg.get("scanner.target_url", "http://localhost:11434"),
    "target_model": cfg.get("scanner.target_model", "llama3"),
    "timeout": cfg.get("scanner.timeout", 90),
    "api_key": cfg.get("scanner.api_key", ""),
}

risk_scorer = RiskScorer()


def get_active_scan_token() -> str | None:
    return active_scan_token


def set_active_scan_token(token: str | None) -> None:
    global active_scan_token
    active_scan_token = token

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
        # Use a separate judge model to avoid confirmation bias (Zheng et al., 2023)
        # Try to use a different model; fall back to same model if only one available
        judge_model = cfg.get("scanner.judge_model", "")
        if judge_model and judge_model != resolved_model:
            judge = LLMJudge.create_with_separate_model(
                api_url=config["target_url"], judge_model=judge_model
            )
        else:
            judge = LLMJudge(judge_client=client)

        meta = MODULES_METADATA.get(module_name, {})
        display_name = meta.get("name", module_name)
        budget_cfg = config.get("budget") if isinstance(config.get("budget"), dict) else {}
        campaign_budget = CampaignBudget(
            max_requests=budget_cfg.get("max_requests"),
            max_tokens=budget_cfg.get("max_tokens"),
            max_duration_sec=budget_cfg.get("max_duration_sec"),
            kill_switch=cancel_event,
        )
        log_audit_event(
            "SCAN_STARTED",
            target_url=config["target_url"],
            scan_id=scan_id,
            details={"module": module_name, "model": resolved_model, "budget": campaign_budget.snapshot()},
        )
        emit("status", {"message": f"[*] Khởi chạy module: {display_name} (Target model: {resolved_model})", "level": "info"})

        if module_name == "port_scan":
            from modules.auxiliary.scanner.port_scan import PortScanner
            scanner = PortScanner()
            from urllib.parse import urlparse as _urlparse
            host = _urlparse(config["target_url"]).hostname or "127.0.0.1"
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

        elif module_name == "code_scanner":
            from modules.auxiliary.scanner.code_scanner import AICodeScanner
            sast_scanner = AICodeScanner()
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            sample_dir = os.path.join(project_root, "data", "samples", "vulnerable_oss_ai_app")
            emit("status", {"message": f"[*] [AI-SAST Engine] Đang quét mã nguồn tĩnh ứng dụng AI tại: {sample_dir}", "level": "info"})
            sast_res = (
                sast_scanner.scan_directory(sample_dir)
                if os.path.exists(sample_dir)
                else sast_scanner.scan_code_snippet(sast_scanner.get_sample_vulnerable_code())
            )
            sast_findings = sast_res.get("findings", [])
            total_items = max(len(sast_findings), 1)
            scan_status["total"] = total_items
            for idx, f in enumerate(sast_findings):
                if is_aborted():
                    break
                payload_str = (
                    f"[{f['rule_id']} | {f['cwe']}] File: {f['file']} (Line {f['line']})\n"
                    f"Code: {f['code_line']}\n\nContext:\n{f.get('context_snippet', '')}"
                )
                resp_str = (
                    f"[SAST FINDING] {f['title']}\n\nMô tả: {f['description']}\n\n"
                    f"Khuyến nghị vá lỗi:\n{f['remediation']}\n\nCode an toàn mẫu:\n{f.get('fix_example', '')}"
                )
                save_finding(
                    scan_id, f"SAST://{f['file']}:{f['line']}", "code_scanner",
                    payload_str, resp_str,
                    f["severity"], f["risk_score"], f["owasp"], f["mitre"]
                )
                emit("finding", {
                    "index": idx + 1,
                    "total": total_items,
                    "name": f"{f['rule_id']}: {f['title']}",
                    "payload": payload_str[:220],
                    "response": resp_str[:300],
                    "is_vuln": True,
                    "reason": f"SAST Rule {f['rule_id']} ({f['cwe']}) tại {f['file']}:{f['line']}",
                    "confidence": "HIGH",
                    "severity": f["severity"],
                    "risk_score": f["risk_score"],
                    "owasp": f["owasp"],
                    "mitre": f["mitre"],
                    "response_time_ms": 12,
                })
                pct = round(((idx + 1) / total_items) * 100)
                scan_status["progress"] = idx + 1
                progress_data = {"current": idx + 1, "total": total_items, "percent": pct, "module": module_name}
                if batch_info:
                    b_curr = batch_info["offset"] + idx + 1
                    b_tot = max(batch_info["total_payloads"], b_curr)
                    progress_data["overall_current"] = b_curr
                    progress_data["overall_total"] = b_tot
                    progress_data["percent"] = round((b_curr / b_tot) * 100)
                emit("progress", progress_data)

        elif module_name == "oss_security":
            from modules.auxiliary.scanner.oss_scanner import OpenSourceAIScanner
            oss_scanner = OpenSourceAIScanner()
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            sample_dir = os.path.join(project_root, "data", "samples", "vulnerable_oss_ai_app")
            emit("status", {"message": f"[*] [OSS & Supply Chain Scanner] Đang quét dịch vụ AI mã nguồn mở ({config['target_url']}), Model Checkpoint & thư viện SCA...", "level": "info"})
            oss_res = oss_scanner.run_full_oss_audit(
                target_url=config["target_url"],
                project_dir=sample_dir if os.path.exists(sample_dir) else project_root,
            )
            oss_findings = oss_res.get("findings", [])
            total_items = max(len(oss_findings), 1)
            scan_status["total"] = total_items
            for idx, f in enumerate(oss_findings):
                if is_aborted():
                    break
                payload_str = f"[{f['finding_id']}] Target/Component: {f['platform']} ({f['category']})\nEvidence: {f['evidence']}"
                resp_str = f"[OPEN-SOURCE AI VULNERABILITY] {f['title']}\n\nChi tiết: {f['description']}\n\nKhuyến nghị khắc phục:\n{f['remediation']}"
                save_finding(
                    scan_id, config["target_url"], "oss_security",
                    payload_str, resp_str,
                    f["severity"], f["risk_score"], f.get("owasp", "LLM03"), f.get("mitre", "AML.T0010")
                )
                emit("finding", {
                    "index": idx + 1,
                    "total": total_items,
                    "name": f"{f['finding_id']}: {f['title'][:65]}",
                    "payload": payload_str[:220],
                    "response": resp_str[:300],
                    "is_vuln": True,
                    "reason": f"Phát hiện lỗ hổng hệ thống/thư viện mã nguồn mở: {f['finding_id']}",
                    "confidence": "HIGH",
                    "severity": f["severity"],
                    "risk_score": f["risk_score"],
                    "owasp": f.get("owasp", "LLM03"),
                    "mitre": f.get("mitre", "AML.T0010"),
                    "response_time_ms": 25,
                })
                pct = round(((idx + 1) / total_items) * 100)
                scan_status["progress"] = idx + 1
                progress_data = {"current": idx + 1, "total": total_items, "percent": pct, "module": module_name}
                if batch_info:
                    b_curr = batch_info["offset"] + idx + 1
                    b_tot = max(batch_info["total_payloads"], b_curr)
                    progress_data["overall_current"] = b_curr
                    progress_data["overall_total"] = b_tot
                    progress_data["percent"] = round((b_curr / b_tot) * 100)
                emit("progress", progress_data)

        else:
            # ── Dynamic module loading via registry ──────────────────
            from modules.registry import load_module
            module = load_module(module_name)
            if module is None:
                emit("error", {"message": f"Module không tồn tại: {module_name}"})
                return

            raw_cp = config.get("custom_payloads")
            if isinstance(raw_cp, dict):
                resolved_cp = raw_cp.get(module_name)
            elif isinstance(raw_cp, list):
                resolved_cp = raw_cp
            else:
                resolved_cp = None

            if isinstance(resolved_cp, list) and len(resolved_cp) > 0:
                payloads = resolved_cp
            else:
                payloads = getattr(module, "payloads", [])
                if config.get("adaptive_mode"):
                    from core.adaptive_generator import AdaptiveGenerator
                    ag = AdaptiveGenerator(seed=42)
                    payloads = ag.mutate_batch(list(payloads), max_variants_per_payload=1)
                    emit("status", {"message": f"[*] [Adaptive Engine] Đã kích hoạt đột biến payload: mở rộng lên {len(payloads)} kịch bản.", "level": "info"})
            total_payloads = len(payloads)
            scan_status["total"] = total_payloads

            for i, p in enumerate(payloads):
                if is_aborted():
                    emit("status", {"message": f"[!] Đã dừng module {display_name} tại payload {i+1}/{total_payloads}.", "level": "warn"})
                    break
                budget_ok, budget_reason = campaign_budget.check_allowed()
                if not budget_ok:
                    log_audit_event(
                        "BUDGET_EXCEEDED",
                        target_url=config["target_url"],
                        scan_id=scan_id,
                        outcome="STOPPED",
                        details={"module": module_name, "reason": budget_reason, "budget": campaign_budget.snapshot()},
                    )
                    emit("status", {"message": f"[!] Dừng sớm do chạm ngưỡng tài nguyên (Governance Budget): {budget_reason}", "level": "warn"})
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
                            chat_msgs = [{"role": r.lower(), "content": txt} for r, txt in conv_history] + [{"role": "user", "content": turn_prompt}]
                            t_resp = client.send_chat(chat_msgs) if hasattr(client, "send_chat") else client.send_prompt(p_ctx)
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
                campaign_budget.record_usage(prompt_text=payload_text, response_text=response_text)

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
                    conf_str = str(confidence or "").upper()
                    ver_status = "CONFIRMED" if ("JUDGE" in conf_str or conf_str == "HIGH") else "NEEDS_VERIFICATION"
                    fid = save_finding(
                        scan_id, config["target_url"], module_name,
                        payload_text, response_text,
                        severity, risk_score, owasp, mitre,
                        verification_status=ver_status,
                    )
                    try:
                        from core.evidence_store import EvidenceStore
                        EvidenceStore().record_evidence(
                            finding_id=str(fid),
                            payload=payload_text,
                            response=response_text,
                            module_name=module_name,
                            detector_result=True,
                            score=risk_score,
                            model_version=resolved_model,
                            run_id=f"scan_{scan_id}",
                        )
                    except Exception:
                        pass

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
        log_audit_event(
            "SCAN_CANCELLED" if is_aborted() else "SCAN_COMPLETED",
            target_url=config["target_url"],
            scan_id=scan_id,
            outcome="CANCELLED" if is_aborted() else "OK",
            details={"module": module_name, "budget": campaign_budget.snapshot()},
        )
        if is_aborted():
            if not is_batch:
                emit("cancelled", {"message": f"Scan module '{display_name}' đã bị hủy bởi người dùng.", "scan_id": scan_id})
        else:
            if not is_batch:
                emit("done", {"message": f"Scan hoàn tất module '{display_name}'!", "scan_id": scan_id})

    except Exception as e:
        logger.error("Scan worker error: %s", e)
        scan_queue.put({
            "type": "error",
            "data": {"message": "Lỗi nội bộ trong quá trình quét. Vui lòng kiểm tra scanner.log."},
            "token": scan_token,
            "ts": datetime.now().isoformat(),
        })
    finally:
        global active_scan_token
        with scan_lock:
            if not is_batch and (scan_token is None or scan_token == active_scan_token):
                scan_status["running"] = False
                scan_status["current_module"] = None
                active_scan_token = None



def _launch_multi_module_scan(data: dict):
    """Shared validated launcher for multi-module scans (no duplicate decorators)."""
    global active_scan_token
    merged_validate = {
        "target_url": data.get("target_url", app_config["target_url"]),
        "target_model": data.get("target_model", app_config["target_model"]),
        "timeout": data.get("timeout", app_config["timeout"]),
    }
    if "modules" in data:
        merged_validate["modules"] = data["modules"]
    if "authorized_targets" in data:
        merged_validate["authorized_targets"] = data["authorized_targets"]

    is_valid, err_msg = validate_scan_request(merged_validate)
    if not is_valid:
        if err_msg and "scope" in err_msg.lower():
            log_audit_event(
                "SCOPE_BLOCKED",
                target_url=str(merged_validate.get("target_url", "")),
                outcome="DENIED",
                details={"reason": err_msg},
            )
        return jsonify({"error": "Validation Error", "message": err_msg}), 400

    if data.get("custom_payloads"):
        cp_ok, cp_err = validate_custom_payloads(data["custom_payloads"])
        if not cp_ok:
            return jsonify({"error": "Validation Error", "message": cp_err}), 400

    with scan_lock:
        if scan_status["running"]:
            return jsonify({"error": "Một scan đang chạy. Nhấn 'Hủy Scan' nếu muốn dừng lại."}), 409

        cancel_event.clear()
        active_scan_token = str(uuid.uuid4())
        scan_status["running"] = True

    config = {**app_config, **{k: v for k, v in data.items() if k in app_config}}
    if "adaptive_mode" in data:
        config["adaptive_mode"] = bool(data["adaptive_mode"])
    if data.get("custom_payloads"):
        config["custom_payloads"] = data["custom_payloads"]
    modules_to_run = data.get("modules", list(MODULES_METADATA.keys()))
    scan_queue.clear_backlog()
    current_token = active_scan_token

    def run_all_worker():
        global active_scan_token
        try:
            total_all_payloads = sum(
                MODULES_METADATA.get(m, {}).get("payloads_count", 6)
                for m in modules_to_run if m in MODULES_METADATA
            )
            batch_state = {"current": 0, "total": max(1, total_all_payloads)}
            scan_queue.put({
                "type": "status",
                "data": {"message": f"🚀 Bắt đầu quét {len(modules_to_run)} module ({total_all_payloads} payloads)...", "level": "info"},
                "token": current_token,
                "ts": datetime.now().isoformat(),
            })
            for mod_key in modules_to_run:
                if cancel_event.is_set():
                    break
                if mod_key not in MODULES_METADATA:
                    continue
                sid = start_scan(config["target_url"], config["target_model"])
                scan_worker(mod_key, config, sid, is_batch=True, batch_state=batch_state, scan_token=current_token)
            if cancel_event.is_set():
                scan_queue.put({
                    "type": "cancelled",
                    "data": {"message": "Phiên quét nhiều module đã bị hủy bởi người dùng."},
                    "token": current_token,
                    "ts": datetime.now().isoformat(),
                })
            else:
                scan_queue.put({
                    "type": "all_done",
                    "data": {"message": f"Hoàn tất quét toàn bộ {len(modules_to_run)} module!"},
                    "token": current_token,
                    "ts": datetime.now().isoformat(),
                })
        except Exception as e:
            logger.error("Multi-module scan worker error: %s", e)
            scan_queue.put({
                "type": "error",
                "data": {"message": "Lỗi nội bộ trong quá trình quét nhiều module."},
                "token": current_token,
                "ts": datetime.now().isoformat(),
            })
        finally:
            with scan_lock:
                if current_token == active_scan_token:
                    scan_status["running"] = False
                    scan_status["current_module"] = None
                    active_scan_token = None

    thread = threading.Thread(target=run_all_worker, daemon=True)
    thread.start()
    return jsonify({"success": True, "modules": modules_to_run, "scan_token": current_token})

