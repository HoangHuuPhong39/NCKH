# -*- coding: utf-8 -*-
"""
web/routes/reports.py - Findings, Scans, Reports (HTML/JSON/SARIF), Replay, Benchmark, Logs & Incidents
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime

from flask import Blueprint, Response, jsonify, request, send_from_directory

from core.config import cfg
from core.db import (
    clear_findings, get_finding_by_id, get_finding_dates, get_findings,
    get_scan_dates, get_scans, get_stats,
)
from core.llm_client import SimpleLLMClient
from core.logger import logger
from core.report import export_json_report, export_sarif_report, generate_html_report
from web.security import rate_limit, require_auth, validate_config_request
from web.services.scan_manager import _parse_int_arg, app_config

reports_bp = Blueprint("reports_bp", __name__)

@reports_bp.route("/api/findings", methods=["GET"])
@require_auth
def api_findings():
    severity = request.args.get("severity")
    module = request.args.get("module")
    date = request.args.get("date")
    scan_id_arg = request.args.get("scan_id")
    scan_id = int(scan_id_arg) if scan_id_arg and scan_id_arg.isdigit() else None
    verification_status = request.args.get("verification_status")
    remediation_status = request.args.get("remediation_status")
    limit = _parse_int_arg("limit", 100, min_val=1, max_val=1000)
    findings = get_findings(
        severity=severity,
        module_name=module,
        date=date,
        limit=limit,
        scan_id=scan_id,
        verification_status=verification_status,
        remediation_status=remediation_status,
    )
    dates = get_finding_dates()
    return jsonify({"findings": findings, "count": len(findings), "dates": dates})


@reports_bp.route("/api/scans", methods=["GET"])
@require_auth
def api_scans():
    date = request.args.get("date")
    limit = _parse_int_arg("limit", 50, min_val=1, max_val=500)
    scans = get_scans(date=date, limit=limit)
    dates = get_scan_dates()
    return jsonify({"scans": scans, "count": len(scans), "dates": dates})


@reports_bp.route("/api/findings", methods=["DELETE"])
@require_auth
def api_clear_findings():
    clear_findings()
    return jsonify({"success": True, "message": "Đã xóa tất cả findings."})


@reports_bp.route("/api/stats", methods=["GET"])
@require_auth
def api_stats():
    # Return aggregated statistics with module severity breakdown
    stats = get_stats()
    return jsonify(stats)


@reports_bp.route("/api/report/generate", methods=["POST"])
@require_auth
def api_generate_report():
    data = request.get_json(silent=True) or {}
    severity = data.get("severity") or request.args.get("severity")
    module = data.get("module") or request.args.get("module")
    scan_id = data.get("scan_id") or request.args.get("scan_id")
    scan_id_int = int(scan_id) if scan_id is not None and str(scan_id).isdigit() else None
    redact = data.get("redact") if "redact" in data else None

    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), cfg.get("storage.reports_dir", "reports"))
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, "report.html")

    success = generate_html_report(
        report_path,
        severity=severity,
        module_name=module,
        scan_id=scan_id_int,
        redact=redact,
    )
    if success:
        return jsonify({
            "success": True,
            "path": report_path,
            "severity": severity,
            "module": module,
            "scan_id": scan_id_int,
        })
    return jsonify({"error": "Không thể tạo báo cáo."}), 500


@reports_bp.route("/api/report/download")
@require_auth
def api_download_report():
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), cfg.get("storage.reports_dir", "reports"))
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, "report.html")
    if not os.path.exists(report_path):
        generate_html_report(report_path)
    return send_from_directory(reports_dir, "report.html", as_attachment=True)


@reports_bp.route("/api/report/view")
@require_auth
def api_view_report():
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), cfg.get("storage.reports_dir", "reports"))
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, "report.html")
    if not os.path.exists(report_path):
        generate_html_report(report_path)
    return send_from_directory(reports_dir, "report.html", as_attachment=False)


@reports_bp.route("/api/report/json")
@require_auth
def api_json_report():
    severity = request.args.get("severity")
    module = request.args.get("module")
    scan_id_arg = request.args.get("scan_id")
    scan_id_int = int(scan_id_arg) if scan_id_arg and scan_id_arg.isdigit() else None
    redact_arg = request.args.get("redact")
    redact = None if redact_arg is None else (redact_arg.lower() in ("true", "1", "yes"))
    data = export_json_report(
        severity=severity,
        module_name=module,
        scan_id=scan_id_int,
        redact=redact,
    )
    return jsonify(data)


@reports_bp.route("/api/report/sarif", methods=["GET"])
@require_auth
def api_sarif_report():
    """Xuất báo cáo chuẩn SARIF 2.1.0 tương thích GitHub Code Scanning / GitLab CI."""
    severity = request.args.get("severity")
    module = request.args.get("module")
    scan_id_arg = request.args.get("scan_id")
    scan_id_int = int(scan_id_arg) if scan_id_arg and scan_id_arg.isdigit() else None
    redact_arg = request.args.get("redact")
    redact = None if redact_arg is None else (redact_arg.lower() in ("true", "1", "yes"))
    download = str(request.args.get("download", "0")).lower() in ("1", "true", "yes")

    sarif_doc = export_sarif_report(
        severity=severity,
        module_name=module,
        scan_id=scan_id_int,
        redact=redact,
    )
    headers = {}
    if download:
        headers["Content-Disposition"] = 'attachment; filename="ai_security_report.sarif"'
    return Response(
        json.dumps(sarif_doc, ensure_ascii=False, indent=2),
        mimetype="application/sarif+json",
        headers=headers,
    )


# ─────────────────────────────────────────────
@reports_bp.route("/api/threat-model", methods=["POST"])
@require_auth
@rate_limit(limit=20, window=60)
def api_threat_model():
    """Phân tích hồ sơ đe dọa (Threat Model & Attack Surface) cho hệ thống mục tiêu."""
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url", app_config["target_url"])
    valid_url, url_err = validate_config_request({"target_url": str(target_url)})
    if not valid_url:
        return jsonify({"success": False, "error": url_err}), 400
    model_name = data.get("target_model", app_config["target_model"])
    system_type = data.get("system_type", "auto")
    try:
        from core.threat_model import ThreatModel
        tm = ThreatModel()
        tm.profile_target(target_url=target_url, model_name=model_name, system_type=system_type)
        report = tm.export_threat_model()
        return jsonify({"success": True, "report": report})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/api/findings/replay", methods=["POST"])
@require_auth
@rate_limit(limit=30, window=60)
def api_finding_replay():
    """Tái lập kiểm thử (Replay Test) một lỗ hổng để kiểm chứng tính tái lập (Reproducibility)."""
    data = request.get_json(silent=True) or {}
    payload_text = data.get("payload", "")
    orig_response = data.get("original_response", "")
    module_name = data.get("module_name", "prompt_injection")
    live_replay = data.get("live", True)

    if not payload_text:
        return jsonify({"success": False, "error": "Thiếu payload để replay."}), 400

    try:
        from modules.detectors.pattern_match import PatternDetector
        detector = PatternDetector()
        t0 = time.perf_counter()

        target_url = data.get("target_url") or app_config["target_url"]
        valid_url, url_err = validate_config_request({"target_url": str(target_url)})
        if not valid_url:
            return jsonify({"success": False, "error": url_err}), 400
        target_model = data.get("target_model") or data.get("model") or app_config["target_model"]
        replay_api_key = data.get("api_key") or app_config.get("api_key", "")
        if replay_api_key and "••••" in replay_api_key:
            replay_api_key = app_config.get("api_key", "")

        if live_replay:
            client = SimpleLLMClient(
                api_url=target_url,
                model_name=target_model,
                timeout=int(app_config.get("timeout", 30)),
                api_key=replay_api_key,
            )
            replay_resp = client.send_prompt(payload_text)
            if replay_resp.startswith("[-]") and orig_response and not orig_response.startswith("[-]"):
                # Fallback sang offline verification nếu server LLM đang tắt
                replay_resp = orig_response
                mode_used = "Offline Evidence Verification (Target Offline)"
            else:
                mode_used = f"Live Target Replay ({client.resolve_model_name()})"
        else:
            replay_resp = orig_response
            mode_used = "Offline Evidence Verification"

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        is_vuln, reason, conf = detector.analyze(replay_resp, payload_text, module_name)
        if conf == "LOW" and live_replay and not replay_resp.startswith("[-]"):
                    from modules.detectors.llm_judge import LLMJudge
                    judge_client = SimpleLLMClient(
                        api_url=app_config["target_url"],
                        model_name=cfg.get("scanner.judge_model", "") or app_config["target_model"],
                        timeout=int(app_config.get("timeout", 30)),
                        api_key=app_config.get("api_key", ""),
                    )
                    judge = LLMJudge(judge_client=judge_client)
                    j_res = judge.evaluate(payload_text, replay_resp, module_name, pattern_result=(is_vuln, reason, conf))
                    if j_res.get("judge_used"):
                        is_vuln = j_res["is_exploited"]
                        reason = f"[Tier-2 LLM-Judge] {j_res['reasoning']}"
                        conf = f"JUDGE ({int(j_res['confidence']*100)}%)"
        orig_words = set(orig_response.lower().split())
        rep_words = set(replay_resp.lower().split())
        similarity = len(orig_words & rep_words) / max(len(orig_words | rep_words), 1)
        is_reproducible = bool(is_vuln or similarity >= 0.4)

        return jsonify({
            "success": True,
            "mode": mode_used,
            "replay_response": replay_resp,
            "is_vulnerable": is_vuln,
            "reason": reason,
            "confidence": conf,
            "similarity_score": round(similarity, 4),
            "is_reproducible": is_reproducible,
            "elapsed_ms": elapsed_ms,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/api/benchmark/run", methods=["POST"])
@require_auth
@rate_limit(limit=10, window=60)
def api_benchmark_run():
    """Chạy nhanh Benchmark (Standard 36 cases hoặc Tiếng Việt 62 cases) từ giao diện Web."""
    data = request.get_json(silent=True) or {}
    dataset_type = data.get("dataset", "vietnamese")
    try:
        from experiments.benchmark import Benchmarker, load_benchmark_dataset
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if dataset_type == "vietnamese":
            ds_path = os.path.join(project_root, "data", "vietnamese_benchmark.json")
        elif dataset_type == "harmbench":
            ds_path = os.path.join(project_root, "data", "harmbench_subset.json")
        else:
            ds_path = os.path.join(project_root, "data", "benchmark_dataset.json")

        cases = load_benchmark_dataset(ds_path)
        target_url = data.get("target_url") or app_config["target_url"]
        valid_url, url_err = validate_config_request({"target_url": str(target_url)})
        if not valid_url:
            return jsonify({"success": False, "error": url_err}), 400
        target_model = data.get("target_model") or data.get("model") or app_config["target_model"]
        live_eval = bool(data.get("live", False))
        bm = Benchmarker(target_url=target_url, model_name=target_model)
        raw_res = bm.run_benchmark(test_cases=cases)
        results = raw_res[0] if isinstance(raw_res, tuple) else raw_res

        rows = []
        tot_tp = tot_fp = tot_tn = tot_fn = 0
        for r in results:
            tot_tp += r.true_positives
            tot_fp += r.false_positives
            tot_tn += r.true_negatives
            tot_fn += r.false_negatives
            rows.append({
                "module": r.module_name,
                "total": r.total_cases,
                "tp": r.true_positives,
                "fp": r.false_positives,
                "tn": r.true_negatives,
                "fn": r.false_negatives,
                "precision": r.precision,
                "recall": r.recall,
                "f1": r.f1_score,
                "latency_ms": r.avg_response_time_ms,
            })

        prec = tot_tp / max(tot_tp + tot_fp, 1)
        rec = tot_tp / max(tot_tp + tot_fn, 1)
        f1 = (2 * prec * rec / max(prec + rec, 1e-9)) if (prec + rec) > 0 else 0.0

        return jsonify({
            "success": True,
            "dataset": dataset_type,
            "total_cases": len(cases),
            "summary": {
                "tp": tot_tp, "fp": tot_fp, "tn": tot_tn, "fn": tot_fn,
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
            },
            "modules": rows,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@reports_bp.route("/api/integrations/status", methods=["GET"])
def api_integrations_status():
    """Trả về trạng thái của 6 bộ công cụ mã nguồn mở tích hợp (Nội dung 5)."""
    from modules.integrations import (
        GarakWrapper, PyRITWrapper, PromptfooWrapper,
        DeepTeamWrapper, GiskardWrapper, ARTWrapper
    )
    tools = [
        {
            "id": "garak",
            "name": "NVIDIA Garak",
            "org": "NVIDIA Corporation (Apache 2.0)",
            "scope": "LLM Probes (PromptInject, DAN, XSS, MalwareGen)",
            "owasp": "LLM01, LLM05",
            "installed": GarakWrapper(app_config["target_url"], app_config["target_model"]).is_available(),
            "cmd": "pip install garak",
        },
        {
            "id": "pyrit",
            "name": "Microsoft PyRIT",
            "org": "Microsoft AI Red Team (MIT)",
            "scope": "Multi-Turn Orchestration & Crescendo Attack",
            "owasp": "LLM01, LLM02, LLM06",
            "installed": PyRITWrapper(app_config["target_url"], app_config["target_model"]).is_available(),
            "cmd": "pip install pyrit",
        },
        {
            "id": "promptfoo",
            "name": "Promptfoo Red-Team",
            "org": "Promptfoo Open Source (MIT)",
            "scope": "CI/CD YAML Evaluation & Red-Teaming Plugins",
            "owasp": "LLM01, LLM02, LLM07",
            "installed": PromptfooWrapper().is_available(),
            "cmd": "npm install -g promptfoo",
        },
        {
            "id": "deepteam",
            "name": "Confident AI DeepTeam",
            "org": "Confident AI (Apache 2.0)",
            "scope": "Agentic AI Security & RAG Poisoning",
            "owasp": "LLM01, LLM06, LLM08",
            "installed": DeepTeamWrapper().is_available(),
            "cmd": "pip install deepteam",
        },
        {
            "id": "giskard",
            "name": "Giskard OSS Scanner",
            "org": "Giskard AI (Apache 2.0)",
            "scope": "Hallucination, Bias, Stereotypes & Data Leakage",
            "owasp": "LLM02, LLM09",
            "installed": GiskardWrapper().is_available(),
            "cmd": "pip install giskard",
        },
        {
            "id": "art",
            "name": "IBM Adversarial Robustness Toolbox (ART)",
            "org": "Trusted-AI / Linux Foundation (MIT)",
            "scope": "ML/DL Evasion (FGSM, PGD, TextFooler)",
            "owasp": "MITRE AML.T0015 / AML.T0043",
            "installed": ARTWrapper().is_available(),
            "cmd": "pip install adversarial-robustness-toolbox",
        },
    ]
    return jsonify({"tools": tools})


@reports_bp.route("/api/logs", methods=["GET"])
@require_auth
def api_logs():
    """Retrieve structured real-time operational logs from scanner.log."""
    limit = _parse_int_arg("limit", 60, min_val=1, max_val=300)
    level_filter = request.args.get("level", "").strip().upper()
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_path = os.path.join(project_root, "logs", "scanner.log")

    logs = []
    total_lines = 0
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_lines = f.readlines()
            total_lines = len(raw_lines)
            log_regex = re.compile(
                r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[([A-Z]+)\] \[([^\]]+)\] (.*)$"
            )
            for line in raw_lines[-limit * 3:]:
                line = line.strip()
                if not line:
                    continue
                m = log_regex.match(line)
                if m:
                    lvl = m.group(2)
                    if level_filter and lvl != level_filter:
                        continue
                    logs.append({
                        "timestamp": m.group(1),
                        "level": lvl,
                        "logger": m.group(3),
                        "message": m.group(4),
                    })
                else:
                    if not level_filter or level_filter == "INFO":
                        logs.append({
                            "timestamp": "",
                            "level": "INFO",
                            "logger": "system",
                            "message": line,
                        })
            logs = logs[-limit:]
        except Exception as e:
            logger.warning(f"Error reading scanner.log: {e}")

    return jsonify({
        "success": True,
        "total_lines": total_lines,
        "count": len(logs),
        "logs": logs,
    })


@reports_bp.route("/api/incidents", methods=["GET"])
@require_auth
def api_incidents():
    """Correlate critical & high severity findings into security incident clusters."""
    try:
        findings = get_findings(limit=250)
        clusters = {}
        for f in findings:
            if f.get("severity") in ("CRITICAL", "HIGH"):
                key = (f.get("module_name"), f.get("mitre_code"))
                if key not in clusters:
                    clusters[key] = []
                clusters[key].append(f)

        incidents = []
        idx = 1
        for (mod, mitre), f_list in clusters.items():
            incidents.append({
                "id": f"INC-{idx:03d}",
                "title": f"Correlated {f_list[0].get('severity')} Attack Vector: {mod}",
                "module": mod,
                "mitre": mitre or "AML.T0051",
                "owasp": f_list[0].get("owasp_code", "LLM01"),
                "severity": f_list[0].get("severity", "HIGH"),
                "count": len(f_list),
                "target_url": f_list[0].get("target_url", app_config["target_url"]),
                "last_seen": f_list[0].get("timestamp", "N/A"),
                "first_seen": f_list[-1].get("timestamp", "N/A"),
                "sample_payload": (f_list[0].get("payload") or "")[:250],
                "finding_ids": [x.get("id") for x in f_list],
            })
            idx += 1
        return jsonify({"success": True, "incidents": incidents, "count": len(incidents)})
    except Exception as e:
        logger.error(f"Incident correlation error: {e}")
        return jsonify({"success": False, "incidents": [], "count": 0, "error": str(e)}), 500


# ─────────────────────────────────────────────
