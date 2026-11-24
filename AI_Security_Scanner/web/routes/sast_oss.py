# -*- coding: utf-8 -*-
"""
web/routes/sast_oss.py - White-Box AI SAST, Open-Source AI Supply Chain, Trivy, Data Hygiene & ML Privacy
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List

from flask import Blueprint, jsonify, request

from core.config import cfg
from core.db import complete_scan, save_finding, start_scan
from core.logger import logger
from web.security import rate_limit, require_auth, validate_config_request
from web.services.scan_manager import app_config

sast_oss_bp = Blueprint("sast_oss_bp", __name__)

# SAST Code Scanner & Open-Source AI Ecosystem Audit Endpoints
# ─────────────────────────────────────────────
@sast_oss_bp.route("/api/code-scan/sample", methods=["GET"])
@require_auth
def api_code_scan_sample():
    """Trả về mẫu code AI lỗi, đường dẫn thư mục mẫu và danh sách 10 quy tắc AI-SAST."""
    from modules.auxiliary.scanner.code_scanner import AICodeScanner, AI_SAST_RULES
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sample_dir = os.path.join(project_root, "data", "samples", "vulnerable_oss_ai_app")
    return jsonify({
        "success": True,
        "sample_code": AICodeScanner.get_sample_vulnerable_code(),
        "sample_dir": sample_dir,
        "project_root": project_root,
        "rules": [
            {
                "rule_id": r["rule_id"],
                "title": r["title"],
                "severity": r["severity"],
                "owasp": r["owasp"],
                "cwe": r["cwe"],
            }
            for r in AI_SAST_RULES
        ],
    })


def _save_uploaded_files_to_dir(files_list, relative_paths, base_dir: str) -> List[str]:
    """Lưu danh sách file upload vào thư mục tạm an toàn, chống path traversal."""
    saved_rel_paths: List[str] = []
    base_real = os.path.realpath(base_dir)
    for idx, f in enumerate(files_list):
        if not f or not f.filename:
            continue
        raw_rel = relative_paths[idx] if idx < len(relative_paths) and relative_paths[idx] else f.filename
        raw_rel = raw_rel.replace("\\", "/").lstrip("/")
        parts = [p for p in raw_rel.split("/") if p and p not in (".", "..")]
        if not parts:
            continue
        safe_rel = os.path.join(*parts)
        dest_path = os.path.realpath(os.path.join(base_real, safe_rel))
        if not (dest_path == base_real or dest_path.startswith(base_real + os.sep)):
            continue
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        f.save(dest_path)
        saved_rel_paths.append(safe_rel.replace("\\", "/"))
    return saved_rel_paths


def _persist_sast_findings(target_label: str, findings: List[Dict[str, Any]]) -> int:
    """Lưu danh sách phát hiện SAST vào Findings DB."""
    scan_id = start_scan(f"SAST://{target_label}", "AI-SAST-Engine")
    for f in findings:
        payload_str = (
            f"[{f['rule_id']} | {f['cwe']}] File: {f['file']} (Line {f['line']})\n"
            f"Code: {f['code_line']}\n\nContext:\n{f.get('context_snippet', '')}"
        )
        resp_str = (
            f"[SAST FINDING] {f['title']}\n\nMô tả: {f['description']}\n\n"
            f"Khuyến nghị vá lỗi:\n{f['remediation']}\n\nCode an toàn mẫu:\n{f.get('fix_example', '')}"
        )
        save_finding(
            scan_id,
            f"SAST://{f['file']}:{f['line']}",
            "code_scanner",
            payload_str,
            resp_str,
            f["severity"],
            f["risk_score"],
            f["owasp"],
            f["mitre"],
        )
    complete_scan(scan_id)
    return scan_id


def _persist_oss_findings(target_url: str, findings: List[Dict[str, Any]]) -> int:
    """Lưu danh sách phát hiện OSS / ModelScan / SCA vào Findings DB."""
    scan_id = start_scan(target_url, "OSS-SupplyChain-Scanner")
    for f in findings:
        payload_str = f"[{f['finding_id']}] Target/Component: {f['platform']} ({f['category']})\nEvidence: {f['evidence']}"
        resp_str = f"[OPEN-SOURCE AI VULNERABILITY] {f['title']}\n\nChi tiết: {f['description']}\n\nKhuyến nghị khắc phục:\n{f['remediation']}"
        save_finding(
            scan_id,
            target_url,
            "oss_security",
            payload_str,
            resp_str,
            f["severity"],
            f["risk_score"],
            f.get("owasp", "LLM03"),
            f.get("mitre", "AML.T0010"),
        )
    complete_scan(scan_id)
    return scan_id


@sast_oss_bp.route("/api/code-scan/run", methods=["POST"])
@require_auth
@rate_limit(limit=20, window=60)
def api_code_scan_run():
    """Thực thi quét mã nguồn tĩnh (SAST) trên đoạn code hoặc thư mục dự án AI."""
    from modules.auxiliary.scanner.code_scanner import AICodeScanner
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "snippet")
    save_to_db = bool(data.get("save_to_db", True))
    use_hybrid_llm = bool(data.get("use_hybrid_llm", False))
    hybrid_mode = (data.get("hybrid_mode") or "selective").strip().lower()
    use_cache = bool(data.get("use_cache", True))
    active_url = (data.get("ollama_url") or data.get("target_url") or app_config.get("target_url") or "").strip() or None
    if use_hybrid_llm and active_url:
        u_ok, u_err = validate_config_request({"target_url": active_url})
        if not u_ok:
            return jsonify({"success": False, "error": u_err}), 400
    active_model = (data.get("llm_model") or data.get("target_model") or app_config.get("target_model") or "").strip() or None

    scanner = AICodeScanner()
    if mode == "directory":
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        default_sample_dir = os.path.join(project_root, "data", "samples", "vulnerable_oss_ai_app")
        target_path = (data.get("target_path") or "").strip() or default_sample_dir
        res = scanner.scan_directory(
            target_path=target_path,
            use_hybrid_llm=use_hybrid_llm,
            ollama_url=active_url,
            llm_model=active_model,
            hybrid_mode=hybrid_mode,
            use_cache=use_cache,
        )
    else:
        code_text = data.get("code")
        if not code_text or not str(code_text).strip():
            code_text = scanner.get_sample_vulnerable_code()
        filename = (data.get("filename") or "vulnerable_ai_app.py").strip()
        res = scanner.scan_code_snippet(
            code=str(code_text),
            filename=filename,
            use_hybrid_llm=use_hybrid_llm,
            ollama_url=active_url,
            llm_model=active_model,
            use_cache=use_cache,
        )

    if not res.get("success"):
        return jsonify(res), 400

    findings = res.get("findings", [])
    if save_to_db and findings:
        res["scan_id"] = _persist_sast_findings(res.get("target", "code_scan"), findings)

    return jsonify(res)


@sast_oss_bp.route("/api/code-scan/upload", methods=["POST"])
@require_auth
@rate_limit(limit=15, window=60)
def api_code_scan_upload():
    """Nhận file/thư mục mã nguồn upload từ máy người dùng và quét SAST."""
    import tempfile
    from modules.auxiliary.scanner.code_scanner import AICodeScanner

    files_list = request.files.getlist("files")
    if not files_list:
        return jsonify({"success": False, "error": "Chưa có tệp mã nguồn nào được tải lên."}), 400

    rel_paths_raw = request.form.get("relative_paths", "[]")
    try:
        relative_paths = json.loads(rel_paths_raw) if rel_paths_raw else []
    except Exception:
        relative_paths = []
    save_to_db = str(request.form.get("save_to_db", "true")).lower() in ("true", "1", "yes")
    use_hybrid_llm = str(request.form.get("use_hybrid_llm", "false")).lower() in ("true", "1", "yes")
    hybrid_mode = (request.form.get("hybrid_mode") or "selective").strip().lower()
    use_cache = str(request.form.get("use_cache", "true")).lower() in ("true", "1", "yes")
    active_url = (request.form.get("ollama_url") or app_config.get("target_url") or "").strip() or None
    if use_hybrid_llm and active_url:
        u_ok, u_err = validate_config_request({"target_url": active_url})
        if not u_ok:
            return jsonify({"success": False, "error": u_err}), 400
    active_model = (request.form.get("llm_model") or app_config.get("target_model") or "").strip() or None

    scanner = AICodeScanner()
    with tempfile.TemporaryDirectory(prefix="ai_sast_upload_") as tmpdir:
        saved = _save_uploaded_files_to_dir(files_list, relative_paths, tmpdir)
        if not saved:
            return jsonify({"success": False, "error": "Không có tệp hợp lệ để quét."}), 400
        res = scanner.scan_directory(
            target_path=tmpdir,
            use_hybrid_llm=use_hybrid_llm,
            ollama_url=active_url,
            llm_model=active_model,
            hybrid_mode=hybrid_mode,
            use_cache=use_cache,
        )
        res["target"] = f"Uploaded ({len(saved)} file)" if len(saved) == 1 else f"Uploaded ({len(saved)} files)"
        res["uploaded_files"] = saved

    if not res.get("success"):
        return jsonify(res), 400

    findings = res.get("findings", [])
    if save_to_db and findings:
        res["scan_id"] = _persist_sast_findings(res["target"], findings)

    return jsonify(res)


@sast_oss_bp.route("/api/oss-scan/sample", methods=["GET"])
@require_auth
def api_oss_scan_sample():
    """Trả về cấu hình mẫu cho bộ quét Hệ thống AI Mã nguồn mở & Chuỗi cung ứng (SCA / ModelScan)."""
    from modules.auxiliary.scanner.oss_scanner import (
        OpenSourceAIScanner, OSS_AI_PLATFORMS, AI_DEPENDENCY_CVE_DB
    )
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sample_dir = os.path.join(project_root, "data", "samples", "vulnerable_oss_ai_app")
    return jsonify({
        "success": True,
        "sample_requirements": OpenSourceAIScanner.get_sample_requirements(),
        "sample_dir": sample_dir,
        "platforms": OSS_AI_PLATFORMS,
        "cve_db": AI_DEPENDENCY_CVE_DB,
    })


@sast_oss_bp.route("/api/oss-scan/run", methods=["POST"])
@require_auth
@rate_limit(limit=15, window=60)
def api_oss_scan_run():
    """Thực thi quét các hệ thống AI mã nguồn mở (Ollama, Open-WebUI, vLLM, Ray...), Model Checkpoint & SCA."""
    from modules.auxiliary.scanner.oss_scanner import OpenSourceAIScanner
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "full")
    target_url = (data.get("target_url") or app_config["target_url"]).strip()
    if mode in ("platforms", "full") and target_url:
        u_ok, u_err = validate_config_request({"target_url": target_url})
        if not u_ok:
            return jsonify({"success": False, "error": u_err}), 400
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    default_sample_dir = os.path.join(project_root, "data", "samples", "vulnerable_oss_ai_app")
    raw_project_dir = (data.get("project_dir") or "").strip()
    project_dir = raw_project_dir or (default_sample_dir if mode == "models" else None)
    requirements_text = data.get("requirements_text")
    save_to_db = bool(data.get("save_to_db", True))
    scan_common_ports = bool(data.get("scan_common_ports", False))

    scanner = OpenSourceAIScanner()
    if mode == "platforms":
        plat_res = scanner.scan_oss_platforms(target_url=target_url, scan_common_ports=scan_common_ports)
        findings = plat_res.get("findings", [])
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s = f.get("severity", "MEDIUM").upper()
            by_sev[s] = by_sev.get(s, 0) + 1
        res = {
            "success": True,
            "mode": "platforms",
            "target_url": target_url,
            "discovered_services": plat_res.get("discovered_services", []),
            "artifacts_scanned": [],
            "packages_scanned": 0,
            "summary": {
                "total_findings": len(findings),
                "services_online": len(plat_res.get("discovered_services", [])),
                "artifacts_checked": 0,
                "packages_checked": 0,
                "by_severity": by_sev,
                "elapsed_ms": plat_res.get("elapsed_ms", 0),
            },
            "findings": findings,
        }
    elif mode == "dependencies":
        req_content = requirements_text if (requirements_text and str(requirements_text).strip()) else scanner.get_sample_requirements()
        sca_res = scanner.scan_dependencies(str(req_content), source_name="requirements.txt")
        findings = sca_res.get("findings", [])
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s = f.get("severity", "MEDIUM").upper()
            by_sev[s] = by_sev.get(s, 0) + 1
        res = {
            "success": True,
            "mode": "dependencies",
            "target_url": target_url,
            "discovered_services": [],
            "artifacts_scanned": ["requirements.txt"],
            "packages_scanned": sca_res.get("packages_scanned", 0),
            "summary": {
                "total_findings": len(findings),
                "services_online": 0,
                "artifacts_checked": 1,
                "packages_checked": sca_res.get("packages_scanned", 0),
                "by_severity": by_sev,
                "elapsed_ms": sca_res.get("elapsed_ms", 0),
            },
            "findings": findings,
        }
    elif mode == "models":
        art_res = scanner.scan_model_artifacts(project_dir, include_requirements=True)
        findings = art_res.get("findings", [])
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s = f.get("severity", "MEDIUM").upper()
            by_sev[s] = by_sev.get(s, 0) + 1
        res = {
            "success": True,
            "mode": "models",
            "target_url": target_url,
            "discovered_services": [],
            "artifacts_scanned": art_res.get("artifacts_scanned", []),
            "packages_scanned": art_res.get("packages_scanned", 0),
            "summary": {
                "total_findings": len(findings),
                "services_online": 0,
                "artifacts_checked": len(art_res.get("artifacts_scanned", [])),
                "packages_checked": art_res.get("packages_scanned", 0),
                "by_severity": by_sev,
                "elapsed_ms": art_res.get("elapsed_ms", 0),
            },
            "findings": findings,
        }
    else:
        res = scanner.run_full_oss_audit(
            target_url=target_url,
            project_dir=project_dir,
            requirements_text=requirements_text,
            scan_common_ports=scan_common_ports,
        )

    findings = res.get("findings", [])
    if save_to_db and findings:
        res["scan_id"] = _persist_oss_findings(target_url, findings)

    return jsonify(res)


@sast_oss_bp.route("/api/oss-scan/upload", methods=["POST"])
@require_auth
@rate_limit(limit=15, window=60)
def api_oss_scan_upload():
    """Nhận file/thư mục Model Checkpoint & Config upload từ máy và quét OSS / ModelScan / SCA."""
    import tempfile
    from modules.auxiliary.scanner.oss_scanner import OpenSourceAIScanner

    files_list = request.files.getlist("files")
    if not files_list:
        return jsonify({"success": False, "error": "Chưa có tệp Model / Config nào được tải lên."}), 400

    rel_paths_raw = request.form.get("relative_paths", "[]")
    try:
        relative_paths = json.loads(rel_paths_raw) if rel_paths_raw else []
    except Exception:
        relative_paths = []

    mode = (request.form.get("mode") or "models").strip().lower()
    target_url = (request.form.get("target_url") or app_config["target_url"]).strip()
    if mode in ("platforms", "full") and target_url:
        u_ok, u_err = validate_config_request({"target_url": target_url})
        if not u_ok:
            return jsonify({"success": False, "error": u_err}), 400
    requirements_text = request.form.get("requirements_text")
    save_to_db = str(request.form.get("save_to_db", "true")).lower() in ("true", "1", "yes")
    scan_common_ports = str(request.form.get("scan_common_ports", "false")).lower() in ("true", "1", "yes")

    scanner = OpenSourceAIScanner()
    with tempfile.TemporaryDirectory(prefix="ai_oss_upload_") as tmpdir:
        saved = _save_uploaded_files_to_dir(files_list, relative_paths, tmpdir)
        if not saved:
            return jsonify({"success": False, "error": "Không có tệp hợp lệ để quét."}), 400

        if mode == "models":
            art_res = scanner.scan_model_artifacts(tmpdir, include_requirements=True)
            findings = art_res.get("findings", [])
            by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            for f in findings:
                s = f.get("severity", "MEDIUM").upper()
                by_sev[s] = by_sev.get(s, 0) + 1
            res = {
                "success": True,
                "mode": "models",
                "target_url": target_url,
                "discovered_services": [],
                "artifacts_scanned": art_res.get("artifacts_scanned", []),
                "packages_scanned": art_res.get("packages_scanned", 0),
                "summary": {
                    "total_findings": len(findings),
                    "services_online": 0,
                    "artifacts_checked": len(art_res.get("artifacts_scanned", [])),
                    "packages_checked": art_res.get("packages_scanned", 0),
                    "by_severity": by_sev,
                    "elapsed_ms": art_res.get("elapsed_ms", 0),
                },
                "findings": findings,
            }
        else:
            res = scanner.run_full_oss_audit(
                target_url=target_url,
                project_dir=tmpdir,
                requirements_text=requirements_text,
                scan_common_ports=scan_common_ports,
            )
        res["uploaded_files"] = saved

    findings = res.get("findings", [])
    if save_to_db and findings:
        res["scan_id"] = _persist_oss_findings(target_url, findings)

    return jsonify(res)




@sast_oss_bp.route("/api/trivy/scan", methods=["POST"])
@require_auth
@rate_limit(limit=15, window=60)
def api_trivy_scan():
    """Quét bảo mật Container / Dockerfile / docker-compose / Supply Chain bằng Trivy (có Static Fallback)."""
    from modules.integrations.trivy_wrapper import TrivyWrapper
    data = request.get_json(silent=True) or {}
    mode = (data.get("mode") or "fs").strip().lower()
    save_to_db = bool(data.get("save_to_db", False))
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    target = (data.get("target") or project_root).strip()

    wrapper = TrivyWrapper()
    if mode == "image":
        res = wrapper.scan_image(target)
    elif mode == "config":
        res = wrapper.scan_config(target, allow_static_fallback=True)
    else:
        res = wrapper.scan_filesystem(target, allow_static_fallback=True)

    if save_to_db and res.get("findings"):
        scan_id = start_scan(f"TRIVY://{target}", "Trivy-Container-Scanner")
        for f in res["findings"]:
            save_finding(
                scan_id=scan_id,
                target_url=f"SAST://{f['target']}",
                module_name="oss_security",
                payload=f"[{f['finding_id']}] {f['title']} | Evidence: {f.get('evidence', '')}",
                response=f"{f.get('description', '')}\nRemediation: {f.get('remediation', '')}",
                severity=f["severity"],
                risk_score=f["risk_score"],
                owasp=f.get("owasp", "LLM03"),
                mitre=f.get("mitre", "AML.T0010"),
                verification_status="CONFIRMED",
                root_cause_type="INFRASTRUCTURE",
            )
        complete_scan(scan_id)
        res["scan_id"] = scan_id

    return jsonify(res)


@sast_oss_bp.route("/api/data-hygiene/scan", methods=["POST"])
@require_auth
@rate_limit(limit=20, window=60)
def api_data_hygiene_scan():
    """Quét an toàn dữ liệu huấn luyện/RAG (PII, Secret, Poisoning Trigger, Trùng lặp, Lệch nhãn, SHA-256 AI-BOM)."""
    from modules.auxiliary.scanner.data_privacy_scanner import AIDataHygieneScanner

    data = request.get_json(silent=True) or {}
    records = data.get("records")
    file_path = (data.get("file_path") or "").strip()
    dataset_name = (data.get("dataset_name") or "inline_dataset").strip()
    save_to_db = bool(data.get("save_to_db", False))

    scanner = AIDataHygieneScanner()
    if isinstance(records, list):
        res = scanner.scan_records(
            records,
            dataset_name=dataset_name,
            provenance_metadata=data.get("provenance"),
        )
    elif file_path:
        res = scanner.scan_file(file_path)
    else:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        default_ds = os.path.join(project_root, "data", "vietnamese_benchmark.json")
        res = scanner.scan_file(default_ds)

    if not res.get("success"):
        return jsonify(res), 400

    if save_to_db and res.get("findings"):
        ds_label = f"DATA://{res.get('dataset', dataset_name)}"
        scan_id = start_scan(ds_label, "AI-Data-Hygiene-Scanner")
        for f in res["findings"]:
            save_finding(
                scan_id=scan_id,
                target_url=ds_label,
                module_name="rag_security",
                payload=f"[{f['finding_id']}] {f['title']} | {f['evidence']}",
                response=f["remediation"],
                severity=f["severity"],
                risk_score=f["risk_score"],
                owasp=f["owasp"],
                mitre=f["mitre"],
                verification_status="CONFIRMED",
                root_cause_type="DATA",
            )
        complete_scan(scan_id)
        res["scan_id"] = scan_id

    return jsonify(res)


@sast_oss_bp.route("/api/ml-privacy/audit", methods=["POST"])
@require_auth
@rate_limit(limit=10, window=60)
def api_ml_privacy_audit():
    """Kiểm thử quyền riêng tư & chống đánh cắp mô hình ML/DL (ML-001 Membership Inference & ML-002 Model Extraction)."""
    from modules.auxiliary.scanner.data_privacy_scanner import MLPrivacyAuditor

    data = request.get_json(silent=True) or {}
    hardened_demo = bool(data.get("hardened_demo", False))
    save_to_db = bool(data.get("save_to_db", False))

    auditor = MLPrivacyAuditor()
    res = auditor.run_full_privacy_audit(hardened_demo=hardened_demo)

    if save_to_db and res.get("findings"):
        target_label = f"ML-PRIVACY://{res.get('mode', 'demo')}"
        scan_id = start_scan(target_label, "ML-Privacy-Auditor")
        for f in res["findings"]:
            save_finding(
                scan_id=scan_id,
                target_url=target_label,
                module_name="ml_adversarial",
                payload=f"[{f['finding_id']}] {f['name']} | Metrics: {json.dumps(f.get('metrics', {}))}",
                response=f["remediation"],
                severity=f["severity"],
                risk_score=f["risk_score"],
                owasp=f["owasp"],
                mitre=f["mitre"],
                verification_status="CONFIRMED",
                root_cause_type="MODEL",
            )
        complete_scan(scan_id)
        res["scan_id"] = scan_id

    return jsonify(res)

