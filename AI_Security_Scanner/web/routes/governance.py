# -*- coding: utf-8 -*-
"""
web/routes/governance.py - Finding Lifecycle, Posture, Regression, Scan Compare, Governance Policy, RAG ACL & Agent Memory
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from core.config import cfg
from core.db import (
    complete_scan, get_finding_by_id, get_findings, get_regression_runs,
    save_finding, start_scan, update_finding_lifecycle,
)
from core.governance import (
    CampaignBudget, get_audit_logs, get_governance_policy, log_audit_event,
)
from core.llm_client import SimpleLLMClient
from core.logger import logger
from core.regression import RegressionTester
from web.security import rate_limit, require_auth, validate_config_request
from web.services.scan_manager import _parse_int_arg, app_config, risk_scorer

governance_bp = Blueprint("governance_bp", __name__)

# ─────────────────────────────────────────────
# Governance, Finding Lifecycle, Posture & Regression Endpoints
# ─────────────────────────────────────────────
@governance_bp.route("/api/findings/<int:finding_id>/status", methods=["PATCH", "POST"])
@require_auth
def api_update_finding_status(finding_id: int):
    """Cập nhật trạng thái xác nhận, khắc phục, nguyên nhân gốc và ghi chú của lỗ hổng."""
    data = request.get_json(silent=True) or {}
    try:
        updated = update_finding_lifecycle(
            finding_id=finding_id,
            verification_status=data.get("verification_status"),
            remediation_status=data.get("remediation_status"),
            root_cause_type=data.get("root_cause_type"),
            notes=data.get("notes"),
        )
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    if updated is None:
        return jsonify({"success": False, "error": f"Finding #{finding_id} không tồn tại."}), 404

    log_audit_event(
        "FINDING_STATUS_UPDATED",
        target_url=updated.get("target_url", ""),
        scan_id=updated.get("scan_id"),
        details={
            "finding_id": finding_id,
            "verification_status": updated.get("verification_status"),
            "remediation_status": updated.get("remediation_status"),
            "root_cause_type": updated.get("root_cause_type"),
        },
    )
    return jsonify({"success": True, "finding": updated})


@governance_bp.route("/api/posture", methods=["GET"])
@require_auth
def api_system_posture():
    """Trả về điểm xếp hạng an toàn tổng thể (Grade A-F, Score 0-100, SLA Matrix)."""
    severity = request.args.get("severity")
    module = request.args.get("module")
    scan_id_arg = request.args.get("scan_id")
    scan_id_int = int(scan_id_arg) if scan_id_arg and scan_id_arg.isdigit() else None
    findings = get_findings(severity=severity, module_name=module, scan_id=scan_id_int, limit=1000)
    posture = risk_scorer.calculate_system_posture(findings)
    return jsonify({"success": True, "posture": posture})


@governance_bp.route("/api/regression/run", methods=["POST"])
@require_auth
@rate_limit(limit=15, window=60)
def api_regression_run():
    """Chạy kiểm thử hồi quy (Regression Retest) trên các lỗ hổng của scan trước."""
    data = request.get_json(silent=True) or {}
    target_url = (data.get("target_url") or app_config["target_url"]).strip()
    valid_url, url_err = validate_config_request({"target_url": target_url})
    if not valid_url:
        return jsonify({"success": False, "error": url_err}), 400

    target_model = (data.get("target_model") or data.get("model") or app_config["target_model"]).strip()
    api_key = data.get("api_key") or app_config.get("api_key", "")
    if api_key and "••••" in api_key:
        api_key = app_config.get("api_key", "")

    baseline_scan_id = data.get("baseline_scan_id")
    if baseline_scan_id is not None:
        try:
            baseline_scan_id = int(baseline_scan_id)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "baseline_scan_id phải là số nguyên."}), 400

    finding_ids = data.get("finding_ids")
    use_judge = bool(data.get("use_judge", False))
    update_db = bool(data.get("update_db", True))

    budget_cfg = data.get("budget") if isinstance(data.get("budget"), dict) else {}
    budget = CampaignBudget(
        max_requests=budget_cfg.get("max_requests"),
        max_tokens=budget_cfg.get("max_tokens"),
        max_duration_sec=budget_cfg.get("max_duration_sec"),
    )

    tester = RegressionTester()
    result = tester.run_regression(
        baseline_scan_id=baseline_scan_id,
        finding_ids=finding_ids,
        target_url=target_url,
        model_name=target_model,
        api_key=api_key,
        timeout=int(data.get("timeout", app_config.get("timeout", 60))),
        use_judge=use_judge,
        update_db=update_db,
        budget=budget,
    )
    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@governance_bp.route("/api/regression/runs", methods=["GET"])
@require_auth
def api_regression_runs():
    """Lấy lịch sử các phiên kiểm thử hồi quy (regression runs)."""
    baseline_arg = request.args.get("baseline_scan_id")
    baseline_id = int(baseline_arg) if baseline_arg and baseline_arg.isdigit() else None
    limit = _parse_int_arg("limit", 20, min_val=1, max_val=200)
    runs = get_regression_runs(baseline_scan_id=baseline_id, limit=limit)
    return jsonify({"success": True, "runs": runs, "count": len(runs)})


@governance_bp.route("/api/scans/compare", methods=["GET"])
@require_auth
def api_scans_compare():
    """So sánh hai phiên quét lịch sử (baseline_id vs target_id) để xem lỗ hổng đã đóng/mới."""
    base_arg = request.args.get("baseline_id")
    target_arg = request.args.get("target_id")
    if not (base_arg and base_arg.isdigit() and target_arg and target_arg.isdigit()):
        return jsonify({
            "success": False,
            "error": "Cần cung cấp tham số số nguyên 'baseline_id' và 'target_id'.",
        }), 400
    tester = RegressionTester()
    res = tester.compare_scans(int(base_arg), int(target_arg))
    return jsonify(res)


@governance_bp.route("/api/governance/policy", methods=["GET"])
@require_auth
def api_get_governance_policy():
    """Xem cấu hình quản trị an toàn vận hành (RoE Scope, Budget, Redaction)."""
    return jsonify({"success": True, "policy": get_governance_policy()})


@governance_bp.route("/api/governance/policy", methods=["POST"])
@require_auth
def api_set_governance_policy():
    """Cập nhật cấu hình quản trị an toàn vận hành (RoE Scope, Budget, Redaction)."""
    data = request.get_json(silent=True) or {}
    if "enforce_scope_whitelist" in data:
        cfg.set("governance.enforce_scope_whitelist", bool(data["enforce_scope_whitelist"]))
    if "authorized_targets" in data:
        if not isinstance(data["authorized_targets"], list):
            return jsonify({"success": False, "error": "authorized_targets phải là danh sách chuỗi."}), 400
        cfg.set("governance.authorized_targets", [str(x).strip() for x in data["authorized_targets"] if str(x).strip()])
    if "redact_reports" in data:
        cfg.set("governance.redact_reports", bool(data["redact_reports"]))
    if "budget" in data and isinstance(data["budget"], dict):
        for k in ("max_requests", "max_tokens", "max_duration_sec"):
            if k in data["budget"]:
                try:
                    val = int(data["budget"][k])
                    if val < 1:
                        return jsonify({"success": False, "error": f"budget.{k} phải >= 1."}), 400
                    cfg.set(f"governance.budget.{k}", val)
                except (ValueError, TypeError):
                    return jsonify({"success": False, "error": f"budget.{k} phải là số nguyên."}), 400

    policy = get_governance_policy()
    log_audit_event("GOVERNANCE_POLICY_UPDATED", details=policy)
    return jsonify({"success": True, "policy": policy})


@governance_bp.route("/api/governance/audit", methods=["GET"])
@require_auth
def api_governance_audit():
    """Xem nhật ký kiểm toán vận hành (Governance Audit Trail JSONL)."""
    limit = _parse_int_arg("limit", 100, min_val=1, max_val=500)
    event_type = request.args.get("event_type")
    logs = get_audit_logs(limit=limit, event_type=event_type)
    return jsonify({"success": True, "audit_logs": logs, "count": len(logs)})


# ─────────────────────────────────────────────
# Step 3 Endpoints: RAG ACL, Agent Memory Poisoning & Trivy Container/IaC
# ─────────────────────────────────────────────
@governance_bp.route("/api/rag-acl/test", methods=["POST"])
@require_auth
def api_rag_acl_test():
    """Kiểm thử phân quyền tầng truy xuất RAG (Cross-Tenant, RBAC, Deleted Docs)."""
    from modules.exploits.rag_security import RAGAccessControlTester
    data = request.get_json(silent=True) or {}
    enforce_acl_demo = bool(data.get("enforce_acl_demo", False))
    save_to_db = bool(data.get("save_to_db", False))

    tester = RAGAccessControlTester()
    res = tester.audit_retriever(enforce_acl_demo=enforce_acl_demo)

    if save_to_db and res.get("findings"):
        scan_id = start_scan("RAG://multi-tenant-store", "RAG-ACL-Auditor")
        for f in res["findings"]:
            save_finding(
                scan_id=scan_id,
                target_url="RAG://multi-tenant-store",
                module_name="rag_security",
                payload=f"[{f['finding_id']}] Query: {f['query']} | User: {f['user_context']}",
                response=f"Leaked docs: {f['leaked_doc_ids']} | Remediation: {f['remediation']}",
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


@governance_bp.route("/api/agent-memory/test", methods=["POST"])
@require_auth
def api_agent_memory_test():
    """Kiểm thử đầu độc bộ nhớ AI Agent liên phiên (AGT-002) và bỏ qua xác nhận con người."""
    from modules.exploits.agent_testing import AgentTesting
    data = request.get_json(silent=True) or {}
    live_mode = bool(data.get("live", False))
    save_to_db = bool(data.get("save_to_db", False))

    llm_client = None
    if live_mode:
        target_url = (data.get("target_url") or app_config["target_url"]).strip()
        valid_url, url_err = validate_config_request({"target_url": target_url})
        if not valid_url:
            return jsonify({"success": False, "error": url_err}), 400
        target_model = (data.get("target_model") or app_config["target_model"]).strip()
        llm_client = SimpleLLMClient(
            api_url=target_url,
            model_name=target_model,
            timeout=int(app_config.get("timeout", 60)),
            api_key=app_config.get("api_key", ""),
        )

    tester = AgentTesting()
    res = tester.run_memory_poisoning_audit(llm_client=llm_client)

    if save_to_db and res.get("is_vulnerable"):
        target_label = data.get("target_url") or "AGENT://sandbox-memory"
        scan_id = start_scan(target_label, "Agent-Memory-Auditor")
        save_finding(
            scan_id=scan_id,
            target_url=target_label,
            module_name="agent_testing",
            payload="[AGT-002] Cross-session persistent memory poisoning & unapproved high-impact call",
            response=(
                f"Poisoned entries: {res.get('poisoned_memory_count', 0)} | "
                f"Unapproved high-impact calls: {res.get('unapproved_high_impact_count', 0)}"
            ),
            severity="CRITICAL",
            risk_score=9.2,
            owasp="LLM06",
            mitre="AML.T0051",
            verification_status="CONFIRMED",
            root_cause_type="APPLICATION",
        )
        complete_scan(scan_id)
        res["scan_id"] = scan_id

    return jsonify(res)

