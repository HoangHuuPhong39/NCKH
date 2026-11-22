# -*- coding: utf-8 -*-
"""
core/regression.py - Automated Security Regression Testing & Scan Comparison Engine

Implements Step 8 ("Kiểm thử lại / Regression Testing") of the AI Security Testing
lifecycle:
  1. Replays previously discovered vulnerability payloads against a hardened target
     (e.g., after enabling AI Guard Proxy, prompt hardening, or model updates).
  2. Automatically evaluates whether each finding is FIXED, STILL_VULNERABLE,
     or REGRESSED (if previously marked FIXED).
  3. Updates finding lifecycle statuses in SQLite and persists regression run history.
  4. Supports comparing any two historical scans (baseline vs. retest).
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.config import cfg
from core.db import (
    get_finding_by_id,
    get_findings,
    get_findings_by_scan,
    get_scan_by_id,
    save_regression_run,
    update_finding_lifecycle,
)
from core.governance import CampaignBudget, check_target_scope, log_audit_event
from core.llm_client import SimpleLLMClient
from core.risk_scorer import RiskScorer
from modules.detectors.pattern_match import PatternDetector
from modules.registry import get_detector_key

STATIC_NON_REPLAYABLE_MODULES = {"code_scanner", "oss_security", "port_scan"}


def _finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Deterministic key matching identical (module, payload) across scans."""
    mod = (finding.get("module_name") or "").strip().lower()
    payload = (finding.get("payload") or "").strip()
    digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"{mod}::{digest}"


class RegressionTester:
    """
    Re-executes baseline vulnerability payloads to verify remediation efficacy
    (e.g., before vs. after enabling AI Guard Proxy or applying prompt hardening).
    """

    def __init__(self) -> None:
        self.detector = PatternDetector()
        self.risk_scorer = RiskScorer()

    def run_regression(
        self,
        baseline_scan_id: Optional[int] = None,
        finding_ids: Optional[List[int]] = None,
        target_url: Optional[str] = None,
        model_name: Optional[str] = None,
        api_key: str = "",
        timeout: int = 60,
        llm_client: Optional[Any] = None,
        use_judge: bool = False,
        update_db: bool = True,
        budget: Optional[CampaignBudget] = None,
        actor: str = "system",
    ) -> Dict[str, Any]:
        """
        Execute a regression retest campaign against *target_url*.

        Returns a structured summary dict containing fix_rate, risk_reduction_pct,
        per-finding diffs, and persisted regression_run_id.
        """
        started_at = datetime.now().isoformat()

        # 1. Collect candidate findings
        candidates: List[Dict[str, Any]] = []
        if finding_ids:
            for fid in finding_ids:
                row = get_finding_by_id(int(fid))
                if row:
                    candidates.append(row)
            if baseline_scan_id is None and candidates:
                baseline_scan_id = candidates[0].get("scan_id")
        elif baseline_scan_id is not None:
            candidates = get_findings_by_scan(int(baseline_scan_id))
        else:
            candidates = get_findings(remediation_status="OPEN", limit=50)
            if candidates:
                baseline_scan_id = candidates[0].get("scan_id")

        if not candidates:
            return {
                "success": False,
                "error": "Không tìm thấy lỗ hổng nào để chạy kiểm thử hồi quy (regression).",
                "baseline_scan_id": baseline_scan_id,
                "total_tested": 0,
                "details": [],
            }

        # Resolve target & model
        baseline_scan = get_scan_by_id(baseline_scan_id) if baseline_scan_id else None
        resolved_url = (
            target_url
            or (baseline_scan.get("target_url") if baseline_scan else None)
            or candidates[0].get("target_url")
            or cfg.get("scanner.target_url", "http://localhost:11434")
        )
        resolved_model = (
            model_name
            or (baseline_scan.get("model_name") if baseline_scan else None)
            or cfg.get("scanner.target_model", "llama3")
        )

        # 2. Enforce RoE Scope Whitelist
        scope_ok, scope_err = check_target_scope(resolved_url)
        if not scope_ok:
            log_audit_event(
                "SCOPE_BLOCKED",
                actor=actor,
                target_url=resolved_url,
                scan_id=baseline_scan_id,
                outcome="DENIED",
                details={"reason": scope_err, "operation": "regression_retest"},
            )
            return {
                "success": False,
                "error": scope_err,
                "baseline_scan_id": baseline_scan_id,
            }

        campaign_budget = budget or CampaignBudget()
        client = llm_client or SimpleLLMClient(
            api_url=resolved_url,
            model_name=resolved_model,
            timeout=int(timeout),
            api_key=api_key or "",
        )

        log_audit_event(
            "REGRESSION_STARTED",
            actor=actor,
            target_url=resolved_url,
            scan_id=baseline_scan_id,
            details={"candidate_count": len(candidates), "model_name": resolved_model},
        )

        # Optional LLM Judge
        judge = None
        if use_judge:
            try:
                from modules.detectors.llm_judge import LLMJudge
                judge_model = cfg.get("scanner.judge_model", "")
                if judge_model and judge_model != resolved_model:
                    judge = LLMJudge.create_with_separate_model(
                        api_url=resolved_url,
                        judge_model=judge_model,
                        timeout=int(timeout),
                        api_key=api_key or "",
                    )
                else:
                    judge = LLMJudge(judge_client=client)
            except Exception:
                judge = None

        details: List[Dict[str, Any]] = []
        total_tested = 0
        fixed_count = 0
        still_vuln_count = 0
        skipped_count = 0
        error_count = 0
        baseline_risks: List[float] = []
        retest_risks: List[float] = []

        for f in candidates:
            fid = f.get("id")
            mod_name = f.get("module_name", "prompt_injection")
            clean_mod = get_detector_key(mod_name)
            payload_text = f.get("payload") or ""
            prev_rem = (f.get("remediation_status") or "OPEN").upper()
            prev_risk = float(f.get("risk_score") or 0.0)

            # Skip static/non-replayable modules or already false-positive items
            if clean_mod in STATIC_NON_REPLAYABLE_MODULES or not payload_text.strip():
                skipped_count += 1
                details.append({
                    "finding_id": fid,
                    "module_name": mod_name,
                    "status": "SKIPPED",
                    "reason": "Static/non-replayable finding — re-run dedicated SAST/OSS/Port scanner.",
                    "baseline_risk": prev_risk,
                    "retest_risk": prev_risk,
                })
                continue

            if (f.get("verification_status") or "").upper() == "FALSE_POSITIVE":
                skipped_count += 1
                details.append({
                    "finding_id": fid,
                    "module_name": mod_name,
                    "status": "SKIPPED",
                    "reason": "Marked as FALSE_POSITIVE.",
                    "baseline_risk": prev_risk,
                    "retest_risk": 0.0,
                })
                continue

            allowed, budget_err = campaign_budget.check_allowed()
            if not allowed:
                log_audit_event(
                    "BUDGET_EXCEEDED",
                    actor=actor,
                    target_url=resolved_url,
                    scan_id=baseline_scan_id,
                    outcome="STOPPED",
                    details={"reason": budget_err, "budget": campaign_budget.snapshot()},
                )
                break

            t0 = time.perf_counter()
            try:
                retest_resp = client.send_prompt(payload_text)
            except Exception as exc:
                retest_resp = f"[ERROR] {exc}"
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            campaign_budget.record_usage(prompt_text=payload_text, response_text=retest_resp)

            # Connection/transport errors: only treat HTTP 403 / explicit AI Guard Proxy block
            # envelopes (NOT arbitrary 200 OK prose mentioning "403" or "blocked") as proxy blocks!
            resp_str = retest_resp or ""
            resp_lower = resp_str.lower()
            is_transport_envelope = resp_str.startswith("[-]") or resp_str.startswith("[ERROR]")
            is_proxy_blocked = is_transport_envelope and (
                "403" in resp_lower
                or "forbidden" in resp_lower
                or "ai guard proxy" in resp_lower
                or "blocked by" in resp_lower
            )

            if is_transport_envelope and not is_proxy_blocked:
                error_count += 1
                details.append({
                    "finding_id": fid,
                    "module_name": mod_name,
                    "status": "ERROR",
                    "reason": retest_resp[:200],
                    "baseline_risk": prev_risk,
                    "retest_risk": prev_risk,
                    "elapsed_ms": elapsed_ms,
                })
                continue

            total_tested += 1
            baseline_risks.append(prev_risk)

            if is_proxy_blocked:
                is_still_vuln = False
                det_reason = "Blocked by AI Guard Proxy / Defense Gate (403 Forbidden)"
                det_conf = "HIGH"
            else:
                is_still_vuln, det_reason, det_conf = self.detector.analyze(
                    retest_resp, original_payload=payload_text, module_name=clean_mod
                )
                if det_conf == "LOW" and judge is not None:
                    jv = judge.evaluate(
                        payload_text,
                        retest_resp,
                        clean_mod,
                        pattern_result=(is_still_vuln, det_reason, det_conf),
                    )
                    if jv.get("judge_used"):
                        is_still_vuln = bool(jv["is_exploited"])
                        det_reason = f"[LLM-Judge] {jv.get('reasoning', '')}"
                        det_conf = f"JUDGE({jv.get('confidence', 0.0):.0%})"

            if is_still_vuln:
                still_vuln_count += 1
                new_risk = self.risk_scorer.calculate_score(
                    module_name=clean_mod,
                    detection_result=True,
                    response_length=len(retest_resp),
                    confidence=det_conf,
                )
                retest_risks.append(new_risk)
                new_rem_status = "REGRESSED" if prev_rem == "FIXED" else "OPEN"
                new_ver_status = "CONFIRMED"
                item_status = "REGRESSED" if prev_rem == "FIXED" else "STILL_VULNERABLE"
            else:
                fixed_count += 1
                new_risk = 0.0
                retest_risks.append(0.0)
                new_rem_status = "FIXED"
                new_ver_status = "CONFIRMED"
                item_status = "FIXED"

            if update_db and fid is not None:
                note = (
                    f"[Regression {datetime.now().strftime('%Y-%m-%d %H:%M')}] "
                    f"{item_status} on {resolved_url} ({det_reason[:120]})"
                )
                update_finding_lifecycle(
                    int(fid),
                    verification_status=new_ver_status,
                    remediation_status=new_rem_status,
                    notes=note,
                )

            details.append({
                "finding_id": fid,
                "module_name": mod_name,
                "owasp_code": f.get("owasp_code", "N/A"),
                "status": item_status,
                "previous_remediation_status": prev_rem,
                "new_remediation_status": new_rem_status,
                "baseline_risk": prev_risk,
                "retest_risk": new_risk,
                "confidence": det_conf,
                "reason": det_reason,
                "retest_response_preview": (retest_resp or "")[:240],
                "elapsed_ms": elapsed_ms,
            })

        completed_at = datetime.now().isoformat()
        fix_rate = round(fixed_count / total_tested, 4) if total_tested > 0 else 0.0
        baseline_avg_risk = round(sum(baseline_risks) / len(baseline_risks), 2) if baseline_risks else 0.0
        retest_avg_risk = round(sum(retest_risks) / len(retest_risks), 2) if retest_risks else 0.0
        risk_reduction_pct = (
            round(((baseline_avg_risk - retest_avg_risk) / baseline_avg_risk) * 100.0, 2)
            if baseline_avg_risk > 0
            else 0.0
        )

        run_id = None
        if update_db:
            run_id = save_regression_run(
                baseline_scan_id=baseline_scan_id,
                target_url=resolved_url,
                model_name=resolved_model,
                started_at=started_at,
                completed_at=completed_at,
                total_tested=total_tested,
                fixed_count=fixed_count,
                still_vulnerable_count=still_vuln_count,
                skipped_count=skipped_count,
                error_count=error_count,
                fix_rate=fix_rate,
                baseline_avg_risk=baseline_avg_risk,
                retest_avg_risk=retest_avg_risk,
                risk_reduction_pct=risk_reduction_pct,
                details=details,
            )

        log_audit_event(
            "REGRESSION_COMPLETED",
            actor=actor,
            target_url=resolved_url,
            scan_id=baseline_scan_id,
            details={
                "regression_run_id": run_id,
                "total_tested": total_tested,
                "fixed_count": fixed_count,
                "still_vulnerable_count": still_vuln_count,
                "fix_rate": fix_rate,
                "risk_reduction_pct": risk_reduction_pct,
                "budget": campaign_budget.snapshot(),
            },
        )

        return {
            "success": True,
            "regression_run_id": run_id,
            "baseline_scan_id": baseline_scan_id,
            "target_url": resolved_url,
            "model_name": resolved_model,
            "started_at": started_at,
            "completed_at": completed_at,
            "summary": {
                "total_candidates": len(candidates),
                "total_tested": total_tested,
                "fixed_count": fixed_count,
                "still_vulnerable_count": still_vuln_count,
                "skipped_count": skipped_count,
                "error_count": error_count,
                "fix_rate": fix_rate,
                "fix_rate_pct": round(fix_rate * 100.0, 2),
                "baseline_avg_risk": baseline_avg_risk,
                "retest_avg_risk": retest_avg_risk,
                "risk_reduction_pct": risk_reduction_pct,
            },
            "budget": campaign_budget.snapshot(),
            "details": details,
        }

    def compare_scans(self, baseline_scan_id: int, target_scan_id: int) -> Dict[str, Any]:
        """Compare two historical scans to identify fixed, persistent, and new vulnerabilities."""
        base_findings = get_findings_by_scan(int(baseline_scan_id))
        target_findings = get_findings_by_scan(int(target_scan_id))

        base_map = {_finding_fingerprint(f): f for f in base_findings}
        target_map = {_finding_fingerprint(f): f for f in target_findings}

        fixed = [f for fp, f in base_map.items() if fp not in target_map]
        persistent = [f for fp, f in target_map.items() if fp in base_map]
        newly_introduced = [f for fp, f in target_map.items() if fp not in base_map]

        base_posture = self.risk_scorer.calculate_system_posture(base_findings)
        target_posture = self.risk_scorer.calculate_system_posture(target_findings)

        return {
            "success": True,
            "baseline_scan_id": int(baseline_scan_id),
            "target_scan_id": int(target_scan_id),
            "summary": {
                "baseline_count": len(base_findings),
                "target_count": len(target_findings),
                "fixed_count": len(fixed),
                "persistent_count": len(persistent),
                "new_findings_count": len(newly_introduced),
                "baseline_grade": base_posture["grade"],
                "target_grade": target_posture["grade"],
                "posture_delta": round(
                    target_posture["posture_score"] - base_posture["posture_score"], 1
                ),
            },
            "fixed": fixed,
            "persistent": persistent,
            "new_findings": newly_introduced,
        }
