# -*- coding: utf-8 -*-
"""
core/risk_scorer.py - CVSS-like Risk Scoring & System Security Posture Engine

Mathematical Formulation (aligned with Thesis & Defense Presentation):
    1. Impact Sub-Score (ISS):
       ISS = 1 - [(1 - C) * (1 - I) * (1 - A)]
    2. Impact Score:
       Impact = 6.42 * ISS
    3. Exploitability Score:
       Exploitability = 4.8 * AC_factor * MT_factor
    4. Base Risk Score (optionally adjusted by Exposure, Confidence, Reproducibility):
       Score = min(10.0, round((Impact + Exploitability) * env_factor, 1))
    5. System Security Posture:
       Aggregates active (non-FIXED, non-FALSE_POSITIVE) findings into a 0-100
       posture score, letter grade (A-F), and SLA action plan.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

MODULE_TO_TAXONOMY: dict[str, str] = {
    "prompt_injection":     "LLM01",
    "jailbreak":            "LLM01_JAILBREAK",
    "multiturn_jailbreak":  "LLM01_JAILBREAK",
    "sensitive_disclosure": "LLM02",
    "code_scanner":         "LLM03",
    "oss_security":         "LLM03",
    "output_handling":      "LLM05",
    "excessive_agency":     "LLM06",
    "agent_testing":        "LLM06",
    "prompt_leak":          "LLM07",
    "rag_security":         "LLM08",
    "misinformation":       "LLM09",
    "model_dos":            "LLM10",
    "ml_adversarial":       "LLM01",
    "port_scan":            "_CUSTOM_PORT_SCAN",
    "model_fingerprint":    "_CUSTOM_MODEL_FINGERPRINT",
}

_CIA_PROFILES = {
    "prompt_injection":     {"C": 0.56, "I": 0.56, "A": 0.00},
    "jailbreak":            {"C": 0.56, "I": 0.56, "A": 0.22},
    "multiturn_jailbreak":  {"C": 0.56, "I": 0.56, "A": 0.22},
    "sensitive_disclosure": {"C": 0.56, "I": 0.22, "A": 0.00},
    "code_scanner":         {"C": 0.56, "I": 0.56, "A": 0.22},
    "oss_security":         {"C": 0.56, "I": 0.56, "A": 0.22},
    "output_handling":      {"C": 0.22, "I": 0.56, "A": 0.22},
    "excessive_agency":     {"C": 0.56, "I": 0.56, "A": 0.56},
    "agent_testing":        {"C": 0.56, "I": 0.56, "A": 0.56},
    "prompt_leak":          {"C": 0.56, "I": 0.00, "A": 0.00},
    "rag_security":         {"C": 0.56, "I": 0.56, "A": 0.00},
    "misinformation":       {"C": 0.00, "I": 0.56, "A": 0.00},
    "model_dos":            {"C": 0.00, "I": 0.00, "A": 0.56},
    "ml_adversarial":       {"C": 0.22, "I": 0.56, "A": 0.22},
    "port_scan":            {"C": 0.22, "I": 0.00, "A": 0.00},
    "model_fingerprint":    {"C": 0.22, "I": 0.00, "A": 0.00},
}

_EXPOSURE_MULTIPLIERS = {
    "PUBLIC":   1.12,
    "INTERNAL": 1.00,
    "SANDBOX":  0.85,
}

SLA_ACTION_MATRIX: Dict[str, Dict[str, str]] = {
    "CRITICAL": {
        "sla": "24 giờ (Khẩn cấp)",
        "action_vi": "Xử lý khẩn cấp; cân nhắc cô lập, bật AI Guard Proxy hoặc tạm dừng chức năng chịu ảnh hưởng.",
        "action_en": "Immediate remediation; consider isolating endpoint, enabling guardrails, or pausing affected capability.",
    },
    "HIGH": {
        "sla": "3–7 ngày (Ưu tiên cao)",
        "action_vi": "Ưu tiên khắc phục ngay trong sprint; áp dụng biện pháp giảm thiểu tạm thời (WAF/Prompt hardening).",
        "action_en": "Prioritize remediation; apply compensating controls (proxy filter / prompt hardening) immediately.",
    },
    "MEDIUM": {
        "sla": "30 ngày (Theo kế hoạch)",
        "action_vi": "Lập kế hoạch xử lý, xác định chủ sở hữu và thời hạn khắc phục rõ ràng.",
        "action_en": "Schedule remediation with clear owner and target release.",
    },
    "LOW": {
        "sla": "90 ngày (Chu kỳ bảo trì)",
        "action_vi": "Theo dõi, ghi nhận và cải thiện theo chu kỳ nâng cấp định kỳ.",
        "action_en": "Track and remediate during routine hardening cycles.",
    },
    "INFO": {
        "sla": "Không bắt buộc",
        "action_vi": "Ghi nhận thông tin bề mặt tấn công để phục vụ đánh giá chuyên sâu.",
        "action_en": "Informational finding recorded for attack surface visibility.",
    },
}


def _normalise_confidence_factor(confidence: Optional[Union[float, int, str]]) -> float:
    """Convert string/numeric confidence into a bounded multiplier [0.85, 1.0]."""
    if confidence is None:
        return 1.0
    if isinstance(confidence, (int, float)):
        c = max(0.0, min(1.0, float(confidence)))
        return 0.85 + 0.15 * c
    label = str(confidence).strip().upper()
    if "HIGH" in label:
        return 1.0
    if "MEDIUM" in label:
        return 0.95
    if "LOW" in label:
        return 0.88
    if "JUDGE" in label:
        # e.g. JUDGE(90%) -> parse percentage
        digits = "".join(ch for ch in label if ch.isdigit())
        if digits:
            pct = max(0.0, min(100.0, float(digits))) / 100.0
            return 0.85 + 0.15 * pct
    return 1.0


class RiskScorer:
    """
    Compute a normalised risk score (0.0 – 10.0) for a detected AI
    vulnerability finding and aggregate System Security Posture (0 – 100, Grade A–F).
    """

    def __init__(self) -> None:
        self._taxonomy: dict[str, dict] = {}
        self._load_taxonomy()

    def _load_taxonomy(self) -> None:
        project_root = Path(__file__).resolve().parent.parent
        taxonomy_path = project_root / "data" / "taxonomy.json"
        if not taxonomy_path.exists():
            return
        try:
            with open(taxonomy_path, encoding="utf-8") as fh:
                data = json.load(fh)
            for category in data.get("categories", []):
                cat_id = category.get("id", "")
                if cat_id:
                    self._taxonomy[cat_id] = category
        except Exception:
            pass

    def calculate_score(
        self,
        module_name: str,
        detection_result: bool,
        response_length: int = 0,
        attack_complexity: str = "LOW",
        exposure: str = "INTERNAL",
        confidence: Optional[Union[float, int, str]] = None,
        reproducibility: Optional[float] = None,
    ) -> float:
        """
        Calculate CVSS-like risk score in [0.0, 10.0].
        Optional modifiers:
          - exposure: 'PUBLIC' | 'INTERNAL' | 'SANDBOX'
          - confidence: 'HIGH' | 'MEDIUM' | 'LOW' | float in [0, 1]
          - reproducibility: empirical ASR@N in [0.0, 1.0]
        """
        if not detection_result:
            return 0.0

        profile = _CIA_PROFILES.get(module_name, {"C": 0.22, "I": 0.22, "A": 0.00})
        c_val, i_val, a_val = profile["C"], profile["I"], profile["A"]

        # 1. Impact Sub-Score (ISS)
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
        # 2. Impact Score
        impact_subscore = 6.42 * iss
        if impact_subscore <= 0:
            return 0.0

        # 3. Exploitability Score
        ac_factor = 0.44 if attack_complexity.upper() == "HIGH" else 0.77
        if module_name in ("excessive_agency", "agent_testing", "jailbreak"):
            mt_factor = 1.05
        elif module_name in ("multiturn_jailbreak",):
            mt_factor = 0.95
        else:
            mt_factor = 1.0

        if module_name in ("port_scan", "model_fingerprint"):
            exploitability_subscore = 2.0 * ac_factor
        else:
            exploitability_subscore = 4.8 * ac_factor * mt_factor

        # 4. Contextual & Evidence Modifiers (default 1.0 -> fully backward compatible)
        exp_mult = _EXPOSURE_MULTIPLIERS.get((exposure or "INTERNAL").upper(), 1.0)
        conf_mult = _normalise_confidence_factor(confidence)
        repro_mult = 1.0
        if reproducibility is not None:
            r = max(0.0, min(1.0, float(reproducibility)))
            repro_mult = 0.80 + 0.25 * r  # [0.80, 1.05]

        # 5. Final Clamped Risk Score
        raw_score = (impact_subscore + exploitability_subscore) * exp_mult * conf_mult * repro_mult
        score = min(10.0, max(0.0, raw_score))
        return round(score, 1)

    def score_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score >= 2.0:
            return "LOW"
        return "INFO"

    def score_to_color(self, severity: str) -> str:
        colors: dict[str, str] = {
            "CRITICAL": "bold red",
            "HIGH":     "red",
            "MEDIUM":   "yellow",
            "LOW":      "cyan",
            "INFO":     "dim white",
        }
        return colors.get(severity, "white")

    def get_sla_action(self, severity: str) -> Dict[str, str]:
        return dict(SLA_ACTION_MATRIX.get((severity or "INFO").upper(), SLA_ACTION_MATRIX["INFO"]))

    def calculate_system_posture(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute an executive system-level security posture from a list of findings.
        Excludes FALSE_POSITIVE and FIXED findings from active risk penalty.
        """
        total = len(findings)
        active: List[Dict[str, Any]] = []
        fixed_count = 0
        false_positive_count = 0
        confirmed_count = 0

        for f in findings:
            ver = (f.get("verification_status") or "NEEDS_VERIFICATION").upper()
            rem = (f.get("remediation_status") or "OPEN").upper()
            if ver == "CONFIRMED":
                confirmed_count += 1
            if ver == "FALSE_POSITIVE":
                false_positive_count += 1
                continue
            if rem == "FIXED":
                fixed_count += 1
                continue
            active.append(f)

        active_by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        scores: List[float] = []
        for f in active:
            sev = (f.get("severity") or "INFO").upper()
            if sev in active_by_sev:
                active_by_sev[sev] += 1
            scores.append(float(f.get("risk_score") or 0.0))

        # Diminishing penalty model so score stays informative in [0, 100]
        penalty = (
            min(55.0, active_by_sev["CRITICAL"] * 22.0)
            + min(35.0, active_by_sev["HIGH"] * 11.0)
            + min(20.0, active_by_sev["MEDIUM"] * 5.0)
            + min(10.0, active_by_sev["LOW"] * 2.0)
            + min(5.0, active_by_sev["INFO"] * 0.5)
        )
        posture_score = round(max(0.0, min(100.0, 100.0 - penalty)), 1)

        if posture_score >= 90:
            grade = "A"
        elif posture_score >= 75:
            grade = "B"
        elif posture_score >= 60:
            grade = "C"
        elif posture_score >= 40:
            grade = "D"
        else:
            grade = "F"

        # Safety cap: any active CRITICAL caps grade at D; >=3 active HIGH caps at C
        grade_order = ["A", "B", "C", "D", "F"]
        if active_by_sev["CRITICAL"] > 0 and grade_order.index(grade) < grade_order.index("D"):
            grade = "D"
        elif active_by_sev["HIGH"] >= 3 and grade_order.index(grade) < grade_order.index("C"):
            grade = "C"

        max_risk = round(max(scores), 1) if scores else 0.0
        avg_risk = round(sum(scores) / len(scores), 2) if scores else 0.0

        if active_by_sev["CRITICAL"] > 0:
            overall_priority = "CRITICAL"
        elif active_by_sev["HIGH"] > 0:
            overall_priority = "HIGH"
        elif active_by_sev["MEDIUM"] > 0:
            overall_priority = "MEDIUM"
        elif active_by_sev["LOW"] > 0:
            overall_priority = "LOW"
        else:
            overall_priority = "INFO"

        sla_summary = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if active_by_sev[sev] > 0:
                info = self.get_sla_action(sev)
                sla_summary.append({
                    "severity": sev,
                    "count": active_by_sev[sev],
                    "sla": info["sla"],
                    "action_vi": info["action_vi"],
                })

        return {
            "posture_score": posture_score,
            "grade": grade,
            "overall_priority": overall_priority,
            "recommended_action": self.get_sla_action(overall_priority)["action_vi"],
            "total_findings": total,
            "active_findings": len(active),
            "fixed_findings": fixed_count,
            "false_positive_findings": false_positive_count,
            "confirmed_findings": confirmed_count,
            "active_by_severity": active_by_sev,
            "max_risk_score": max_risk,
            "avg_risk_score": avg_risk,
            "sla_breakdown": sla_summary,
        }
