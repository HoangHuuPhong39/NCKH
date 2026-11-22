# -*- coding: utf-8 -*-
"""
core/report.py - Two-Tier Executive & Technical Report Generator

Features:
  1. Executive Summary & System Security Posture (Grade A–F, Score 0–100, SLA Matrix)
  2. Multi-Standard Compliance Traceability (OWASP LLM Top 10:2025, MITRE ATLAS, NIST AI RMF 1.0)
  3. Automatic Sensitive Data Redaction (API keys, JWT, CCCD, VN Phone, Credit Cards, Emails)
  4. Finding Lifecycle Badges (Verification Status, Remediation Status, Root Cause Type)
  5. Interactive HTML Report & Enriched JSON Export for CI/CD / SIEM
"""

import html
import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.config import cfg
from core.governance import log_audit_event, redact_finding
from core.risk_scorer import RiskScorer

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    cfg.get("storage.database_path", "data/scanner.db"),
)

SEVERITY_COLORS_HTML = {
    "CRITICAL": "#ff4757",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffa726",
    "LOW": "#26c6da",
    "INFO": "#42a5f5",
}

GRADE_COLORS_HTML = {
    "A": "#2ea043",
    "B": "#3fb950",
    "C": "#d29922",
    "D": "#ff6b35",
    "F": "#ff4757",
}

REMEDIATION_COLORS_HTML = {
    "OPEN": "#ff6b35",
    "IN_PROGRESS": "#ffa726",
    "FIXED": "#2ea043",
    "ACCEPTED_RISK": "#8b949e",
    "REGRESSED": "#ff4757",
}

VERIFICATION_COLORS_HTML = {
    "CONFIRMED": "#58a6ff",
    "NEEDS_VERIFICATION": "#d29922",
    "FALSE_POSITIVE": "#8b949e",
    "UNREPRODUCIBLE": "#a371f7",
}

try:
    from core.owasp_mapper import OWASPMapper
    _mapper = OWASPMapper()
except Exception:
    _mapper = None

_risk_scorer = RiskScorer()

OWASP_REMEDIATION_FALLBACK = {
    "LLM01": [
        "Triển khai xác thực và lọc đầu vào chặt chẽ",
        "Áp dụng nguyên tắc phân quyền tối thiểu (Least Privilege)",
        "Tách biệt ngữ cảnh người dùng và ngữ cảnh hệ thống",
        "Giám sát và ghi log tất cả các prompt đầu vào",
        "Sử dụng kỹ thuật Prompt Hardening và Instruction Defense",
    ],
    "LLM02": [
        "Lọc và kiểm tra đầu ra trước khi trả về người dùng",
        "Áp dụng kỹ thuật Differential Privacy trong huấn luyện",
        "Làm sạch dữ liệu huấn luyện, loại bỏ PII và credentials",
        "Triển khai hệ thống theo dõi và che giấu dữ liệu nhạy cảm",
    ],
    "LLM05": [
        "Xử lý và khử trùng (sanitize/encode) toàn bộ đầu ra từ LLM trước khi hiển thị hoặc thực thi",
        "Thiết lập Content Security Policy (CSP) chặt chẽ",
        "Áp dụng Parameterized Query cho cơ sở dữ liệu",
        "Không truyền trực tiếp output của LLM vào các hàm eval(), exec(), os.system()",
    ],
    "LLM07": [
        "Không lưu trữ bí mật, API key hoặc dữ liệu nhạy cảm trong System Prompt",
        "Sử dụng các kỹ thuật bảo vệ prompt (instruction defense)",
        "Lọc đầu ra để ngăn chặn việc lặp lại nguyên văn System Prompt",
    ],
    "LLM09": [
        "Tích hợp mô hình RAG (Retrieval-Augmented Generation) với nguồn dữ liệu đã kiểm chứng",
        "Hiển thị độ tin cậy và nguồn trích dẫn minh bạch",
        "Thiết lập hàng rào kiểm chứng sự thật (fact-checking guardrails)",
    ],
    "LLM10": [
        "Triển khai giới hạn tần suất yêu cầu (Rate Limiting)",
        "Đặt giới hạn tối đa token đầu vào và đầu ra",
        "Theo dõi tài nguyên hệ thống và cảnh báo bất thường",
        "Triển khai hàng đợi yêu cầu (Request Queuing) và timeout hợp lý",
    ],
    "N/A": [
        "Hạn chế quyền truy cập mạng vào API endpoint",
        "Sử dụng tường lửa (firewall) để kiểm soát cổng mở",
        "Áp dụng xác thực (authentication) cho tất cả API endpoint",
        "Thường xuyên kiểm tra các cổng đang mở trên máy chủ",
    ],
}


def get_remediation_for_code(code: str) -> list[str]:
    """Lấy danh sách khuyến nghị từ OWASPMapper (taxonomy.json) hoặc fallback."""
    if _mapper:
        rems = _mapper.get_remediation(code)
        if rems:
            return rems
    return OWASP_REMEDIATION_FALLBACK.get(code, OWASP_REMEDIATION_FALLBACK.get("N/A", []))


def _get_findings_from_db(
    severity: Optional[str] = None,
    module_name: Optional[str] = None,
    scan_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Lấy findings từ database có hỗ trợ lọc theo severity, module_name và scan_id."""
    try:
        from core.db import _get_conn
        conn = _get_conn()
        cursor = conn.cursor()
        cols = {row[1] for row in cursor.execute("PRAGMA table_info(findings)")}

        select_cols = [
            "id", "target_url", "module_name", "payload", "response",
            "severity", "risk_score", "owasp_code", "mitre_code", "timestamp",
        ]
        for opt_col in (
            "scan_id", "verification_status", "remediation_status",
            "root_cause_type", "confidence_score", "verified_at", "notes",
        ):
            if opt_col in cols:
                select_cols.append(opt_col)

        query = f"SELECT {', '.join(select_cols)} FROM findings WHERE 1=1"
        params: List[Any] = []
        if severity and severity != "ALL":
            query += " AND severity = ?"
            params.append(severity)
        if module_name and module_name != "ALL":
            query += " AND module_name = ?"
            params.append(module_name)
        if scan_id is not None and "scan_id" in cols:
            query += " AND scan_id = ?"
            params.append(int(scan_id))
        query += " ORDER BY risk_score DESC"
        try:
            cursor.execute(query, params)
            rows = [dict(r) for r in cursor.fetchall()]
            return rows
        finally:
            conn.close()
    except Exception as exc:
        from core.logger import logger
        logger.error("Failed to fetch findings from DB for report: %s", exc)
        return []


def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts


def _count_lifecycle(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    ver_counts: Dict[str, int] = {}
    rem_counts: Dict[str, int] = {}
    rc_counts: Dict[str, int] = {}
    for f in findings:
        v = (f.get("verification_status") or "NEEDS_VERIFICATION").upper()
        r = (f.get("remediation_status") or "OPEN").upper()
        rc = (f.get("root_cause_type") or "MODEL").upper()
        ver_counts[v] = ver_counts.get(v, 0) + 1
        rem_counts[r] = rem_counts.get(r, 0) + 1
        rc_counts[rc] = rc_counts.get(rc, 0) + 1
    return {
        "by_verification": ver_counts,
        "by_remediation": rem_counts,
        "by_root_cause": rc_counts,
    }


def _should_redact(redact: Optional[bool]) -> bool:
    if redact is not None:
        return bool(redact)
    return bool(cfg.get("governance.redact_reports", True))


def generate_html_report(
    output_file: str = "report.html",
    severity: Optional[str] = None,
    module_name: Optional[str] = None,
    scan_id: Optional[int] = None,
    redact: Optional[bool] = None,
) -> bool:
    """
    Tạo báo cáo HTML 2 tầng (Executive Summary + Chi tiết Kỹ thuật),
    tự động che giấu dữ liệu nhạy cảm (PII/Secrets) và hiển thị System Security Posture.
    """
    try:
        raw_findings = _get_findings_from_db(
            severity=severity, module_name=module_name, scan_id=scan_id
        )
        do_redact = _should_redact(redact)
        findings = [redact_finding(f) for f in raw_findings] if do_redact else raw_findings

        sev_counts = _count_by_severity(findings)
        posture = _risk_scorer.calculate_system_posture(findings)
        standards_meta = _mapper.get_standards_metadata() if _mapper else {}
        total = len(findings)
        generated_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        target = html.escape(findings[0]["target_url"] if findings else "N/A")
        owasp_codes = list(dict.fromkeys(f.get("owasp_code", "N/A") for f in findings))

        def badge(text: str, color: str) -> str:
            return (
                f'<span style="background:{color}20;color:{color};border:1px solid {color};'
                f'padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;display:inline-block">'
                f'{html.escape(text)}</span>'
            )

        def risk_bar(score: float) -> str:
            color = SEVERITY_COLORS_HTML.get(
                "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score >= 2 else "INFO",
                "#42a5f5",
            )
            pct = min(int((score or 0) / 10 * 100), 100)
            return (
                f'<div style="display:flex;align-items:center;gap:8px">'
                f'<div style="background:#1c2128;border-radius:3px;height:6px;width:54px;overflow:hidden">'
                f'<div style="background:{color};height:100%;width:{pct}%"></div></div>'
                f'<span style="color:{color};font-weight:700;font-size:12px">{score:.1f}</span>'
                f'</div>'
            )

        # Executive Posture & SLA Rows
        grade = posture["grade"]
        grade_color = GRADE_COLORS_HTML.get(grade, "#58a6ff")
        sla_rows = ""
        for item in posture["sla_breakdown"]:
            s_color = SEVERITY_COLORS_HTML.get(item["severity"], "#8b949e")
            sla_rows += f"""
            <tr>
              <td>{badge(item['severity'], s_color)}</td>
              <td style="font-weight:700;color:#e6edf3">{item['count']}</td>
              <td style="color:#ffa726;font-weight:600">{html.escape(item['sla'])}</td>
              <td style="color:#c9d1d9">{html.escape(item['action_vi'])}</td>
            </tr>"""

        # Standards reference pills
        standards_pills = ""
        if standards_meta:
            for _, meta in standards_meta.items():
                label = f"{meta.get('name', '')} ({meta.get('version', '')})"
                standards_pills += (
                    f'<span style="background:#161b22;border:1px solid #30363d;color:#8b949e;'
                    f'padding:3px 9px;border-radius:12px;font-size:11px">{html.escape(label)}</span> '
                )

        redaction_banner = (
            '<span style="background:rgba(46,160,67,0.18);color:#3fb950;border:1px solid #2ea043;'
            'padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600">'
            'PII / Secret Redaction: ENABLED</span>'
            if do_redact
            else '<span style="background:rgba(255,107,53,0.18);color:#ff6b35;border:1px solid #ff6b35;'
            'padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600">'
            'PII / Secret Redaction: OFF</span>'
        )

        # Findings rows
        findings_rows = ""
        for i, f in enumerate(findings, 1):
            sev = (f.get("severity") or "INFO").upper()
            score = float(f.get("risk_score") or 0.0)
            ts = html.escape((f.get("timestamp") or "")[:16].replace("T", " "))
            raw_payload = f.get("payload") or ""
            raw_response = f.get("response") or ""
            payload_full = html.escape(raw_payload)
            response_full = html.escape(raw_response)
            mod_html = html.escape(f.get("module_name", "-"))
            owasp_code = f.get("owasp_code") or "N/A"
            mitre_code = html.escape(f.get("mitre_code") or "-")
            ver_status = (f.get("verification_status") or "NEEDS_VERIFICATION").upper()
            rem_status = (f.get("remediation_status") or "OPEN").upper()
            root_cause = (f.get("root_cause_type") or "MODEL").upper()
            redacted_labels = f.get("redacted_fields") or []
            nist_rmf = _mapper.get_nist_rmf_for_module(owasp_code) if _mapper else []
            nist_str = html.escape(", ".join(nist_rmf[:2])) if nist_rmf else "-"

            # Truncate BEFORE html.escape() to avoid slicing entities like &lt; mid-sequence
            payload_short = html.escape(raw_payload[:110] + ("..." if len(raw_payload) > 110 else ""))
            response_short = html.escape(raw_response[:130] + ("..." if len(raw_response) > 130 else ""))
            redacted_note = (
                f'<div style="margin-top:4px;font-size:10px;color:#3fb950">Redacted: {html.escape(", ".join(redacted_labels))}</div>'
                if redacted_labels
                else ""
            )

            findings_rows += f"""
            <tr class="finding-row" onclick="toggleDetails('detail-{i}')" style="cursor:pointer" title="Nhấn để xem chi tiết">
              <td style="color:#8b949e;text-align:center">{i}</td>
              <td>
                <code style="font-size:11px;background:#0d1117;padding:2px 6px;border-radius:4px">{mod_html}</code><br>
                <span style="font-size:10px;color:#8b949e">Cause: {html.escape(root_cause)}</span>
              </td>
              <td>{badge(sev, SEVERITY_COLORS_HTML.get(sev, '#8b949e'))}</td>
              <td>{risk_bar(score)}</td>
              <td>
                {badge(rem_status, REMEDIATION_COLORS_HTML.get(rem_status, '#8b949e'))}<br>
                <div style="margin-top:4px">{badge(ver_status, VERIFICATION_COLORS_HTML.get(ver_status, '#8b949e'))}</div>
              </td>
              <td>
                <span style="background:rgba(88,166,255,0.15);color:#58a6ff;border:1px solid rgba(88,166,255,0.4);padding:1px 6px;border-radius:3px;font-size:11px">{html.escape(owasp_code)}</span><br>
                <span style="font-size:10px;color:#8b949e">{mitre_code}</span><br>
                <span style="font-size:10px;color:#7ee787">NIST: {nist_str}</span>
              </td>
              <td style="font-family:monospace;font-size:11px;color:#8b949e;max-width:200px;word-break:break-all">{payload_short}{redacted_note}</td>
              <td style="font-size:12px;max-width:230px;word-break:break-all;color:#c9d1d9">{response_short}</td>
              <td style="font-size:11px;color:#555;white-space:nowrap">{ts}</td>
            </tr>
            <tr id="detail-{i}" style="display:none;background-color:#161b22">
              <td colspan="9" style="padding:20px;border-bottom:1px solid #30363d">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
                    <div>
                        <div style="font-weight:700;color:#58a6ff;margin-bottom:8px;font-size:12px;text-transform:uppercase">Payload (Đầu vào)</div>
                        <div style="font-family:monospace;font-size:12px;color:#c9d1d9;background:#0d1117;padding:12px;border-radius:6px;border:1px solid #30363d;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto">{payload_full}</div>
                    </div>
                    <div>
                        <div style="font-weight:700;color:#58a6ff;margin-bottom:8px;font-size:12px;text-transform:uppercase">Response (Phản hồi AI)</div>
                        <div style="font-family:monospace;font-size:12px;color:#c9d1d9;background:#0d1117;padding:12px;border-radius:6px;border:1px solid #30363d;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto">{response_full}</div>
                    </div>
                </div>
              </td>
            </tr>
            """

        remediation_blocks = ""
        for code in owasp_codes:
            rems = get_remediation_for_code(code)
            nist_rmf = _mapper.get_nist_rmf_for_module(code) if _mapper else []
            nist_aml = _mapper.get_nist_aml_for_module(code) if _mapper else "N/A"
            if rems:
                items = "".join(f"<li>{html.escape(r)}</li>" for r in rems)
                nist_line = (
                    f'<div style="font-size:11px;color:#7ee787;margin-bottom:8px">'
                    f'NIST AI RMF: {html.escape(", ".join(nist_rmf))} &nbsp;|&nbsp; NIST AML: {html.escape(nist_aml)}</div>'
                    if nist_rmf
                    else ""
                )
                remediation_blocks += f"""
                <div style="margin-bottom:16px;padding:16px;background:#1c2128;border-radius:8px;border-left:4px solid #58a6ff">
                  <div style="font-weight:700;color:#58a6ff;margin-bottom:4px">{html.escape(code)} — Khuyến nghị khắc phục</div>
                  {nist_line}
                  <ul style="margin:0;padding-left:20px;color:#c9d1d9;font-size:13px;line-height:1.9">{items}</ul>
                </div>"""

        stat_cards = ""
        for sev, color in SEVERITY_COLORS_HTML.items():
            cnt = sev_counts.get(sev, 0)
            stat_cards += f"""
            <div style="text-align:center;padding:18px;background:#1c2128;border:1px solid #30363d;border-radius:8px">
              <div style="font-size:28px;font-weight:800;color:{color}">{cnt}</div>
              <div style="font-size:11px;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:0.5px">{sev}</div>
            </div>"""

        html_doc = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Security Assessment Report — Executive &amp; Technical</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:0}}
    .header{{background:linear-gradient(135deg,#1a1f2e,#0d1117);padding:36px 40px;border-bottom:1px solid #30363d}}
    .header h1{{font-size:24px;font-weight:800;color:#58a6ff;margin-bottom:8px}}
    .header .meta{{font-size:13px;color:#8b949e;line-height:1.8}}
    .container{{max-width:1260px;margin:0 auto;padding:32px 40px}}
    h2{{font-size:16px;font-weight:700;color:#e6edf3;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d}}
    table{{width:100%;border-collapse:collapse;font-size:12px}}
    th{{background:#1c2128;color:#8b949e;padding:10px 10px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #30363d}}
    td{{padding:10px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
    tr.finding-row:hover td{{background:rgba(88,166,255,0.04)}}
    .exec-grid{{display:grid;grid-template-columns:220px 1fr;gap:20px;margin-bottom:24px}}
    .grade-card{{background:#161b22;border:2px solid {grade_color};border-radius:12px;padding:20px;text-align:center}}
    .kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}
    .kpi-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}}
    .stat-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px}}
    .footer{{text-align:center;padding:24px;color:#555;font-size:12px;border-top:1px solid #21262d;margin-top:40px}}
  </style>
  <script>
    function toggleDetails(id) {{
      var el = document.getElementById(id);
      el.style.display = (el.style.display === "none") ? "table-row" : "none";
    }}
  </script>
</head>
<body>
  <div class="header">
    <div style="max-width:1260px;margin:0 auto">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
        <h1>Báo Cáo Đánh Giá An Toàn Hệ Thống AI (Executive &amp; Technical)</h1>
        {redaction_banner}
      </div>
      <div class="meta">
        Target: <strong style="color:#e6edf3">{target}</strong> &nbsp;·&nbsp;
        Ngày tạo: <strong style="color:#e6edf3">{generated_at}</strong> &nbsp;·&nbsp;
        Tổng phát hiện: <strong style="color:#ff6b35">{total}</strong> (Đang mở: <strong>{posture['active_findings']}</strong> · Đã khắc phục: <strong style="color:#3fb950">{posture['fixed_findings']}</strong>)
      </div>
      <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:6px">{standards_pills}</div>
    </div>
  </div>

  <div class="container">
    <h2>1. Tóm tắt Quản trị &amp; Xếp hạng Mức độ An toàn (Executive Posture)</h2>
    <div class="exec-grid">
      <div class="grade-card">
        <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:1px">Security Grade</div>
        <div style="font-size:56px;font-weight:900;color:{grade_color};line-height:1.1;margin:6px 0">{grade}</div>
        <div style="font-size:14px;font-weight:700;color:#e6edf3">{posture['posture_score']} / 100</div>
        <div style="font-size:11px;color:#8b949e;margin-top:4px">Max Risk: {posture['max_risk_score']}/10</div>
      </div>
      <div>
        <div class="kpi-grid">
          <div class="kpi-box">
            <div style="font-size:11px;color:#8b949e">Lỗ hổng đang mở (Active)</div>
            <div style="font-size:24px;font-weight:800;color:#ff6b35;margin-top:4px">{posture['active_findings']}</div>
          </div>
          <div class="kpi-box">
            <div style="font-size:11px;color:#8b949e">Đã khắc phục (Fixed)</div>
            <div style="font-size:24px;font-weight:800;color:#3fb950;margin-top:4px">{posture['fixed_findings']}</div>
          </div>
          <div class="kpi-box">
            <div style="font-size:11px;color:#8b949e">Đã xác nhận (Confirmed)</div>
            <div style="font-size:24px;font-weight:800;color:#58a6ff;margin-top:4px">{posture['confirmed_findings']}</div>
          </div>
          <div class="kpi-box">
            <div style="font-size:11px;color:#8b949e">Dương tính giả (FP)</div>
            <div style="font-size:24px;font-weight:800;color:#8b949e;margin-top:4px">{posture['false_positive_findings']}</div>
          </div>
        </div>
        <div style="margin-top:12px;padding:14px;background:#161b22;border-left:4px solid {grade_color};border-radius:6px;font-size:13px;color:#c9d1d9">
          <strong style="color:#e6edf3">Khuyến nghị điều hành ({html.escape(posture['overall_priority'])}):</strong>
          {html.escape(posture['recommended_action'])}
        </div>
      </div>
    </div>

    {"" if not sla_rows else f'''
    <div style="margin-bottom:24px;overflow-x:auto">
      <table>
        <thead>
          <tr><th>Mức độ (Active)</th><th>Số lượng</th><th>SLA Đề xuất</th><th>Hướng xử lý ưu tiên</th></tr>
        </thead>
        <tbody>{sla_rows}</tbody>
      </table>
    </div>'''}

    <h2>2. Phân bố theo mức độ nghiêm trọng</h2>
    <div class="stat-grid">{stat_cards}</div>

    <h2>3. Chi tiết Kỹ thuật &amp; Vòng đời Xác nhận Lỗ hổng</h2>
    {"<p style='color:#8b949e;padding:24px 0'>Chưa phát hiện lỗ hổng nào.</p>" if not findings else f'''
    <div style="overflow-x:auto">
    <table>
      <thead>
        <tr>
          <th>#</th><th>Module / Nguyên nhân</th><th>Severity</th><th>Risk</th>
          <th>Trạng thái / Xác nhận</th><th>OWASP / MITRE / NIST</th>
          <th>Payload</th><th>Phản hồi AI</th><th>Thời gian</th>
        </tr>
      </thead>
      <tbody>{findings_rows}</tbody>
    </table>
    </div>'''}

    <h2>4. Khuyến nghị Khắc phục Theo Chuẩn Quốc tế</h2>
    {remediation_blocks or "<p style='color:#8b949e'>Không có khuyến nghị (chưa có findings).</p>"}

    <div class="footer">
      AI Security Scanner v2.1 · OWASP LLM Top 10 (2025) · MITRE ATLAS · NIST AI RMF 1.0 · NIST AML<br>
      Báo cáo được tạo tự động vào {generated_at}
    </div>
  </div>
</body>
</html>"""

        from core.path_security import resolve_safe_output_path
        import uuid

        safe_out = resolve_safe_output_path(output_file)
        safe_out.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = safe_out.with_name(f".{safe_out.name}.{uuid.uuid4().hex[:8]}.tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        os.replace(tmp_path, safe_out)

        log_audit_event(
            "REPORT_GENERATED",
            target_url=findings[0]["target_url"] if findings else "",
            scan_id=scan_id,
            details={
                "format": "html",
                "output_file": str(safe_out),
                "total_findings": total,
                "grade": grade,
                "redacted": do_redact,
            },
        )
        return True

    except Exception as e:
        print(f"Lỗi khi tạo báo cáo: {e}")
        return False


def export_json_report(
    severity: Optional[str] = None,
    module_name: Optional[str] = None,
    scan_id: Optional[int] = None,
    redact: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Xuất báo cáo JSON (Executive Posture + Technical Findings + Standards Metadata)
    phục vụ tích hợp CI/CD, SIEM và Web API.
    """
    raw_findings = _get_findings_from_db(
        severity=severity, module_name=module_name, scan_id=scan_id
    )
    do_redact = _should_redact(redact)
    findings = [redact_finding(f) for f in raw_findings] if do_redact else raw_findings

    # Enrich each finding with NIST AI RMF & NIST AML metadata
    if _mapper:
        for f in findings:
            code = f.get("owasp_code") or f.get("module_name", "")
            f["nist_ai_rmf"] = _mapper.get_nist_rmf_for_module(code)
            f["nist_aml"] = _mapper.get_nist_aml_for_module(code)

    sev_counts = _count_by_severity(findings)
    lifecycle = _count_lifecycle(findings)
    posture = _risk_scorer.calculate_system_posture(findings)
    standards_meta = _mapper.get_standards_metadata() if _mapper else {}

    return {
        "generated_at": datetime.now().isoformat(),
        "redacted": do_redact,
        "filter": {"severity": severity, "module": module_name, "scan_id": scan_id},
        "standards_metadata": standards_meta,
        "system_posture": posture,
        "summary": {
            "total_findings": len(findings),
            "by_severity": sev_counts,
            "lifecycle": lifecycle,
        },
        "findings": findings,
    }


def show_console_summary():
    """In bảng tóm tắt nhanh ra terminal (dùng cho CLI)."""
    findings = _get_findings_from_db()
    sev = _count_by_severity(findings)
    return sev, len(findings)


def export_sarif_report(
    severity: Optional[str] = None,
    module_name: Optional[str] = None,
    scan_id: Optional[int] = None,
    redact: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Xuất phát hiện lỗ hổng theo chuẩn công nghiệp SARIF 2.1.0
    (Static Analysis Results Interchange Format) tương thích trực tiếp với
    GitHub Code Scanning, GitLab SAST và hệ thống quản lý lỗ hổng doanh nghiệp.
    """
    raw_findings = _get_findings_from_db(
        severity=severity, module_name=module_name, scan_id=scan_id
    )
    do_redact = _should_redact(redact)
    findings = [redact_finding(f) for f in raw_findings] if do_redact else raw_findings

    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for idx, f in enumerate(findings, 1):
        sev = (f.get("severity") or "INFO").upper()
        owasp_code = f.get("owasp_code") or "N/A"
        mitre_code = f.get("mitre_code") or "N/A"
        mod_name = f.get("module_name") or "ai_scanner"
        risk_score = float(f.get("risk_score") or 0.0)
        rule_id = f"{owasp_code}/{mod_name}" if owasp_code != "N/A" else f"AI-SEC/{mod_name}"

        nist_rmf = _mapper.get_nist_rmf_for_module(owasp_code) if _mapper else []
        nist_aml = _mapper.get_nist_aml_for_module(owasp_code) if _mapper else "N/A"

        if rule_id not in rules_by_id:
            cat_info = _mapper.get_category_info(owasp_code) if _mapper else {}
            rems = get_remediation_for_code(owasp_code)
            tags = ["security", "ai-security", owasp_code, mitre_code] + list(nist_rmf)
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": cat_info.get("name", mod_name),
                "shortDescription": {
                    "text": f"{cat_info.get('name', mod_name)} ({owasp_code} | {mitre_code})",
                },
                "fullDescription": {
                    "text": cat_info.get("description", f"AI Security finding detected by module {mod_name}."),
                },
                "help": {
                    "text": "\n".join(f"- {r}" for r in rems) if rems else "Review and harden AI component.",
                },
                "defaultConfiguration": {
                    "level": level_map.get(sev, "warning"),
                },
                "properties": {
                    "tags": [t for t in tags if t and t != "N/A"],
                    "security-severity": f"{risk_score:.1f}",
                    "owasp_llm_2025": owasp_code,
                    "mitre_atlas": mitre_code,
                    "nist_ai_rmf": nist_rmf,
                    "nist_aml": nist_aml,
                },
            }

        target_url = f.get("target_url") or "ai-target"
        location_obj: Dict[str, Any]
        if target_url.startswith("SAST://"):
            loc_str = target_url[len("SAST://"):]
            file_uri = loc_str
            line_no = 1
            if ":" in loc_str:
                parts = loc_str.rsplit(":", 1)
                if parts[1].isdigit():
                    file_uri = parts[0]
                    line_no = max(1, int(parts[1]))
            location_obj = {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri.replace("\\", "/")},
                    "region": {"startLine": line_no},
                }
            }
        else:
            location_obj = {
                "physicalLocation": {
                    "artifactLocation": {"uri": target_url},
                },
                "logicalLocations": [
                    {
                        "name": mod_name,
                        "fullyQualifiedName": f"{target_url}::{mod_name}",
                        "kind": "module",
                    }
                ],
            }

        payload_preview = (f.get("payload") or "")[:240]
        response_preview = (f.get("response") or "")[:240]
        ver_status = (f.get("verification_status") or "NEEDS_VERIFICATION").upper()
        rem_status = (f.get("remediation_status") or "OPEN").upper()

        sarif_result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": level_map.get(sev, "warning"),
            "message": {
                "text": (
                    f"[{sev} | Risk {risk_score:.1f}/10] Module '{mod_name}' ({owasp_code}/{mitre_code}) "
                    f"[{rem_status}/{ver_status}]. Payload: {payload_preview}"
                ),
            },
            "locations": [location_obj],
            "partialFingerprints": {
                "findingId": str(f.get("id", idx)),
                "moduleOwasp": f"{mod_name}:{owasp_code}",
            },
            "properties": {
                "finding_id": f.get("id", idx),
                "severity": sev,
                "security-severity": f"{risk_score:.1f}",
                "owasp_code": owasp_code,
                "mitre_code": mitre_code,
                "nist_ai_rmf": nist_rmf,
                "verification_status": ver_status,
                "remediation_status": rem_status,
                "root_cause_type": (f.get("root_cause_type") or "MODEL").upper(),
                "response_preview": response_preview,
                "redacted": do_redact,
                "timestamp": f.get("timestamp", ""),
            },
        }
        if rem_status == "FIXED" or ver_status == "FALSE_POSITIVE":
            sarif_result["suppressions"] = [
                {
                    "kind": "inSource",
                    "status": "accepted",
                    "justification": f"Marked as {rem_status} / {ver_status}",
                }
            ]
        results.append(sarif_result)

    posture = _risk_scorer.calculate_system_posture(findings)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Security Scanner",
                        "version": "2.1.0",
                        "informationUri": "https://github.com/HoangHuuPhong39/NCKH",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": {
                    "generated_at": datetime.now().isoformat(),
                    "redacted": do_redact,
                    "system_posture": posture,
                    "standards_metadata": _mapper.get_standards_metadata() if _mapper else {},
                },
            }
        ],
    }
