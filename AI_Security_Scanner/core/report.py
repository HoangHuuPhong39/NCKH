"""
Report Generator - Tạo báo cáo HTML đẹp và xuất JSON cho AI Security Scanner.
"""

import sqlite3
import json
import os
from datetime import datetime

from core.config import cfg

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), cfg.get("storage.database_path", "data/scanner.db"))
SEVERITY_COLORS_HTML = {
    "CRITICAL": "#ff4757",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffa726",
    "LOW": "#26c6da",
    "INFO": "#42a5f5",
}

try:
    from core.owasp_mapper import OWASPMapper
    _mapper = OWASPMapper()
except Exception:
    _mapper = None

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


def _get_findings_from_db(severity=None, module_name=None):
    """Lấy findings từ database có hỗ trợ lọc theo severity và module_name."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = """
            SELECT target_url, module_name, payload, response,
                   severity, risk_score, owasp_code, mitre_code, timestamp
            FROM findings
            WHERE 1=1
        """
        params = []
        if severity and severity != "ALL":
            query += " AND severity = ?"
            params.append(severity)
        if module_name and module_name != "ALL":
            query += " AND module_name = ?"
            params.append(module_name)
        query += " ORDER BY risk_score DESC"
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def _count_by_severity(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts


def generate_html_report(output_file="report.html", severity=None, module_name=None):
    """Tạo báo cáo HTML đầy đủ, có màu sắc, summary và khuyến nghị."""
    try:
        import html
        findings = _get_findings_from_db(severity=severity, module_name=module_name)
        sev_counts = _count_by_severity(findings)
        total = len(findings)
        generated_at = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        # Target info
        target = html.escape(findings[0]["target_url"] if findings else "N/A")

        # Build remediation section (unique OWASP codes)
        owasp_codes = list(dict.fromkeys(f.get("owasp_code", "N/A") for f in findings))

        def sev_badge(sev):
            color = SEVERITY_COLORS_HTML.get(sev, "#8b949e")
            return f'<span style="background:{color}20;color:{color};border:1px solid {color};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">{html.escape(sev)}</span>'

        def risk_bar(score):
            color = SEVERITY_COLORS_HTML.get(
                "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score >= 2 else "INFO", "#42a5f5"
            )
            pct = min(int((score or 0) / 10 * 100), 100)
            return (
                f'<div style="display:flex;align-items:center;gap:8px">'
                f'<div style="background:#1c2128;border-radius:3px;height:6px;width:60px;overflow:hidden">'
                f'<div style="background:{color};height:100%;width:{pct}%"></div></div>'
                f'<span style="color:{color};font-weight:700;font-size:12px">{score:.1f}</span>'
                f'</div>'
            )

        findings_rows = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            score = f.get("risk_score") or 0.0
            ts = html.escape((f.get("timestamp") or "")[:16].replace("T", " "))
            payload_full = html.escape(f.get("payload") or "")
            response_full = html.escape(f.get("response") or "")
            module_name = html.escape(f.get('module_name','-'))
            owasp_code = html.escape(f.get('owasp_code','-'))
            mitre_code = html.escape(f.get('mitre_code','-'))
            
            payload_short = payload_full[:120] + "..." if len(payload_full) > 120 else payload_full
            response_short = response_full[:150] + "..." if len(response_full) > 150 else response_full
            
            findings_rows += f"""
            <tr class="finding-row" onclick="toggleDetails('detail-{i}')" style="cursor:pointer" title="Nhấn để xem chi tiết">
              <td style="color:#8b949e;text-align:center">{i}</td>
              <td><code style="font-size:11px;background:#0d1117;padding:2px 6px;border-radius:4px">{module_name}</code></td>
              <td>{sev_badge(sev)}</td>
              <td>{risk_bar(score)}</td>
              <td>
                <span style="background:rgba(88,166,255,0.15);color:#58a6ff;border:1px solid rgba(88,166,255,0.4);padding:1px 6px;border-radius:3px;font-size:11px">{owasp_code}</span><br>
                <span style="font-size:10px;color:#555">{mitre_code}</span>
              </td>
              <td style="font-family:monospace;font-size:11px;color:#8b949e;max-width:220px;word-break:break-all">{payload_short}</td>
              <td style="font-size:12px;max-width:260px;word-break:break-all;color:#c9d1d9">{response_short}</td>
              <td style="font-size:11px;color:#555;white-space:nowrap">{ts}</td>
            </tr>
            <tr id="detail-{i}" style="display:none;background-color:#161b22">
              <td colspan="8" style="padding:20px;border-bottom:1px solid #30363d">
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
            if rems:
                items = "".join(f"<li>{html.escape(r)}</li>" for r in rems)
                remediation_blocks += f"""
                <div style="margin-bottom:16px;padding:16px;background:#1c2128;border-radius:8px;border-left:4px solid #58a6ff">
                  <div style="font-weight:700;color:#58a6ff;margin-bottom:8px">{html.escape(code)} — Khuyến nghị khắc phục</div>
                  <ul style="margin:0;padding-left:20px;color:#c9d1d9;font-size:13px;line-height:2">{items}</ul>
                </div>"""

        stat_cards = ""
        for sev, color in SEVERITY_COLORS_HTML.items():
            cnt = sev_counts.get(sev, 0)
            stat_cards += f"""
            <div style="text-align:center;padding:20px;background:#1c2128;border:1px solid #30363d;border-radius:8px">
              <div style="font-size:30px;font-weight:800;color:{color}">{cnt}</div>
              <div style="font-size:11px;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:0.5px">{sev}</div>
            </div>"""

        html_doc = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Security Scan Report</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;padding:0}}
    .header{{background:linear-gradient(135deg,#1a1f2e,#0d1117);padding:40px;border-bottom:1px solid #30363d}}
    .header h1{{font-size:24px;font-weight:800;color:#58a6ff;margin-bottom:8px}}
    .header .meta{{font-size:13px;color:#8b949e}}
    .container{{max-width:1200px;margin:0 auto;padding:32px 40px}}
    h2{{font-size:16px;font-weight:700;color:#e6edf3;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #30363d}}
    table{{width:100%;border-collapse:collapse;font-size:12px}}
    th{{background:#1c2128;color:#8b949e;padding:10px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #30363d}}
    td{{padding:10px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
    tr.finding-row:hover td{{background:rgba(88,166,255,0.04)}}
    .stat-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:32px}}
    .footer{{text-align:center;padding:24px;color:#555;font-size:12px;border-top:1px solid #21262d;margin-top:40px}}
  </style>
  <script>
    function toggleDetails(id) {{
      var el = document.getElementById(id);
      if (el.style.display === "none") {{
        el.style.display = "table-row";
      }} else {{
        el.style.display = "none";
      }}
    }}
  </script>
</head>
<body>
  <div class="header">
    <div style="max-width:1200px;margin:0 auto">
      <h1>Báo Cáo Kiểm Thử An Toàn Hệ Thống AI</h1>
      <div class="meta">
        Target: <strong style="color:#e6edf3">{target}</strong> &nbsp;·&nbsp;
        Ngày tạo: <strong style="color:#e6edf3">{generated_at}</strong> &nbsp;·&nbsp;
        Tổng cộng: <strong style="color:#ff6b35">{total}</strong> lỗ hổng
      </div>
    </div>
  </div>

  <div class="container">
    <h2>Tổng quan theo mức độ nghiêm trọng</h2>
    <div class="stat-grid">{stat_cards}</div>

    <h2>Chi tiết Lỗ hổng phát hiện</h2>
    {"<p style='color:#8b949e;padding:24px 0'>Chưa phát hiện lỗ hổng nào.</p>" if not findings else f'''
    <div style="overflow-x:auto">
    <table>
      <thead>
        <tr>
          <th>#</th><th>Module</th><th>Severity</th><th>Risk Score</th>
          <th>OWASP / MITRE</th><th>Payload</th><th>Phản hồi AI</th><th>Thời gian</th>
        </tr>
      </thead>
      <tbody>{findings_rows}</tbody>
    </table>
    </div>'''}

    <h2>Khuyến nghị Khắc phục</h2>
    {remediation_blocks or "<p style='color:#8b949e'>Không có khuyến nghị (chưa có findings).</p>"}

    <div class="footer">
      AI Security Scanner v2.0 · OWASP LLM Top 10 · MITRE ATLAS<br>
      Báo cáo được tạo tự động vào {generated_at}
    </div>
  </div>
</body>
</html>"""

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_doc)
        return True

    except Exception as e:
        print(f"Lỗi khi tạo báo cáo: {e}")
        return False


def export_json_report(severity=None, module_name=None):
    """Xuất toàn bộ findings dưới dạng JSON (dùng cho CI/CD và Web API), hỗ trợ lọc."""
    findings = _get_findings_from_db(severity=severity, module_name=module_name)
    sev_counts = _count_by_severity(findings)
    return {
        "generated_at": datetime.now().isoformat(),
        "filter": {"severity": severity, "module": module_name},
        "summary": {
            "total_findings": len(findings),
            "by_severity": sev_counts,
        },
        "findings": findings,
    }


def show_console_summary():
    """In bảng tóm tắt nhanh ra terminal (dùng cho CLI)."""
    findings = _get_findings_from_db()
    sev = _count_by_severity(findings)
    return sev, len(findings)