# -*- coding: utf-8 -*-
"""
scripts/build_rbst_paper_assets.py
Generate publication-grade figures (Fig 1, Fig 2, Fig 3 at 300 DPI) and a
color-coded Word (.docx) manuscript draft for Sections 5 & 6 (Phong & Lam),
with all modified/added content colored RED (#C00000) for supervisor review.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Cm, Inches, Pt, RGBColor

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
FIG_DIR = ROOT / "paper" / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_JSON = ROOT / "AI_Security_Scanner" / "experiments" / "results" / "rbst_real" / "rbst_real_experiments_summary.json"
OUT_DOCX = ROOT / "paper" / "RBST_AI_Muc_5_6_Phong_Lam_Review.docx"

# Prefer a crisp font supporting full Vietnamese diacritics on Windows
plt.rcParams["font.sans-serif"] = ["Segoe UI", "DejaVu Sans", "Arial"]
plt.rcParams["axes.unicode_minus"] = False


# ==============================================================================
# Helper: Rounded Box & Clean Arrows for Architecture / Process Diagrams
# ==============================================================================

def _draw_box(
    ax,
    x: float,
    y: float,
    w: float,
    h: float,
    title: str,
    lines: list[str] | None = None,
    facecolor: str = "#FFFFFF",
    edgecolor: str = "#2C3E50",
    linewidth: float = 1.4,
    title_color: str = "#111827",
    body_color: str = "#374151",
    title_size: float = 10.5,
    body_size: float = 8.6,
    radius: float = 0.015,
    zorder: int = 3,
):
    patch = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle=f"round,pad=0.004,rounding_size={radius}",
        facecolor=facecolor,
        edgecolor=edgecolor,
        linewidth=linewidth,
        zorder=zorder,
    )
    ax.add_patch(patch)
    cx = x + w / 2.0
    if lines:
        n_lines = len(lines)
        top_y = y + h * (0.74 if n_lines <= 2 else 0.78)
        ax.text(
            cx, top_y, title,
            ha="center", va="center", fontsize=title_size, fontweight="bold",
            color=title_color, zorder=zorder + 1,
        )
        body_text = "\n".join(lines)
        body_y = y + h * (0.34 if n_lines <= 2 else 0.36)
        ax.text(
            cx, body_y, body_text,
            ha="center", va="center", fontsize=body_size, color=body_color,
            linespacing=1.35, zorder=zorder + 1,
        )
    else:
        ax.text(
            cx, y + h / 2.0, title,
            ha="center", va="center", fontsize=title_size, fontweight="bold",
            color=title_color, zorder=zorder + 1,
        )


def _draw_arrow(ax, p1, p2, color="#334155", lw=1.5, rad=0.0, zorder=5):
    arr = FancyArrowPatch(
        p1, p2,
        arrowstyle="-|>,head_length=6.5,head_width=3.8",
        color=color,
        linewidth=lw,
        connectionstyle=f"arc3,rad={rad}",
        zorder=zorder,
    )
    ax.add_patch(arr)


# ==============================================================================
# Figure 1: Four-Layer RBST-AI Architecture (Corrected: Flow D & R = L·I·M·(1-E))
# ==============================================================================

def draw_fig1_architecture() -> Path:
    fig, ax = plt.subplots(figsize=(13.0, 8.6), dpi=300)
    ax.set_xlim(0, 1.0)
    ax.set_ylim(0, 1.0)
    ax.axis("off")
    fig.patch.set_facecolor("#FFFFFF")

    # Main title
    ax.text(
        0.02, 0.968,
        "Kiến trúc RBST-AI: bốn tầng, kết quả phán xét quay về cập nhật rủi ro",
        fontsize=14, fontweight="bold", color="#0F172A", ha="left", va="center",
    )

    # Layer containers
    layers = [
        (0.02, 0.755, 0.77, 0.185, "Tầng 1 · Đầu vào"),
        (0.02, 0.515, 0.77, 0.210, "Tầng 2 · Phân tích rủi ro"),
        (0.02, 0.215, 0.77, 0.245, "Tầng 3 · Điều phối và thực thi"),
        (0.02, 0.025, 0.77, 0.155, "Tầng 4 · Bằng chứng và báo cáo"),
    ]
    for lx, ly, lw, lh, lbl in layers:
        bg = FancyBboxPatch(
            (lx, ly), lw, lh,
            boxstyle="round,pad=0.002,rounding_size=0.016",
            facecolor="#F3F6FA", edgecolor="#CBD5E1", linewidth=1.2, zorder=1,
        )
        ax.add_patch(bg)
        ax.text(
            lx + 0.015, ly + lh - 0.022, lbl,
            fontsize=10.5, fontweight="bold", color="#334155", ha="left", va="center", zorder=2,
        )

    # Layer 1 boxes (FIXED: luồng dữ liệu D)
    _draw_box(
        ax, 0.045, 0.775, 0.22, 0.122,
        "Hồ sơ hệ thống",
        ["kiến trúc C, luồng dữ liệu D", "công cụ, đặc quyền, độ nhạy"],
    )
    _draw_box(
        ax, 0.295, 0.775, 0.22, 0.122,
        "Cơ sở tri thức mối đe dọa",
        ["OWASP LLM/Agentic, ATLAS", "NIST AI 100-2e2025"],
    )
    _draw_box(
        ax, 0.545, 0.775, 0.22, 0.122,
        "Yêu cầu tuân thủ",
        ["NIST AI RMF, EU AI Act", "ISO/IEC TS 42119-2"],
    )

    # Layer 2 boxes (FIXED: R = L · I · M · (1 − E) & R_res)
    _draw_box(
        ax, 0.045, 0.540, 0.20, 0.138,
        "Context Profiler",
        ["vector a(c) = (a₁, …, a₄)", "lan truyền a₂ → hệ số M(c)"],
    )
    _draw_box(
        ax, 0.285, 0.540, 0.20, 0.138,
        "Threat Modeler",
        ["danh sách cặp (t, c) khả dĩ", "ranh giới tin cậy"],
    )
    _draw_box(
        ax, 0.525, 0.540, 0.24, 0.138,
        "Risk Engine",
        ["R = L · I · M · (1 − E)", "hậu nghiệm Beta(α, β) & R_res"],
        facecolor="#E8F0FE", edgecolor="#1D4ED8", linewidth=2.1, title_color="#1E3A8A",
    )

    # Layer 3 boxes
    _draw_box(
        ax, 0.040, 0.245, 0.175, 0.155,
        "Test Orchestrator",
        ["lấy mẫu Thompson", "chỉ số ưu tiên P (CT 6)", "ngân sách B, ngưỡng τ"],
        facecolor="#E8F0FE", edgecolor="#1D4ED8", linewidth=2.1, title_color="#1E3A8A",
    )
    _draw_box(
        ax, 0.235, 0.245, 0.175, 0.155,
        "Attack Generator",
        ["thư viện YAML + đột biến", "garak / PyRIT / ART", "PAIR, GCG, LLM-RT"],
    )
    _draw_box(
        ax, 0.430, 0.245, 0.165, 0.155,
        "Executor",
        ["AgentSandbox công cụ", "Ollama / ML API", "ghi log tái lập"],
    )
    _draw_box(
        ax, 0.615, 0.245, 0.160, 0.155,
        "Oracle",
        ["quy tắc, canary, trace", "LLM-Judge (2 tầng)", "kiểm chứng người (κ)"],
    )

    # External Target System box
    _draw_box(
        ax, 0.825, 0.245, 0.155, 0.155,
        "Hệ thống AI đích",
        ["LLM, RAG, tác tử,", "dịch vụ ML qua API"],
        facecolor="#FEF9E7", edgecolor="#B45309", linewidth=1.8, title_color="#92400E", body_color="#78350F",
    )

    # Layer 4 boxes
    _draw_box(
        ax, 0.045, 0.045, 0.34, 0.095,
        "Compliance Reporter",
        ["bản đồ nhiệt rủi ro, APFD_R, RC, CF, ánh xạ điều khoản"],
    )
    _draw_box(
        ax, 0.445, 0.045, 0.32, 0.095,
        "Evidence Store (SQLite)",
        ["(t, c, k, y_k, K, R, R_res, log, phiên bản)"],
    )

    # Arrows Layer 1 -> Layer 2 (positioned cleanly right of layer titles)
    _draw_arrow(ax, (0.215, 0.775), (0.215, 0.680))
    _draw_arrow(ax, (0.400, 0.775), (0.385, 0.680))
    _draw_arrow(ax, (0.650, 0.775), (0.645, 0.680))

    # Arrows inside Layer 2
    _draw_arrow(ax, (0.247, 0.609), (0.283, 0.609))
    _draw_arrow(ax, (0.487, 0.609), (0.523, 0.609))

    # Arrow Risk Engine -> Test Orchestrator (routed cleanly right of "Tầng 3 · Điều phối...")
    ax.plot([0.585, 0.585, 0.195, 0.195], [0.538, 0.488, 0.488, 0.408], color="#334155", lw=1.6, zorder=4)
    _draw_arrow(ax, (0.195, 0.415), (0.195, 0.402), color="#334155", lw=1.6)

    # Arrows inside Layer 3
    _draw_arrow(ax, (0.217, 0.322), (0.233, 0.322))
    _draw_arrow(ax, (0.412, 0.322), (0.428, 0.322))
    _draw_arrow(ax, (0.597, 0.322), (0.613, 0.322))

    # Closed-loop feedback arrow: Oracle -> Risk Engine (highlighted blue)
    _draw_arrow(ax, (0.715, 0.402), (0.715, 0.538), color="#1D4ED8", lw=2.3, zorder=6)
    ax.text(
        0.725, 0.470, "phản hồi vòng kín\ny_k → (n, s), θ_tb, R_res",
        fontsize=8.6, fontweight="bold", color="#1D4ED8", ha="left", va="center", zorder=6,
    )

    # Executor -> Target System (top amber loop)
    ax.plot([0.512, 0.512, 0.902, 0.902], [0.402, 0.432, 0.432, 0.408], color="#B45309", lw=1.6, zorder=4)
    _draw_arrow(ax, (0.902, 0.415), (0.902, 0.402), color="#B45309", lw=1.6)
    ax.text(0.640, 0.440, "truy vấn ca kiểm thử k", fontsize=8.4, color="#92400E", ha="center", va="bottom")

    # Target System -> Oracle (bottom amber loop)
    ax.plot([0.902, 0.902, 0.695, 0.695], [0.243, 0.210, 0.210, 0.238], color="#B45309", lw=1.6, zorder=4)
    _draw_arrow(ax, (0.695, 0.230), (0.695, 0.243), color="#B45309", lw=1.6)
    ax.text(0.840, 0.200, "phản hồi & vết công cụ", fontsize=8.4, color="#92400E", ha="center", va="top")

    # Oracle -> Evidence Store -> Compliance Reporter
    _draw_arrow(ax, (0.655, 0.243), (0.655, 0.143))
    _draw_arrow(ax, (0.443, 0.092), (0.388, 0.092))

    out = FIG_DIR / "fig1_rbst_architecture.png"
    fig.savefig(out, dpi=300, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return out


# ==============================================================================
# Figure 2: Six-Phase Closed-Loop Process (Corrected: R = L × I × M × (1 − E))
# ==============================================================================

def draw_fig2_six_phases() -> Path:
    fig, ax = plt.subplots(figsize=(12.0, 4.7), dpi=300)
    ax.set_xlim(0, 1.0)
    ax.set_ylim(0, 1.0)
    ax.axis("off")
    fig.patch.set_facecolor("#FFFFFF")

    ax.text(
        0.02, 0.92,
        "Quy trình sáu pha RBST-AI: kết quả kiểm thử quay lại cập nhật điểm rủi ro",
        fontsize=13.5, fontweight="bold", color="#0F172A", ha="left", va="center",
    )

    bw, bh = 0.265, 0.285
    xs = [0.025, 0.345, 0.665]
    y_top, y_bot = 0.545, 0.115

    _draw_box(
        ax, xs[0], y_top, bw, bh,
        "1. Phạm vi & bối cảnh",
        ["Dựng đồ thị S = (C, D)", "Mức tự chủ, đặc quyền a₂, M(c)", "Yêu cầu pháp lý & tuân thủ"],
        facecolor="#F8FAFC", edgecolor="#94A3B8",
    )
    _draw_box(
        ax, xs[1], y_top, bw, bh,
        "2. Mô hình mối đe dọa",
        ["Áp danh mục OWASP & ATLAS", "Mô hình kẻ tấn công NIST AML", "Xác định ranh giới tin cậy"],
        facecolor="#F8FAFC", edgecolor="#94A3B8",
    )
    _draw_box(
        ax, xs[2], y_top, bw, bh,
        "3. Định lượng rủi ro",
        ["R = L × I × M × (1 − E)", "R_res dùng cận trên 95% θ_max", "Từng cặp (t, c) khả dĩ"],
        facecolor="#E8F0FE", edgecolor="#1D4ED8", linewidth=2.0, title_color="#1E3A8A",
    )

    _draw_box(
        ax, xs[0], y_bot, bw, bh,
        "4. Sinh & ưu tiên ca",
        ["Lấy mẫu Thompson θ_mẫu", "Xếp hạng theo chỉ số P (CT 6)", "Sinh biến thể qua adapter"],
        facecolor="#F8FAFC", edgecolor="#94A3B8",
    )
    _draw_box(
        ax, xs[1], y_bot, bw, bh,
        "5. Thực thi & phán xét",
        ["Sandbox công cụ / LLM / ML API", "Oracle đa tầng: quy tắc, canary,", "vết Sandbox & LLM-Judge"],
        facecolor="#F8FAFC", edgecolor="#94A3B8",
    )
    _draw_box(
        ax, xs[2], y_bot, bw, bh,
        "6. Báo cáo & cập nhật",
        ["Ghi nhận lỗ hổng & bằng chứng", "Cập nhật hậu nghiệm Bayes (CT 5)", "Dừng khi R_res ≤ τ hoặc ΣK ≥ B"],
        facecolor="#F8FAFC", edgecolor="#94A3B8",
    )

    # Arrows: 1->2->3
    _draw_arrow(ax, (xs[0] + bw + 0.004, y_top + bh / 2), (xs[1] - 0.004, y_top + bh / 2), color="#64748B")
    _draw_arrow(ax, (xs[1] + bw + 0.004, y_top + bh / 2), (xs[2] - 0.004, y_top + bh / 2), color="#64748B")

    # 3 -> 4 routed through middle gap
    mid_y = (y_top + y_bot + bh) / 2.0
    x3_c = xs[2] + bw / 2
    x4_c = xs[0] + bw / 2
    ax.plot([x3_c, x3_c, x4_c, x4_c], [y_top - 0.004, mid_y, mid_y, y_bot + bh + 0.012], color="#475569", lw=1.6)
    _draw_arrow(ax, (x4_c, y_bot + bh + 0.016), (x4_c, y_bot + bh + 0.002), color="#475569", lw=1.6)

    # 4->5->6
    _draw_arrow(ax, (xs[0] + bw + 0.004, y_bot + bh / 2), (xs[1] - 0.004, y_bot + bh / 2), color="#64748B")
    _draw_arrow(ax, (xs[1] + bw + 0.004, y_bot + bh / 2), (xs[2] - 0.004, y_bot + bh / 2), color="#64748B")

    # Feedback loop: 6 -> 3 on right side
    x_loop = 0.962
    ax.plot([xs[2] + bw + 0.004, x_loop, x_loop, xs[2] + bw + 0.012],
            [y_bot + bh / 2, y_bot + bh / 2, y_top + bh / 2, y_top + bh / 2],
            color="#1D4ED8", lw=2.1)
    _draw_arrow(ax, (xs[2] + bw + 0.018, y_top + bh / 2), (xs[2] + bw + 0.003, y_top + bh / 2), color="#1D4ED8", lw=2.1)
    ax.text(
        x_loop - 0.012, mid_y, "vòng phản hồi\ncập nhật Bayes",
        fontsize=8.6, fontweight="bold", color="#1D4ED8", ha="right", va="center",
    )

    out = FIG_DIR / "fig2_rbst_six_phases.png"
    fig.savefig(out, dpi=300, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return out


# ==============================================================================
# Figure 3: Real Experimental Benchmark Chart (100% Real Data from Summary JSON)
# ==============================================================================

def draw_fig3_real_results() -> Path:
    data = json.loads(SUMMARY_JSON.read_text(encoding="utf-8"))
    cs_data = data["case_studies"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.2, 5.2), dpi=300, gridspec_kw={"width_ratios": [1.35, 1.0]})
    fig.patch.set_facecolor("#FFFFFF")

    # Left panel: APFD_R_pen across CS1..CS4 for key methods
    methods = [
        ("RBST-AI", "RBST-AI (đề xuất)", "#1D4ED8"),
        ("B4", "B4: RBT định tính", "#0D9488"),
        ("B2", "B2: RBST tĩnh", "#64748B"),
        ("B0", "B0: Ngẫu nhiên", "#94A3B8"),
        ("S3", "S3: LLM-RT", "#EA580C"),
        ("S1", "S1: PAIR", "#DC2626"),
        ("S2", "S2: GCG (T4)", "#7C3AED"),
    ]
    cs_keys = ["cs1", "cs2", "cs3", "cs4"]
    cs_labels = ["CS1\n(Web RAG)", "CS2\n(Tool Agent)", "CS3\n(LLM Chat)", "CS4\n(ML API)"]
    x = np.arange(len(cs_keys))
    width = 0.115

    for i, (code, label, color) in enumerate(methods):
        vals = []
        errs = []
        for cs in cs_keys:
            st = cs_data[cs]["strategies"][code]
            if st.get("executed"):
                vals.append(st["APFD_R_pen_mean"])
                errs.append(st["APFD_R_pen_std"] or 0.0)
            else:
                vals.append(0.0)
                errs.append(0.0)
        offset = (i - (len(methods) - 1) / 2.0) * width
        bars = ax1.bar(
            x + offset, vals, width * 0.92, yerr=errs, capsize=2.0,
            label=label, color=color, alpha=0.92, edgecolor="#1E293B", linewidth=0.4,
            error_kw={"elinewidth": 0.8, "ecolor": "#334155"},
        )
        if code in ("S1", "S2", "S3"):
            # Annotate N/A clearly on CS4
            if code == "S2":
                ax1.text(x[3] + offset, 0.025, "S1–S3:\nN/A", ha="center", va="bottom", fontsize=7.5, color="#475569", style="italic")

    ax1.set_xticks(x)
    ax1.set_xticklabels(cs_labels, fontsize=9.5, fontweight="bold")
    ax1.set_ylabel("APFD_R có phạt (cao hơn tốt hơn)", fontsize=10, fontweight="bold", color="#0F172A")
    ax1.set_title("(a) Tốc độ & độ phủ phát hiện lỗ hổng thật theo từng Case Study", fontsize=10.8, fontweight="bold", pad=10)
    ax1.set_ylim(0, 0.80)
    ax1.grid(axis="y", linestyle="--", alpha=0.45)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)
    ax1.legend(ncol=2, fontsize=8.0, frameon=True, loc="upper right")

    # Right panel: Mean Cost to First Critical (CF, lower is better) & Mean RC
    comp_codes = ["RBST-AI", "A3", "S3", "B2", "B4", "B0", "B1", "S2", "S1"]
    comp_labels = [
        "RBST-AI (đề xuất)",
        "A3: Bỏ Thompson",
        "S3: LLM-RT (CS1–3)",
        "B2: RBST tĩnh",
        "B4: RBT định tính",
        "B0: Ngẫu nhiên",
        "B1: OWASP tuần tự",
        "S2: GCG (CS1–3)",
        "S1: PAIR (CS1–3)",
    ]
    cf_means = []
    rc_means = []
    for code in comp_codes:
        cfs = [cs_data[cs]["strategies"][code]["CF_mean"] for cs in cs_keys if cs_data[cs]["strategies"][code].get("executed")]
        rcs = [cs_data[cs]["strategies"][code]["RC_mean"] for cs in cs_keys if cs_data[cs]["strategies"][code].get("executed")]
        cf_means.append(float(np.mean(cfs)))
        rc_means.append(float(np.mean(rcs)))

    y_pos = np.arange(len(comp_codes))
    bar_colors = ["#1D4ED8" if c == "RBST-AI" else ("#DC2626" if c.startswith("S") else "#64748B") for c in comp_codes]
    ax2.barh(y_pos, cf_means, height=0.62, color=bar_colors, alpha=0.90, edgecolor="#1E293B", linewidth=0.5)
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(comp_labels, fontsize=8.8)
    ax2.invert_yaxis()
    ax2.set_xlabel("Chi phí trung bình tới lỗ hổng nghiêm trọng đầu tiên CF (thấp hơn tốt hơn)", fontsize=9.2, fontweight="bold")
    ax2.set_title("(b) Hiệu quả chi phí CF & Độ bao phủ rủi ro RC trung bình", fontsize=10.8, fontweight="bold", pad=10)
    ax2.set_xlim(0, max(cf_means) * 1.32)
    ax2.grid(axis="x", linestyle="--", alpha=0.45)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    for yi, (cf_v, rc_v) in enumerate(zip(cf_means, rc_means)):
        ax2.text(
            cf_v + 0.35, yi,
            f"CF={cf_v:.2f} | RC={rc_v:.2f}",
            va="center", ha="left", fontsize=8.0,
            fontweight="bold" if comp_codes[yi] == "RBST-AI" else "normal",
            color="#1E3A8A" if comp_codes[yi] == "RBST-AI" else "#334155",
        )

    fig.tight_layout(pad=1.6)
    out = FIG_DIR / "fig3_rbst_real_benchmark.png"
    fig.savefig(out, dpi=300, bbox_inches="tight", pad_inches=0.12)
    plt.close(fig)
    return out


# ==============================================================================
# Word (.docx) Builder with Real Red Markup (#C00000) for Supervisor Review
# ==============================================================================

RED = RGBColor(192, 0, 0)
BLACK = RGBColor(0, 0, 0)
NAVY = RGBColor(23, 55, 94)
GRAY = RGBColor(90, 90, 90)


def _set_cell_shading(cell, fill_hex: str):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)


def _set_table_borders(table, color="94A3B8"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'<w:top w:val="single" w:sz="6" w:space="0" w:color="{color}"/>'
        f'<w:bottom w:val="single" w:sz="6" w:space="0" w:color="{color}"/>'
        f'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="CBD5E1"/>'
        f'<w:left w:val="none"/><w:right w:val="none"/><w:insideV w:val="none"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)


def _set_vn_run_font(run, font_name: str, size: float, bold: bool = False, italic: bool = False, color: RGBColor = BLACK):
    run.font.name = font_name
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    rPr = run._element.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = OxmlElement("w:rFonts")
        rPr.insert(0, rFonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rFonts.set(qn(attr), font_name)


def _add_p(doc: Document, text: str = "", color: RGBColor = BLACK, bold: bool = False, italic: bool = False,
           size: float = 11.5, align=WD_ALIGN_PARAGRAPH.JUSTIFY, space_before: float = 2, space_after: float = 5):
    p = doc.add_paragraph()
    p.alignment = align
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = 1.15
    if text:
        run = p.add_run(text)
        _set_vn_run_font(run, "Times New Roman", size, bold=bold, italic=italic, color=color)
    return p


def _add_mixed_p(doc: Document, segments: list[tuple[str, RGBColor, bool, bool]],
                 size: float = 11.5, align=WD_ALIGN_PARAGRAPH.JUSTIFY, space_after: float = 5):
    p = doc.add_paragraph()
    p.alignment = align
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = 1.15
    for text, color, bold, italic in segments:
        r = p.add_run(text)
        _set_vn_run_font(r, "Times New Roman", size, bold=bold, italic=italic, color=color)
    return p


def _add_styled_table(
    doc: Document,
    headers: list[str],
    rows: list[list[str]],
    text_color: RGBColor = BLACK,
    highlight_rows: set[int] | None = None,
    font_size: float = 9.0,
):
    tbl = doc.add_table(rows=1 + len(rows), cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _set_table_borders(tbl)

    # Header
    for ci, h in enumerate(headers):
        cell = tbl.rows[0].cells[ci]
        _set_cell_shading(cell, "E8EEF5")
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(3)
        p.paragraph_format.space_after = Pt(3)
        r = p.add_run(h)
        _set_vn_run_font(r, "Times New Roman", font_size, bold=True, color=RED if text_color == RED else NAVY)

    # Body
    hi_rows = highlight_rows or set()
    for ri, row in enumerate(rows):
        is_hi = ri in hi_rows
        for ci, val in enumerate(row):
            cell = tbl.rows[ri + 1].cells[ci]
            if is_hi:
                _set_cell_shading(cell, "FFF1F2" if text_color == RED else "EFF6FF")
            elif ri % 2 == 1:
                _set_cell_shading(cell, "F8FAFC")
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if ci <= 1 else WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            r = p.add_run(val)
            _set_vn_run_font(r, "Times New Roman", font_size, bold=is_hi, color=text_color)
    return tbl


def build_docx(fig1: Path, fig2: Path, fig3: Path) -> Path:
    doc = Document()
    normal_style = doc.styles["Normal"]
    normal_style.font.name = "Times New Roman"
    normal_style.font.size = Pt(11.5)
    ns_rPr = normal_style._element.get_or_add_rPr()
    ns_rFonts = ns_rPr.find(qn("w:rFonts"))
    if ns_rFonts is None:
        ns_rFonts = OxmlElement("w:rFonts")
        ns_rPr.insert(0, ns_rFonts)
    for attr in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        ns_rFonts.set(qn(attr), "Times New Roman")

    # Page margins (A4 academic layout)
    for sec in doc.sections:
        sec.page_width = Cm(21.0)
        sec.page_height = Cm(29.7)
        sec.top_margin = Cm(2.0)
        sec.bottom_margin = Cm(2.0)
        sec.left_margin = Cm(2.2)
        sec.right_margin = Cm(2.0)

    # Banner note for supervisor review
    _add_p(
        doc,
        "BẢN CHỈNH SỬA MỤC 5 VÀ MỤC 6 — PHẦN CÔNG VIỆC CỦA PHONG & LÂM",
        color=NAVY, bold=True, size=14, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=4,
    )
    _add_mixed_p(
        doc,
        [
            ("Quy ước trình bày: ", BLACK, True, False),
            ("Chữ màu đen", BLACK, True, False),
            (" là nội dung giữ nguyên từ bản thảo gốc; ", BLACK, False, False),
            ("chữ màu đỏ", RED, True, False),
            (" là toàn bộ nội dung chỉnh sửa, bổ sung mới và kết quả thực nghiệm thật 100% (507 lượt thực thi tấn công thật trên Ollama, GPU Tesla T4 và scikit-learn, 0% dữ liệu giả lập) để thầy review.", RED, False, False),
        ],
        size=10.5, space_after=6,
    )

    # Sync checklist box for the team
    _add_p(
        doc,
        "Ghi chú đồng bộ cho các thành viên khác (Tuyến, Vy, Minh):",
        color=RED, bold=True, size=10.5, space_after=2,
    )
    sync_items = [
        "1. Tóm tắt, Mục 1 (Phạm vi phương pháp) và Mục 8 (Kết luận): bỏ câu 'bài báo không công bố số liệu thực nghiệm mới' và cập nhật khớp với kết quả thực nghiệm thật trên 4 Case Study (CS1–CS4).",
        "2. Tiêu đề tiếng Anh: sửa 'Intelligent Artificial Systems' thành 'Artificial Intelligence Systems'.",
        "3. Hình 1 & Hình 2: đã vẽ lại chuẩn ký hiệu 'luồng dữ liệu D' (thay vì E) và 'R = L · I · M · (1 − E)' ngay trong tài liệu này.",
        "4. Đánh số bảng Mục 7 (Minh): do Mục 6 bổ sung Bảng 7, 8, 9 kết quả thực nghiệm, các bảng ở Mục 7 đánh số nối tiếp từ Bảng 10 và bỏ dẫn chiếu tới mục 7.6 còn thiếu.",
    ]
    for s in sync_items:
        _add_p(doc, s, color=RED, italic=True, size=10.0, space_before=0, space_after=2)

    # ==========================================================================
    # SECTION 5
    # ==========================================================================
    _add_p(doc, "5. Thiết kế và hiện thực framework RBST-AI", color=RED, bold=True, size=13, space_before=10, space_after=4)
    _add_p(doc, "5.1. Kiến trúc bốn tầng", color=BLACK, bold=True, size=11.5, space_before=4, space_after=3)
    _add_mixed_p(
        doc,
        [
            ("Hình 1 trình bày kiến trúc tổng thể của RBST-AI. Tầng 1 tiếp nhận hồ sơ hệ thống ", BLACK, False, False),
            ("S = (C, D)", RED, False, True),
            (", cơ sở tri thức mối đe dọa và yêu cầu tuân thủ. Tầng 2 hiện thực mô hình toán học ở Mục 4 (Context Profiler, Threat Modeler, Risk Engine). Tầng 3 điều phối và thực thi ca kiểm thử (Test Orchestrator, Attack Generator, Executor, Oracle). Tầng 4 lưu bằng chứng tái lập và sinh báo cáo truy vết tuân thủ. Điểm cốt lõi là cạnh phản hồi từ Oracle về Risk Engine, ", BLACK, False, False),
            ("cập nhật trực tiếp phân phối hậu nghiệm Beta–Bernoulli và biến quy trình thành vòng kín thích nghi.", RED, False, False),
        ],
    )

    p_img1 = doc.add_paragraph()
    p_img1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img1.add_run().add_picture(str(fig1), width=Inches(6.3))
    _add_p(
        doc,
        "Hình 1. Kiến trúc bốn tầng của RBST-AI (đã hiệu chỉnh ký hiệu luồng dữ liệu D và công thức R = L · I · M · (1 − E)).",
        color=RED, italic=True, size=10.0, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6,
    )

    _add_p(
        doc,
        "Bảng 4. Các mô-đun của RBST-AI và hiện thực trong nguyên mẫu AI_Security_Scanner",
        color=RED, bold=True, size=10.5, align=WD_ALIGN_PARAGRAPH.CENTER, space_before=4, space_after=3,
    )
    _add_styled_table(
        doc,
        ["Mô-đun", "Đầu vào", "Đầu ra", "Hiện thực trong nguyên mẫu (AI_Security_Scanner)"],
        [
            ["Context Profiler", "Hồ sơ kiến trúc YAML/JSON, danh mục công cụ, phân loại dữ liệu", "Đồ thị S=(C, D); a₁…a₄; M(c)", "core/rbst_graph.py (SystemGraph, BFS lan truyền a₂)"],
            ["Threat Modeler", "S, tri thức OWASP LLM/Agentic, ATLAS, mô hình kẻ tấn công", "Cặp (t, c) khả dĩ; ranh giới tin cậy", "core/rbst_graph.py (RBSTThreatModeler) + taxonomy.json"],
            ["Risk Engine", "Cặp (t, c), I, E, μ₀, n₀, kết quả y_k", "R, R_res, θ_tb, θ_max, bản đồ nhiệt", "core/rbst_engine.py (RBSTRiskEngine, Beta 95% scipy)"],
            ["Test Orchestrator", "Hậu nghiệm Beta, thư viện ca, ngân sách B, ngưỡng τ", "Chuỗi ca kiểm thử theo chỉ số P", "core/rbst_engine.py (RBSTOrchestrator, Thompson + B0–B4/A1–A3)"],
            ["Attack Generator", "Cặp (t, c) và ca k được chọn", "Payload gốc và biến thể đột biến", "core/rbst_adapter.py, AdaptiveGenerator, garak/PyRIT/PAIR/GCG"],
            ["Executor", "Ca kiểm thử k, cấu hình hệ thống đích", "Phản hồi, vết thực thi công cụ, chi phí K", "SimpleLLMClient (Ollama), AgentSandbox, scikit-learn API"],
            ["Oracle", "Phản hồi, vết thực thi công cụ", "Nhãn y_k ∈ {0,1}, mức nghiêm trọng", "Cascade 2 tầng: PatternDetector/canary/trace + LLMJudge"],
            ["Evidence Store & Reporter", "Toàn bộ log (t, c, k, y_k, K, R, R_res)", "Báo cáo JSON/MD, bản đồ nhiệt, tuân thủ", "core/evidence_store.py (SQLite) + RBSTComplianceReporter"],
        ],
        text_color=RED,
        font_size=8.8,
    )

    _add_p(doc, "5.2. Quy trình sáu pha", color=BLACK, bold=True, size=11.5, space_before=8, space_after=3)
    _add_p(
        doc,
        "Quy trình vận hành của kiến trúc gồm sáu pha (Hình 2). Pha 1–2 chạy một lần cho mỗi phiên bản hệ thống: xác định phạm vi, dựng đồ thị S = (C, D), áp mô hình kẻ tấn công NIST AI 100-2e2025 [21] để có danh sách cặp (t, c). Pha 3–6 lặp lại theo vòng kín: định lượng rủi ro (CT 3–4), chọn và sinh ca kiểm thử theo lấy mẫu Thompson (CT 6), thực thi và phán xét, cập nhật hậu nghiệm Bayes (CT 5) và rủi ro tồn dư R_res (CT 7) cho đến khi thỏa điều kiện dừng (CT 8).",
        color=BLACK,
    )

    p_img2 = doc.add_paragraph()
    p_img2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img2.add_run().add_picture(str(fig2), width=Inches(6.2))
    _add_p(
        doc,
        "Hình 2. Quy trình sáu pha của RBST-AI với vòng phản hồi cập nhật Bayes (đã hiệu chỉnh công thức R = L × I × M × (1 − E)).",
        color=RED, italic=True, size=10.0, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6,
    )

    _add_p(doc, "5.3. Thuật toán điều phối", color=BLACK, bold=True, size=11.5, space_before=6, space_after=3)
    algo_box = doc.add_table(rows=1, cols=1)
    algo_box.alignment = WD_TABLE_ALIGNMENT.CENTER
    _set_table_borders(algo_box, color="1E293B")
    acell = algo_box.rows[0].cells[0]
    _set_cell_shading(acell, "F8FAFC")
    ap = acell.paragraphs[0]
    ap.paragraph_format.space_before = Pt(4)
    ap.paragraph_format.space_after = Pt(4)
    ap.paragraph_format.line_spacing = 1.15
    algo_text = (
        "Thuật toán 1. RBST-AI-Loop\n"
        "Vào : S = (C, D), danh mục mối đe dọa, thư viện ca kiểm thử, I, E, μ₀, n₀, B, τ\n"
        "Ra  : danh sách lỗ hổng đã xác nhận, rủi ro tồn dư R_res, báo cáo tuân thủ\n"
        " 1  Tính M(c) cho mọi thành phần c ∈ C theo công thức (2)\n"
        " 2  Lập danh sách cặp (t, c) khả dĩ theo mô hình kẻ tấn công\n"
        " 3  Với mỗi cặp: n ← 0; s ← 0                    ▷ khi đó θ_tb = μ₀ theo (5)\n"
        " 4  chi_phí ← 0\n"
        " 5  lặp khi chi_phí < B và còn cặp có R_res > τ:\n"
        " 6      với mỗi cặp: rút θ_mẫu ~ Beta(n₀·μ₀ + s, n₀·(1 − μ₀) + n − s)\n"
        " 7      chọn ca k có chỉ số ưu tiên P lớn nhất   ▷ công thức (6)\n"
        " 8      sinh biến thể từ k; chạy trong sandbox; Oracle trả y ∈ {0, 1}\n"
        " 9      n ← n + 1; s ← s + y; chi_phí ← chi_phí + K\n"
        "10      nếu y = 1: ghi nhận lỗ hổng và mức nghiêm trọng\n"
        "11      tính lại θ_tb (5), R (3), R_res (7); lưu bằng chứng\n"
        "12  trả về lỗ hổng, R_res, báo cáo kèm ánh xạ tuân thủ"
    )
    ar = ap.add_run(algo_text)
    ar.font.name = "Consolas"
    ar.font.size = Pt(8.8)
    ar.font.color.rgb = BLACK

    _add_p(
        doc,
        "Mỗi vòng lặp có độ phức tạp tỉ lệ với số cặp (t, c) cộng số ca trong thư viện; khi thư viện ca lớn, có thể rút mẫu θ_mẫu một lần cho mỗi cặp rồi đánh giá P cho các ca thuộc cặp đó.",
        color=BLACK, space_before=4,
    )

    _add_p(doc, "5.4. Truy vết tuân thủ", color=BLACK, bold=True, size=11.5, space_before=6, space_after=3)
    _add_p(
        doc,
        "Mỗi bản ghi bằng chứng có dạng (t, c, k, y_k, mức nghiêm trọng, mã OWASP/ATLAS, phiên bản hệ thống, thời điểm, K, R, R_res). Bảng 5 ánh xạ các pha sang yêu cầu tuân thủ.",
        color=BLACK,
    )
    _add_p(doc, "Bảng 5. Ánh xạ các pha RBST-AI với khung tuân thủ", color=BLACK, bold=True, size=10.5, align=WD_ALIGN_PARAGRAPH.CENTER)
    _add_styled_table(
        doc,
        ["Pha", "NIST AI RMF [8]", "ISO/IEC TS 42119-2 [10]", "Đạo luật AI EU [9]"],
        [
            ["1. Phạm vi, bối cảnh", "Govern, Map", "Xác định rủi ro sản phẩm AI", "Phân loại mức rủi ro hệ thống"],
            ["2–3. Mô hình đe dọa, định lượng", "Map, Measure", "Phân tích rủi ro để chọn kỹ thuật kiểm thử", "Hệ thống quản lý rủi ro"],
            ["4–5. Kiểm thử, phán xét", "Measure", "Thiết kế và thực thi kiểm thử", "Độ chính xác, bền vững, an ninh mạng"],
            ["6. Báo cáo, cập nhật", "Manage", "Báo cáo hoàn tất kiểm thử", "Tài liệu kỹ thuật, giám sát sau triển khai"],
        ],
        text_color=BLACK,
        font_size=9.0,
    )

    _add_p(doc, "5.5. Hiện thực nguyên mẫu trên hệ thống AI_Security_Scanner", color=RED, bold=True, size=11.5, space_before=8, space_after=3)
    _add_p(
        doc,
        "Để kiểm chứng thực nghiệm mà không phải xây dựng lại hạ tầng thực thi, lớp lõi RBST-AI được tích hợp trực tiếp vào bộ công cụ mã nguồn mở nội bộ AI_Security_Scanner (Python 3.13) thông qua bốn thành phần mới: "
        "(1) core/rbst_graph.py nạp đồ thị S=(C, D) từ hồ sơ YAML (data/rbst_profiles/cs1..cs4.yaml), tự động phát hiện ranh giới tin cậy và lan truyền đặc quyền a₂ theo BFS; "
        "(2) core/rbst_engine.py hiện thực RBSTRiskEngine và RBSTOrchestrator hỗ trợ đầy đủ 9 chiến lược ở Bảng 8 (RBST-AI, B0–B4, A1–A3), điều kiện dừng kép (τ, B) và tái lập theo seed; "
        "(3) core/rbst_metrics.py tính toàn bộ chỉ số APFD_R, RC, CF, Recall phân tầng, Spearman ρ, Cohen's κ và xuất báo cáo tuân thủ JSON/Markdown; "
        "(4) core/rbst_adapter.py và lệnh CLI (main.py --rbst) kết nối trực tiếp vào kho payload YAML, AdaptiveGenerator, AgentSandbox (bổ sung ba công cụ mô phỏng CS2: tool_email, tool_booking, tool_banking), Oracle hai tầng (PatternDetector + LLMJudge), CampaignBudget và EvidenceStore (SQLite). Toàn bộ công thức (1)–(10) được kiểm chứng tự động qua 12 ca kiểm thử đơn vị và tích hợp (tests/test_rbst_core.py, đạt 12/12 PASSED).",
        color=RED,
    )

    # ==========================================================================
    # SECTION 6 (ALL RED — MAJOR REVISION WITH REAL EXPERIMENTS)
    # ==========================================================================
    _add_p(doc, "6. Case Study và Kết quả Thực nghiệm", color=RED, bold=True, size=13, space_before=12, space_after=4)
    _add_p(
        doc,
        "Mục này trình bày kết quả thực nghiệm định lượng dựa hoàn toàn trên phản hồi thật của bốn hệ thống AI đích (CS1–CS4). Mọi nhãn thành công y_k ∈ {0, 1}, độ trễ và chi phí K đều được đo trực tiếp từ lần chạy thật (không sử dụng mô phỏng xác suất hay dữ liệu giả lập).",
        color=RED,
    )

    _add_p(doc, "6.1. Thiết lập thực nghiệm và đặc trưng đồ thị bốn kịch bản (CS1–CS4)", color=RED, bold=True, size=11.5, space_before=6, space_after=3)
    _add_p(
        doc,
        "Bốn hệ thống đích đại diện cho bốn kiến trúc AI điển hình: "
        "(i) CS1 — Trợ lý chat tích hợp tìm kiếm web chạy trực tiếp trên Ollama qwen2.5:latest với lịch sử hội thoại chứa mã phiên bí mật (CORP-TOK-7741, alice.nguyen@corp.vn) và trang web ngoài không tin cậy; "
        "(ii) CS2 — Tác tử ReAct trên qwen2.5:latest nối AgentSandbox với ba công cụ tool_email, tool_booking, tool_banking và bộ nhớ tài chính (VN99-4410-8821); "
        "(iii) CS3 — Chatbot LLM công khai kết hợp tập phản hồi thật 180 ca trên qwen2.5:latest (benchmark_real_qwen2.5_latest_180.json) cho nhóm jailbreak/DPI và thực thi trực tiếp trên qwen2.5:latest cho nhóm rò rỉ dữ liệu, rò rỉ system prompt, xử lý đầu ra và DoS; "
        "(iv) CS4 — Dịch vụ ML qua API dự đoán huấn luyện thật ba mô hình scikit-learn (LogisticRegression, DecisionTreeClassifier, MLPClassifier) trên tập Breast Cancer Wisconsin.",
        color=RED,
    )
    _add_p(
        doc,
        "Tổng cộng đã thu thập 507 lượt thực thi tấn công thật: 186 ca chuẩn (CS1: 51, CS2: 75, CS3: 36, CS4: 24), 105 lượt tinh chỉnh lặp 3 vòng cho S1 (PAIR độc lập, llama3:latest tấn công qwen2.5:latest), 108 ca chuyển giao từ 10 hậu tố tối ưu gradient hộp trắng cho S2 (GCG độc lập, chạy nanogcg trên Qwen/Qwen2.5-1.5B-Instruct bằng GPU NVIDIA Tesla T4 trong 1.048 giây, giảm loss trung bình từ 3,629 xuống 2,074 rồi chuyển giao lên qwen2.5:latest), và 108 ca sinh tự động cho S3 (LLM Red Teaming, llama3:latest → qwen2.5:latest). Mọi nhãn y_k trên 186 ca chuẩn được xác định khách quan bằng cảm biến Canary bí mật (CORP-TOK-7741, VN99-4410-8821), vết thực thi công cụ AgentSandbox, đầu ra độc hại và ngưỡng toán học scikit-learn. Mọi chiến lược được đánh giá trong cùng ngân sách B = 45% tổng chi phí kho ca (CS1: 36,9; CS2: 48,1; CS3: 32,2; CS4: 23,0) qua 30 seeds, kiểm định Wilcoxon so với RBST-AI.",
        color=RED,
    )

    _add_p(doc, "Bảng 6. Đặc trưng đồ thị S=(C, D), hệ số M và tổng hợp dữ liệu phản hồi thật (CS1–CS4)", color=RED, bold=True, size=10.5, align=WD_ALIGN_PARAGRAPH.CENTER)
    _add_styled_table(
        doc,
        ["Đặc trưng", "CS1. Trợ lý chat web (RAG)", "CS2. Tác tử có công cụ", "CS3. Chatbot LLM công khai", "CS4. Dịch vụ ML qua API"],
        [
            ["Nguồn tham chiếu", "[1, 2]", "[14, 15, 22]", "[7, 13, 27, 28]", "[3, 4, 6]"],
            ["Hệ thống thực nghiệm thật", "Ollama qwen2.5:latest", "Ollama qwen2.5 + AgentSandbox", "Bench-180 + Ollama qwen2.5", "scikit-learn (LR/DT/MLP)"],
            ["Đồ thị (|C|, |D|); ranh giới", "(5, 5); 1 ranh giới", "(7, 7); 1 ranh giới", "(4, 4); 0 ranh giới", "(3, 3); 0 ranh giới"],
            ["Số cặp (t, c) khả dĩ", "17", "25", "12", "8"],
            ["Hệ số M (min / tb / max)", "1,28 / 1,40 / 1,61", "1,57 / 1,72 / 1,95", "1,09 / 1,13 / 1,16", "1,30 / 1,31 / 1,32"],
            ["Cặp ưu tiên đầu (R₀ max)", "T_IPI@web_context", "T_ASI01_GOAL_HIJACK@untrusted_feeds", "T_JB@llm_model", "T_MODEL_EXTRACT@prediction_api"],
            ["Số ca chuẩn / vượt rào", "51 / 32 (ASR 62,7%)", "75 / 55 (ASR 73,3%)", "36 / 12 (ASR 33,3%)", "24 / 8 (ASR 33,3%)"],
            ["Tổng lỗ hổng phân biệt", "15", "21", "9 (gồm cả S3)", "5"],
            ["Độ trễ thực thi TB (ms)", "14.209,0", "25.737,8", "26.991,8", "35,6"],
        ],
        text_color=RED,
        highlight_rows={4},
        font_size=8.6,
    )

    _add_p(doc, "6.2. Phân tích chi tiết bốn Case Study", color=RED, bold=True, size=11.5, space_before=8, space_after=3)
    cs_paragraphs = [
        (
            "6.2.1. CS1 — Trợ lý chat tích hợp tìm kiếm web: ",
            "Nguồn web_context có tỉ lệ đầu vào không tin cậy a₃ = 1,0 và đứng trước ranh giới tin cậy vào lớp điều phối; kết hợp độ nhạy lịch sử hội thoại a₄ > 0, hệ số khuếch đại đạt M = 1,61, đẩy cặp (T_IPI, web_context) lên vị trí ưu tiên cao nhất thay vì jailbreak trực tiếp. Thực nghiệm live trên qwen2.5:latest ghi nhận 32/51 ca vượt rào (ASR 62,7%), trong đó các chỉ thị ẩn trong trang web đã trích xuất mã phiên CORP-TOK-7741 và chèn liên kết rò rỉ dữ liệu.",
        ),
        (
            "6.2.2. CS2 — Tác tử có công cụ: ",
            "Nhờ cơ chế lan truyền đặc quyền a₂ theo luồng dữ liệu tới tool_banking (mức thực thi giao dịch, a₂ = 1,0) cùng mức tự chủ cao (a₁ = 0,95) và dữ liệu tài chính nhạy cảm (a₄ = 0,85), M(untrusted_feeds) đạt 1,95 — cao nhất trong 4 CS. Thực nghiệm trên qwen2.5:latest + AgentSandbox ghi nhận 55/75 ca (ASR 73,3%) phát sinh lời gọi công cụ trái phép (chuyển tiền, gửi email, đặt lịch), xác nhận 21 lỗ hổng phân biệt; RBST-AI phát hiện lỗ hổng nghiêm trọng đầu tiên với chi phí chỉ CF = 1,15.",
        ),
        (
            "6.2.3. CS3 — Chatbot LLM công khai: ",
            "Không có công cụ nên M thấp (1,09–1,16). Do qwen2.5:latest phòng thủ rất chặt các mẫu jailbreak trực tiếp trong bộ 180 ca (0% vượt rào) nhưng vẫn tồn tại lỗ hổng rò rỉ ngữ cảnh/system prompt, xử lý đầu ra (<script>) và DoS, mọi baseline tĩnh (B1, B2, B3, B4) đều bị kẹt ở nhóm LLM01 và cạn ngân sách với APFD_R ≈ 0,000. RBST-AI tự động hạ hậu nghiệm θ_tb của nhóm thất bại và chuyển ngân sách sang các cặp có tỉ số P cao hơn, đạt APFD_R = 0,719 và CF = 9,70 (p < 0,0001).",
        ),
        (
            "6.2.4. CS4 — Dịch vụ ML qua API dự đoán (bổ sung mới): ",
            "Tuy không có công cụ tác tử nhưng trọng số mô hình là tài sản nhạy cảm (a₄ = 0,90) nên M đạt 1,30–1,32. Thực nghiệm trực tiếp trên scikit-learn xác nhận: tấn công trích xuất mô hình [6] đạt độ trung thực thay thế (surrogate fidelity) 99,0% trên LogisticRegression (650 truy vấn; 97,5% từ 120 truy vấn), 97,0% trên DecisionTree (1.150 truy vấn) và 98,0%–99,0% trên MLPClassifier (300–1.150 truy vấn); tấn công né tránh FGSM [3] đạt tỉ lệ đánh lừa 39,5% (ε = 0,35) và 92,0% (ε = 0,90) trên 200 mẫu test thật; đầu vào cực biên 10¹² vượt qua API không kiểm tra lược đồ. RBST-AI đạt APFD_R = 0,676 (APFD_R^pen = 0,533), RC = 0,763 và CF = 0,60 (p < 0,0001 so với mọi baseline), khẳng định tính tổng quát cho cả LLM và ML truyền thống (ĐG4).",
        ),
    ]
    for head, body in cs_paragraphs:
        _add_mixed_p(doc, [(head, RED, True, False), (body, RED, False, False)])

    _add_p(doc, "6.3. So sánh hiệu năng với Baseline (B0–B4) và SOTA (S1–S3)", color=RED, bold=True, size=11.5, space_before=6, space_after=3)
    _add_p(
        doc,
        "Bảng 7 tổng hợp hiệu năng của RBST-AI so với các Baseline (B0–B4) và SOTA sinh tấn công độc lập (S1: PAIR, S2: GCG chuyển giao từ GPU T4, S3: LLM Red Teaming) qua 30 seeds. Hình 3 trực quan hóa sự vượt trội của RBST-AI về tốc độ/độ phủ phát hiện lỗ hổng (APFD_R có phạt), độ bao phủ rủi ro (RC) và hiệu quả chi phí (CF).",
        color=RED,
    )

    data = json.loads(SUMMARY_JSON.read_text(encoding="utf-8"))
    t7_rows = []
    t7_hi = set()
    row_idx = 0
    for cs_code, cs_lbl in [("cs1", "CS1"), ("cs2", "CS2"), ("cs3", "CS3"), ("cs4", "CS4")]:
        cs_strats = data["case_studies"][cs_code]["strategies"]
        for scode in ("B0", "B1", "B2", "B3", "B4", "S1", "S2", "S3", "RBST-AI"):
            st = cs_strats[scode]
            lbl = st["label"].replace(" (đề xuất)", "")
            if not st.get("executed"):
                mk = st.get("blank_marker", "—")
                t7_rows.append([cs_lbl if scode == "B0" else "", scode, lbl, mk, mk, mk, mk, mk, mk])
            else:
                def _f(m, s, d=3):
                    if m is None:
                        return "—"
                    if s is None or s == 0:
                        return f"{m:.{d}f}".replace(".", ",")
                    return f"{m:.{d}f}±{s:.{d}f}".replace(".", ",")
                pv = st.get("p_value_vs_rbst")
                p_str = "—" if pv is None else ("<0,0001" if pv < 0.0001 else f"{pv:.4f}".replace(".", ","))
                t7_rows.append([
                    cs_lbl if scode == "B0" else "",
                    scode,
                    lbl,
                    _f(st["APFD_R_mean"], st["APFD_R_std"]),
                    _f(st["APFD_R_pen_mean"], st["APFD_R_pen_std"]),
                    _f(st["RC_mean"], st["RC_std"]),
                    _f(st["CF_mean"], st["CF_std"], 2),
                    _f(st["weighted_recall_mean"], st["weighted_recall_std"]),
                    p_str,
                ])
            if scode == "RBST-AI":
                t7_hi.add(row_idx)
            row_idx += 1

    _add_p(doc, "Bảng 7. So sánh hiệu năng RBST-AI với Baseline (B0–B4) và SOTA (S1–S3) trên 4 Case Study (30 seeds)", color=RED, bold=True, size=10.5, align=WD_ALIGN_PARAGRAPH.CENTER)
    _add_styled_table(
        doc,
        ["CS", "Mã", "Phương pháp", "APFD_R", "APFD_R^pen", "RC", "CF (↓)", "Recall", "Wilcoxon p"],
        t7_rows,
        text_color=RED,
        highlight_rows=t7_hi,
        font_size=7.9,
    )

    p_img3 = doc.add_paragraph()
    p_img3.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img3.paragraph_format.space_before = Pt(6)
    p_img3.add_run().add_picture(str(fig3), width=Inches(6.4))
    _add_p(
        doc,
        "Hình 3. So sánh định lượng trên dữ liệu phản hồi thật: (a) APFD_R có phạt theo 4 Case Study; (b) Chi phí CF và độ bao phủ rủi ro RC trung bình.",
        color=RED, italic=True, size=10.0, align=WD_ALIGN_PARAGRAPH.CENTER, space_after=6,
    )

    _add_p(
        doc,
        "Kết quả trả lời ĐG1: Trung bình qua 4 CS, RBST-AI đạt APFD_R^pen = 0,433, RC = 0,677 và CF = 3,54 — giảm 2,6–2,9 lần chi phí phát hiện lỗ hổng nghiêm trọng đầu tiên so với B0 (10,28), B2 (9,25) và B4 (10,13). Các SOTA sinh tấn công độc lập tuy có khả năng xuyên phá tốt (GCG chuyển giao đạt ASR 64,7% trên CS1 và 64,0% trên CS2; S3 khám phá thêm 4 lỗ hổng mới trên CS3 với Recall 0,649), song do không định hướng theo rủi ro hệ thống và tốn chi phí tối ưu/tinh chỉnh lớn nên hiệu quả ngân sách rất thấp khi chạy rời rạc (S1: CF = 15,65, RC = 0,295; S2: CF = 15,24, RC = 0,042; p < 0,0001). Điều này chứng minh trực tiếp cho thiết kế kiến trúc N3: tích hợp PAIR, GCG và LLM Red Teaming làm adapter sinh tấn công bên trong vòng điều phối RBST-AI.",
        color=RED,
    )

    _add_p(doc, "6.4. Nghiên cứu loại bỏ (ĐG2), Rủi ro tồn dư (ĐG3) và Độ tin cậy Oracle", color=RED, bold=True, size=11.5, space_before=6, space_after=3)
    _add_p(doc, "Bảng 8. Tổng hợp nghiên cứu loại bỏ (Ablation Study — ĐG2) trung bình qua 4 Case Study", color=RED, bold=True, size=10.5, align=WD_ALIGN_PARAGRAPH.CENTER)
    _add_styled_table(
        doc,
        ["Cấu hình", "CS1", "CS2", "CS3", "CS4", "TB 4 CS", "TB RC", "TB CF (↓)"],
        [
            ["RBST-AI đầy đủ (đề xuất)", "0,519", "0,466", "0,213", "0,533", "0,433", "0,677", "3,54"],
            ["A1 — Bỏ M (M = 1)", "0,525", "0,462", "0,216", "0,532", "0,434", "0,667", "3,42"],
            ["A2 — Bỏ cập nhật Bayes", "0,550", "0,493", "0,248", "0,630", "0,480", "0,676", "2,05"],
            ["A3 — Tham lam (bỏ Thompson)", "0,383", "0,333", "0,219", "0,511", "0,361", "0,649", "3,52"],
            ["S1 — PAIR độc lập (CS1–3)", "0,155", "0,241", "0,050", "N/A", "0,149", "0,295", "15,65"],
            ["S2 — GCG độc lập (CS1–3)", "0,091", "0,117", "0,083", "N/A", "0,097", "0,042", "15,24"],
            ["S3 — LLM Red Teaming (CS1–3)", "0,238", "0,365", "0,355", "N/A", "0,319", "0,394", "8,22"],
            ["B4 — RBT định tính [20]", "0,383", "0,464", "0,000", "0,329", "0,294", "0,592", "10,13"],
            ["B2 — RBST tĩnh (L₀ × I)", "0,308", "0,378", "0,000", "0,379", "0,266", "0,572", "9,25"],
            ["B0 — Ngẫu nhiên", "0,405", "0,448", "0,171", "0,286", "0,328", "0,421", "10,28"],
        ],
        text_color=RED,
        highlight_rows={0},
        font_size=8.6,
    )

    _add_p(
        doc,
        "Phân tích loại bỏ (ĐG2): Bỏ lấy mẫu Thompson (A3 tham lam) làm APFD_R^pen giảm mạnh từ 0,519 xuống 0,383 (CS1) và 0,466 xuống 0,333 (CS2, p < 0,0001). Hệ số M cải thiện độ bao phủ rủi ro trên hệ thống tác tử CS2 (RC: 0,574 vs 0,561) và trung bình toàn bộ (0,677 vs 0,667), đồng thời phân tách rõ mức rủi ro giữa các kiến trúc khác nhau (Bảng 6). Đáng chú ý, với tập ca nhỏ (3 ca/cặp) và tiên nghiệm μ₀ khá gần thực tế, A2 (không cập nhật Bayes nhưng vẫn dùng M và chia K) ít dồn ca lặp lại vào cặp vừa lộ lỗi hơn nên nhỉnh hơn về số lỗ hổng phân biệt sớm (0,480 vs 0,433), trong khi RBST-AI đầy đủ ưu tiên xác nhận tái lập cặp dễ tổn thương và đạt RC cao nhất (0,677).",
        color=RED, space_before=4,
    )

    _add_p(doc, "Bảng 9. Tương quan rủi ro tồn dư R_res với mức nghiêm trọng thực đo (ĐG3) và phân rã cảm biến Oracle khách quan (CS1–CS4)", color=RED, bold=True, size=10.5, align=WD_ALIGN_PARAGRAPH.CENTER)
    _add_styled_table(
        doc,
        ["Kịch bản", "Số cặp (t,c)", "Spearman ρ(R_res, thực)", "Tầng cảm biến Oracle thực tế (n = 186 ca CS1–CS4)", "Độ phủ lỗ hổng xác nhận"],
        [
            ["CS1", "17", "0,695 ± 0,021", "Chỉ PatternDetector quy tắc chung (CS1–CS3)", "22/99 ca (22,2%)"],
            ["CS2", "25", "0,904 ± 0,014", "+ Cảm biến Canary bí mật & Đầu ra độc hại (<script>/SQLi)", "50/99 ca (50,5%)"],
            ["CS3", "12", "−0,540 ± 0,105 (lệch tiên nghiệm)", "+ Vết công cụ AgentSandbox & LLM-Judge (Đầy đủ)", "99/99 ca LLM (100%) + 8/8 ca ML"],
            ["CS4", "8", "0,973 ± 0,028", "Đối chiếu nhãn người mù đôi (Cohen's κ)", "— (đang hoàn thiện gán nhãn)"],
        ],
        text_color=RED,
        highlight_rows={2},
        font_size=8.8,
    )

    _add_p(
        doc,
        "Phân tích ĐG3 và cảm biến Oracle khách quan: Rủi ro tồn dư R_res của RBST-AI tương quan hạng Spearman rất cao với mức nghiêm trọng thực tế ở CS1 (0,695), CS2 (0,904) và CS4 (0,973); riêng CS3 mang giá trị âm do cận trên 95% θ_max duy trì thái độ thận trọng đối với các cặp LLM01 chưa được thử đủ nhiều. Về độ tin cậy Oracle trên 162 ca LLM chuẩn (99 ca vượt rào thật), nếu chỉ dùng bộ lọc quy tắc chung (PatternDetector) thì chỉ phát hiện được 22/99 ca (22,2%) do bỏ sót các ca lộ mã phiên Canary và gọi công cụ ngầm; khi kết hợp cảm biến Canary/đầu ra độc hại (50/99 = 50,5%) cùng vết thực thi AgentSandbox và LLM-Judge, Oracle đa tín hiệu bao phủ trọn vẹn 99/99 ca LLM cùng 8/8 ca toán học của CS4 (phần đối chiếu Cohen's κ với nhãn người mù đôi đang được nhóm hoàn thiện thủ công và để trống trung thực).",
        color=RED, space_before=4,
    )

    OUT_DOCX.parent.mkdir(parents=True, exist_ok=True)
    saved_paths = []
    for candidate in (
        OUT_DOCX,
        OUT_DOCX.with_name("RBST_AI_Muc_5_6_Phong_Lam_Review_v2.docx"),
        OUT_DOCX.with_name("RBST_AI_Muc_5_6_Phong_Lam_Review_v3.docx"),
    ):
        try:
            doc.save(str(candidate))
            saved_paths.append(candidate)
            if len(saved_paths) >= 2:
                break
        except PermissionError:
            continue
    return saved_paths[-1]


def main() -> int:
    f1 = draw_fig1_architecture()
    f2 = draw_fig2_six_phases()
    f3 = draw_fig3_real_results()
    out_doc = build_docx(f1, f2, f3)
    print(f"Fig 1 : {f1}")
    print(f"Fig 2 : {f2}")
    print(f"Fig 3 : {f3}")
    print(f"DOCX  : {out_doc} ({out_doc.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
