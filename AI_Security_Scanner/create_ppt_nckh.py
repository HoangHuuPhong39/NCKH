# -*- coding: utf-8 -*-
"""
PowerPoint trình bày đề tài NCKH: AI Security Scanner
Học viện Kỹ thuật Mật mã — dựa trên BaoCao_NCKH.docx
"""
from __future__ import annotations

import os
from math import cos, sin, pi

from PIL import Image, ImageDraw, ImageFont
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LEGEND_POSITION, XL_LABEL_POSITION
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import nsmap
from pptx.util import Inches, Pt, Emu
from lxml import etree

# ── Paths ──────────────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(BASE, "ppt_assets")
OUT = os.path.join(BASE, "PP_TrinhBay_AI_Security_Scanner.pptx")
os.makedirs(ASSETS, exist_ok=True)

# ── Palette (HVKTMM-inspired: deep navy + crimson + gold) ───────────────────
NAVY = RGBColor(0x0B, 0x1F, 0x3A)
NAVY_MID = RGBColor(0x14, 0x36, 0x5C)
CRIMSON = RGBColor(0xB8, 0x22, 0x2F)
GOLD = RGBColor(0xC9, 0xA2, 0x27)
TEAL = RGBColor(0x1A, 0x7A, 0x7A)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
OFF_WHITE = RGBColor(0xF5, 0xF7, 0xFA)
SLATE = RGBColor(0x2C, 0x3E, 0x50)
MUTED = RGBColor(0x5A, 0x6A, 0x7A)
LIGHT_LINE = RGBColor(0xD0, 0xD8, 0xE0)
GREEN = RGBColor(0x1B, 0x8A, 0x5A)
ORANGE = RGBColor(0xD4, 0x7A, 0x1A)

W = Inches(13.333)
H = Inches(7.5)


# ── Logo generation ─────────────────────────────────────────────────────────
def _font(size: int):
    for name in (
        "C:/Windows/Fonts/arialbd.ttf",
        "C:/Windows/Fonts/segoeuib.ttf",
        "C:/Windows/Fonts/arial.ttf",
    ):
        if os.path.exists(name):
            return ImageFont.truetype(name, size)
    return ImageFont.load_default()


def create_logos():
    """Create distinctive AI Security Scanner logos used on every slide."""
    # Main circular badge
    size = 512
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx = cy = size // 2

    # Outer ring (navy)
    d.ellipse([16, 16, size - 16, size - 16], fill=(11, 31, 58, 255))
    # Gold ring
    d.ellipse([40, 40, size - 40, size - 40], fill=(201, 162, 39, 255))
    # Inner navy
    d.ellipse([56, 56, size - 56, size - 56], fill=(11, 31, 58, 255))

    # Shield
    shield = [
        (cx, 110),
        (cx + 130, 150),
        (cx + 130, 280),
        (cx, 400),
        (cx - 130, 280),
        (cx - 130, 150),
    ]
    d.polygon(shield, fill=(184, 34, 47, 255))
    # Inner shield highlight
    shield2 = [
        (cx, 140),
        (cx + 95, 170),
        (cx + 95, 265),
        (cx, 360),
        (cx - 95, 265),
        (cx - 95, 170),
    ]
    d.polygon(shield2, fill=(20, 54, 92, 255))

    # AI letter mark
    f = _font(110)
    d.text((cx, 230), "AI", fill=(255, 255, 255, 255), font=f, anchor="mm")

    # Circuit nodes around
    for angle in range(0, 360, 45):
        rad = angle * pi / 180
        x = cx + int(200 * cos(rad))
        y = cy + int(200 * sin(rad))
        d.ellipse([x - 8, y - 8, x + 8, y + 8], fill=(201, 162, 39, 255))

    path = os.path.join(ASSETS, "logo_main.png")
    img.save(path)

    # Compact header mark (wide)
    mark = Image.new("RGBA", (220, 64), (0, 0, 0, 0))
    md = ImageDraw.Draw(mark)
    badge = img.resize((56, 56), Image.Resampling.LANCZOS)
    mark.paste(badge, (4, 4), badge)
    mf = _font(22)
    md.text((70, 18), "AI SECURITY", fill=(11, 31, 58, 255), font=mf)
    mf2 = _font(14)
    md.text((70, 40), "SCANNER", fill=(184, 34, 47, 255), font=mf2)
    mark_path = os.path.join(ASSETS, "logo_mark.png")
    mark.save(mark_path)

    # White version for dark slides
    mark_w = Image.new("RGBA", (220, 64), (0, 0, 0, 0))
    mwd = ImageDraw.Draw(mark_w)
    # remake badge with white text — reuse resized
    mark_w.paste(badge, (4, 4), badge)
    mwd.text((70, 18), "AI SECURITY", fill=(255, 255, 255, 255), font=mf)
    mwd.text((70, 40), "SCANNER", fill=(201, 162, 39, 255), font=mf2)
    mark_w_path = os.path.join(ASSETS, "logo_mark_white.png")
    mark_w.save(mark_w_path)

    # Academy seal-style badge
    seal = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    sd = ImageDraw.Draw(seal)
    sd.ellipse([20, 20, size - 20, size - 20], fill=(11, 31, 58, 255))
    sd.ellipse([40, 40, size - 40, size - 40], outline=(201, 162, 39, 255), width=8)
    sd.ellipse([70, 70, size - 70, size - 70], outline=(184, 34, 47, 255), width=4)
    sf = _font(48)
    sd.text((cx, cy - 40), "HVKTMM", fill=(201, 162, 39, 255), font=sf, anchor="mm")
    sf2 = _font(22)
    sd.text((cx, cy + 30), "KY THUAT MAT MA", fill=(255, 255, 255, 255), font=sf2, anchor="mm")
    sd.text((cx, cy + 70), "ACADEMY", fill=(200, 210, 220, 255), font=_font(18), anchor="mm")
    seal_path = os.path.join(ASSETS, "logo_hvktmm.png")
    seal.save(seal_path)

    # Demo mock screenshots
    _make_dashboard_mock()
    _make_cli_mock()
    _make_rag_mock()

    return path, mark_path, mark_w_path, seal_path


def _make_dashboard_mock():
    w, h = 1100, 620
    img = Image.new("RGB", (w, h), (15, 23, 42))
    d = ImageDraw.Draw(img)
    # top bar
    d.rectangle([0, 0, w, 48], fill=(11, 31, 58))
    d.text((20, 14), "AI Security Scanner  |  Dashboard", fill=(201, 162, 39), font=_font(18))
    d.text((920, 14), "Dark Mode", fill=(160, 180, 200), font=_font(14))
    # KPI cards
    cards = [
        (30, 70, "Findings", "24", (184, 34, 47)),
        (300, 70, "Critical", "6", (184, 34, 47)),
        (570, 70, "High", "9", (212, 122, 26)),
        (840, 70, "Score TB", "6.8", (26, 122, 122)),
    ]
    for x, y, label, val, col in cards:
        d.rounded_rectangle([x, y, x + 240, y + 100], radius=10, fill=(30, 41, 59))
        d.text((x + 20, y + 18), label, fill=(160, 180, 200), font=_font(14))
        d.text((x + 20, y + 45), val, fill=col, font=_font(36))
    # chart area
    d.rounded_rectangle([30, 200, 520, 580], radius=10, fill=(30, 41, 59))
    d.text((50, 220), "Severity Distribution", fill=(255, 255, 255), font=_font(16))
    # fake donut segments as bars
    segs = [("Critical", 6, (184, 34, 47)), ("High", 9, (212, 122, 26)),
            ("Medium", 5, (201, 162, 39)), ("Low", 4, (26, 122, 122))]
    bx = 80
    for name, n, col in segs:
        bh = n * 28
        d.rectangle([bx, 520 - bh, bx + 70, 520], fill=col)
        d.text((bx, 530), name[:4], fill=(180, 190, 200), font=_font(12))
        bx += 100
    # findings table
    d.rounded_rectangle([550, 200, 1070, 580], radius=10, fill=(30, 41, 59))
    d.text((570, 220), "Live Findings (SSE)", fill=(255, 255, 255), font=_font(16))
    rows = [
        ("jailbreak", "CRITICAL", "9.6"),
        ("prompt_injection", "HIGH", "8.5"),
        ("output_handling", "HIGH", "7.8"),
        ("rag_security", "HIGH", "8.0"),
        ("prompt_leak", "MEDIUM", "6.2"),
    ]
    yy = 270
    for mod, sev, sc in rows:
        d.text((570, yy), mod, fill=(200, 210, 220), font=_font(13))
        col = (184, 34, 47) if sev == "CRITICAL" else ((212, 122, 26) if sev == "HIGH" else (201, 162, 39))
        d.text((820, yy), sev, fill=col, font=_font(13))
        d.text((980, yy), sc, fill=(255, 255, 255), font=_font(13))
        yy += 45
    img.save(os.path.join(ASSETS, "mock_dashboard.png"))


def _make_cli_mock():
    w, h = 900, 520
    img = Image.new("RGB", (w, h), (12, 14, 18))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 28], fill=(40, 44, 52))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([12 + i * 18, 8, 22 + i * 18, 18], fill=c)
    d.text((80, 6), "ai-scanner — Rich Console", fill=(180, 180, 180), font=_font(12))
    lines = [
        ("$ python main.py", (201, 162, 39)),
        ("AI Security Scanner v1.0  |  HVKTMM NCKH 2026", (100, 180, 255)),
        (">>> show modules", (0, 255, 140)),
        ("  [1] prompt_injection   OWASP LLM01   HIGH", (200, 200, 200)),
        ("  [2] jailbreak          OWASP LLM01   CRITICAL", (200, 200, 200)),
        ("  [3] rag_security       OWASP LLM08   HIGH", (200, 200, 200)),
        (">>> use jailbreak", (0, 255, 140)),
        (">>> set target http://localhost:11434  model llama3:8b", (0, 255, 140)),
        (">>> run", (0, 255, 140)),
        ("[*] Dispatching 6 payloads ...", (180, 180, 100)),
        ("[+] JB-02 DAN  |  exploited=true  |  score=9.6 CRITICAL", (255, 80, 80)),
        ("[*] Tier-2 LLM-as-Judge: confidence=0.95", (100, 200, 255)),
        ("[=] Scan complete  |  Findings: 4  |  Report: reports/", (0, 220, 160)),
    ]
    y = 50
    for text, col in lines:
        d.text((24, y), text, fill=col, font=_font(14))
        y += 32
    img.save(os.path.join(ASSETS, "mock_cli.png"))


def _make_rag_mock():
    w, h = 1000, 520
    img = Image.new("RGB", (w, h), (245, 247, 250))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 50], fill=(11, 31, 58))
    d.text((24, 14), "DEMO: Indirect Prompt Injection on RAG Pipeline", fill=(255, 255, 255), font=_font(18))
    boxes = [
        (40, 90, 280, 200, "1. Document Store", "PDF / Web / KB\n+ poisoned chunk", (184, 34, 47)),
        (360, 90, 600, 200, "2. Retriever", "Vector search\nembeds payload", (20, 54, 92)),
        (680, 90, 920, 200, "3. LLM Answer", "Follows injected\ninstruction", (26, 122, 122)),
    ]
    for x1, y1, x2, y2, title, body, col in boxes:
        d.rounded_rectangle([x1, y1, x2, y2], radius=12, fill=col)
        d.text((x1 + 16, y1 + 20), title, fill=(255, 255, 255), font=_font(16))
        d.text((x1 + 16, y1 + 55), body, fill=(230, 235, 240), font=_font(14))
    # arrows
    for ax in (290, 610):
        d.polygon([(ax, 140), (ax + 50, 155), (ax, 170)], fill=(201, 162, 39))
    d.rounded_rectangle([40, 260, 960, 480], radius=12, fill=(255, 255, 255), outline=(208, 216, 224), width=2)
    d.text((60, 280), "Kịch bản kiểm thử", fill=(11, 31, 58), font=_font(18))
    steps = [
        "• Chèn payload độc hại vào tài liệu tri thức nội bộ (Indirect Injection)",
        "• Người dùng hỏi bình thường → Retriever kéo chunk nhiễm độc vào context",
        "• LLM thực thi chỉ dẫn ẩn → lộ dữ liệu / hành vi ngoài ý muốn",
        "• Module rag_security phát hiện → Risk Score HIGH (8.0) + remediation OWASP LLM08",
    ]
    yy = 320
    for s in steps:
        d.text((60, yy), s, fill=(44, 62, 80), font=_font(15))
        yy += 36
    img.save(os.path.join(ASSETS, "mock_rag.png"))


# ── Slide helpers ───────────────────────────────────────────────────────────
def solid(shape, rgb):
    shape.fill.solid()
    shape.fill.fore_color.rgb = rgb
    shape.line.fill.background()


def add_text(slide, left, top, width, height, text, *, size=18, bold=False,
             color=SLATE, align=PP_ALIGN.LEFT, font="Calibri", anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    try:
        tf._txBody.bodyPr.set("anchor", "t" if anchor == MSO_ANCHOR.TOP else "ctr")
    except Exception:
        pass
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(size)
    p.font.bold = bold
    p.font.color.rgb = color
    p.font.name = font
    p.alignment = align
    return box


def add_bullets(slide, left, top, width, height, items, *, size=16, color=SLATE, spacing=8):
    box = slide.shapes.add_textbox(left, top, width, height)
    tf = box.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = "•  " + item
        p.font.size = Pt(size)
        p.font.color.rgb = color
        p.font.name = "Calibri"
        p.space_after = Pt(spacing)
        p.level = 0
    return box


def slide_chrome(slide, title: str, page: int, total: int, logo_mark: str, dark=False):
    """Header bar + footer with logo on every content slide."""
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, H)
    solid(bg, OFF_WHITE if not dark else NAVY)

    # left accent stripe
    accent = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.12), H)
    solid(accent, CRIMSON)

    # header
    header = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, Inches(0.95))
    solid(header, NAVY if not dark else NAVY_MID)

    gold_line = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, Inches(0.95), W, Inches(0.05)
    )
    solid(gold_line, GOLD)

    if os.path.exists(logo_mark):
        slide.shapes.add_picture(logo_mark, Inches(0.25), Inches(0.18), height=Inches(0.6))

    add_text(
        slide, Inches(2.6), Inches(0.22), Inches(9.5), Inches(0.55),
        title, size=24, bold=True, color=WHITE, font="Calibri"
    )

    # footer
    footer = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, H - Inches(0.38), W, Inches(0.38))
    solid(footer, NAVY if not dark else NAVY_MID)
    add_text(
        slide, Inches(0.35), H - Inches(0.34), Inches(9), Inches(0.3),
        "Học viện Kỹ thuật Mật mã  ·  NCKH 2026  ·  AI Security Scanner",
        size=11, color=GOLD, font="Calibri"
    )
    add_text(
        slide, Inches(11.5), H - Inches(0.34), Inches(1.5), Inches(0.3),
        f"{page}/{total}", size=11, color=WHITE, align=PP_ALIGN.RIGHT, font="Calibri"
    )


def card(slide, left, top, width, height, fill=WHITE, border=None):
    sh = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    sh.fill.solid()
    sh.fill.fore_color.rgb = fill
    if border:
        sh.line.color.rgb = border
        sh.line.width = Pt(1.25)
    else:
        sh.line.color.rgb = LIGHT_LINE
        sh.line.width = Pt(1)
    try:
        sh.adjustments[0] = 0.08
    except Exception:
        pass
    return sh


def section_pill(slide, left, top, width, text, fill=CRIMSON):
    sh = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, Inches(0.38))
    solid(sh, fill)
    try:
        sh.adjustments[0] = 0.5
    except Exception:
        pass
    add_text(slide, left, top + Inches(0.04), width, Inches(0.32), text,
             size=12, bold=True, color=WHITE, align=PP_ALIGN.CENTER)


# ── Build presentation ─────────────────────────────────────────────────────
def build():
    logo_main, logo_mark, logo_mark_w, logo_seal = create_logos()
    mock_dash = os.path.join(ASSETS, "mock_dashboard.png")
    mock_cli = os.path.join(ASSETS, "mock_cli.png")
    mock_rag = os.path.join(ASSETS, "mock_rag.png")

    prs = Presentation()
    prs.slide_width = W
    prs.slide_height = H
    blank = prs.slide_layouts[6]
    TOTAL = 18

    # ========== 1. TITLE ==========
    s = prs.slides.add_slide(blank)
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, H)
    solid(bg, NAVY)
    # decorative panels
    left_panel = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.35), H)
    solid(left_panel, CRIMSON)
    top_gold = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, Inches(0.08))
    solid(top_gold, GOLD)
    bot_gold = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, H - Inches(0.08), W, Inches(0.08))
    solid(bot_gold, GOLD)

    s.shapes.add_picture(logo_seal, Inches(0.7), Inches(0.55), height=Inches(1.35))
    s.shapes.add_picture(logo_main, Inches(11.3), Inches(0.55), height=Inches(1.35))

    add_text(s, Inches(2.3), Inches(0.55), Inches(8.5), Inches(0.4),
             "BAN CƠ YẾU CHÍNH PHỦ", size=14, color=GOLD, align=PP_ALIGN.CENTER, bold=True)
    add_text(s, Inches(2.3), Inches(0.9), Inches(8.5), Inches(0.45),
             "HỌC VIỆN KỸ THUẬT MẬT MÃ", size=22, color=WHITE, align=PP_ALIGN.CENTER, bold=True)
    add_text(s, Inches(2.3), Inches(1.35), Inches(8.5), Inches(0.35),
             "Viện Nghiên cứu và Đào tạo Công nghệ Tiên tiến  ·  Bộ môn Kỹ thuật An toàn Mạng",
             size=12, color=RGBColor(0xA0, 0xB4, 0xC8), align=PP_ALIGN.CENTER)

    line = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(4.5), Inches(1.85), Inches(4.3), Inches(0.04))
    solid(line, GOLD)

    add_text(s, Inches(0.8), Inches(2.2), Inches(11.7), Inches(0.4),
             "BÁO CÁO NGHIÊN CỨU KHOA HỌC", size=16, color=GOLD, align=PP_ALIGN.CENTER, bold=True)
    add_text(s, Inches(0.8), Inches(2.7), Inches(11.7), Inches(1.4),
             "Nghiên cứu và xây dựng bộ công cụ kiểm thử an toàn\n"
             "cho hệ thống Trí tuệ Nhân tạo\n(AI Security Scanner)",
             size=28, color=WHITE, align=PP_ALIGN.CENTER, bold=True)
    add_text(s, Inches(1.5), Inches(4.3), Inches(10.3), Inches(0.55),
             "Dựa trên OWASP Top 10 for LLM Applications 2025  ·  MITRE ATLAS  ·  NIST AI RMF 1.0",
             size=14, color=RGBColor(0xC0, 0xD0, 0xE0), align=PP_ALIGN.CENTER)

    # info bar
    info = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.5), Inches(5.2), Inches(10.3), Inches(1.5))
    info.fill.solid()
    info.fill.fore_color.rgb = NAVY_MID
    info.line.color.rgb = GOLD
    info.line.width = Pt(1.5)
    add_text(s, Inches(1.8), Inches(5.4), Inches(4.5), Inches(1.1),
             "Sinh viên thực hiện:\nNhóm tác giả AI Security Scanner\nChuyên ngành: An toàn Thông tin",
             size=13, color=WHITE)
    add_text(s, Inches(7.0), Inches(5.4), Inches(4.5), Inches(1.1),
             "Giảng viên hướng dẫn:\nHội đồng Khoa học chuyên ngành\nHà Nội — 2026",
             size=13, color=WHITE)

    # ========== 2. MỤC LỤC ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "Nội dung trình bày", 2, TOTAL, logo_mark)
    toc = [
        ("01", "Bối cảnh & Mục tiêu nghiên cứu", CRIMSON),
        ("02", "Tiêu chuẩn quốc tế (OWASP · MITRE · NIST)", TEAL),
        ("03", "Taxonomy 12 module & Mô hình CVSS-like", NAVY),
        ("04", "Phương pháp Two-Tier Hybrid Detection", CRIMSON),
        ("05", "Kiến trúc hệ thống & Web Dashboard", TEAL),
        ("06", "Tích hợp Garak & PyRIT", NAVY),
        ("07", "Demo hệ thống & Kiểm thử AI định lượng", CRIMSON),
        ("08", "Kết luận & Hướng phát triển", TEAL),
    ]
    for i, (num, label, col) in enumerate(toc):
        col_i = i % 2
        row = i // 2
        left = Inches(0.55 + col_i * 6.3)
        top = Inches(1.35 + row * 1.35)
        c = card(s, left, top, Inches(6.0), Inches(1.15))
        badge = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left + Inches(0.2), top + Inches(0.28), Inches(0.85), Inches(0.55))
        solid(badge, col)
        add_text(s, left + Inches(0.2), top + Inches(0.35), Inches(0.85), Inches(0.4),
                 num, size=18, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        add_text(s, left + Inches(1.25), top + Inches(0.35), Inches(4.5), Inches(0.5),
                 label, size=16, bold=True, color=SLATE)

    # ========== 3. BỐI CẢNH ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "1. Bối cảnh & Tính cấp thiết", 3, TOTAL, logo_mark)
    section_pill(s, Inches(0.5), Inches(1.2), Inches(2.8), "VẤN ĐỀ")
    add_bullets(s, Inches(0.5), Inches(1.7), Inches(6.0), Inches(3.2), [
        "LLM & AI Agents bùng nổ trong mọi lĩnh vực",
        "Không tách biệt kênh điều khiển / kênh dữ liệu",
        "Rủi ro mới: Prompt Injection, Jailbreak, RAG poisoning",
        "WAF truyền thống gần như vô hiệu với ngôn ngữ tự nhiên",
        "Tại VN: kiểm thử thủ công hoặc bỏ ngỏ trước Production",
    ], size=15, spacing=10)

    c = card(s, Inches(7.0), Inches(1.2), Inches(5.7), Inches(5.4), fill=NAVY)
    add_text(s, Inches(7.3), Inches(1.45), Inches(5.2), Inches(0.4),
             "Không gian tấn công AI", size=18, bold=True, color=GOLD)
    threats = [
        ("Prompt Injection", "CRITICAL"),
        ("Jailbreak / Safety Bypass", "CRITICAL"),
        ("Sensitive Data Leak (PII)", "HIGH"),
        ("Excessive Agency", "CRITICAL"),
        ("RAG / Embedding Poison", "HIGH"),
        ("Improper Output (XSS/SQLi)", "HIGH"),
    ]
    yy = 2.05
    for name, sev in threats:
        add_text(s, Inches(7.4), Inches(yy), Inches(3.6), Inches(0.35), name, size=14, color=WHITE)
        col = CRIMSON if sev == "CRITICAL" else ORANGE
        pill = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(11.0), Inches(yy), Inches(1.4), Inches(0.32))
        solid(pill, col)
        add_text(s, Inches(11.0), Inches(yy + 0.02), Inches(1.4), Inches(0.28),
                 sev, size=10, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        yy += 0.7

    # ========== 4. MỤC TIÊU ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "1. Mục tiêu nghiên cứu (6 nội dung)", 4, TOTAL, logo_mark)
    goals = [
        ("NC1", "Lý thuyết & chuẩn quốc tế", "OWASP 2025, MITRE ATLAS, NIST AI RMF"),
        ("NC2", "Taxonomy & CVSS-like", "12 module + công thức rủi ro 0–10"),
        ("NC3", "Two-Tier Detection", "PatternDetector + LLM-as-Judge"),
        ("NC4", "Hiện thực hệ thống", "12 module, Web SSE, OpenAPI 3.0"),
        ("NC5", "Tích hợp OSS", "NVIDIA Garak & Microsoft PyRIT"),
        ("NC6", "Thực nghiệm định lượng", "43 cases × 4 mô hình LLM"),
    ]
    for i, (code, title, desc) in enumerate(goals):
        col_i = i % 3
        row = i // 3
        left = Inches(0.45 + col_i * 4.25)
        top = Inches(1.3 + row * 2.7)
        c = card(s, left, top, Inches(4.05), Inches(2.4))
        badge = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, Inches(4.05), Inches(0.55))
        solid(badge, CRIMSON if row == 0 else TEAL)
        add_text(s, left, top + Inches(0.1), Inches(4.05), Inches(0.4),
                 code + "  ·  " + title, size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        add_text(s, left + Inches(0.25), top + Inches(0.9), Inches(3.55), Inches(1.2),
                 desc, size=15, color=SLATE, align=PP_ALIGN.CENTER)

    # ========== 5. TIÊU CHUẨN ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "2. Tiêu chuẩn quốc tế áp dụng", 5, TOTAL, logo_mark)
    standards = [
        ("OWASP LLM Top 10\n2025", "10 hạng mục lỗ hổng\nứng dụng LLM &\nAgentic AI", CRIMSON),
        ("MITRE ATLAS", "Ma trận chiến thuật\ntấn công AI\n(Red Team view)", NAVY),
        ("NIST AI RMF 1.0", "GOVERN · MAP\nMEASURE · MANAGE", TEAL),
        ("ISO/IEC 42001\n& EU AI Act", "Quản trị AIMS &\nphân cấp rủi ro pháp lý", GOLD),
    ]
    for i, (title, body, col) in enumerate(standards):
        left = Inches(0.4 + i * 3.2)
        top = Inches(1.4)
        head = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, Inches(3.0), Inches(1.5))
        solid(head, col if col != GOLD else NAVY)
        add_text(s, left + Inches(0.1), top + Inches(0.35), Inches(2.8), Inches(1.0),
                 title, size=15, bold=True, color=WHITE if col != GOLD else GOLD, align=PP_ALIGN.CENTER)
        body_c = card(s, left, top + Inches(1.6), Inches(3.0), Inches(3.2))
        add_text(s, left + Inches(0.2), top + Inches(2.1), Inches(2.6), Inches(2.4),
                 body, size=14, color=SLATE, align=PP_ALIGN.CENTER)

    # ========== 6. TAXONOMY ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "3. Taxonomy — 12 module kiểm thử", 6, TOTAL, logo_mark)
    modules = [
        ("prompt_injection", "LLM01", "HIGH", 8.5),
        ("jailbreak", "LLM01", "CRITICAL", 9.5),
        ("multiturn_jailbreak", "LLM01", "CRITICAL", 9.5),
        ("prompt_leak", "LLM07", "MEDIUM", 6.5),
        ("sensitive_disclosure", "LLM02", "HIGH", 8.0),
        ("output_handling", "LLM05", "HIGH", 7.5),
        ("excessive_agency", "LLM06", "CRITICAL", 7.8),
        ("rag_security", "LLM08", "HIGH", 8.0),
        ("misinformation", "LLM09", "MEDIUM", 6.0),
        ("model_dos", "LLM10", "MEDIUM", 7.0),
        ("model_fingerprint", "Recon", "INFO", 3.0),
        ("port_scan", "Recon", "INFO", 4.0),
    ]
    # table header
    headers = ["#", "Module", "OWASP", "Severity", "Base"]
    widths = [0.5, 3.2, 1.4, 1.5, 0.9]
    left0 = Inches(0.5)
    top0 = Inches(1.2)
    x = left0
    for htxt, ww in zip(headers, widths):
        cell = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, top0, Inches(ww), Inches(0.38))
        solid(cell, NAVY)
        add_text(s, x, top0 + Inches(0.05), Inches(ww), Inches(0.3),
                 htxt, size=12, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        x += Inches(ww)
    for i, (mod, owasp, sev, base) in enumerate(modules):
        y = top0 + Inches(0.38 + i * 0.42)
        bgc = WHITE if i % 2 == 0 else RGBColor(0xE8, 0xEE, 0xF4)
        x = left0
        vals = [str(i + 1), mod, owasp, sev, f"{base}"]
        for v, ww in zip(vals, widths):
            cell = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, Inches(ww), Inches(0.42))
            solid(cell, bgc)
            cell.line.color.rgb = LIGHT_LINE
            cell.line.width = Pt(0.5)
            clr = CRIMSON if v == "CRITICAL" else (ORANGE if v == "HIGH" else SLATE)
            add_text(s, x, y + Inches(0.05), Inches(ww), Inches(0.32),
                     v, size=11, color=clr, align=PP_ALIGN.CENTER, bold=(v in ("CRITICAL", "HIGH")))
            x += Inches(ww)

    # right note
    c = card(s, Inches(8.3), Inches(1.2), Inches(4.5), Inches(5.5), fill=NAVY)
    add_text(s, Inches(8.55), Inches(1.45), Inches(4.0), Inches(0.4),
             "Ánh xạ đa khung chuẩn", size=16, bold=True, color=GOLD)
    add_bullets(s, Inches(8.55), Inches(2.0), Inches(4.0), Inches(4.3), [
        "OWASP LLM Top 10 2025",
        "MITRE ATLAS (AML.Txxxx)",
        "CWE (điểm yếu phần mềm)",
        "CAPEC (mẫu tấn công)",
        "10 Exploits + 2 Auxiliary",
        "Payload song ngữ Anh–Việt",
        "Mỗi finding gắn remediation",
    ], size=14, color=WHITE, spacing=12)

    # ========== 7. CVSS + chart ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "3. Mô hình định lượng rủi ro CVSS-like", 7, TOTAL, logo_mark)
    add_text(s, Inches(0.5), Inches(1.2), Inches(7), Inches(0.4),
             "Score = min(10, max(0, S_base × M_exp + B_brevity))",
             size=18, bold=True, color=NAVY)
    add_bullets(s, Inches(0.5), Inches(1.75), Inches(6.5), Inches(2.5), [
        "S_base: điểm cơ sở theo Taxonomy (3.0 – 9.5)",
        "M_exp: hệ số bằng chứng khai thác (0.5 – 1.0)",
        "B_brevity: thưởng payload/phản hồi ngắn (+0.5)",
        "Phân cấp: CRITICAL ≥9 · HIGH ≥7 · MEDIUM ≥4 · LOW · INFO",
    ], size=15, spacing=8)

    # severity distribution chart (LLaMA example from report board)
    chart_data = CategoryChartData()
    chart_data.categories = ["CRITICAL", "HIGH", "MEDIUM", "LOW/INFO"]
    chart_data.add_series("Số findings (ví dụ LLaMA-3)", (6, 9, 5, 4))
    chart = s.shapes.add_chart(
        XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(7.2), Inches(1.3), Inches(5.5), Inches(3.5), chart_data
    ).chart
    chart.has_legend = False
    plot = chart.plots[0]
    plot.has_data_labels = True
    plot.data_labels.font.size = Pt(11)
    plot.data_labels.font.bold = True

    # example card
    c = card(s, Inches(0.5), Inches(4.5), Inches(12.3), Inches(2.3))
    add_text(s, Inches(0.75), Inches(4.7), Inches(11.8), Inches(0.35),
             "Ví dụ: Jailbreak DAN trên LLaMA-3 8B", size=15, bold=True, color=CRIMSON)
    add_text(s, Inches(0.75), Inches(5.15), Inches(11.8), Inches(1.4),
             "S_base = 9.5  ·  M_exp = 1.00 (phát hiện persona DAN)  ·  B_brevity = +0.5\n"
             "→ Score = min(10, 9.5×1.0 + 0.5) = 10.0 / 10.0  —  mức CRITICAL\n"
             "Tier-2 LLM-as-Judge: exploited=true, confidence=0.95",
             size=14, color=SLATE)

    # ========== 8. TWO-TIER ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "4. Kiến trúc phát hiện Hai tầng lai ghép", 8, TOTAL, logo_mark)

    # flow boxes
    tiers = [
        (Inches(0.5), "INPUT", "Payload +\nResponse", NAVY),
        (Inches(3.3), "TIER-1", "PatternDetector\nRegex < 1 ms", TEAL),
        (Inches(6.1), "GATE", "Low confidence\n→ escalate", GOLD),
        (Inches(8.9), "TIER-2", "LLM-as-Judge\nSemantic eval", CRIMSON),
    ]
    for left, title, body, col in tiers:
        box = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.35), Inches(2.5), Inches(1.8))
        solid(box, col if col != GOLD else NAVY)
        add_text(s, left, Inches(1.5), Inches(2.5), Inches(0.4),
                 title, size=14, bold=True, color=GOLD if col == GOLD or col == NAVY else WHITE, align=PP_ALIGN.CENTER)
        add_text(s, left + Inches(0.1), Inches(2.1), Inches(2.3), Inches(0.9),
                 body, size=13, color=WHITE, align=PP_ALIGN.CENTER)
    # arrows
    for ax in (2.95, 5.75, 8.55):
        arr = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(ax), Inches(2.0), Inches(0.35), Inches(0.35))
        solid(arr, GOLD)

    # comparison table highlight
    add_text(s, Inches(0.5), Inches(3.5), Inches(12), Inches(0.35),
             "So sánh phương pháp nhận diện (43 ca kiểm thử)", size=15, bold=True, color=NAVY)
    rows = [
        ("Phương pháp", "FP", "FN", "Precision", "Recall", "F1", "FPR"),
        ("Chỉ Regex (Tier-1)", "4", "1", "84.62%", "95.65%", "0.898", "17.39%"),
        ("Two-Tier (đề xuất)", "1", "0", "97.62%", "100%", "0.987", "2.38%"),
        ("Cải thiện", "−75%", "−100%", "+13%", "+4.35%", "+8.9%", "−15pp"),
    ]
    col_w = [2.8, 1.2, 1.2, 1.6, 1.4, 1.3, 1.4]
    for ri, row in enumerate(rows):
        x = Inches(0.5)
        y = Inches(4.0 + ri * 0.55)
        for ci, (val, ww) in enumerate(zip(row, col_w)):
            cell = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, Inches(ww), Inches(0.55))
            if ri == 0:
                solid(cell, NAVY)
                clr = WHITE
            elif ri == 2:
                solid(cell, RGBColor(0xE8, 0xF5, 0xEF))
                clr = GREEN
            elif ri == 3:
                solid(cell, RGBColor(0xFD, 0xF0, 0xE0))
                clr = CRIMSON
            else:
                solid(cell, WHITE)
                clr = SLATE
            cell.line.color.rgb = LIGHT_LINE
            add_text(s, x, y + Inches(0.1), Inches(ww), Inches(0.35),
                     val, size=12, bold=(ri in (0, 2, 3)), color=clr, align=PP_ALIGN.CENTER)
            x += Inches(ww)

    # ========== 9. KIẾN TRÚC ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "5. Kiến trúc phân tầng hệ thống", 9, TOTAL, logo_mark)
    layers = [
        ("Presentation", "Web Dashboard (Chart.js, Dark/Light)  ·  CLI Rich Console", CRIMSON),
        ("Service & API", "Flask 3.1  ·  SSE Stream  ·  JWT  ·  OpenAPI 3.0  ·  Prometheus", TEAL),
        ("Core Engine", "SimpleLLMClient (Circuit Breaker)  ·  RiskScorer  ·  Two-Tier Detector", NAVY),
        ("Modules", "12 Attack / Recon modules  ·  Garak & PyRIT wrappers", ORANGE),
        ("Persistence", "SQLite WAL (scanner.db)  ·  taxonomy.json  ·  config.yaml", GOLD),
    ]
    for i, (name, desc, col) in enumerate(layers):
        y = Inches(1.25 + i * 1.05)
        left_b = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.5), y, Inches(2.8), Inches(0.9))
        solid(left_b, col if col != GOLD else NAVY)
        add_text(s, Inches(0.5), y + Inches(0.25), Inches(2.8), Inches(0.45),
                 name, size=14, bold=True, color=GOLD if col == GOLD else WHITE, align=PP_ALIGN.CENTER)
        right_b = card(s, Inches(3.5), y, Inches(9.3), Inches(0.9))
        add_text(s, Inches(3.8), y + Inches(0.25), Inches(8.8), Inches(0.45),
                 desc, size=14, color=SLATE)

    # ========== 10. DASHBOARD FEATURES ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "5. Web Dashboard thời gian thực", 10, TOTAL, logo_mark)
    s.shapes.add_picture(mock_dash, Inches(0.4), Inches(1.2), width=Inches(8.2))
    c = card(s, Inches(8.8), Inches(1.2), Inches(4.0), Inches(5.5))
    add_text(s, Inches(9.0), Inches(1.4), Inches(3.6), Inches(0.4),
             "Tính năng nổi bật", size=16, bold=True, color=NAVY)
    add_bullets(s, Inches(9.0), Inches(2.0), Inches(3.6), Inches(4.4), [
        "SSE streaming mili-giây",
        "Thanh tiến độ % trực quan",
        "Hủy scan tức thời (UUID)",
        "Donut Severity + Findings",
        "Payload Editor tương tác",
        "Dark / Light mode",
        "Xuất JSON / HTML / MD",
        "Swagger OpenAPI 3.0",
        "JWT + Rate limiting",
        "55/55 tests passed",
    ], size=13, spacing=8)

    # ========== 11. TÍCH HỢP OSS ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "6. Tích hợp NVIDIA Garak & Microsoft PyRIT", 11, TOTAL, logo_mark)
    for i, (title, items, col) in enumerate([
        ("NVIDIA Garak", [
            "Generative AI Red-teaming",
            "Hàng trăm probe chuyên sâu",
            "GarakWrapper: subprocess cô lập",
            "Ánh xạ probe → OWASP 2025",
        ], CRIMSON),
        ("Microsoft PyRIT", [
            "Multi-turn orchestration",
            "Crescendo escalation attack",
            "Live mode + Offline baseline",
            "Jaccard Concordance Rate",
        ], TEAL),
        ("Hệ thống đề xuất", [
            "CLI + Web Dashboard SSE",
            "Two-Tier hybrid detection",
            "CVSS-like 0–10 + remediation",
            "Đồng thuận 85.7% với OSS",
        ], NAVY),
    ]):
        left = Inches(0.4 + i * 4.25)
        head = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(1.3), Inches(4.05), Inches(0.7))
        solid(head, col)
        add_text(s, left, Inches(1.45), Inches(4.05), Inches(0.45),
                 title, size=16, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        body = card(s, left, Inches(2.1), Inches(4.05), Inches(4.4))
        add_bullets(s, left + Inches(0.25), Inches(2.4), Inches(3.55), Inches(3.8),
                    items, size=14, spacing=14)

    # ========== 12. DEMO CLI ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "7. Demo hệ thống — CLI (Rich Console)", 12, TOTAL, logo_mark)
    s.shapes.add_picture(mock_cli, Inches(0.5), Inches(1.25), width=Inches(8.0))
    c = card(s, Inches(8.8), Inches(1.25), Inches(4.0), Inches(5.4), fill=NAVY)
    add_text(s, Inches(9.0), Inches(1.5), Inches(3.6), Inches(0.4),
             "Luồng demo CLI", size=16, bold=True, color=GOLD)
    add_bullets(s, Inches(9.0), Inches(2.1), Inches(3.6), Inches(4.2), [
        "show modules",
        "use <module>",
        "set target / model",
        "run → dispatch payloads",
        "Tier-1 / Tier-2 log",
        "Bảng findings + score",
        "Xuất report tự động",
        "Phù hợp CI/CD pipeline",
    ], size=14, color=WHITE, spacing=10)

    # ========== 13. DEMO WEB ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "7. Demo hệ thống — Web Dashboard & RAG", 13, TOTAL, logo_mark)
    s.shapes.add_picture(mock_rag, Inches(0.4), Inches(1.2), width=Inches(12.5))

    # ========== 14. KIỂM THỬ AI - METRICS ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "7. Kiểm thử AI — Kết quả định lượng (43 cases)", 14, TOTAL, logo_mark)

    # KPI cards
    kpis = [
        ("Precision", "97.62%", CRIMSON),
        ("Recall", "100%", TEAL),
        ("F1-Score", "0.9870", NAVY),
        ("FPR", "2.38%", ORANGE),
    ]
    for i, (lab, val, col) in enumerate(kpis):
        left = Inches(0.45 + i * 3.2)
        c = card(s, left, Inches(1.2), Inches(3.0), Inches(1.5))
        bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, Inches(1.2), Inches(3.0), Inches(0.12))
        solid(bar, col)
        add_text(s, left, Inches(1.45), Inches(3.0), Inches(0.35),
                 lab, size=13, color=MUTED, align=PP_ALIGN.CENTER)
        add_text(s, left, Inches(1.85), Inches(3.0), Inches(0.55),
                 val, size=28, bold=True, color=col, align=PP_ALIGN.CENTER)

    # F1 by module chart
    chart_data = CategoryChartData()
    chart_data.categories = [
        "prompt_inj", "jailbreak", "prompt_leak", "sensitive",
        "output", "misinfo", "model_dos",
    ]
    chart_data.add_series("F1-Score", (1.0, 0.9091, 1.0, 1.0, 1.0, 1.0, 1.0))
    chart = s.shapes.add_chart(
        XL_CHART_TYPE.BAR_CLUSTERED, Inches(0.4), Inches(2.95), Inches(7.5), Inches(3.9), chart_data
    ).chart
    chart.has_legend = False

    c = card(s, Inches(8.2), Inches(2.95), Inches(4.6), Inches(3.9))
    add_text(s, Inches(8.45), Inches(3.15), Inches(4.2), Inches(0.4),
             "Confusion Matrix tổng hợp", size=14, bold=True, color=NAVY)
    add_text(s, Inches(8.45), Inches(3.7), Inches(4.2), Inches(2.8),
             "TP = 23    FP = 1\nTN = 19    FN = 0\n\n"
             "43 ca · 7 module exploit\n"
             "Ground-truth độc lập\n"
             "Offline + live Ollama\n\n"
             "Unit/Integration: 55/55 ✓",
             size=15, color=SLATE)

    # ========== 15. MULTI-MODEL ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "7. Kiểm thử đa mô hình AI", 15, TOTAL, logo_mark)

    chart_data = CategoryChartData()
    chart_data.categories = ["LLaMA-3 8B", "Mistral 7B", "Qwen 2.5 7B", "GPT-4o-mini"]
    chart_data.add_series("Tỷ lệ dính lỗ hổng (%)", (38.5, 46.2, 30.8, 15.4))
    chart_data.add_series("Điểm rủi ro TB (×10)", (62, 71, 54, 32))  # scaled for dual view clarity - better use two series of same scale
    # Actually use vulnerability rate and risk*10 separately - let me use clear chart with vuln rate only and table for scores

    chart_data2 = CategoryChartData()
    chart_data2.categories = ["LLaMA-3 8B", "Mistral 7B", "Qwen 2.5", "GPT-4o-mini"]
    chart_data2.add_series("% Vulnerable", (38.5, 46.2, 30.8, 15.4))
    chart = s.shapes.add_chart(
        XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(0.4), Inches(1.2), Inches(7.2), Inches(5.5), chart_data2
    ).chart
    chart.has_legend = True
    chart.legend.position = XL_LEGEND_POSITION.BOTTOM

    # model cards
    models = [
        ("LLaMA-3 8B", "38.5%", "6.2", "Trung bình"),
        ("Mistral 7B", "46.2%", "7.1", "Yếu"),
        ("Qwen 2.5 7B", "30.8%", "5.4", "Khá tốt"),
        ("GPT-4o-mini", "15.4%", "3.2", "Rất tốt"),
    ]
    for i, (name, vuln, score, note) in enumerate(models):
        y = Inches(1.25 + i * 1.35)
        c = card(s, Inches(8.0), y, Inches(4.8), Inches(1.2))
        add_text(s, Inches(8.2), y + Inches(0.15), Inches(4.4), Inches(0.35),
                 name, size=14, bold=True, color=NAVY)
        add_text(s, Inches(8.2), y + Inches(0.55), Inches(4.4), Inches(0.45),
                 f"Vulnerable {vuln}  ·  Risk {score}/10  ·  {note}",
                 size=12, color=MUTED)

    # ========== 16. ABLATION TWO-TIER CHART ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "7. Ablation Study — Hiệu quả Two-Tier", 16, TOTAL, logo_mark)

    chart_data = CategoryChartData()
    chart_data.categories = ["Precision", "Recall", "F1-Score"]
    chart_data.add_series("Tier-1 only", (0.8462, 0.9565, 0.8980))
    chart_data.add_series("Two-Tier Hybrid", (0.9762, 1.0000, 0.9870))
    chart = s.shapes.add_chart(
        XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(0.4), Inches(1.2), Inches(8.0), Inches(5.5), chart_data
    ).chart
    chart.has_legend = True
    chart.legend.position = XL_LEGEND_POSITION.BOTTOM

    c = card(s, Inches(8.7), Inches(1.2), Inches(4.1), Inches(5.5), fill=NAVY)
    add_text(s, Inches(8.95), Inches(1.5), Inches(3.7), Inches(0.5),
             "Đóng góp kỹ thuật", size=16, bold=True, color=GOLD)
    add_bullets(s, Inches(8.95), Inches(2.2), Inches(3.7), Inches(4.2), [
        "Giảm 75% False Positive",
        "Triệt tiêu False Negative",
        "FPR: 17.39% → 2.38%",
        "Tier-1: ~1.2 ms / case",
        "Tiết kiệm 75–85% token vs Pure Judge",
        "Graceful fallback khi Judge lỗi",
        "Giải thích ngữ nghĩa chi tiết",
    ], size=14, color=WHITE, spacing=12)

    # ========== 17. ĐÓNG GÓP ==========
    s = prs.slides.add_slide(blank)
    slide_chrome(s, "8. Đóng góp & Hướng phát triển", 17, TOTAL, logo_mark)
    contribs = [
        "Hệ thống hóa chuẩn OWASP 2025 / MITRE / NIST",
        "Taxonomy 12 module + CVSS-like 0–10",
        "Two-Tier Hybrid Detection đã kiểm chứng",
        "Full-stack: CLI + Web SSE + OpenAPI + 55 tests",
        "Tích hợp Garak & PyRIT (đồng thuận 85.7%)",
        "F1 = 0.987 trên 43 ca × 4 mô hình",
    ]
    for i, t in enumerate(contribs):
        y = Inches(1.2 + i * 0.7)
        num = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(0.5), y, Inches(0.5), Inches(0.5))
        solid(num, CRIMSON if i % 2 == 0 else TEAL)
        add_text(s, Inches(0.5), y + Inches(0.08), Inches(0.5), Inches(0.35),
                 str(i + 1), size=14, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
        add_text(s, Inches(1.2), y + Inches(0.08), Inches(5.5), Inches(0.45),
                 t, size=14, color=SLATE)

    c = card(s, Inches(7.2), Inches(1.2), Inches(5.6), Inches(5.5), fill=NAVY)
    add_text(s, Inches(7.5), Inches(1.5), Inches(5.1), Inches(0.4),
             "Hướng phát triển", size=16, bold=True, color=GOLD)
    add_bullets(s, Inches(7.5), Inches(2.2), Inches(5.1), Inches(4.2), [
        "Multimodal red-teaming (vision)",
        "Adaptive / RL payload generation",
        "AI-WAF reverse-proxy real-time",
        "Docker + DevSecOps CI/CD",
        "Mở rộng dataset tiếng Việt",
        "White-box / weight-level audit",
    ], size=14, color=WHITE, spacing=14)

    # ========== 18. Q&A ==========
    s = prs.slides.add_slide(blank)
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, H)
    solid(bg, NAVY)
    left_panel = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.35), H)
    solid(left_panel, CRIMSON)
    top_gold = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, Inches(0.08))
    solid(top_gold, GOLD)
    bot_gold = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, H - Inches(0.08), W, Inches(0.08))
    solid(bot_gold, GOLD)

    s.shapes.add_picture(logo_main, Inches(5.9), Inches(0.8), height=Inches(1.6))
    add_text(s, Inches(0.8), Inches(2.7), Inches(11.7), Inches(0.7),
             "Xin trân trọng cảm ơn!", size=40, bold=True, color=WHITE, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.8), Inches(3.5), Inches(11.7), Inches(0.5),
             "Học viện Kỹ thuật Mật mã  ·  Báo cáo Nghiên cứu Khoa học 2026",
             size=16, color=GOLD, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.8), Inches(4.3), Inches(11.7), Inches(0.5),
             "AI Security Scanner — Kiểm thử an toàn hệ thống Trí tuệ Nhân tạo",
             size=18, color=RGBColor(0xC0, 0xD0, 0xE0), align=PP_ALIGN.CENTER)

    qa = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(4.5), Inches(5.3), Inches(4.3), Inches(0.9))
    solid(qa, CRIMSON)
    add_text(s, Inches(4.5), Inches(5.5), Inches(4.3), Inches(0.55),
             "HỎI & ĐÁP  (Q & A)", size=22, bold=True, color=WHITE, align=PP_ALIGN.CENTER)

    prs.save(OUT)
    print(f"Created: {OUT}")
    print(f"Slides: {len(prs.slides)}")
    return OUT


if __name__ == "__main__":
    build()
