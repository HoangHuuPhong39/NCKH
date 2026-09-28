# -*- coding: utf-8 -*-
"""
scripts/bckh_builder.py - Base Academic Document Builder for BC_NCKH.docx

Provides standardized styling, table generation, figure embedding, callout boxes,
code snippets, and academic formatting compliant with Vietnamese thesis regulations
(Times New Roman, Left 3cm, Right 2cm, Top 2cm, Bottom 2cm, standard line spacing).
"""

import os
from docx import Document
from docx.shared import Inches, Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn


# Color Palette (Academic Deep Navy Theme)
COLOR_PRIMARY_HEX = "1B365D"       # Deep Navy
COLOR_SECONDARY_HEX = "2E4053"     # Slate Charcoal
COLOR_ACCENT_HEX = "0B5394"        # Royal Blue
COLOR_BG_LIGHT_HEX = "F4F6F9"      # Soft Gray-Blue
COLOR_BG_CODE_HEX = "EBF1F5"       # Monospace Code Background
COLOR_BORDER_HEX = "BDC3C7"        # Table Border Light Gray
COLOR_ZEBRA_HEX = "F8F9FA"         # Table Alternate Row

COLOR_PRIMARY = RGBColor(27, 54, 93)
COLOR_SECONDARY = RGBColor(46, 64, 83)
COLOR_TEXT = RGBColor(30, 30, 30)
COLOR_MUTED = RGBColor(100, 100, 100)


class BCKHBuilder:
    """Document Builder tailored for comprehensive academic research reports."""

    def __init__(self):
        self.doc = Document()
        self.figure_count = 0
        self.table_count = 0
        self._setup_page_layout()
        self._setup_styles()

    def _setup_page_layout(self):
        """Standard Vietnamese Thesis Margins: Left 3cm, Right 2cm, Top 2cm, Bottom 2cm."""
        sections = self.doc.sections
        for section in sections:
            section.top_margin = Cm(2.0)
            section.bottom_margin = Cm(2.0)
            section.left_margin = Cm(3.0)
            section.right_margin = Cm(2.0)
            section.page_width = Cm(21.0)
            section.page_height = Cm(29.7)

            # Running header and footer
            header = section.header
            hp = header.paragraphs[0]
            hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            hrun = hp.add_run("BÁO CÁO NCKH: BỘ CÔNG CỤ KIỂM THỬ AN TOÀN CHO HỆ THỐNG AI")
            hrun.font.name = "Times New Roman"
            hrun.font.size = Pt(8.5)
            hrun.font.italic = True
            hrun.font.color.rgb = RGBColor(120, 120, 120)

            footer = section.footer
            fp = footer.paragraphs[0]
            fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
            frun = fp.add_run("Trang ")
            frun.font.name = "Times New Roman"
            frun.font.size = Pt(9.5)
            frun.font.color.rgb = RGBColor(100, 100, 100)
            self._add_page_number(frun)

    def _add_page_number(self, run):
        """Adds Word page number field to a run."""
        fldChar1 = parse_xml(r'<w:fldChar %s w:fldCharType="begin"/>' % nsdecls('w'))
        instrText = parse_xml(r'<w:instrText %s xml:space="preserve"> PAGE </w:instrText>' % nsdecls('w'))
        fldChar2 = parse_xml(r'<w:fldChar %s w:fldCharType="separate"/>' % nsdecls('w'))
        fldChar3 = parse_xml(r'<w:fldChar %s w:fldCharType="end"/>' % nsdecls('w'))
        run._r.append(fldChar1)
        run._r.append(instrText)
        run._r.append(fldChar2)
        run._r.append(fldChar3)

    def _setup_styles(self):
        """Sets default font and standard academic styles."""
        # Normal
        normal_style = self.doc.styles['Normal']
        normal_style.font.name = 'Times New Roman'
        normal_style.font.size = Pt(13)
        normal_style.font.color.rgb = COLOR_TEXT
        normal_style.paragraph_format.line_spacing = 1.35
        normal_style.paragraph_format.space_after = Pt(6)
        normal_style.paragraph_format.space_before = Pt(0)
        normal_style.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    def add_page_break(self):
        """Inserts a clean page break."""
        self.doc.add_page_break()

    def add_cover_page(self, title, subtitle, school, faculty, student, supervisor, year="2026", logo_path=None):
        """Creates an elegant academic cover page with border and metadata."""
        p_top = self.doc.add_paragraph()
        p_top.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_top.paragraph_format.space_before = Pt(0)
        p_top.paragraph_format.space_after = Pt(4)
        r_school = p_top.add_run(school.upper() + "\n")
        r_school.font.size = Pt(14)
        r_school.font.bold = True
        r_school.font.color.rgb = COLOR_PRIMARY

        r_fac = p_top.add_run(faculty.upper() + "\n")
        r_fac.font.size = Pt(13)
        r_fac.font.bold = True
        r_fac.font.color.rgb = COLOR_SECONDARY

        r_line = p_top.add_run("-------------------- *** --------------------\n")
        r_line.font.size = Pt(10)
        r_line.font.color.rgb = COLOR_MUTED

        if logo_path and os.path.exists(logo_path):
            p_logo = self.doc.add_paragraph()
            p_logo.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_logo.paragraph_format.space_before = Pt(10)
            p_logo.paragraph_format.space_after = Pt(14)
            p_logo.add_run().add_picture(logo_path, width=Inches(1.6))

        p_rep = self.doc.add_paragraph()
        p_rep.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_rep.paragraph_format.space_before = Pt(20)
        p_rep.paragraph_format.space_after = Pt(8)
        r_rep = p_rep.add_run("BÁO CÁO NGHIÊN CỨU KHOA HỌC\n")
        r_rep.font.size = Pt(15)
        r_rep.font.bold = True
        r_rep.font.color.rgb = COLOR_SECONDARY

        p_title = self.doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_title.paragraph_format.space_before = Pt(12)
        p_title.paragraph_format.space_after = Pt(12)
        r_title = p_title.add_run(title.upper() + "\n")
        r_title.font.size = Pt(18)
        r_title.font.bold = True
        r_title.font.color.rgb = COLOR_PRIMARY

        p_sub = self.doc.add_paragraph()
        p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_sub.paragraph_format.space_before = Pt(4)
        p_sub.paragraph_format.space_after = Pt(40)
        r_sub = p_sub.add_run(subtitle)
        r_sub.font.size = Pt(13)
        r_sub.font.italic = True
        r_sub.font.color.rgb = COLOR_SECONDARY

        # Metadata table
        table = self.doc.add_table(rows=4, cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        meta_data = [
            ("Sinh viên thực hiện:", student),
            ("Chuyên ngành:", "An toàn Thông tin / Trí tuệ Nhân tạo"),
            ("Giảng viên hướng dẫn:", supervisor),
            ("Mã đề tài / Năm học:", f"NCKH-{year} · Học kỳ I, Năm 2026")
        ]
        for idx, (label, val) in enumerate(meta_data):
            cell_lbl = table.cell(idx, 0)
            cell_val = table.cell(idx, 1)
            cell_lbl.width = Inches(2.2)
            cell_val.width = Inches(3.8)

            p_lbl = cell_lbl.paragraphs[0]
            p_lbl.paragraph_format.space_after = Pt(4)
            r_l = p_lbl.add_run(label)
            r_l.font.bold = True
            r_l.font.size = Pt(12)
            r_l.font.color.rgb = COLOR_SECONDARY

            p_val = cell_val.paragraphs[0]
            p_val.paragraph_format.space_after = Pt(4)
            r_v = p_val.add_run(val)
            r_v.font.size = Pt(12)
            r_v.font.color.rgb = COLOR_TEXT

        p_bottom = self.doc.add_paragraph()
        p_bottom.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_bottom.paragraph_format.space_before = Pt(50)
        r_bot = p_bottom.add_run(f"HÀ NỘI – {year}")
        r_bot.font.size = Pt(12.5)
        r_bot.font.bold = True
        r_bot.font.color.rgb = COLOR_SECONDARY

        self.add_page_break()

    def add_heading_1(self, text):
        """Adds Heading 1: 16pt, Bold, Upper, Navy, Page break before."""
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(24)
        p.paragraph_format.space_after = Pt(8)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text.upper())
        run.font.size = Pt(16)
        run.font.bold = True
        run.font.color.rgb = COLOR_PRIMARY
        return p

    def add_heading_2(self, text):
        """Adds Heading 2: 14pt, Bold, Slate, keep_with_next."""
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.size = Pt(14)
        run.font.bold = True
        run.font.color.rgb = COLOR_SECONDARY
        return p

    def add_heading_3(self, text):
        """Adds Heading 3: 13pt, Bold Italic."""
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.size = Pt(13)
        run.font.bold = True
        run.font.italic = True
        run.font.color.rgb = COLOR_SECONDARY
        return p

    def add_heading_4(self, text):
        """Adds Heading 4: 13pt, Italic."""
        p = self.doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(text)
        run.font.size = Pt(13)
        run.font.italic = True
        run.font.color.rgb = COLOR_MUTED
        return p

    def add_p(self, text, bold=False, italic=False, align=WD_ALIGN_PARAGRAPH.JUSTIFY, space_after=6, indent=True):
        """Adds standard justified paragraph with optional first line indent."""
        p = self.doc.add_paragraph()
        p.alignment = align
        p.paragraph_format.space_after = Pt(space_after)
        p.paragraph_format.line_spacing = 1.35
        if indent and align == WD_ALIGN_PARAGRAPH.JUSTIFY:
            p.paragraph_format.first_line_indent = Cm(0.8)
        run = p.add_run(text)
        run.font.name = "Times New Roman"
        run.font.size = Pt(13)
        run.font.bold = bold
        run.font.italic = italic
        run.font.color.rgb = COLOR_TEXT
        return p

    def add_bullet(self, text, bold_prefix="", level=0):
        """Adds a clean academic bullet item."""
        p = self.doc.add_paragraph(style='List Bullet')
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.3
        p.paragraph_format.left_indent = Cm(1.0 + (level * 0.5))

        if bold_prefix:
            r_pre = p.add_run(bold_prefix + ": ")
            r_pre.font.name = "Times New Roman"
            r_pre.font.size = Pt(13)
            r_pre.font.bold = True
            r_pre.font.color.rgb = COLOR_SECONDARY

        run = p.add_run(text)
        run.font.name = "Times New Roman"
        run.font.size = Pt(13)
        run.font.color.rgb = COLOR_TEXT
        return p

    def add_callout(self, text, title="ĐỊNH NGHĨA / NGUYÊN TẮC CỐT LÕI"):
        """Adds a shaded, bordered callout box for emphasis and key definitions."""
        table = self.doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = table.cell(0, 0)
        cell.width = Inches(6.0)

        # Background color
        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{COLOR_BG_LIGHT_HEX}"/>')
        cell._tc.get_or_add_tcPr().append(shd)

        # Border styling: thick left border, thin light borders around
        tcBorders = parse_xml(f'''
            <w:tcBorders {nsdecls("w")}>
                <w:top w:val="single" w:sz="4" w:space="0" w:color="{COLOR_BORDER_HEX}"/>
                <w:left w:val="single" w:sz="28" w:space="0" w:color="{COLOR_PRIMARY_HEX}"/>
                <w:bottom w:val="single" w:sz="4" w:space="0" w:color="{COLOR_BORDER_HEX}"/>
                <w:right w:val="single" w:sz="4" w:space="0" w:color="{COLOR_BORDER_HEX}"/>
            </w:tcBorders>
        ''')
        cell._tc.get_or_add_tcPr().append(tcBorders)

        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.line_spacing = 1.25

        if title:
            r_t = p.add_run(f"📌 {title.upper()}\n")
            r_t.font.name = "Times New Roman"
            r_t.font.size = Pt(11.5)
            r_t.font.bold = True
            r_t.font.color.rgb = COLOR_PRIMARY

        r_body = p.add_run(text)
        r_body.font.name = "Times New Roman"
        r_body.font.size = Pt(12)
        r_body.font.italic = True
        r_body.font.color.rgb = COLOR_SECONDARY

        # Empty spacing paragraph
        p_sp = self.doc.add_paragraph()
        p_sp.paragraph_format.space_after = Pt(4)

    def add_code_block(self, code_text, caption=None):
        """Adds a shaded monospace code box for payloads or script snippets."""
        if caption:
            p_cap = self.doc.add_paragraph()
            p_cap.alignment = WD_ALIGN_PARAGRAPH.LEFT
            p_cap.paragraph_format.space_before = Pt(6)
            p_cap.paragraph_format.space_after = Pt(2)
            r_cap = p_cap.add_run(f"Trích đoạn mã / Payload: {caption}")
            r_cap.font.name = "Times New Roman"
            r_cap.font.size = Pt(11)
            r_cap.font.bold = True
            r_cap.font.color.rgb = COLOR_SECONDARY

        table = self.doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = table.cell(0, 0)
        cell.width = Inches(6.0)

        shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{COLOR_BG_CODE_HEX}"/>')
        cell._tc.get_or_add_tcPr().append(shd)

        tcBorders = parse_xml(f'''
            <w:tcBorders {nsdecls("w")}>
                <w:top w:val="single" w:sz="4" w:space="0" w:color="{COLOR_BORDER_HEX}"/>
                <w:left w:val="single" w:sz="16" w:space="0" w:color="{COLOR_ACCENT_HEX}"/>
                <w:bottom w:val="single" w:sz="4" w:space="0" w:color="{COLOR_BORDER_HEX}"/>
                <w:right w:val="single" w:sz="4" w:space="0" w:color="{COLOR_BORDER_HEX}"/>
            </w:tcBorders>
        ''')
        cell._tc.get_or_add_tcPr().append(tcBorders)

        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(3)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.15

        r_code = p.add_run(code_text)
        r_code.font.name = "Consolas"
        r_code.font.size = Pt(10)
        r_code.font.color.rgb = RGBColor(20, 20, 20)

        p_sp = self.doc.add_paragraph()
        p_sp.paragraph_format.space_after = Pt(4)

    def add_academic_table(self, headers, rows, caption=None, col_widths=None):
        """
        Creates an academic styled table with:
        - Table caption above: Bảng X.Y: ...
        - Navy header row with bold white text
        - Light zebra background alternating rows
        - Neat thin gray borders
        """
        self.table_count += 1
        if caption:
            p_cap = self.doc.add_paragraph()
            p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_cap.paragraph_format.space_before = Pt(10)
            p_cap.paragraph_format.space_after = Pt(4)
            p_cap.paragraph_format.keep_with_next = True
            r_cap = p_cap.add_run(f"Bảng {self.table_count}: {caption}")
            r_cap.font.name = "Times New Roman"
            r_cap.font.size = Pt(11.5)
            r_cap.font.bold = True
            r_cap.font.italic = True
            r_cap.font.color.rgb = COLOR_PRIMARY

        table = self.doc.add_table(rows=len(rows) + 1, cols=len(headers))
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        # Header Row
        hdr_row = table.rows[0]
        # Repeat header on every page
        trPr = hdr_row._tr.get_or_add_trPr()
        trPr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))

        for c_idx, h_text in enumerate(headers):
            cell = hdr_row.cells[c_idx]
            shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{COLOR_PRIMARY_HEX}"/>')
            cell._tc.get_or_add_tcPr().append(shd)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.15
            run = p.add_run(str(h_text))
            run.font.name = "Times New Roman"
            run.font.size = Pt(11)
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)

        # Body Rows
        for r_idx, row_data in enumerate(rows):
            row = table.rows[r_idx + 1]
            # Prevent row split across pages
            trPr_b = row._tr.get_or_add_trPr()
            trPr_b.append(parse_xml(f'<w:cantSplit {nsdecls("w")}/>'))

            is_zebra = (r_idx % 2 == 1)
            bg_hex = COLOR_ZEBRA_HEX if is_zebra else "FFFFFF"

            for c_idx, val in enumerate(row_data):
                cell = row.cells[c_idx]
                if is_zebra:
                    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{bg_hex}"/>')
                    cell._tc.get_or_add_tcPr().append(shd)

                p = cell.paragraphs[0]
                p.paragraph_format.space_before = Pt(3)
                p.paragraph_format.space_after = Pt(3)
                p.paragraph_format.line_spacing = 1.15
                
                # Align numbers / short badges center, text justify/left
                text_str = str(val)
                if any(k in headers[c_idx].lower() for k in ["stt", "cases", "tp", "fp", "tn", "fn", "mã", "port"]):
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                else:
                    p.alignment = WD_ALIGN_PARAGRAPH.LEFT

                run = p.add_run(text_str)
                run.font.name = "Times New Roman"
                run.font.size = Pt(11)
                run.font.color.rgb = COLOR_TEXT

        # Apply Column Widths if provided
        if col_widths and len(col_widths) == len(headers):
            for row in table.rows:
                for c_idx, w in enumerate(col_widths):
                    row.cells[c_idx].width = Inches(w)

        # Apply borders to table
        tblBorders = parse_xml(f'''
            <w:tblBorders {nsdecls("w")}>
                <w:top w:val="single" w:sz="6" w:space="0" w:color="{COLOR_PRIMARY_HEX}"/>
                <w:left w:val="none"/>
                <w:bottom w:val="single" w:sz="8" w:space="0" w:color="{COLOR_PRIMARY_HEX}"/>
                <w:right w:val="none"/>
                <w:insideH w:val="single" w:sz="4" w:space="0" w:color="{COLOR_BORDER_HEX}"/>
                <w:insideV w:val="none"/>
            </w:tblBorders>
        ''')
        table._tbl.tblPr.append(tblBorders)

        p_sp = self.doc.add_paragraph()
        p_sp.paragraph_format.space_after = Pt(6)

    def add_figure(self, image_path, caption, width_inches=5.8):
        """Embeds a figure with proper academic caption centered below."""
        if not os.path.exists(image_path):
            return

        self.figure_count += 1
        p_img = self.doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img.paragraph_format.space_before = Pt(10)
        p_img.paragraph_format.space_after = Pt(4)
        p_img.paragraph_format.keep_with_next = True
        p_img.add_run().add_picture(image_path, width=Inches(width_inches))

        p_cap = self.doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap.paragraph_format.space_before = Pt(2)
        p_cap.paragraph_format.space_after = Pt(10)
        r_cap = p_cap.add_run(f"Hình {self.figure_count}: {caption}")
        r_cap.font.name = "Times New Roman"
        r_cap.font.size = Pt(11)
        r_cap.font.bold = True
        r_cap.font.italic = True
        r_cap.font.color.rgb = COLOR_SECONDARY

    def add_formula(self, formula_text, formula_num=None):
        """Formats an academic mathematical formula with right-aligned numbering."""
        table = self.doc.add_table(rows=1, cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell_f = table.cell(0, 0)
        cell_n = table.cell(0, 1)
        cell_f.width = Inches(5.2)
        cell_n.width = Inches(0.8)

        p_f = cell_f.paragraphs[0]
        p_f.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_f.paragraph_format.space_before = Pt(4)
        p_f.paragraph_format.space_after = Pt(4)
        r_f = p_f.add_run(formula_text)
        r_f.font.name = "Cambria Math"
        r_f.font.size = Pt(12)
        r_f.font.bold = True
        r_f.font.color.rgb = COLOR_PRIMARY

        p_n = cell_n.paragraphs[0]
        p_n.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p_n.paragraph_format.space_before = Pt(4)
        p_n.paragraph_format.space_after = Pt(4)
        if formula_num:
            r_n = p_n.add_run(f"({formula_num})")
            r_n.font.name = "Times New Roman"
            r_n.font.size = Pt(11.5)
            r_n.font.italic = True
            r_n.font.color.rgb = COLOR_MUTED

        p_sp = self.doc.add_paragraph()
        p_sp.paragraph_format.space_after = Pt(4)

    def add_table(self, headers, rows, caption=None, col_widths=None):
        """Alias for add_academic_table."""
        return self.add_academic_table(headers, rows, caption=caption, col_widths=col_widths)

    def add_callout_box(self, text, title="ĐỊNH NGHĨA / NGUYÊN TẮC CỐT LÕI", box_type=None):
        """Alias for add_callout."""
        return self.add_callout(text, title=title)

    def add_math_block(self, formula_text, formula_id=None):
        """Alias for add_formula."""
        return self.add_formula(formula_text, formula_num=formula_id)

    def add_figure_placeholder(self, caption, width_inches=5.8):
        """Adds a clean academic figure placeholder block."""
        self.figure_count += 1
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run(f"[HÌNH ẢNH MINH HỌA - {caption.upper()}]")
        r.font.name = "Times New Roman"
        r.font.size = Pt(11)
        r.font.italic = True
        r.font.color.rgb = COLOR_MUTED

        p_cap = self.doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap.paragraph_format.space_before = Pt(2)
        p_cap.paragraph_format.space_after = Pt(8)
        r_cap = p_cap.add_run(caption)
        r_cap.font.name = "Times New Roman"
        r_cap.font.size = Pt(11)
        r_cap.font.italic = True
        r_cap.font.bold = True
        r_cap.font.color.rgb = COLOR_SECONDARY

    def save(self, filepath):
        """Saves document to the target path."""
        self.doc.save(filepath)
        print(f"[✓] Document successfully saved to: {filepath}")
