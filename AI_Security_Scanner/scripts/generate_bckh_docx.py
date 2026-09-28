# -*- coding: utf-8 -*-
"""
scripts/generate_bckh_docx.py - Master Compiler for the Academic Thesis Report BC_NCKH.docx

Generates the complete 60-80 page academic report conforming to Vietnamese university standards:
- File name: BC_NCKH.docx (saved in root folder)
- Font: Times New Roman 13pt, line spacing 1.35, 6pt space after, justified
- Margins: Left 3.0cm, Right/Top/Bottom 2.0cm
- Headers/Footers with academic title and centered page numbers
- All 6 core contents covered with extreme academic rigor
- Embedded screenshots and figures (Figures 4.1 to 4.6)
- Academic tables with Navy headers (#1B365D) and zebra striping
- Mathematical equations and CVSS-like scoring formulas
"""

import os
import sys
import time

# Ensure UTF-8 stdout/stderr on Windows terminal
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.bckh_builder import BCKHBuilder
from scripts.content_front_matter import generate_front_matter
from scripts.content_chapter1 import generate_chapter1
from scripts.content_chapter2 import generate_chapter2
from scripts.content_chapter3 import build_chapter3
from scripts.content_chapter4 import build_chapter4
from scripts.content_chapter5 import build_chapter5
from scripts.content_chapter6 import build_chapter6
from scripts.content_back_matter import build_back_matter


def main():
    start_time = time.time()
    print("=" * 70)
    print(" BẮT ĐẦU BIÊN TẬP BÁO CÁO NGHIÊN CỨU KHOA HỌC: BC_NCKH.docx")
    print("=" * 70)

    # 1. Định nghĩa các đường dẫn ảnh và tài nguyên
    logo_path = os.path.join(PROJECT_ROOT, "web", "static", "logo.jpg")
    
    # User uploaded screenshots from chat history
    artifacts_dir = r"C:\Users\pc\.gemini\antigravity\brain\fe7fcbf9-066d-4776-b234-5a804007f48f\.user_uploaded"
    image_paths = {
        "cli": os.path.join(artifacts_dir, "media_1790185271433.png"),
        "web_dark": os.path.join(artifacts_dir, "media_1790346061990.png"),
        "terminal": os.path.join(artifacts_dir, "media_1790345726395.png"),
        "findings": os.path.join(artifacts_dir, "media_1790273435528.png"),
        "remediation": os.path.join(artifacts_dir, "media_1790331917071.png"),
        "charts": os.path.join(artifacts_dir, "media_1790334026139.png"),
    }

    # 2. Khởi tạo đối tượng Builder
    print("[1/9] Đang khởi tạo Document Builder với lề chuẩn và Header/Footer...")
    builder = BCKHBuilder()

    # 3. Biên soạn Phần đầu (Front Matter)
    print("[2/9] Đang biên soạn Trang bìa, Lời cam đoan, Lời cảm ơn, Tóm tắt, Mục lục...")
    generate_front_matter(builder)

    # 4. Biên soạn Chương 1
    print("[3/9] Đang biên soạn Chương 1: Tổng quan Lý thuyết & Tiêu chuẩn Quốc tế...")
    generate_chapter1(builder)

    # 5. Biên soạn Chương 2
    print("[4/9] Đang biên soạn Chương 2: Phân loại Taxonomy & Mô hình Toán học CVSS-like...")
    generate_chapter2(builder)

    # 6. Biên soạn Chương 3
    print("[5/9] Đang biên soạn Chương 3: Phương pháp luận & Kiến trúc Hai Tầng Lai Ghép...")
    build_chapter3(builder)

    # 7. Biên soạn Chương 4
    print("[6/9] Đang biên soạn Chương 4: Thiết kế Kiến trúc, 12 Modules & Web Dashboard...")
    build_chapter4(builder, image_paths=image_paths)

    # 8. Biên soạn Chương 5
    print("[7/9] Đang biên soạn Chương 5: Tích hợp Công cụ Mã nguồn mở Garak & PyRIT...")
    build_chapter5(builder)

    # 9. Biên soạn Chương 6
    print("[8/9] Đang biên soạn Chương 6: Thực nghiệm Định lượng, Two-Tier Ablation & Đa mô hình...")
    build_chapter6(builder)

    # 10. Biên soạn Phần cuối (Back Matter)
    print("[9/9] Đang biên soạn Kết luận, Tài liệu tham khảo (IEEE) & 3 Phụ lục...")
    build_back_matter(builder)

    # 11. Lưu tài liệu Word ra gốc thư mục dự án
    output_filename = os.path.join(PROJECT_ROOT, "BC_NCKH.docx")
    print(f"\nĐang lưu văn bản ra file: {output_filename} ...")
    builder.save(output_filename)

    elapsed = time.time() - start_time
    file_size_mb = os.path.getsize(output_filename) / (1024 * 1024)

    # 12. Thống kê dữ liệu văn bản
    doc = builder.doc
    total_paragraphs = len(doc.paragraphs)
    total_tables = len(doc.tables)
    total_words = sum(len(p.text.split()) for p in doc.paragraphs)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                total_words += sum(len(p.text.split()) for p in cell.paragraphs)

    # Ước lượng số trang (khoảng 350-400 từ/trang đối với 13pt 1.35 line spacing kèm bảng biểu & ảnh)
    # Bảng biểu và ảnh chiếm không gian vật lý lớn (mỗi bảng ~0.5 - 1.0 trang, mỗi ảnh ~0.5 trang)
    estimated_pages_from_content = int(total_words / 320) + int(total_tables * 0.4) + int(len(image_paths) * 0.5)

    print("\n" + "=" * 70)
    print(" BIÊN TẬP THÀNH CÔNG BÁO CÁO NGHIÊN CỨU KHOA HỌC!")
    print("=" * 70)
    print(f"File kết quả       : {output_filename}")
    print(f"Kích thước file    : {file_size_mb:.2f} MB")
    print(f"Thời gian biên tập : {elapsed:.2f} giây")
    print(f"Tổng số đoạn văn   : {total_paragraphs}")
    print(f"Tổng số bảng biểu  : {total_tables} bảng")
    print(f"Tổng số từ         : {total_words:,} từ (Tiếng Việt học thuật)")
    print(f"Ước lượng số trang : ~{estimated_pages_from_content} trang Word (A4, 13pt, 1.35 line spacing)")
    print("=" * 70)


if __name__ == "__main__":
    main()
