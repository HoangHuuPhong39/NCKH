# -*- coding: utf-8 -*-
"""
scripts/generate_bckh_docx.py - Master Compiler for the Academic Thesis Report BC_NCKH.docx
"""

import os
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

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


def _resolve_img(primary_path: str, fallback_path: str) -> str:
    """Ưu tiên lấy ảnh trong ppt_assets của dự án, nếu không có mới dùng fallback."""
    if os.path.exists(primary_path):
        return primary_path
    return fallback_path


def main():
    start_time = time.time()
    print("=" * 70)
    print(" BẮT ĐẦU BIÊN TẬP BÁO CÁO NGHIÊN CỨU KHOA HỌC: BC_NCKH.docx")
    print("=" * 70)

    ppt_assets_dir = os.path.join(PROJECT_ROOT, "ppt_assets")
    artifacts_dir = r"C:\Users\pc\.gemini\antigravity\brain\fe7fcbf9-066d-4776-b234-5a804007f48f\.user_uploaded"

    image_paths = {
        "cli": _resolve_img(
            os.path.join(ppt_assets_dir, "mock_cli.png"),
            os.path.join(artifacts_dir, "media_1790185271433.png"),
        ),
        "web_dark": _resolve_img(
            os.path.join(ppt_assets_dir, "mock_dashboard.png"),
            os.path.join(artifacts_dir, "media_1790331917071.png"),
        ),
        "terminal": _resolve_img(
            os.path.join(artifacts_dir, "media_1790334026139.png"),
            os.path.join(ppt_assets_dir, "mock_cli.png"),
        ),
        "findings": _resolve_img(
            os.path.join(artifacts_dir, "media_1790273435528.png"),
            os.path.join(ppt_assets_dir, "mock_dashboard.png"),
        ),
        "remediation": _resolve_img(
            os.path.join(artifacts_dir, "media_1790331917071.png"),
            os.path.join(ppt_assets_dir, "mock_dashboard.png"),
        ),
        "charts": _resolve_img(
            os.path.join(ppt_assets_dir, "mock_rag.png"),
            os.path.join(artifacts_dir, "media_1790334026139.png"),
        ),
    }

    print("[1/9] Đang khởi tạo Document Builder với lề chuẩn và Header/Footer...")
    builder = BCKHBuilder()

    print("[2/9] Đang biên soạn Trang bìa HVKTMM, Lời cam đoan, Tóm tắt, Mục lục, RQ1-RQ8...")
    generate_front_matter(builder)

    print("[3/9] Đang biên soạn Chương 1: Tổng quan Lý thuyết, Tiêu chuẩn & Khoảng trống G1-G7...")
    generate_chapter1(builder)

    print("[4/9] Đang biên soạn Chương 2: Mô hình Đe dọa, Taxonomy Đa tầng & Công thức CVSS-like...")
    generate_chapter2(builder)

    print("[5/9] Đang biên soạn Chương 3: Sinh Payload Thích Nghi (13 chiến lược) & Two-Tier Hybrid...")
    build_chapter3(builder)

    print("[6/9] Đang biên soạn Chương 4: Kiến trúc Hệ thống, Agent Sandbox, Evidence Store & Web UI...")
    build_chapter4(builder, image_paths=image_paths)

    print("[7/9] Đang biên soạn Chương 5: Tích hợp Liên minh 6 Công cụ Mã nguồn mở Quốc tế...")
    build_chapter5(builder)

    print("[8/9] Đang biên soạn Chương 6: Thực nghiệm Đa mô hình, Benchmark Tiếng Việt & Ablation...")
    build_chapter6(builder)

    print("[9/9] Đang biên soạn Kết luận, Tài liệu tham khảo (IEEE) & Phụ lục...")
    build_back_matter(builder)

    output_filename = os.path.join(PROJECT_ROOT, "BC_NCKH.docx")
    print(f"\nĐang lưu văn bản ra file: {output_filename} ...")
    builder.save(output_filename)

    # Đồng thời cập nhật luôn bản BaoCao_NCKH.docx nếu có
    alt_filename = os.path.join(PROJECT_ROOT, "BaoCao_NCKH.docx")
    try:
        builder.save(alt_filename)
    except Exception:
        pass

    elapsed = time.time() - start_time
    file_size_mb = os.path.getsize(output_filename) / (1024 * 1024)

    doc = builder.doc
    total_paragraphs = len(doc.paragraphs)
    total_tables = len(doc.tables)
    total_words = sum(len(p.text.split()) for p in doc.paragraphs)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                total_words += sum(len(p.text.split()) for p in cell.paragraphs)

    estimated_pages = int(total_words / 320) + int(total_tables * 0.4) + int(len(image_paths) * 0.5)

    print("\n" + "=" * 70)
    print(" BIÊN TẬP THÀNH CÔNG BÁO CÁO NGHIÊN CỨU KHOA HỌC!")
    print("=" * 70)
    print(f"File kết quả       : {output_filename}")
    print(f"Kích thước file    : {file_size_mb:.2f} MB")
    print(f"Thời gian biên tập : {elapsed:.2f} giây")
    print(f"Tổng số đoạn văn   : {total_paragraphs}")
    print(f"Tổng số bảng biểu  : {total_tables} bảng")
    print(f"Tổng số từ         : {total_words:,} từ")
    print(f"Ước lượng số trang : ~{estimated_pages} trang Word (A4, 13pt, 1.35 line spacing)")
    print("=" * 70)


if __name__ == "__main__":
    main()