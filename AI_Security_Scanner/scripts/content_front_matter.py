# -*- coding: utf-8 -*-
"""
scripts/content_front_matter.py - Front matter & Introduction for BC_NCKH.docx
Chuẩn hóa theo Học viện Kỹ thuật Mật mã và Đề xuất hướng nghiên cứu (RQ1 - RQ8).
"""

import os
from docx.shared import Pt
from scripts.bckh_builder import COLOR_PRIMARY, COLOR_TEXT, COLOR_MUTED


def generate_front_matter(b):
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    logo_hv = os.path.join(project_root, "ppt_assets", "logo_hvktmm.png")
    if not os.path.exists(logo_hv):
        logo_hv = os.path.join(project_root, "web", "static", "logo.jpg")

    # 1. BÌA CHÍNH (Front Cover - Học viện Kỹ thuật Mật mã)
    b.add_cover_page(
        title="NGHIÊN CỨU VÀ XÂY DỰNG BỘ CÔNG CỤ KIỂM THỬ AN TOÀN CHO HỆ THỐNG TRÍ TUỆ NHÂN TẠO (AI SECURITY SCANNER)",
        subtitle="Chuẩn hóa theo Khung Quốc Tế OWASP Top 10 for LLM Applications 2025 và Ma Trận MITRE ATLAS",
        school="BAN CƠ YẾU CHÍNH PHỦ",
        faculty="HỌC VIỆN KỸ THUẬT MẬT MÃ · KHOA AN TOÀN THÔNG TIN",
        student="NHÓM SINH VIÊN NGHIÊN CỨU KHOA HỌC",
        supervisor="GIẢNG VIÊN HƯỚNG DẪN KHOA HỌC",
        year="2026",
        logo_path=logo_hv
    )

    # 2. BÌA PHỤ (Sub-cover)
    b.add_cover_page(
        title="PHÂN TÍCH, THIẾT KẾ VÀ PHÁT TRIỂN BỘ CÔNG CỤ KIỂM THỬ AN TOÀN ĐA TẦNG CHO CÁC HỆ THỐNG AI",
        subtitle="ĐỀ TÀI NGHIÊN CỨU KHOA HỌC SINH VIÊN",
        school="HỌC VIỆN KỸ THUẬT MẬT MÃ",
        faculty="KHOA AN TOÀN THÔNG TIN",
        student="NHÓM TÁC GIẢ ĐỀ TÀI AI SECURITY SCANNER",
        supervisor="HỘI ĐỒNG KHOA HỌC CHUYÊN NGÀNH AN TOÀN THÔNG TIN",
        year="2026",
        logo_path=None
    )

    # 3. LỜI CAM ĐOAN
    b.add_heading_1("LỜI CAM ĐOAN")
    b.add_p(
        "Nhóm nghiên cứu xin cam đoan công trình nghiên cứu khoa học với đề tài: \"Nghiên cứu và xây dựng bộ công cụ kiểm thử an toàn cho hệ thống Trí tuệ nhân tạo (AI Security Scanner)\" "
        "là kết quả nghiên cứu độc lập, nghiêm túc và trung thực dưới sự định hướng khoa học tận tình của Giảng viên hướng dẫn. "
        "Toàn bộ các số liệu thực nghiệm, kết quả đo đạc định lượng, mã nguồn phần mềm, cấu trúc cơ sở dữ liệu và các phân tích học thuật được trình bày trong báo cáo này "
        "đều được thực hiện trực tiếp trên hệ thống phòng thí nghiệm của nhóm nghiên cứu."
    )
    b.add_p(
        "Các tài liệu tham khảo, bài báo khoa học trong nước và quốc tế, tiêu chuẩn công nghiệp (OWASP LLM Top 10 2025, MITRE ATLAS, NIST AI RMF, ISO/IEC 42001) "
        "đều được trích dẫn nguồn gốc rõ ràng, đầy đủ theo đúng chuẩn mực liêm chính học thuật."
    )
    b.add_p("Hà Nội, năm 2026", italic=True)
    b.add_p("Đại diện nhóm nghiên cứu\n(Ký và ghi rõ họ tên)", bold=True)
    b.add_page_break()

    # 4. LỜI CẢM ƠN
    b.add_heading_1("LỜI CẢM ƠN")
    b.add_p(
        "Để hoàn thành công trình nghiên cứu khoa học này, nhóm tác giả xin bày tỏ lòng biết ơn sâu sắc nhất tới Giảng viên hướng dẫn – người đã định hướng phương pháp luận khoa học, "
        "truyền cảm hứng nghiên cứu và tận tình chỉ bảo nhóm trong suốt quá trình triển khai đề tài từ những ngày đầu đặt nền móng lý thuyết, xác lập 7 khoảng trống khoa học và 8 câu hỏi nghiên cứu "
        "cho đến khi hoàn thiện toàn diện hệ thống thực nghiệm đa tầng."
    )
    b.add_p(
        "Nhóm xin chân thành cảm ơn Ban Giám đốc Học viện Kỹ thuật Mật mã, Ban Chủ nhiệm Khoa An toàn Thông tin và các Thầy/Cô giáo trong bộ môn đã tạo điều kiện thuận lợi về cơ sở vật chất, "
        "môi trường học thuật chuyên nghiệp và truyền đạt những kiến thức nền tảng quý báu trong suốt quá trình học tập và nghiên cứu."
    )
    b.add_page_break()

    # 5. TÓM TẮT ĐỀ TÀI
    b.add_heading_1("TÓM TẮT ĐỀ TÀI")
    b.add_p(
        "Sự bùng nổ của các mô hình ngôn ngữ lớn (LLM), kiến trúc Tạo sinh tăng cường truy xuất (RAG) và các hệ thống tác tử AI tự chủ (Autonomous AI Agents) "
        "đang thúc đẩy cuộc cách mạng công nghệ sâu rộng. Tuy nhiên, ba nghịch lý bảo mật cốt lõi gồm: (1) Sự hòa trộn giữa kênh lệnh và kênh dữ liệu, "
        "(2) Tính chất sinh xác suất phi tất định, và (3) Ngôn ngữ tự nhiên trở thành mã khai thác đã mở ra bề mặt tấn công hoàn toàn mới. "
        "Các lỗ hổng như Prompt Injection, Jailbreak, rò rỉ dữ liệu nhạy cảm (PII/Credentials), lạm quyền gọi công cụ (Excessive Agency / Tool Abuse) và đầu độc RAG đang đe dọa trực tiếp đến các hệ thống AI."
    )
    b.add_p(
        "Bám sát 6 nội dung nghiên cứu trọng điểm và giải quyết 7 khoảng trống khoa học (G1–G7), đề tài đã thiết kế và phát triển hoàn chỉnh bộ công cụ kiểm thử an toàn đa tầng AI Security Scanner: "
        "(1) Hệ thống hóa chuẩn OWASP Top 10 for LLM 2025, MITRE ATLAS và NIST AI RMF; "
        "(2) Xây dựng bộ phân tích hồ sơ đe dọa tự động (System Profiler & Threat Model), Taxonomy 14 module kiểm thử đa tầng (LLM, RAG, Agent Sandbox, ML Adversarial) và mô hình định lượng rủi ro CVSS-like; "
        "(3) Đề xuất bộ sinh testcase thích nghi (Adaptive Attack Generator với 13 chiến lược đột biến có vòng lặp phản hồi), ngôn ngữ đặc tả kịch bản YAML DSL và Kiến trúc phát hiện hai tầng lai ghép (Two-Tier Hybrid: PatternDetector < 1ms kết hợp LLM-as-a-Judge); "
        "(4) Hiện thực hóa hệ thống với CLI Rich Console, Web Dashboard thời gian thực (SSE), lưu trữ chứng cứ và tái lập kiểm thử (Evidence & Replay Store), OpenAPI 3.0 và 92 bài kiểm thử tự động (100% passed); "
        "(5) Tích hợp liên minh 6 công cụ mã nguồn mở quốc tế (NVIDIA Garak, Microsoft PyRIT, Promptfoo, DeepTeam, Giskard OSS, IBM ART); "
        "(6) Thực nghiệm định lượng đa mô hình (LLaMA-3, Mistral, Qwen, GPT-4o-mini), nghiên cứu cắt bỏ thành phần (Ablation Study) và xây dựng bộ Benchmark 62 kịch bản tiếng Việt chuyên sâu chứng minh sự tồn tại của khoảng cách an toàn đa ngôn ngữ (p = 0.018 < 0.05)."
    )
    b.add_p("Từ khóa: An toàn AI, Kiểm thử Đa tầng, LLM Security, RAG Poisoning, Agent Sandbox, Adaptive Red-Teaming, OWASP LLM 2025, MITRE ATLAS, Two-Tier Detection, Benchmark Tiếng Việt.", bold=True)

    b.add_heading_2("ABSTRACT (ENGLISH)")
    b.add_p(
        "The rapid proliferation of Large Language Models (LLMs), Retrieval-Augmented Generation (RAG) pipelines, and autonomous AI Agents has introduced an unprecedented attack surface. "
        "This research presents the AI Security Scanner, an automated multi-tier security testing framework addressing seven research gaps (G1–G7) and eight research questions (RQ1–RQ8). "
        "The system integrates automated threat profiling, YAML testcase DSL, a 13-strategy feedback-driven Adaptive Attack Generator, an isolated Agent Sandbox, a Two-Tier Hybrid Detector (sub-millisecond regex filtering coupled with confidence-gated LLM-as-a-Judge), a CVSS-like mathematical risk scorer, and an Evidence Replay Store. "
        "Furthermore, it unifies six leading open-source frameworks (NVIDIA Garak, Microsoft PyRIT, Promptfoo, DeepTeam, Giskard, and IBM ART). "
        "Empirical evaluations across four model families and a novel 62-scenario Vietnamese AI Security Benchmark demonstrate a Precision of 97.62%, Recall of 100%, F1-Score of 0.9870, and statistically verify the cross-lingual safety gap (p = 0.018 < 0.05)."
    )
    b.add_p("Keywords: AI Security, Multi-Tier Red-Teaming, LLM Penetration Testing, RAG Security, Agent Sandbox, OWASP LLM Top 10, MITRE ATLAS, Two-Tier Detection.", bold=True)
    b.add_page_break()

    # 6. MỤC LỤC
    b.add_heading_1("MỤC LỤC")
    toc_items = [
        ("LỜI CAM ĐOAN", "i"),
        ("LỜI CẢM ƠN", "ii"),
        ("TÓM TẮT ĐỀ TÀI (TIẾNG VIỆT & TIẾNG ANH)", "iii"),
        ("DANH MỤC TỪ VIẾT TẮT", "v"),
        ("LỜI MỞ ĐẦU (TÍNH CẤP THIẾT, MỤC TIÊU & CÂU HỎI NGHIÊN CỨU RQ1-RQ8)", "1"),
        ("CHƯƠNG 1: TỔNG QUAN LÝ THUYẾT, TIÊU CHUẨN VÀ KHOẢNG TRỐNG KHOA HỌC", "6"),
        ("CHƯƠNG 2: MÔ HÌNH HÓA ĐE DỌA, TAXONOMY ĐA TẦNG VÀ CHẤM ĐIỂM RỦI RO CVSS-LIKE", "22"),
        ("CHƯƠNG 3: PHƯƠNG PHÁP SINH PAYLOAD THÍCH NGHI VÀ PHÁT HIỆN HAI TẦNG LAI GHÉP", "38"),
        ("CHƯƠNG 4: THIẾT KẾ KIẾN TRÚC VÀ HIỆN THỰC HÓA BỘ CÔNG CỤ KIỂM THỬ TỰ ĐỘNG", "52"),
        ("CHƯƠNG 5: TÍCH HỢP LIÊN MINH 6 CÔNG CỤ MÃ NGUỒN MỞ VÀ ĐỐI CHUẨN QUỐC TẾ", "68"),
        ("CHƯƠNG 6: THỰC NGHIỆM ĐỊNH LƯỢNG, ABLATION STUDY VÀ BENCHMARK TIẾNG VIỆT", "80"),
        ("KẾT LUẬN, ĐÓNG GÓP KHOA HỌC VÀ HƯỚNG PHÁT TRIỂN", "95"),
        ("TÀI LIỆU THAM KHẢO", "99"),
        ("PHỤ LỤC A, B, C", "103"),
    ]
    for item, page in toc_items:
        p = b.doc.add_paragraph()
        p.paragraph_format.space_after = Pt(3)
        r1 = p.add_run(item)
        r1.font.bold = True
        r1.font.size = Pt(12)
        r1.font.color.rgb = COLOR_PRIMARY
        dots_len = max(5, 72 - len(item))
        r_dots = p.add_run(" " + ". " * (dots_len // 2) + " ")
        r_dots.font.color.rgb = COLOR_MUTED
        r2 = p.add_run(page)
        r2.font.bold = True
        r2.font.size = Pt(12)
        r2.font.color.rgb = COLOR_PRIMARY
    b.add_page_break()

    # 7. DANH MỤC TỪ VIẾT TẮT
    b.add_heading_1("DANH MỤC TỪ VIẾT TẮT")
    abbrev_data = [
        ("AI / LLM", "Artificial Intelligence / Large Language Model", "Trí tuệ nhân tạo / Mô hình ngôn ngữ lớn"),
        ("OWASP", "Open Web Application Security Project", "Dự án bảo mật ứng dụng web mở"),
        ("MITRE ATLAS", "Adversarial Threat Landscape for AI Systems", "Ma trận hiểm họa đối kháng cho hệ thống AI"),
        ("NIST AI RMF", "NIST AI Risk Management Framework", "Khung quản trị rủi ro AI của Viện Tiêu chuẩn Mỹ"),
        ("RAG", "Retrieval-Augmented Generation", "Tạo sinh tăng cường truy xuất tri thức"),
        ("ASR", "Attack Success Rate", "Tỷ lệ tấn công thành công"),
        ("CVSS / ISS", "Common Vulnerability Scoring System / Impact Sub-Score", "Hệ thống chấm điểm lỗ hổng / Chỉ số tác động"),
        ("DSL", "Domain-Specific Language", "Ngôn ngữ đặc tả chuyên biệt (YAML Testcase)"),
        ("SSE", "Server-Sent Events", "Giao thức truyền phát sự kiện thời gian thực"),
        ("ART", "Adversarial Robustness Toolbox", "Bộ công cụ kiểm thử bền vững học máy đối kháng"),
        ("PyRIT", "Python Risk Identification Tool", "Công cụ nhận diện rủi ro AI tạo sinh của Microsoft"),
    ]
    b.add_academic_table(
        headers=["Ký hiệu", "Tên tiếng Anh đầy đủ", "Ý nghĩa / Dịch nghĩa tiếng Việt"],
        rows=abbrev_data,
        caption="Danh mục các từ viết tắt và thuật ngữ kỹ thuật sử dụng trong báo cáo",
        col_widths=[1.4, 2.5, 2.5]
    )
    b.add_page_break()

    # 8. LỜI MỞ ĐẦU
    b.add_heading_1("LỜI MỞ ĐẦU")
    b.add_heading_2("1. Tính Cấp Thiết Của Đề Tài")
    b.add_p(
        "Sự bùng nổ của các mô hình ngôn ngữ lớn (LLMs) như GPT-4o, LLaMA-3, Mistral, Qwen cùng các kiến trúc RAG và AI Agent đang chuyển dịch vai trò của AI "
        "từ công cụ hỗ trợ tham vấn sang trực tiếp ra quyết định và điều hành tác vụ trong ngân hàng số, y tế, dịch vụ công và doanh nghiệp. "
        "Tuy nhiên, các giải pháp bảo mật truyền thống (WAF, IDS/IPS, Antivirus) hoàn toàn bất lực trước các đòn thao túng ẩn trong ngôn ngữ tự nhiên. "
        "Đặc biệt tại Việt Nam, các công cụ mã nguồn mở quốc tế chưa hỗ trợ ngữ cảnh tiếng Việt và thiếu khả năng kiểm thử xuyên tầng (LLM – RAG – Agent – ML). "
        "Do đó, việc nghiên cứu phương pháp và phát triển bộ công cụ kiểm thử an toàn tự động cho các hệ thống AI là nhiệm vụ cấp thiết."
    )

    b.add_heading_2("2. Mục Tiêu Nghiên Cứu (Bám Sát 6 Nội Dung Thực Hiện)")
    b.add_bullet("Nghiên cứu các phương pháp, kỹ thuật và tiêu chí kiểm thử an toàn đối với hệ thống AI; trên cơ sở đó phát triển bộ công cụ hỗ trợ tự động kiểm tra, phát hiện, đánh giá và báo cáo các nguy cơ, điểm yếu và lỗ hổng an toàn của hệ thống AI.", "Mục tiêu tổng quát")
    b.add_bullet("Nghiên cứu tổng quan lý thuyết, 3 nghịch lý bảo mật AI, chuẩn OWASP LLM Top 10 2025, MITRE ATLAS, NIST AI RMF và xác lập 7 khoảng trống khoa học (G1–G7).", "Nội dung 1")
    b.add_bullet("Xây dựng mô hình hóa đe dọa tự động (Threat Model), Taxonomy 14 module đa tầng, ngôn ngữ YAML DSL và tiêu chí chấm điểm rủi ro toán học CVSS-like.", "Nội dung 2")
    b.add_bullet("Nghiên cứu phương pháp sinh testcase đối kháng thích nghi (Adaptive Generator 13 chiến lược đột biến) và kiến trúc phát hiện hai tầng lai ghép (Two-Tier Hybrid).", "Nội dung 3")
    b.add_bullet("Thiết kế, phát triển bộ công cụ kiểm thử tự động hoàn chỉnh gồm Agent Sandbox, Evidence Replay Store, CLI Scanner và Web Dashboard thời gian thực (SSE).", "Nội dung 4")
    b.add_bullet("Tích hợp liên minh 6 công cụ mã nguồn mở quốc tế (Garak, PyRIT, Promptfoo, DeepTeam, Giskard, ART) và đối chuẩn cơ chế đánh giá rủi ro.", "Nội dung 5")
    b.add_bullet("Thực nghiệm, kiểm chứng định lượng đa mô hình, thực hiện Ablation Study và đánh giá trên bộ Benchmark 62 kịch bản tiếng Việt kèm kiểm định thống kê.", "Nội dung 6")

    b.add_heading_2("3. Hệ Thống Câu Hỏi Nghiên Cứu (RQ1 – RQ8)")
    rq_rows = [
        ("RQ1", "Mô hình hóa thống nhất", "Làm thế nào mô hình hóa một hệ thống AI gồm LLM, RAG, Agent, tool/API và dữ liệu thành một đối tượng kiểm thử thống nhất?"),
        ("RQ2", "Sinh testcase thích nghi", "Làm thế nào tự động sinh testcase đối kháng có tính đa dạng, có mục tiêu và thích nghi theo phản hồi động của hệ thống?"),
        ("RQ3", "Phối hợp chiến lược", "Làm thế nào phối hợp nhiều chiến lược tấn công (13 phép đột biến, LLM-generated, multi-turn) để tối đa hóa độ bao phủ và tỷ lệ ASR?"),
        ("RQ4", "Phát hiện & Bằng chứng", "Làm thế nào phát hiện và xác nhận lỗ hổng với bằng chứng có thể tái lập (Replay), triệt tiêu đồng thời False Positive và False Negative?"),
        ("RQ5", "Chấm điểm thống nhất", "Làm thế nào xây dựng mô hình scoring CVSS-like thống nhất kết hợp Impact (CIA), Exploitability và Reproducibility?"),
        ("RQ6", "Đánh giá đa mô hình", "Làm thế nào đánh giá công bằng và có ý nghĩa thống kê các hệ thống AI khác nhau qua nhiều random seeds?"),
        ("RQ7", "Đặc trưng RAG & Agent", "Những đặc trưng kiến trúc nào của RAG (Vector DB) và Agent (Tool Calling) làm mở rộng bề mặt tấn công (RMR, URR, TAR, DER)?"),
        ("RQ8", "Benchmark Tiếng Việt", "Làm thế nào xây dựng bộ benchmark tiếng Việt thực tế để đo lường hiệu quả guardrail nội địa và kiểm định khoảng cách an toàn đa ngôn ngữ?")
    ]
    b.add_academic_table(
        headers=["Mã RQ", "Trọng tâm khoa học", "Nội dung Câu hỏi Nghiên cứu"],
        rows=rq_rows,
        caption="Hệ thống 8 câu hỏi nghiên cứu (RQ1 – RQ8) định hướng toàn bộ đề tài",
        col_widths=[0.8, 1.8, 4.4]
    )

    b.add_heading_2("4. Đối Tượng Và Phạm Vi Nghiên Cứu (5 Phạm Vi Đa Tầng)")
    b.add_bullet("Kiểm thử Prompt Injection, Jailbreak đơn lượt và đa lượt (Crescendo), System Prompt Leakage, Sensitive Disclosure, Misinformation, Model DoS.", "Phạm vi 1 – LLM / GenAI")
    b.add_bullet("Kiểm thử đầu độc tài liệu tri thức (RAG Poisoning), thao túng truy xuất (Retrieval Manipulation), tiêm nhiễm gián tiếp và rò rỉ dữ liệu qua ngữ cảnh.", "Phạm vi 2 – Hệ thống RAG")
    b.add_bullet("Kiểm thử lạm dụng công cụ (Tool Abuse), vượt quyền hạn (Excessive Agency), tiêm nhiễm tham số hàm trong môi trường cô lập Agent Sandbox.", "Phạm vi 3 – AI Agent & Tool/API")
    b.add_bullet("Kiểm thử độ bền vững trước mẫu đối kháng (Adversarial Examples: Homoglyph, Zero-width, Unicode Normalization, FGSM/PGD/TextFooler).", "Phạm vi 4 – Mô hình ML / DL")
    b.add_bullet("Tự động hóa toàn trình từ chuẩn hóa YAML DSL, lưu vết bằng chứng (Evidence Store), tái lập kiểm thử (Replay) đến xuất báo cáo quản trị rủi ro.", "Phạm vi 5 – Đánh giá Tự động & Tái lập")

    b.add_page_break()