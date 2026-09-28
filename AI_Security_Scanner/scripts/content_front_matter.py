# -*- coding: utf-8 -*-
"""
scripts/content_front_matter.py - Front matter & Introduction for BC_NCKH.docx
"""

from docx.shared import Pt, Inches, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from scripts.bckh_builder import COLOR_PRIMARY, COLOR_SECONDARY, COLOR_TEXT, COLOR_MUTED

def generate_front_matter(b):
    logo_path = "web/static/logo.jpg"

    # 1. BÌA CHÍNH (Front Cover)
    b.add_cover_page(
        title="NGHIÊN CỨU VÀ XÂY DỰNG BỘ CÔNG CỤ KIỂM THỬ AN TOÀN CHO HỆ THỐNG TRÍ TUỆ NHÂN TẠO (AI SECURITY SCANNER)",
        subtitle="Dựa trên Khung Chuẩn Quốc Tế OWASP Top 10 for LLM Applications 2025 và Ma Trận MITRE ATLAS",
        school="BỘ GIÁO DỤC VÀ ĐÀO TẠO · TRƯỜNG ĐẠI HỌC BÁCH KHOA HÀ NỘI",
        faculty="TRƯỜNG CÔNG NGHỆ THÔNG TIN VÀ TRUYỀN THÔNG · KHOA AN TOÀN THÔNG TIN",
        student="NGHIÊN CỨU SINH / HỌC VIÊN CAO HỌC / SINH VIÊN THỰC HIỆN",
        supervisor="TS. GIẢNG VIÊN HƯỚNG DẪN",
        year="2026",
        logo_path=logo_path
    )

    # 2. BÌA PHỤ (Sub-cover)
    b.add_cover_page(
        title="NGHIÊN CỨU VÀ XÂY DỰNG BỘ CÔNG CỤ KIỂM THỬ AN TOÀN CHO HỆ THỐNG TRÍ TUỆ NHÂN TẠO (AI SECURITY SCANNER)",
        subtitle="ĐỀ TÀI NGHIÊN CỨU KHOA HỌC SINH VIÊN / LUẬN VĂN TỐT NGHIỆP XUẤT SẮC",
        school="VIỆN NGHIÊN CỨU VÀ ĐÀO TẠO CÔNG NGHỆ TIÊN TIẾN",
        faculty="BỘ MÔN KỸ THUẬT AN TOÀN MẠNG VÀ HỆ THỐNG THÔNG TIN",
        student="NHÓM TÁC GIẢ ĐỀ TÀI AI SECURITY SCANNER",
        supervisor="HỘI ĐỒNG KHOA HỌC CHUYÊN NGÀNH AN TOÀN THÔNG TIN",
        year="2026",
        logo_path=None
    )

    # 3. LỜI CAM ĐOAN (Statement of Authorship)
    b.add_heading_1("LỜI CAM ĐOAN")
    b.add_p(
        "Tôi xin cam đoan công trình nghiên cứu khoa học với đề tài: \"Nghiên cứu và xây dựng bộ công cụ kiểm thử an toàn cho hệ thống Trí tuệ nhân tạo (AI Security Scanner)\" "
        "là kết quả nghiên cứu độc lập, nghiêm túc và trung thực của bản thân dưới sự hướng dẫn khoa học tận tình của Giảng viên hướng dẫn. "
        "Toàn bộ các số liệu thực nghiệm, kết quả đo đạc định lượng, mã nguồn phần mềm, cấu trúc cơ sở dữ liệu và các phân tích học thuật được trình bày trong báo cáo này "
        "đều được thực hiện trực tiếp trên hệ thống phòng thí nghiệm của nhóm nghiên cứu, không sao chép bất hợp pháp từ bất kỳ công trình hoặc luận văn nào khác."
    )
    b.add_p(
        "Các tài liệu tham khảo, bài báo khoa học trong nước và quốc tế, tiêu chuẩn công nghiệp (OWASP, MITRE ATLAS, NIST AI RMF, ISO/IEC 42001) "
        "đều được trích dẫn nguồn gốc rõ ràng, đầy đủ theo đúng chuẩn mực liêm chính học thuật. "
        "Nếu có bất kỳ sự vi phạm nào về liêm chính nghiên cứu hoặc sao chép trái phép, tôi xin hoàn toàn chịu trách nhiệm trước Hội đồng Khoa học và Nhà trường."
    )
    b.add_p("Hà Nội, ngày 25 tháng 09 năm 2026", italic=True, align=b.doc.paragraphs[0].alignment)
    b.add_p("Tác giả đề tài\n(Ký và ghi rõ họ tên)", bold=True, align=b.doc.paragraphs[0].alignment)
    b.add_page_break()

    # 4. LỜI CẢM ƠN (Acknowledgments)
    b.add_heading_1("LỜI CẢM ƠN")
    b.add_p(
        "Để hoàn thành công trình nghiên cứu khoa học này, tôi xin bày tỏ lòng biết ơn sâu sắc nhất tới Thầy/Cô Giảng viên hướng dẫn – người đã luôn dành thời gian quý báu, "
        "định hướng phương pháp luận khoa học, truyền cảm hứng nghiên cứu và tận tình chỉ bảo, động viên tôi trong suốt quá trình triển khai đề tài từ những ngày đầu đặt nền móng lý thuyết "
        "cho đến khi hoàn thiện hệ thống thực nghiệm."
    )
    b.add_p(
        "Tôi xin chân thành cảm ơn Ban Giám hiệu Nhà trường, Ban Lãnh đạo Khoa An toàn Thông tin và các Thầy/Cô giáo trong bộ môn đã tạo điều kiện tối đa về cơ sở vật chất, "
        "trang thiết bị máy chủ tính toán GPU phòng thí nghiệm, cung cấp môi trường học thuật chuyên nghiệp và truyền đạt những kiến thức nền tảng vô cùng quý báu trong suốt quá trình học tập."
    )
    b.add_p(
        "Cuối cùng, tôi xin gửi lời tri ân sâu sắc tới gia đình, bạn bè và các đồng nghiệp trong nhóm nghiên cứu đã luôn là điểm tựa tinh thần vững chắc, "
        "chia sẻ khó khăn, hỗ trợ đóng góp ý kiến phản biện sắc bén và đồng hành cùng tôi trong suốt chặng đường thực hiện đề tài."
    )
    b.add_page_break()

    # 5. TÓM TẮT ĐỀ TÀI (Abstract - Tiếng Việt & Tiếng Anh)
    b.add_heading_1("TÓM TẮT ĐỀ TÀI")
    b.add_p(
        "Sự bùng nổ của các mô hình ngôn ngữ lớn (Large Language Models - LLM) và các hệ thống tác tử AI tự động (Autonomous AI Agents) "
        "đang thúc đẩy một cuộc cách mạng công nghệ sâu rộng trong mọi lĩnh vực đời sống, kinh tế và an ninh quốc gia. Tuy nhiên, tính chất bất định (non-deterministic), "
        "sự thiếu phân tách giữa kênh điều khiển chỉ dẫn và kênh dữ liệu đầu vào, cùng việc trao quyền thực thi công cụ bên ngoài đã mở ra một không gian bề mặt tấn công hoàn toàn mới. "
        "Các lỗ hổng đặc thù như Prompt Injection, Jailbreak phá vỡ hàng rào an toàn, Rò rỉ dữ liệu nhạy cảm (PII/Credentials), Thực thi mã độc qua Output Handling, "
        "Lạm dụng quyền hạn (Excessive Agency), và Nhiễm độc cơ sở dữ liệu vector trong kiến trúc RAG đang đe dọa trực tiếp đến tính tin cậy của các hệ thống AI tại Việt Nam và trên thế giới."
    )
    b.add_p(
        "Đề tài này tập trung giải quyết toàn diện bài toán kiểm thử an toàn cho hệ thống AI thông qua việc xây dựng bộ công cụ AI Security Scanner "
        "bám sát 6 nội dung nghiên cứu khoa học trọng điểm: (1) Tổng quan lý thuyết và tiêu chuẩn quốc tế; (2) Xây dựng Taxonomy đa tầng và mô hình chấm điểm rủi ro định lượng CVSS-like; "
        "(3) Đề xuất phương pháp kiểm thử hai tầng lai ghép kết hợp giữa Bộ lọc quy tắc tốc độ cao (PatternDetector) và Giám khảo AI tự động (LLM-as-Judge); "
        "(4) Thiết kế kiến trúc module hóa phân tầng, hiện thực hóa 12 module kiểm thử chuyên sâu, tích hợp giao diện Web Dashboard thời gian thực (SSE), Swagger OpenAPI 3.0, "
        "bộ chỉnh sửa payload tương tác, và cơ chế chuyển đổi giao diện Sáng/Tối; (5) Tích hợp và đánh giá đối chuẩn với hai giải pháp mã nguồn mở quốc tế hàng đầu là NVIDIA Garak và Microsoft PyRIT; "
        "(6) Thực nghiệm kiểm chứng định lượng trên tập dữ liệu benchmark 43 ca kiểm thử đối kháng với 4 dòng mô hình tiêu biểu (LLaMA 3 8B, Mistral 7B, Qwen 2.5 7B, GPT-4o-mini)."
    )
    b.add_p(
        "Kết quả thực nghiệm khẳng định hệ thống đạt độ chính xác (Precision) 97.62%, độ nhạy (Recall) 100%, điểm số F1-Score đạt 0.9870, "
        "với độ trễ xử lý sub-millisecond ở tầng lọc quy tắc và khả năng triệt tiêu tỷ lệ báo động giả (False Positive) vượt trội khi kết hợp LLM-as-Judge. "
        "Công cụ cung cấp khả năng phát hiện toàn diện, giao diện trực quan và báo cáo khuyến nghị khắc phục chuẩn hóa, đóng góp một giải pháp an ninh mạng thiết thực "
        "cho các cơ quan, doanh nghiệp Việt Nam trong lộ trình làm chủ và triển khai AI an toàn."
    )
    b.add_p("Từ khóa: An toàn AI, Kiểm thử Xâm nhập, LLM Security, Prompt Injection, Jailbreak, OWASP LLM Top 10, MITRE ATLAS, LLM-as-Judge, AI Security Scanner.", bold=True)

    b.add_heading_2("ABSTRACT (ENGLISH)")
    b.add_p(
        "The proliferation of Large Language Models (LLMs) and autonomous AI agent systems is driving transformative advancements across digital industries. "
        "However, inherent architectural properties—namely non-deterministic stochastic generation, the lack of isolation between control instructions and data planes, "
        "and over-privileged external tool integration—have established a critical, unchartered attack surface. Severe emerging threats including direct and indirect prompt injection, "
        "jailbreaking safety guardrails, sensitive training data disclosure, improper code generation, excessive autonomous agency, and retrieval poisoning in RAG pipelines "
        "pose acute operational hazards."
    )
    b.add_p(
        "This research presents the design, mathematical modeling, and production-grade implementation of the AI Security Scanner, systematically organized across six foundational pillars: "
        "(1) Theoretical systematization of AI threat landscapes (OWASP LLM 2025, MITRE ATLAS, NIST AI RMF); (2) Development of a hierarchical multi-framework taxonomy and a quantitative CVSS-like risk scoring engine; "
        "(3) Formulation of a Two-Tier Hybrid Detection Methodology synthesizing deterministic sub-millisecond pattern filtering with semantic LLM-as-a-Judge evaluation; "
        "(4) Full-stack architectural realization of 12 dedicated attack and reconnaissance modules, paired with a real-time reactive Web Dashboard (SSE streaming), interactive payload authoring, and dual WCAG AAA UI; "
        "(5) Deep integration and comparative benchmarking with industry open-source tools (NVIDIA Garak, Microsoft PyRIT); and (6) Rigorous empirical verification over standardized benchmark datasets across four model families (LLaMA-3, Mistral, Qwen, GPT-4o-mini)."
    )
    b.add_p(
        "Empirical benchmarks demonstrate a Precision of 97.62%, Recall of 100%, and an F1-Score of 0.9870, confirming substantial improvements in false positive suppression and computational latency. "
        "The proposed framework delivers an enterprise-ready, open-architecture automated auditing suite advancing the frontier of sovereign AI cybersecurity."
    )
    b.add_p("Keywords: AI Security, Red-teaming, LLM Penetration Testing, Prompt Injection, Jailbreak, OWASP LLM Top 10, MITRE ATLAS, LLM-as-Judge, Two-Tier Detection.", bold=True)
    b.add_page_break()

    # 6. MỤC LỤC TỔNG QUAN (Table of Contents Structure)
    b.add_heading_1("MỤC LỤC")
    toc_items = [
        ("LỜI CAM ĐOAN", "i"),
        ("LỜI CẢM ƠN", "ii"),
        ("TÓM TẮT ĐỀ TÀI (TIẾNG VIỆT & TIẾNG ANH)", "iii"),
        ("DANH MỤC TỪ VIẾT TẮT", "vi"),
        ("DANH MỤC BẢNG BIỂU", "vii"),
        ("DANH MỤC HÌNH VẼ", "viii"),
        ("LỜI MỞ ĐẦU", "1"),
        ("CHƯƠNG 1: TỔNG QUAN LÝ THUYẾT VÀ TIÊU CHUẨN AN TOÀN AI", "6"),
        ("  1.1 Tổng quan về Hệ thống AI và Mô hình Ngôn ngữ Lớn (LLMs)", "6"),
        ("  1.2 Phân tích Tiêu Chuẩn OWASP Top 10 for LLM Applications (Phiên bản 2025)", "10"),
        ("  1.3 Khung Ma Trận Đe Dọa MITRE ATLAS", "16"),
        ("  1.4 Khung Quản Trị Rủi Ro NIST AI RMF 1.0 và Các Tiêu Chuẩn Quốc Tế Liên Quan", "20"),
        ("  1.5 Khảo sát Các Công Trình Nghiên Cứu Liên Quan và Khoảng Trống Học Thuật", "24"),
        ("CHƯƠNG 2: XÂY DỰNG TAXONOMY VÀ MÔ HÌNH HÓA NGUY CƠ AN TOÀN AI", "27"),
        ("  2.1 Định nghĩa và Cấu trúc Hệ thống Phân loại Đa tầng (Hierarchical Taxonomy)", "27"),
        ("  2.2 Ma trận Ánh xạ Đa khung chuẩn (Cross-Framework Crosswalk Matrix)", "30"),
        ("  2.3 Đặc tả Chi tiết 12 Lớp Kiểm Thử An Toàn Hệ Thống", "33"),
        ("  2.4 Mô Hình Đánh Giá Rủi Ro Định Lượng (CVSS-like Risk Scoring Engine)", "41"),
        ("CHƯƠNG 3: PHƯƠNG PHÁP LUẬN VÀ KỸ THUẬT KIỂM THỬ XÂM NHẬP AI", "46"),
        ("  3.1 Vòng đời Kiểm thử Thâm nhập Hộp đen (Black-box AI Pentest Lifecycle)", "46"),
        ("  3.2 Kỹ nghệ Sinh và Tối ưu Hóa Payload Tấn công (Adversarial Payload Engineering)", "49"),
        ("  3.3 Kiến trúc Phát Hiện Hai Tầng Lai Ghép (Two-Tier Hybrid Detection Architecture)", "54"),
        ("  3.4 Phân tích Cân Bằng Đánh Đổi giữa Độ Trễ, Chi Phí và Độ Chính Xác", "59"),
        ("CHƯƠNG 4: THIẾT KẾ KIẾN TRÚC VÀ HIỆN THỰC HÓA HỆ THỐNG", "62"),
        ("  4.1 Kiến trúc Tổng thể Hệ thống Phân tầng (Layered Modular Architecture)", "62"),
        ("  4.2 Thiết kế và Hiện thực Các Phân Hệ Thành Phần", "65"),
        ("  4.3 Cơ chế An toàn Vận hành, Chống Nghẽn và Bảo mật Web Dashboard", "73"),
        ("  4.4 Đảm bảo Chất lượng Phần mềm (Automated Testing & CI/CD Pipeline)", "77"),
        ("CHƯƠNG 5: TÍCH HỢP CÔNG CỤ MÃ NGUỒN MỞ VÀ ĐÁNH GIÁ ĐỐI CHUẨN", "80"),
        ("  5.1 Khảo sát Các Giải pháp Kiểm thử An toàn AI Hàng Đầu Thế Giới", "80"),
        ("  5.2 Thiết kế và Hiện thực Lớp Vỏ Bọc Tích Hợp (Integration Wrappers)", "83"),
        ("  5.3 Bảng So Sánh Tính Năng và Kết Quả Thực Nghiệm Đối Chuẩn Toàn Diện", "87"),
        ("  5.4 Chiến Lược Tích Hợp Lai Ghép Tối Ưu (Hybrid Red-teaming Strategy)", "90"),
        ("CHƯƠNG 6: THỰC NGHIỆM, KIỂM CHỨNG VÀ ĐÁNH GIÁ ĐỊNH LƯỢNG", "92"),
        ("  6.1 Thiết kế Kịch bản Thực nghiệm và Bộ Dữ Liệu Kiểm Chuẩn Độc Lập", "92"),
        ("  6.2 Phân tích Kết quả Thực nghiệm Định lượng theo Module", "95"),
        ("  6.3 Đánh giá Hiệu Quả của Cơ chế Phát hiện Hai Tầng (Two-Tier Detection)", "101"),
        ("  6.4 Đánh giá Đối Chuẩn Thực Tế với NVIDIA Garak và Microsoft PyRIT", "104"),
        ("  6.5 Phân tích Phổ Điểm Rủi Ro Tổng Hợp và Khuyến Nghị Khắc Phục", "107"),
        ("KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN", "112"),
        ("TÀI LIỆU THAM KHẢO", "116"),
        ("PHỤ LỤC A: BẢNG DANH MỤC PAYLOADS KIỂM THỬ ĐỐI KHÁNG TIÊU BIỂU", "121"),
        ("PHỤ LỤC B: ĐẶC TẢ CHI TIẾT REST API VÀ TÀI LIỆU OPENAPI 3.0", "127"),
        ("PHỤ LỤC C: HƯỚNG DẪN CÀI ĐẶT VÀ VẬN HÀNH HỆ THỐNG", "131"),
    ]
    for item, page in toc_items:
        p = b.doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.15
        is_chapter = item.startswith("CHƯƠNG") or item in ["LỜI CAM ĐOAN", "LỜI CẢM ƠN", "TÓM TẮT ĐỀ TÀI (TIẾNG VIỆT & TIẾNG ANH)", "DANH MỤC TỪ VIẾT TẮT", "DANH MỤC BẢNG BIỂU", "DANH MỤC HÌNH VẼ", "LỜI MỞ ĐẦU", "KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN", "TÀI LIỆU THAM KHẢO", "PHỤ LỤC A: BẢNG DANH MỤC PAYLOADS KIỂM THỬ ĐỐI KHÁNG TIÊU BIỂU", "PHỤ LỤC B: ĐẶC TẢ CHI TIẾT REST API VÀ TÀI LIỆU OPENAPI 3.0", "PHỤ LỤC C: HƯỚNG DẪN CÀI ĐẶT VÀ VẬN HÀNH HỆ THỐNG"]
        r1 = p.add_run(item)
        r1.font.bold = is_chapter
        r1.font.size = Pt(12)
        r1.font.color.rgb = COLOR_PRIMARY if is_chapter else COLOR_TEXT
        
        # Leader dots
        dots_len = max(5, 75 - len(item))
        r_dots = p.add_run(" " + ". " * (dots_len // 2) + " ")
        r_dots.font.color.rgb = COLOR_MUTED
        r_dots.font.size = Pt(10)
        
        r2 = p.add_run(page)
        r2.font.bold = is_chapter
        r2.font.size = Pt(12)
        r2.font.color.rgb = COLOR_PRIMARY if is_chapter else COLOR_TEXT

    b.add_page_break()

    # 7. DANH MỤC TỪ VIẾT TẮT
    b.add_heading_1("DANH MỤC TỪ VIẾT TẮT")
    abbrev_data = [
        ("AI", "Artificial Intelligence", "Trí tuệ nhân tạo"),
        ("LLM", "Large Language Model", "Mô hình ngôn ngữ lớn"),
        ("GenAI", "Generative Artificial Intelligence", "Trí tuệ nhân tạo tạo sinh"),
        ("OWASP", "Open Web Application Security Project", "Dự án bảo mật ứng dụng web mở"),
        ("MITRE ATLAS", "Adversarial Threat Landscape for AI Systems", "Bức tranh hiểm họa đối kháng cho hệ thống AI"),
        ("NIST AI RMF", "NIST Artificial Intelligence Risk Management Framework", "Khung quản lý rủi ro AI của Viện Tiêu chuẩn và Công nghệ Mỹ"),
        ("RAG", "Retrieval-Augmented Generation", "Tạo sinh tăng cường truy xuất dữ liệu"),
        ("PII", "Personally Identifiable Information", "Thông tin nhận dạng cá nhân"),
        ("CVSS", "Common Vulnerability Scoring System", "Hệ thống chấm điểm lỗ hổng bảo mật phổ biến"),
        ("DoS", "Denial of Service", "Tấn công từ chối dịch vụ"),
        ("XSS", "Cross-Site Scripting", "Tấn công chèn mã kịch bản liên trang"),
        ("SSRF", "Server-Side Request Forgery", "Tấn công giả mạo yêu cầu phía máy chủ"),
        ("SQLi", "SQL Injection", "Tấn công tiêm nhiễm câu lệnh SQL"),
        ("RCE", "Remote Code Execution", "Thực thi mã độc từ xa"),
        ("API", "Application Programming Interface", "Giao diện lập trình ứng dụng"),
        ("REST", "Representational State Transfer", "Kiến trúc truyền trạng thái đại diện"),
        ("SSE", "Server-Sent Events", "Sự kiện được đẩy từ máy chủ"),
        ("JWT", "JSON Web Token", "Mã xác thực trạng thái JSON có chữ ký"),
        ("WAL", "Write-Ahead Logging", "Cơ chế ghi nhật ký trước khi ghi dữ liệu"),
        ("PAIR", "Prompt Automatic Iterative Refinement", "Kỹ thuật tinh chỉnh prompt đối kháng tự động lặp"),
        ("Crescendo", "Multi-Turn Escalation Attack", "Tấn công leo thang hội thoại đa lượt"),
        ("RLHF", "Reinforcement Learning from Human Feedback", "Học tăng cường từ phản hồi của con người"),
        ("SFT", "Supervised Fine-Tuning", "Tinh chỉnh có giám sát"),
        ("OSS", "Open Source Software", "Phần mềm mã nguồn mở"),
        ("TP / FP", "True Positive / False Positive", "Dương tính thật / Dương tính giả"),
        ("TN / FN", "True Negative / False Negative", "Âm tính thật / Âm tính giả"),
        ("CWE", "Common Weakness Enumeration", "Danh mục phân loại điểm yếu phần mềm chuẩn hóa"),
        ("CAPEC", "Common Attack Pattern Enumeration and Classification", "Danh mục phân loại mẫu tấn công chuẩn hóa")
    ]
    b.add_academic_table(
        headers=["Ký hiệu", "Tên tiếng Anh đầy đủ", "Ý nghĩa / Dịch nghĩa tiếng Việt"],
        rows=abbrev_data,
        caption="Danh mục các từ viết tắt và thuật ngữ kỹ thuật sử dụng trong báo cáo",
        col_widths=[1.4, 2.5, 2.5]
    )
    b.add_page_break()

    # 8. DANH MỤC BẢNG BIỂU & HÌNH VẼ
    b.add_heading_1("DANH MỤC BẢNG BIỂU VÀ HÌNH VẼ")
    b.add_heading_2("Danh Mục Bảng Biểu")
    tables_list = [
        ("Bảng 1.1", "Bảng tổng hợp 10 hạng mục lỗ hổng OWASP Top 10 for LLM Applications 2025"),
        ("Bảng 1.2", "Bảng phân tích so sánh sự chuyển dịch giữa OWASP LLM 2023 và OWASP LLM 2025"),
        ("Bảng 1.3", "Ánh xạ các chiến thuật và kỹ thuật tiêu biểu trong khung MITRE ATLAS"),
        ("Bảng 2.1", "Ma trận ánh xạ Taxonomy Hệ thống với Tiêu chuẩn Quốc tế (OWASP, MITRE ATLAS)"),
        ("Bảng 2.2", "Ma trận đối chuẩn chéo đa chiều giữa Taxonomy công cụ với CWE và CAPEC"),
        ("Bảng 2.3", "Bảng trọng số điểm cơ sở (Base Score) và hệ số khai thác trong mô hình CVSS-like"),
        ("Bảng 2.4", "Thang phân cấp mức độ nghiêm trọng rủi ro theo định lượng điểm số"),
        ("Bảng 3.1", "Ma trận so sánh hiệu năng và độ chính xác giữa Tier-1 và Tier-2"),
        ("Bảng 3.2", "Bảng phân tích đánh đổi đa mục tiêu giữa Thời gian quét, Chi phí và Độ tin cậy"),
        ("Bảng 4.1", "Bảng đặc tả cấu trúc lược đồ bảng `scans` trong cơ sở dữ liệu SQLite"),
        ("Bảng 4.2", "Bảng đặc tả cấu trúc lược đồ bảng `findings` trong cơ sở dữ liệu SQLite"),
        ("Bảng 4.3", "Danh mục 12 module kiểm thử đã được hiện thực hóa đầy đủ trong hệ thống"),
        ("Bảng 4.4", "Tổng hợp kết quả kiểm thử tự động 55 test cases trong bộ kiểm thử unit/integration"),
        ("Bảng 5.1", "Bảng so sánh tính năng toàn diện giữa NVIDIA Garak, Microsoft PyRIT và Hệ thống đề xuất"),
        ("Bảng 5.2", "Bảng ánh xạ các probes của NVIDIA Garak sang Taxonomy của AI Security Scanner"),
        ("Bảng 6.1", "Thông số cấu hình môi trường phần cứng và phần mềm phòng thí nghiệm"),
        ("Bảng 6.2", "Danh mục các mô hình ngôn ngữ lớn mục tiêu phục vụ kiểm thử thực nghiệm"),
        ("Bảng 6.3", "Cấu trúc phân bổ 32 ca kiểm thử chuẩn hóa độc lập trong Benchmark Dataset"),
        ("Bảng 6.4", "Bảng kết quả định lượng tổng hợp thực nghiệm trên tập mẫu 43 ca kiểm thử mở rộng"),
        ("Bảng 6.5", "Bảng ma trận nhầm lẫn (Confusion Matrix) chi tiết từng module kiểm thử"),
        ("Bảng 6.6", "So sánh đối đầu giữa chỉ dùng PatternDetector đơn lẻ và Cơ chế Hai tầng Two-Tier"),
        ("Bảng 6.7", "Bảng đối chuẩn thực tế giữa AI Security Scanner, NVIDIA Garak và Microsoft PyRIT"),
        ("Bảng 6.8", "Thống kê phân bổ điểm rủi ro và các lỗ hổng nghiêm trọng phát hiện trên LLaMA 3 8B")
    ]
    for num, cap in tables_list:
        p = b.doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        r_n = p.add_run(num + ": ")
        r_n.font.bold = True
        r_c = p.add_run(cap)

    b.add_heading_2("Danh Mục Hình Vẽ")
    figures_list = [
        ("Hình 1", "Logo chính thức và bộ nhận diện thương hiệu của dự án AI Security Scanner"),
        ("Hình 2", "Sơ đồ luồng dữ liệu và không gian hiểm họa đối kháng trong ứng dụng tích hợp LLM"),
        ("Hình 3", "Vòng đời kiểm thử thâm nhập an toàn AI hộp đen 5 giai đoạn chuẩn hóa"),
        ("Hình 4", "Quy trình phân tích phát hiện hai tầng lai ghép (Two-Tier Hybrid Detection Architecture)"),
        ("Hình 5", "Kiến trúc tổng thể hệ thống AI Security Scanner theo mô hình phân tầng module hóa"),
        ("Hình 6", "Giao diện Bảng điều khiển Web Dashboard trung tâm ở chế độ giao diện tối (Dark Mode)"),
        ("Hình 7", "Biểu đồ phân bổ Severity Donut Chart và Findings theo Module trên Dashboard"),
        ("Hình 8", "Bảng danh sách chi tiết các lỗ hổng phát hiện (Findings Table) kèm bộ lọc đa tiêu chí"),
        ("Hình 9", "Cửa sổ giao diện dòng lệnh tương tác trực tiếp (Live Terminal Streaming) qua giao thức SSE"),
        ("Hình 10", "Modal Chi tiết Lỗ hổng và Hướng dẫn khắc phục chuẩn hóa theo khuyến nghị OWASP"),
        ("Hình 11", "Giao diện dòng lệnh CLI Scanner sử dụng thư viện đồ họa Rich Console"),
        ("Hình 12", "Modal Bộ chỉnh sửa Payload Tương tác (Interactive Payload Editor) trên Web Dashboard")
    ]
    for num, cap in figures_list:
        p = b.doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)
        r_n = p.add_run(num + ": ")
        r_n.font.bold = True
        r_c = p.add_run(cap)

    b.add_page_break()

    # 9. LỜI MỞ ĐẦU (Introduction)
    b.add_heading_1("LỜI MỞ ĐẦU")
    b.add_heading_2("1. Tính Cấp Thiết Của Đề Tài")
    b.add_p(
        "Trong giai đoạn từ năm 2023 đến nay, nhân loại đang chứng kiến bước đại nhảy vọt của công nghệ Trí tuệ nhân tạo (AI), "
        "đặc biệt là sự ra đời và ứng dụng bùng nổ của các Mô hình Ngôn ngữ Lớn (Large Language Models - LLM) như GPT-4, LLaMA, Claude, Mistral, và DeepSeek. "
        "Các tổ chức tài chính, doanh nghiệp thương mại điện tử, cơ quan y tế, và các cơ quan chính phủ trên toàn cầu đang ráo riết tích hợp LLM "
        "vào các quy trình nghiệp vụ cốt lõi: từ trợ lý ảo chăm sóc khách hàng, phân tích văn bản pháp lý, tự động hóa lập trình phần mềm, "
        "cho đến việc xây dựng các hệ sinh thái Tác tử AI tự quản (Autonomous AI Agents) có khả năng tự động ra quyết định và gọi các công cụ API bên ngoài."
    )
    b.add_p(
        "Tuy nhiên, sự phát triển với tốc độ chưa từng có này cũng kéo theo những thách thức an ninh mạng vô cùng nghiêm trọng. "
        "Không giống như các phần mềm truyền thống vốn được xây dựng trên nền tảng logic tất định (deterministic Boolean logic), "
        "các hệ thống LLM vận hành dựa trên các mạng nơ-ron xác suất phức tạp với hàng tỷ đến hàng trăm tỷ tham số. "
        "Trong kiến trúc cơ bản của mô hình ngôn ngữ, không hề tồn tại ranh giới vật lý hay logic rạch ròi giữa 'kênh điều khiển' (chỉ dẫn hệ thống của nhà phát triển) "
        "và 'kênh dữ liệu' (nội dung đầu vào do người dùng nhập vào). Điều này dẫn đến sự xuất hiện của các hình thái tấn công đối kháng hoàn toàn mới, "
        "tiêu biểu là Prompt Injection và Jailbreak."
    )
    b.add_p(
        "Kẻ tấn công có thể chèn các câu lệnh tinh vi nhằm thao túng mô hình bỏ qua mọi rào cản đạo đức và an toàn, ép mô hình tiết lộ bí mật kinh doanh, "
        "dữ liệu nhạy cảm cá nhân (PII), trích xuất mã nguồn System Prompt, hoặc nguy hiểm hơn là sinh ra mã độc (XSS, SQLi, SSRF) và điều khiển các tác tử AI "
        "thực thi các lệnh xóa dữ liệu sản xuất hay giao dịch tài chính trái phép. "
        "Trước thực trạng đó, các tổ chức bảo mật uy tín hàng đầu thế giới đã ban hành các tiêu chuẩn định danh rủi ro: Dự án OWASP công bố bảng xếp hạng "
        "OWASP Top 10 for LLM Applications (cập nhật mới nhất phiên bản 2025), tổ chức MITRE xây dựng ma trận hiểm họa đối kháng MITRE ATLAS, "
        "và Viện Tiêu chuẩn Công nghệ Mỹ phát hành khung quản lý rủi ro NIST AI RMF 1.0."
    )
    b.add_p(
        "Mặc dù các tiêu chuẩn lý thuyết đã hình thành, nhưng tại Việt Nam hiện nay, hầu hết các doanh nghiệp và tổ chức triển khai AI vẫn đang trong tình trạng "
        "'kiểm thử thủ công' hoặc 'hoàn toàn bỏ ngỏ' khâu kiểm tra an ninh an toàn trước khi đưa mô hình vào môi trường sản xuất (Production). "
        "Các công cụ kiểm thử mã nguồn mở quốc tế như NVIDIA Garak hay Microsoft PyRIT tuy mạnh mẽ nhưng lại có rào cản triển khai rất lớn: "
        "phụ thuộc vào hệ sinh thái thư viện nặng nề, thiếu giao diện điều khiển tương tác trực quan, thời gian quét chậm, và đặc biệt là chưa có cơ chế ánh xạ chuẩn hóa "
        "để cung cấp báo cáo định lượng và hướng dẫn khắc phục cụ thể phù hợp với thực tiễn tại Việt Nam. "
        "Do đó, việc nghiên cứu, làm chủ phương pháp luận và xây dựng một bộ công cụ kiểm thử an toàn AI tự động hóa hoàn chỉnh, trực quan, có cơ chế phát hiện thông minh "
        "là một nhiệm vụ khoa học có tính cấp thiết đặc biệt cao cả về mặt lý luận lẫn ứng dụng thực tiễn."
    )

    b.add_heading_2("2. Mục Tiêu Nghiên Cứu")
    b.add_p("Đề tài hướng tới mục tiêu tổng quát và 6 mục tiêu cụ thể bám sát 6 nội dung nghiên cứu:")
    b.add_bullet("Nghiên cứu cơ sở lý luận, phương pháp luận và hiện thực hóa thành công một bộ công cụ phần mềm tự động hóa toàn diện mang tên AI Security Scanner, có khả năng đánh giá, phát hiện và định lượng các lỗ hổng an toàn thông tin trên các ứng dụng và mô hình ngôn ngữ lớn.", "Mục tiêu tổng quát");
    b.add_bullet("Hệ thống hóa toàn diện cơ sở lý thuyết về an toàn hệ thống AI, phân tích chuyên sâu chuẩn OWASP Top 10 for LLM Applications 2025, ma trận chiến thuật MITRE ATLAS và khung quản lý rủi ro NIST AI RMF 1.0.", "Mục tiêu 1 (Nội dung 1)");
    b.add_bullet("Thiết kế và chuẩn hóa bộ phân loại lỗ hổng an toàn AI (Taxonomy) đa tầng, xây dựng ma trận ánh xạ liên khung chuẩn và phát triển mô hình toán học chấm điểm rủi ro định lượng CVSS-like.", "Mục tiêu 2 (Nội dung 2)");
    b.add_bullet("Đề xuất quy trình kiểm thử hộp đen chuẩn hóa và sáng tạo cơ chế phát hiện hai tầng lai ghép (Two-Tier Hybrid Detection) kết hợp giữa bộ lọc quy tắc regex hiệu năng cao và Giám khảo AI tự động (LLM-as-Judge).", "Mục tiêu 3 (Nội dung 3)");
    b.add_bullet("Thiết kế kiến trúc hệ thống module hóa phân tầng, hiện thực hóa 12 module kiểm thử chuyên sâu, xây dựng bảng điều khiển Web Dashboard thời gian thực (SSE), bộ chỉnh sửa payload tương tác, hỗ trợ Dark/Light mode, tích hợp chuẩn OpenAPI 3.0 và Prometheus metrics.", "Mục tiêu 4 (Nội dung 4)");
    b.add_bullet("Thiết kế lớp vỏ bọc tích hợp (wrappers) để kết nối và đối chuẩn thực nghiệm với hai công cụ mã nguồn mở hàng đầu thế giới là NVIDIA Garak và Microsoft PyRIT.", "Mục tiêu 5 (Nội dung 5)");
    b.add_bullet("Xây dựng bộ dữ liệu kiểm chuẩn độc lập (Benchmark Ground Truth Dataset) và tiến hành thực nghiệm định lượng toàn diện trên các dòng mô hình AI thực tế (LLaMA 3, Mistral, Qwen, GPT-4o-mini), đánh giá độ chính xác, độ nhạy, F1-score và độ trễ.", "Mục tiêu 6 (Nội dung 6)");

    b.add_heading_2("3. Đối Tượng Và Phạm Vi Nghiên Cứu")
    b.add_bullet("Các mô hình ngôn ngữ lớn mã nguồn mở và thương mại (LLaMA 3, Mistral 7B, Qwen 2.5, OpenAI GPT); các ứng dụng phần mềm tích hợp LLM (Chatbot, RAG Pipeline, AI Assistant); các giao diện lập trình ứng dụng RESTful API phục vụ suy luận mô hình (Ollama Local API, OpenAI Chat Completions API, vLLM).", "Đối tượng nghiên cứu");
    b.add_bullet("Đề tài tập trung vào kiểm thử an toàn mức ứng dụng (Application-level Security) và suy luận mô hình theo phương pháp Hộp đen (Black-box Red-teaming). Phạm vi kiểm thử tập trung vào tập hợp con các lỗ hổng nguy hiểm và phổ biến nhất theo OWASP LLM 2025 (LLM01, LLM02, LLM05, LLM06, LLM07, LLM08, LLM09, LLM10) và kỹ thuật thăm dò trinh sát kiến trúc (AML.T0008). Không bao gồm việc tấn công can thiệp vào trọng số nhị phân phần cứng (Hardware fault injection) hoặc can thiệp trực tiếp vào mã nguồn của bộ nhớ GPU.", "Phạm vi nghiên cứu");

    b.add_heading_2("4. Phương Pháp Nghiên Cứu")
    b.add_p(
        "Đề tài áp dụng kết hợp chặt chẽ các phương pháp nghiên cứu khoa học chuyên ngành Công nghệ thông tin và An toàn thông tin:"
    )
    b.add_bullet("Thu thập, tổng hợp, phân tích và so sánh các tài liệu kỹ thuật, tiêu chuẩn an toàn quốc tế (OWASP, MITRE, NIST, ISO) và các công trình nghiên cứu khoa học được công bố tại các hội nghị uy tín hàng đầu (NeurIPS, USENIX Security, IEEE S&P, ACM CCS).", "Phương pháp nghiên cứu lý thuyết");
    b.add_bullet("Sử dụng lý thuyết xác suất, lý thuyết thông tin và nguyên lý của chuẩn CVSS v3.1 để xây dựng công thức tính toán điểm rủi ro định lượng có xét đến độ nghiêm trọng bản chất, bằng chứng khai thác và tính tuân phục tức thì của mô hình.", "Phương pháp mô hình hóa toán học");
    b.add_bullet("Áp dụng quy trình kỹ thuật phần mềm chuẩn mực (Software Engineering) với kiến trúc module hóa phân tầng, thiết kế hướng đối tượng (OOP), lập trình REST API, Server-Sent Events, cơ sở dữ liệu SQLite chế độ WAL và xây dựng pipeline kiểm thử tự động CI/CD.", "Phương pháp thực nghiệm kỹ thuật");
    b.add_bullet("Xây dựng tập mẫu ground truth chuẩn mực, tiến hành chạy kiểm thử thực tế trên hệ thống máy chủ phòng thí nghiệm, đo lường độ trễ mili-giây, thu thập ma trận nhầm lẫn (Confusion Matrix) và phân tích các chỉ số thống kê toán học (Precision, Recall, F1-Score).", "Phương pháp đánh giá định lượng");

    b.add_heading_2("5. Ý Nghĩa Khoa Học Và Thực Tiễn Của Đề Tài")
    b.add_bullet("Đóng góp một quy trình kiểm thử thâm nhập an toàn AI hộp đen có cơ sở khoa học chặt chẽ; đề xuất mô hình đánh giá hai tầng lai ghép (Two-Tier Hybrid Detection) giải quyết được bài toán cân bằng giữa tốc độ xử lý sub-millisecond của bộ lọc quy tắc và khả năng hiểu ngữ nghĩa sâu sắc của LLM-as-a-Judge; đóng góp một mô hình tính điểm rủi ro định lượng chuyên biệt cho AI.", "Ý nghĩa khoa học");
    b.add_bullet("Cung cấp một bộ công cụ phần mềm hoàn chỉnh, độc lập, mã nguồn mở, dễ dàng cài đặt và vận hành tại các cơ quan, tổ chức, doanh nghiệp tại Việt Nam. Công cụ giúp các đội ngũ bảo mật (SecOps) và kỹ sư AI (MLOps) chủ động rà quét, phát hiện lỗ hổng sớm (Shift-Left Security), nhận diện rò rỉ dữ liệu nhạy cảm và nhận được hướng dẫn khắc phục cụ thể trước khi triển khai hệ thống AI ra cộng đồng.", "Ý nghĩa thực tiễn");

    b.add_heading_2("6. Bố Cục Của Báo Cáo")
    b.add_p("Ngoài phần Mở đầu, Kết luận, Tài liệu tham khảo và Phụ lục, nội dung chính của báo cáo được cấu trúc thành 6 chương tương ứng với 6 nội dung nghiên cứu khoa học cốt lõi:")
    b.add_bullet("Trình bày cơ sở lý luận về an toàn AI, phân tích chi tiết tiêu chuẩn OWASP LLM 2025, ma trận MITRE ATLAS, khung NIST AI RMF và các công trình liên quan.", "Chương 1: Tổng quan lý thuyết và tiêu chuẩn an toàn AI (Nội dung 1)");
    b.add_bullet("Xây dựng bộ phân loại lỗ hổng chuẩn hóa, ma trận ánh xạ liên khung chuẩn và công thức toán học tính điểm rủi ro định lượng CVSS-like.", "Chương 2: Xây dựng Taxonomy và mô hình hóa nguy cơ an toàn AI (Nội dung 2)");
    b.add_bullet("Đặc tả vòng đời kiểm thử hộp đen, kỹ nghệ sinh payload đối kháng, và thiết kế chi tiết kiến trúc phát hiện hai tầng lai ghép (PatternDetector + LLMJudge).", "Chương 3: Phương pháp luận và kỹ thuật kiểm thử xâm nhập AI (Nội dung 3)");
    b.add_bullet("Mô tả chi tiết thiết kế kiến trúc phân tầng, phân tích sâu việc hiện thực hóa 12 module kiểm thử, bộ điều phối kết nối AI, Web Dashboard thời gian thực, Swagger OpenAPI 3.0 và hệ thống kiểm thử tự động 55 test cases.", "Chương 4: Thiết kế kiến trúc và hiện thực hóa hệ thống (Nội dung 4)");
    b.add_bullet("Khảo sát, thiết kế các lớp vỏ bọc tích hợp (wrappers) kết nối với NVIDIA Garak và Microsoft PyRIT, phân tích so sánh đối chuẩn tính năng toàn diện.", "Chương 5: Tích hợp công cụ mã nguồn mở và đánh giá đối chuẩn (Nội dung 5)");
    b.add_bullet("Trình bày toàn bộ thiết kế thực nghiệm, công bố bảng số liệu thực nghiệm gốc trên 43 test cases, đánh giá hiệu năng các dòng mô hình (LLaMA 3, Mistral, Qwen, GPT), minh chứng tính ưu việt của mô hình Two-Tier và phân tích phân bổ rủi ro tổng hợp.", "Chương 6: Thực nghiệm, kiểm chứng và đánh giá định lượng (Nội dung 6)");

    b.add_page_break()
