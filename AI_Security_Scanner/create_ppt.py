import collections
import collections.abc
from pptx import Presentation
from pptx.util import Inches, Pt, Cm
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor

def create_presentation(bg_img_path, output_path):
    prs = Presentation()
    
    # Kích thước slide 16:9
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    
    # Định nghĩa nội dung 20 slides
    slides_data = [
        {
            "title": "BÁO CÁO NGHIÊN CỨU KHOA HỌC",
            "content": (
                "Đề tài: Nghiên cứu, Thiết kế và Phát triển Bộ Công Cụ Đánh Giá Lỗ Hổng \n"
                "và Kiểm Thử An Toàn Cho Các Ứng Dụng LLM và AI Agents\n\n"
                "Sinh viên thực hiện: ...\n"
                "Giảng viên hướng dẫn: ..."
            )
        },
        {
            "title": "MỤC LỤC",
            "content": (
                "1. Tổng quan Lý thuyết & Tiêu chuẩn Quốc tế\n"
                "2. Phân loại Taxonomy & Mô hình Toán học CVSS-like\n"
                "3. Phương pháp luận & Kiến trúc Hai Tầng Lai Ghép\n"
                "4. Thiết kế Kiến trúc, 12 Modules & Web Dashboard\n"
                "5. Tích hợp Công cụ Mã nguồn mở (Garak & PyRIT)\n"
                "6. Thực nghiệm Định lượng, Kịch bản Kiểm thử & Đa mô hình\n"
                "7. Demo Hệ thống"
            )
        },
        {
            "title": "1. TỔNG QUAN LÝ THUYẾT & TIÊU CHUẨN QUỐC TẾ",
            "content": (
                "- Sự bùng nổ của Mô hình Ngôn ngữ lớn (LLM) và Tác tử AI (AI Agents).\n"
                "- Rủi ro an toàn phi truyền thống: Social engineering on AI, Prompt Injection, Jailbreak.\n"
                "- Hàng rào bảo mật kinh điển (WAF) không hiệu quả với ngôn ngữ tự nhiên.\n"
                "- Cần thiết có một bộ công cụ đánh giá tự động (Red-teaming)."
            )
        },
        {
            "title": "1. TIÊU CHUẨN QUỐC TẾ ÁP DỤNG",
            "content": (
                "- Chuẩn hóa theo OWASP Top 10 for LLM Applications (Phiên bản 2025).\n"
                "- Đối chiếu ma trận kỹ thuật MITRE ATLAS (Adversarial Threat Landscape for AI Systems).\n"
                "- Mục tiêu: Đồng bộ 100% danh mục lỗ hổng theo chuẩn quốc tế mới nhất."
            )
        },
        {
            "title": "2. PHÂN LOẠI LỖ HỔNG (TAXONOMY)",
            "content": (
                "Xây dựng ma trận Module Tấn công & Phân loại Lỗ hổng:\n"
                "- Prompt Injection (LLM01) - Mức độ HIGH\n"
                "- Jailbreak / Safety Bypass (LLM01) - Mức độ CRITICAL\n"
                "- Sensitive Information Disclosure (LLM02) - Mức độ HIGH\n"
                "- Excessive Agency (LLM06) - Mức độ CRITICAL\n"
                "- Vector & Embedding Weaknesses / RAG (LLM08) - Mức độ HIGH"
            )
        },
        {
            "title": "2. MÔ HÌNH TOÁN HỌC CVSS-LIKE",
            "content": (
                "Mô hình Định lượng Rủi ro (Risk Engine):\n"
                "- Tự động tính toán điểm rủi ro từ 0.0 đến 10.0.\n"
                "- Dựa trên: Base Score (Điểm cơ sở của lỗ hổng).\n"
                "- Exploitability Multiplier (Hệ số khả năng khai thác).\n"
                "- Brevity Bonus (Phần thưởng cho payload ngắn gọn).\n"
                "- Hỗ trợ xếp hạng rủi ro chính xác và tự động."
            )
        },
        {
            "title": "3. PHƯƠNG PHÁP LUẬN (METHODOLOGY)",
            "content": (
                "Cơ chế Kiểm thử Đối kháng (Red-teaming):\n"
                "- Phương pháp tiếp cận: Kiểm thử hộp đen tự động hóa (Black-box testing).\n"
                "- Giao tiếp thông qua API RESTful với các LLM Target (Ollama, OpenAI, vLLM).\n"
                "- Không cần can thiệp vào mô hình nội bộ, tập trung vào đầu vào/đầu ra."
            )
        },
        {
            "title": "3. KIẾN TRÚC HAI TẦNG LAI GHÉP (TWO-TIER HYBRID DETECTION)",
            "content": (
                "Tier-1 (Pattern Matching - Phân tích cú pháp nhanh):\n"
                "- Sử dụng bộ lọc biểu thức chính quy (Regex) tốc độ cao (< 1ms/payload).\n"
                "- Phát hiện nhanh các chỉ báo vi phạm và phản hồi từ chối an toàn rõ ràng.\n\n"
                "Tier-2 (LLM-as-Judge - Giám khảo AI):\n"
                "- Khi Tier-1 trả kết quả độ tin cậy thấp (phân vân).\n"
                "- Sử dụng mô hình LLM độc lập (Evaluator) để phân tích ngữ nghĩa sâu.\n"
                "- Giúp loại bỏ triệt để tỷ lệ báo động giả (False Positives)."
            )
        },
        {
            "title": "4. THIẾT KẾ KIẾN TRÚC HỆ THỐNG",
            "content": (
                "- User -> UI (CLI / Web Dashboard)\n"
                "- Resilient HTTP Client -> Target LLM\n"
                "- Result -> Tier 1 (Pattern Detector)\n"
                "- If Low Confidence -> Tier 2 (LLM-as-Judge)\n"
                "- -> Risk Scorer -> SQLite Database -> Report Generator"
            )
        },
        {
            "title": "4. 12 MODULES KIỂM THỬ",
            "content": (
                "Hệ thống phát triển sẵn nhiều module tấn công:\n"
                "1. prompt_injection (Direct & Indirect)\n"
                "2. jailbreak (DAN, AIM, STAN)\n"
                "3. sensitive_disclosure\n"
                "4. output_handling (XSS, SQLi, SSRF)\n"
                "5. excessive_agency (Thao túng Tools)\n"
                "6. rag_security (Vector & Embedding)\n"
                "... và các module hạ tầng mạng."
            )
        },
        {
            "title": "4. WEB DASHBOARD THỜI GIAN THỰC",
            "content": (
                "Bảng điều khiển Web hiện đại:\n"
                "- Truyền phát dữ liệu từng mili-giây qua chuẩn Server-Sent Events (SSE).\n"
                "- Thanh tiến độ hiển thị phần trăm trực quan (%).\n"
                "- Tính năng Hủy Scan tức thời (Instant Abort) với khóa phiên UUIDv4.\n"
                "- Báo cáo rủi ro trực quan và xuất file HTML/JSON."
            )
        },
        {
            "title": "5. TÍCH HỢP CÔNG CỤ MÃ NGUỒN MỞ",
            "content": (
                "Tích hợp và đối chuẩn (Benchmarking) với các công cụ hàng đầu:\n"
                "- NVIDIA Garak: Generative AI Red-teaming Architecture.\n"
                "- Tận dụng các bộ payload chuyên sâu từ Garak để làm phong phú dữ liệu quét.\n"
                "- So sánh hiệu năng phát hiện với công cụ quốc tế."
            )
        },
        {
            "title": "5. TÍCH HỢP MICROSOFT PyRIT",
            "content": (
                "- Microsoft PyRIT: Python Risk Identification Tool for generative AI.\n"
                "- Khung đối chuẩn (Scientific Benchmark Harness) để kiểm chứng tỷ lệ Precision, Recall, F1.\n"
                "- Khẳng định tính hiệu quả của phương pháp lai ghép 2 tầng."
            )
        },
        {
            "title": "6. KỊCH BẢN KIỂM THỬ (TEST SCENARIOS)",
            "content": (
                "Tập dữ liệu Ground Truth:\n"
                "- Xây dựng tập dữ liệu gồm 32+ ca kiểm thử đã được dán nhãn độc lập.\n"
                "- Đánh giá mô hình ngoại tuyến (Offline Benchmark).\n"
                "- Đánh giá đa mô hình (Multi-model: llama3, mistral, qwen:7b)."
            )
        },
        {
            "title": "6. THỰC NGHIỆM ĐỊNH LƯỢNG",
            "content": (
                "Quá trình đánh giá hiệu năng (Ablation Study):\n"
                "- So sánh hiệu quả giữa chỉ dùng Tier-1 và dùng cả Tier-1 + Tier-2.\n"
                "- Kết quả thực nghiệm cho thấy Tier-2 giúp giảm đáng kể False Positive Rate.\n"
                "- Tốc độ xử lý được tối ưu nhờ Tier-1 xử lý 80% trường hợp rõ ràng."
            )
        },
        {
            "title": "7. DEMO HỆ THỐNG: GIAO DIỆN CLI",
            "content": (
                "Giao diện dòng lệnh tương tác mạnh mẽ (Rich Console):\n"
                "- Lệnh: show modules, use <module>, set target, run.\n"
                "- Hiển thị bảng tổng hợp báo cáo trực tiếp trên Terminal.\n"
                "- Hỗ trợ tự động hóa trong các luồng CI/CD tương lai."
            )
        },
        {
            "title": "7. DEMO HỆ THỐNG: WEB DASHBOARD",
            "content": (
                "Giao diện Web trực quan:\n"
                "- Theo dõi tiến độ từng payload đang gửi đi.\n"
                "- Xem log chi tiết của LLM-as-Judge khi đưa ra quyết định.\n"
                "- Biểu đồ thống kê CVSS theo mức độ Low/Medium/High/Critical."
            )
        },
        {
            "title": "7. DEMO HỆ THỐNG: TẤN CÔNG GIÁN TIẾP TRÊN RAG",
            "content": (
                "Kịch bản Demo RAG Security:\n"
                "- Minh họa Indirect Prompt Injection.\n"
                "- Tiêm nhiễm payload độc hại vào cơ sở dữ liệu tri thức nội bộ.\n"
                "- LLM truy xuất tài liệu và bị thao túng hành vi ngoài ý muốn.\n"
                "- Cơ chế phòng vệ cách ly ngữ cảnh."
            )
        },
        {
            "title": "ĐÓNG GÓP & HƯỚNG PHÁT TRIỂN",
            "content": (
                "Đóng góp của đề tài:\n"
                "- Xây dựng thành công hệ thống đánh giá tự động bám sát OWASP 2025.\n"
                "- Đề xuất kiến trúc Hai tầng lai ghép hiệu quả cao.\n\n"
                "Hướng phát triển:\n"
                "- Đóng gói Docker, tích hợp DevSecOps / CI/CD.\n"
                "- Nghiên cứu kỹ thuật tấn công hộp trắng (White-box)."
            )
        },
        {
            "title": "KẾT LUẬN & Q/A",
            "content": (
                "Cảm ơn Quý Thầy Cô trong Hội đồng đã lắng nghe!\n\n\n"
                "Phần Hỏi / Đáp (Q&A)"
            )
        }
    ]

    for slide_data in slides_data:
        slide_layout = prs.slide_layouts[6] # Blank layout
        slide = prs.slides.add_slide(slide_layout)
        
        # Add background image
        try:
            pic = slide.shapes.add_picture(bg_img_path, 0, 0, width=prs.slide_width, height=prs.slide_height)
            # Không thể send_to_back qua python-pptx một cách trực tiếp, picture đã được add đầu tiên sẽ nằm dưới cùng
        except Exception as e:
            print(f"Lỗi thêm ảnh nền: {e}")
        
        # Add shape to make text readable (semi-transparent rectangle or just solid)
        # Using a slight semi-transparent white box for text readability, but python-pptx doesn't support transparency natively easily.
        # We'll use a very light grey box or just use white text with shadow. Let's use black text on a white solid rectangle for title, 
        # or we just rely on formatting. Let's add a white background box for text to make sure it's readable over the noisy background.
        
        left = Inches(1.0)
        top_title = Inches(0.8)
        width_title = Inches(11.3)
        height_title = Inches(1.2)
        
        # Title Box
        txBox_title = slide.shapes.add_textbox(left, top_title, width_title, height_title)
        fill = txBox_title.fill
        fill.solid()
        fill.fore_color.rgb = RGBColor(255, 255, 255) # White background for readability
        
        tf_title = txBox_title.text_frame
        p_title = tf_title.add_paragraph()
        p_title.text = slide_data['title']
        p_title.font.name = 'Times New Roman'
        p_title.font.size = Pt(24)
        p_title.font.bold = True
        p_title.font.color.rgb = RGBColor(0, 0, 0)
        p_title.alignment = PP_ALIGN.CENTER
        
        # Content Box
        top_content = Inches(2.2)
        height_content = Inches(4.5)
        txBox_content = slide.shapes.add_textbox(left, top_content, width_title, height_content)
        fill = txBox_content.fill
        fill.solid()
        fill.fore_color.rgb = RGBColor(255, 255, 255) # White background
        
        tf_content = txBox_content.text_frame
        tf_content.word_wrap = True
        
        for line in slide_data['content'].split('\n'):
            p = tf_content.add_paragraph()
            p.text = line
            p.font.name = 'Times New Roman'
            p.font.size = Pt(18)
            p.font.color.rgb = RGBColor(0, 0, 0)

    prs.save(output_path)
    print(f"Đã tạo file PowerPoint: {output_path}")

if __name__ == '__main__':
    bg_path = r"C:\Users\pc\.gemini\antigravity\brain\f8fc2e93-7a3f-4101-87f5-7a7f0454c882\.user_uploaded\media_1790501512781.png"
    out_path = r"d:\TTCS\NCKH\AI_Security_Scanner\PP_NCKH1.pptx"
    create_presentation(bg_path, out_path)
