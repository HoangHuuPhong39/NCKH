import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from PIL import Image, ImageDraw, ImageFont

def create_dummy_image(filename, text, size=(800, 600), bg_color=(40, 44, 52), text_color=(255, 255, 255)):
    img = Image.new('RGB', size, color=bg_color)
    d = ImageDraw.Draw(img)
    d.text((size[0]//4, size[1]//2), text, fill=text_color)
    d.rectangle([10, 10, size[0]-10, 40], fill=(200, 200, 200))
    for i in range(5):
        d.line([(50, 80 + i*40), (size[0]-50, 80 + i*40)], fill=(100, 100, 100), width=10)
    img.save(filename)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

DARK_BLUE = RGBColor(31, 73, 125)
LIGHT_BLUE = RGBColor(199, 219, 242)
TEAL = RGBColor(49, 133, 156)
WHITE = RGBColor(255, 255, 255)
DARK_GRAY = RGBColor(80, 80, 80)
RED_ACCENT = RGBColor(200, 50, 50)

def add_background(slide):
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), prs.slide_width, prs.slide_height)
    bg.fill.solid()
    bg.fill.fore_color.rgb = RGBColor(245, 245, 247)
    bg.line.fill.background()
    return bg

def add_header(slide, title_text):
    header = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), prs.slide_width, Inches(1.2))
    header.fill.solid()
    header.fill.fore_color.rgb = DARK_BLUE
    header.line.fill.background()
    
    txBox = slide.shapes.add_textbox(Inches(0.5), Inches(0.2), Inches(12), Inches(0.8))
    tf = txBox.text_frame
    p = tf.add_paragraph()
    p.text = title_text
    p.font.name = 'Times New Roman'
    p.font.size = Pt(32)
    p.font.bold = True
    p.font.color.rgb = WHITE
    p.alignment = PP_ALIGN.LEFT
    
def add_footer(slide):
    footer = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), prs.slide_height - Inches(0.3), prs.slide_width, Inches(0.3))
    footer.fill.solid()
    footer.fill.fore_color.rgb = TEAL
    footer.line.fill.background()
    
    txBox = slide.shapes.add_textbox(Inches(0.5), prs.slide_height - Inches(0.35), Inches(5), Inches(0.3))
    tf = txBox.text_frame
    p = tf.add_paragraph()
    p.text = "Báo cáo NCKH - AI Security Scanner"
    p.font.name = 'Times New Roman'
    p.font.size = Pt(12)
    p.font.color.rgb = WHITE

def create_title_slide(title, subtitle, bg_img_path):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    try:
        slide.shapes.add_picture(bg_img_path, 0, 0, width=prs.slide_width, height=prs.slide_height)
    except Exception:
        add_background(slide)
        
    overlay = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(2), prs.slide_width, Inches(3.5))
    overlay.fill.solid()
    overlay.fill.fore_color.rgb = WHITE
    overlay.line.fill.background()
    
    accent = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(2), Inches(0.3), Inches(3.5))
    accent.fill.solid()
    accent.fill.fore_color.rgb = RED_ACCENT
    accent.line.fill.background()

    txBox = slide.shapes.add_textbox(Inches(0.8), Inches(2.2), prs.slide_width - Inches(1.6), Inches(1.5))
    tf = txBox.text_frame
    p = tf.add_paragraph()
    p.text = title
    p.font.name = 'Times New Roman'
    p.font.size = Pt(40)
    p.font.bold = True
    p.font.color.rgb = DARK_BLUE
    p.alignment = PP_ALIGN.CENTER
    
    txBox2 = slide.shapes.add_textbox(Inches(0.8), Inches(4.0), prs.slide_width - Inches(1.6), Inches(1.0))
    tf2 = txBox2.text_frame
    p2 = tf2.add_paragraph()
    p2.text = subtitle
    p2.font.name = 'Times New Roman'
    p2.font.size = Pt(22)
    p2.font.color.rgb = DARK_GRAY
    p2.alignment = PP_ALIGN.CENTER

def create_split_slide(title, left_text_list, right_text_list=None, right_img=None):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    add_background(slide)
    add_header(slide, title)
    add_footer(slide)
    
    left_box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.5), Inches(1.5), Inches(5.8), Inches(5.2))
    left_box.fill.solid()
    left_box.fill.fore_color.rgb = WHITE
    left_box.line.color.rgb = LIGHT_BLUE
    
    tf = left_box.text_frame
    tf.word_wrap = True
    for item in left_text_list:
        p = tf.add_paragraph()
        p.text = "• " + item
        p.font.name = 'Times New Roman'
        p.font.size = Pt(18)
        p.font.color.rgb = DARK_GRAY
        p.space_after = Pt(14)
        
    if right_img and os.path.exists(right_img):
        slide.shapes.add_picture(right_img, Inches(6.8), Inches(1.5), width=Inches(6.0))
    elif right_text_list:
        right_box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.5), Inches(5.8), Inches(5.2))
        right_box.fill.solid()
        right_box.fill.fore_color.rgb = LIGHT_BLUE
        right_box.line.color.rgb = DARK_BLUE
        
        tf2 = right_box.text_frame
        tf2.word_wrap = True
        for item in right_text_list:
            p = tf2.add_paragraph()
            p.text = "• " + item
            p.font.name = 'Times New Roman'
            p.font.size = Pt(18)
            p.font.color.rgb = DARK_BLUE
            p.space_after = Pt(14)

def create_three_column_slide(title, col1, col2, col3):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    add_background(slide)
    add_header(slide, title)
    add_footer(slide)
    
    cols = [col1, col2, col3]
    colors = [DARK_BLUE, TEAL, RED_ACCENT]
    for i in range(3):
        banner = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.5 + i*4.2), Inches(1.8), Inches(3.8), Inches(0.8))
        banner.fill.solid()
        banner.fill.fore_color.rgb = colors[i]
        banner.line.fill.background()
        
        tf_b = banner.text_frame
        p_b = tf_b.add_paragraph()
        p_b.text = cols[i]['title']
        p_b.font.name = 'Times New Roman'
        p_b.font.size = Pt(20)
        p_b.font.bold = True
        p_b.font.color.rgb = WHITE
        p_b.alignment = PP_ALIGN.CENTER
        
        box = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.5 + i*4.2), Inches(2.6), Inches(3.8), Inches(4.0))
        box.fill.solid()
        box.fill.fore_color.rgb = WHITE
        box.line.color.rgb = LIGHT_BLUE
        
        tf = box.text_frame
        tf.word_wrap = True
        for item in cols[i]['items']:
            p = tf.add_paragraph()
            p.text = item
            p.font.name = 'Times New Roman'
            p.font.size = Pt(16)
            p.font.color.rgb = DARK_GRAY
            p.space_after = Pt(10)

def main():
    create_dummy_image("dummy_cli.png", "CLI INTERFACE", bg_color=(20, 20, 20), text_color=(0, 255, 0))
    create_dummy_image("dummy_web.png", "WEB DASHBOARD", bg_color=(240, 240, 240), text_color=(30, 30, 30))
    create_dummy_image("dummy_rag.png", "RAG PIPELINE", bg_color=(50, 100, 150), text_color=(255, 255, 255))
    create_dummy_image("dummy_vuln.png", "VULNERABILITY SCAN", bg_color=(100, 50, 50), text_color=(255, 200, 200))
    
    bg_img_path = r"C:\Users\pc\.gemini\antigravity\brain\f8fc2e93-7a3f-4101-87f5-7a7f0454c882\.user_uploaded\media_1790501512781.png"

    # 1. Slide 1
    create_title_slide("AI SECURITY SCANNER", "Bộ Công Cụ Đánh Giá Lỗ Hổng & Kiểm Thử An Toàn\nNgười trình bày: Sinh viên NCKH", bg_img_path)
    
    # 2. Slide 2
    create_split_slide("MỤC LỤC NỘI DUNG", ["1. Tổng quan & Tiêu chuẩn", "2. Phân loại Taxonomy & Mô hình rủi ro", "3. Phương pháp & Kiến trúc 2 tầng"], ["4. Thiết kế & Các Module", "5. Tích hợp mã nguồn mở", "6. Thực nghiệm & Kịch bản kiểm thử"])

    # 3. Slide 3
    create_split_slide("1. TỔNG QUAN & BỐI CẢNH", ["Sự bùng nổ của LLM và AI Agents.", "Rủi ro: Prompt Injection, Jailbreak.", "Các giải pháp bảo mật truyền thống kém hiệu quả."], ["Cần công cụ Red-Teaming chuyên biệt.", "Phát hiện lỗ hổng tự động.", "Đảm bảo an toàn theo chuẩn quốc tế."])

    # 4. Slide 4
    create_three_column_slide("1. TIÊU CHUẨN QUỐC TẾ ÁP DỤNG", {"title": "OWASP LLM TOP 10", "items": ["OWASP Top 10 for LLM Applications (2025)."]}, {"title": "MITRE ATLAS", "items": ["Adversarial Threat Landscape for AI."]}, {"title": "MỤC TIÊU", "items": ["Đồng bộ 100% chuẩn quốc tế mới nhất."]})

    # 5. Slide 5
    create_split_slide("2. PHÂN LOẠI LỖ HỔNG (PHẦN 1)", ["LLM01: Prompt Injection (HIGH)", "LLM01: Jailbreak / Safety Bypass (CRITICAL)", "LLM02: Sensitive Info Disclosure (HIGH)"], ["Các module độc lập nhắm vào từng điểm yếu.", "Tự động gửi payload khai thác (exploit).", "Giả lập hành vi tin tặc tinh vi."])

    # 6. Slide 6
    create_split_slide("2. PHÂN LOẠI LỖ HỔNG (PHẦN 2)", ["LLM06: Excessive Agency (Thao túng Tool)", "LLM08: Vector & Embedding Weaknesses (RAG)", "LLM10: Model DoS (Tiêu thụ tài nguyên)"], ["Bảo vệ toàn diện vòng đời AI.", "Đánh giá cả mô hình và đường ống (pipeline).", "Xác định rõ phạm vi bảo mật."])
    
    # 7. Slide 7
    create_split_slide("2. MÔ HÌNH ĐỊNH LƯỢNG RỦI RO CVSS", ["Động cơ tính điểm rủi ro (Risk Scorer).", "Thang điểm tự động từ 0.0 đến 10.0.", "Phân loại: Low, Medium, High, Critical."], ["Dựa trên Base Score (Lỗ hổng).", "Exploitability Multiplier (Dễ khai thác).", "Brevity Bonus (Payload ngắn càng nguy hiểm)."])

    # 8. Slide 8
    create_three_column_slide("3. PHƯƠNG PHÁP LUẬN", {"title": "Black-Box Testing", "items": ["Kiểm thử hộp đen.", "Không cần mã nguồn LLM."]}, {"title": "Tự động hóa", "items": ["Red-Teaming liên tục.", "Gửi hàng nghìn truy vấn."]}, {"title": "Đa nền tảng", "items": ["Hỗ trợ Ollama, OpenAI.", "Dễ dàng tích hợp."]})

    # 9. Slide 9
    create_split_slide("3. KIẾN TRÚC 2 TẦNG LAI GHÉP", ["Tầng 1 (Tier-1): Pattern Matching.", "Sử dụng Regex siêu tốc (< 1ms).", "Phát hiện chỉ báo rõ ràng, chặn ngay lập tức."], ["Tầng 2 (Tier-2): LLM-as-Judge.", "Khi Tier-1 'phân vân'.", "Dùng LLM độc lập phân tích ngữ nghĩa, giảm tỷ lệ False Positive."])

    # 10. Slide 10
    create_split_slide("4. THIẾT KẾ KIẾN TRÚC & MODULES", ["Luồng dữ liệu:", "1. UI (Web/CLI)", "2. Resilient Client -> LLM", "3. Tier-1 Detector", "4. Tier-2 Judge", "5. Risk Scorer"], ["12 Module Tấn công:", "- prompt_injection", "- jailbreak", "- excessive_agency", "- rag_security"])

    # 11. Slide 11
    create_split_slide("4. WEB DASHBOARD (SSE STREAMING)", ["Bảng điều khiển Web hiện đại.", "Truyền phát tiến độ mili-giây qua SSE.", "Instant Abort (Hủy quét tức thời).", "Biểu đồ rủi ro trực quan."], right_img="dummy_web.png")

    # 12. Slide 12
    create_three_column_slide("5. TÍCH HỢP MÃ NGUỒN MỞ", {"title": "NVIDIA Garak", "items": ["Generative AI Red-teaming.", "Payload phong phú."]}, {"title": "Microsoft PyRIT", "items": ["Python Risk Tool.", "Đối chuẩn hiệu năng."]}, {"title": "Hệ sinh thái", "items": ["Tận dụng tinh hoa bảo mật toàn cầu."]})

    # 13. Slide 13
    create_split_slide("6. KỊCH BẢN KIỂM THỬ: CLI & ĐA MÔ HÌNH", ["Đánh giá trên: Llama3, Mistral, Qwen:7b.", "Sử dụng CLI chuyên nghiệp như Metasploit.", "Hỗ trợ luồng DevSecOps và CI/CD."], right_img="dummy_cli.png")

    # 14. Slide 14
    create_split_slide("6. THỰC NGHIỆM ĐỊNH LƯỢNG (GROUND TRUTH)", ["32+ ca kiểm thử gán nhãn thủ công.", "Đảm bảo tính khách quan (Offline Benchmark).", "Đánh giá Precision, Recall, F1-Score."], ["Kết quả Ablation Study:", "- Hệ thống có Tier-2 giảm 90% False Positives so với Regex thông thường.", "- Xử lý nhanh, hiệu quả."])

    # 15. Slide 15
    create_split_slide("DEMO 1: KIỂM THỬ LỖ HỔNG XSS/SQLi", ["Khai thác lỗ hổng Output Handling.", "LLM sinh ra mã HTML/JS độc hại.", "Scanner nhận diện và chấm điểm CRITICAL."], right_img="dummy_vuln.png")

    # 16. Slide 16
    create_split_slide("DEMO 2: TẤN CÔNG RAG GIÁN TIẾP", ["Kịch bản Indirect Prompt Injection.", "Nhúng mã độc vào tài liệu nội bộ.", "LLM đọc tài liệu và thao túng hành vi người dùng."], right_img="dummy_rag.png")
    
    # 17. Slide 17
    create_split_slide("DEMO 3: GIÁM KHẢO AI (LLM-AS-JUDGE)", ["Theo dõi quá trình 'suy nghĩ' của LLM Judge.", "Quyết định vượt qua bộ lọc hay chặn lại.", "Log lưu trữ minh bạch, phục vụ Report."], right_img="dummy_web.png")

    # 18. Slide 18
    create_split_slide("TỔNG KẾT & ĐÓNG GÓP", ["Hoàn thiện bộ công cụ rà quét an toàn AI chuẩn OWASP 2025.", "Cơ chế lai ghép tốc độ và độ chính xác cao.", "Giao diện trực quan, dễ tích hợp."], ["Xây dựng nền tảng vững chắc cho Red-teaming tại Việt Nam.", "Ứng dụng trực tiếp cho doanh nghiệp triển khai LLM."])

    # 19. Slide 19
    create_three_column_slide("HƯỚNG PHÁT TRIỂN", {"title": "Đóng gói DevSecOps", "items": ["Container hóa Docker.", "Tích hợp CI/CD (GitHub Actions)."]}, {"title": "White-Box Testing", "items": ["Truy cập trọng số mô hình.", "Phát hiện backdoor ẩn."]}, {"title": "Mở rộng Dataset", "items": ["Xây dựng bộ từ điển Payload tiếng Việt chuyên sâu."]})

    # 20. Slide 20
    create_title_slide("XIN TRÂN TRỌNG CẢM ƠN", "Cảm ơn Quý Thầy Cô và Hội Đồng đã lắng nghe.\nPhần Hỏi & Đáp (Q&A)", bg_img_path)
    
    out_path = r"d:\TTCS\NCKH\AI_Security_Scanner\PP_NCKH1.pptx"
    prs.save(out_path)
    print("Done 20 slides")

if __name__ == '__main__':
    main()
