# -*- coding: utf-8 -*-
"""
scripts/content_chapter1.py - Chapter 1: Theoretical Background & Standards (Noi dung 1)
"""

def generate_chapter1(b):
    b.add_heading_1("CHƯƠNG 1: TỔNG QUAN LÝ THUYẾT VÀ TIÊU CHUẨN AN TOÀN AI")

    # 1.1 Tổng quan về LLM
    b.add_heading_2("1.1 Tổng Quan Về Hệ Thống AI Và Mô Hình Ngôn Ngữ Lớn (LLMs)")
    b.add_p(
        "Kỷ nguyên hiện đại của Trí tuệ nhân tạo (AI) được đánh dấu bởi sự thống trị của các kiến trúc dựa trên nền tảng "
        "Transformer (Vaswani et al., 2017). Khác với các mô hình mạng nơ-ron hồi quy tuần tự truyền thống (RNN, LSTM), "
        "Transformer sử dụng cơ chế Tự chú ý đa đầu (Multi-Head Self-Attention) cho phép mô hình nắm bắt được các mối tương quan ngữ nghĩa "
        "phức tạp giữa các từ trong câu mà không bị giới hạn bởi khoảng cách vật lý trong chuỗi dữ liệu. "
        "Trên nền tảng kiến trúc này, các Mô hình Ngôn ngữ Lớn (Large Language Models - LLM) được huấn luyện qua ba giai đoạn liên hoàn:"
    )
    b.add_bullet(
        "Mô hình được cho đọc hàng nghìn tỷ token văn bản phi cấu trúc từ Internet (Common Crawl, Wikipedia, sách, mã nguồn GitHub). "
        "Mục tiêu tối ưu hóa là dự đoán xác suất của token tiếp theo (Causal Language Modeling: P(w_t | w_1, ..., w_{t-1})). "
        "Giai đoạn này tạo ra một mô hình nền tảng (Base Model) có hiểu biết sâu rộng về ngôn ngữ và tri thức nhân loại nhưng chưa thể tương tác hội thoại an toàn.",
        "Giai đoạn 1: Tiền huấn luyện tự giám sát (Self-Supervised Pre-training)"
    )
    b.add_bullet(
        "Mô hình nền tảng được tiếp tục huấn luyện trên hàng chục nghìn đến hàng trăm nghìn cặp dữ liệu mẫu chất lượng cao dạng (Chỉ dẫn, Phản hồi mẫu) "
        "do con người biên soạn kỹ lưỡng. Giai đoạn này biến mô hình từ một cỗ máy sinh từ vô định thành một trợ lý ảo biết tuân theo mệnh lệnh của người dùng.",
        "Giai đoạn 2: Tinh chỉnh có giám sát (Supervised Fine-Tuning - SFT)"
    )
    b.add_bullet(
        "Mô hình được huấn luyện để thích ứng với các tiêu chuẩn đạo đức và an toàn của con người (AI Alignment). "
        "Sử dụng các thuật toán như PPO (Proximal Policy Optimization) hoặc DPO (Direct Preference Optimization), "
        "hệ thống tối ưu hóa chính sách sinh văn bản sao cho thỏa mãn đồng thời ba tiêu chí: Hữu ích (Helpful), Trung thực (Honest) và Vô hại (Harmless).",
        "Giai đoạn 3: Tinh chỉnh căn chỉnh an toàn (RLHF / DPO Alignment)"
    )

    b.add_p(
        "Mặc dù đã trải qua quy trình căn chỉnh an toàn nghiêm ngặt, bản chất kiến trúc của LLM vẫn tồn tại các điểm yếu an ninh cốt lõi "
        "hoàn toàn khác biệt so với các phần mềm truyền thống:"
    )
    b.add_bullet(
        "Các phần mềm truyền thống (như hệ cơ sở dữ liệu SQL, máy chủ web) luôn phân định rạch ròi giữa mã lệnh thực thi (Code) và dữ liệu đầu vào (Data). "
        "Ví dụ: Kỹ thuật tham số hóa (Parameterized Queries) trong SQL tách biệt tuyệt đối giữa câu lệnh SELECT và biến đầu vào của người dùng. "
        "Ngược lại, trong LLM, cả chỉ dẫn hệ thống của lập trình viên (System Prompt), dữ liệu nghiệp vụ, và câu hỏi của kẻ tấn công (User Prompt) "
        "đều được ghép nối thành một chuỗi token duy nhất đưa vào ma trận Attention. Do đó, mô hình hoàn toàn có thể hiểu nhầm dữ liệu độc hại của người dùng "
        "thành một mệnh lệnh điều khiển mới có quyền ưu tiên cao hơn.",
        "Sự hòa trộn giữa kênh điều khiển và kênh dữ liệu (Mixed Control/Data Plane)"
    )
    b.add_bullet(
        "LLM sinh văn bản dựa trên phân phối xác suất ngẫu nhiên (nhiệt độ suy luận Temperature > 0 và Top-p sampling). "
        "Cùng một câu hỏi đầu vào, mô hình có thể từ chối ở lần gọi này nhưng lại chấp nhận sinh mã độc ở lần gọi khác, "
        "khiến các giải pháp kiểm thử bảo mật dựa trên kiểm tra chữ ký tĩnh truyền thống (Static Signature Matching) hoàn toàn bất lực.",
        "Tính chất sinh xác suất và bất định (Stochastic Non-determinism)"
    )
    b.add_bullet(
        "Kẻ tấn công không cần phải có kiến thức chuyên sâu về mã nhị phân hay khai thác tràn bộ nhớ đệm (Buffer Overflow), "
        "mà có thể sử dụng chính ngôn ngữ tự nhiên hàng ngày (tiếng Anh, tiếng Việt, tiếng lóng, tiếng đảo ngữ, mã hóa mật mã) "
        "để thao túng tâm lý và lừa gạt mô hình AI bỏ qua các quy tắc bảo vệ.",
        "Sử dụng ngôn ngữ tự nhiên làm véc-tơ tấn công (Natural Language as Attack Vector)"
    )

    # Callout box
    b.add_callout(
        "Định đề An toàn AI: Không thể bảo đảm tuyệt đối tính an toàn của một mô hình ngôn ngữ lớn chỉ bằng các biện pháp căn chỉnh nội tại (RLHF/System Prompt). "
        "Mọi ứng dụng tích hợp LLM trong môi trường sản xuất bắt buộc phải có cơ chế kiểm thử đối kháng chủ động (Red-teaming) và thiết lập hàng rào phòng thủ ngoại vi (Guardrails) đa tầng.",
        "NGUYÊN LÝ AN TOÀN AI HIỆN ĐẠI"
    )

    # 1.2 Phân tích OWASP LLM Top 10 (2025)
    b.add_heading_2("1.2 Phân Tích Tiêu Chuẩn OWASP Top 10 For LLM Applications (Phiên Bản 2025)")
    b.add_p(
        "Vào đầu năm 2025, Dự án Bảo mật Ứng dụng Web Mở (OWASP) đã chính thức ban hành phiên bản cập nhật toàn diện "
        "**OWASP Top 10 for Large Language Model Applications 2025**. Phiên bản này phản ánh trung thực sự chuyển dịch của các mối hiểm họa "
        "khi các hệ thống LLM phát triển từ các mô hình hỏi đáp đơn giản (Chatbots) sang các hệ sinh thái tác tử tự hành (Agentic AI) "
        "và tích hợp cơ sở dữ liệu tri thức mở rộng (RAG Architecture)."
    )

    # Bảng 1.1
    owasp_10_rows = [
        ("LLM01", "Prompt Injection & Jailbreak", "Ghi đè chỉ dẫn hệ thống trực tiếp/gián tiếp; dùng nhân vật nhập vai phá bỏ rào cản.", "CRITICAL", "Lọc đầu vào; phân tách ngữ cảnh; áp dụng nguyên tắc đặc quyền tối thiểu."),
        ("LLM02", "Sensitive Information Disclosure", "Mô hình để lộ dữ liệu cá nhân (PII), khóa bí mật API, hoặc dữ liệu huấn luyện nhạy cảm.", "HIGH", "Lọc đầu ra; khử trùng dữ liệu huấn luyện; kỹ thuật Differential Privacy."),
        ("LLM03", "Supply Chain Vulnerabilities", "Lỗ hổng từ các mô hình bên thứ ba bị nhiễm độc, plugin lỗi, hoặc gói thư viện phụ thuộc.", "HIGH", "Ký số mô hình (Model Signing); kiểm tra mã băm SHA256; audit chuỗi cung ứng."),
        ("LLM04", "Data and Model Poisoning", "Dữ liệu huấn luyện hoặc fine-tuning bị đầu độc cố ý nhằm tạo backdoor hoặc làm lệch hành vi.", "CRITICAL", "Kiểm soát nguồn dữ liệu; phát hiện dị thường dữ liệu; huấn luyện đối kháng."),
        ("LLM05", "Improper Output Handling", "Ứng dụng hạ tầng tin tưởng mù quáng vào kết quả LLM, dẫn đến XSS, SQLi, SSRF hoặc RCE.", "HIGH", "Khử trùng và mã hóa (sanitize/encode) toàn bộ output trước khi hiển thị hoặc thực thi."),
        ("LLM06", "Excessive Agency", "Cấp quyền hạn thực thi công cụ bên ngoài vượt mức mà không có cơ chế phê duyệt của con người.", "CRITICAL", "Human-in-the-loop cho hành động rủi ro cao; phân quyền tối thiểu; giới hạn phạm vi API."),
        ("LLM07", "System Prompt Disclosure", "Kẻ tấn công trích xuất nguyên văn System Prompt chứa logic nghiệp vụ và bí mật hệ thống.", "MEDIUM", "Không lưu trữ secrets trong prompt; kỹ thuật Instruction Defense; lọc output."),
        ("LLM08", "Vector & Embedding Weaknesses", "Tấn công tiêm nhiễm gián tiếp qua cơ sở dữ liệu vector hoặc bẻ gãy bộ chia tách RAG.", "HIGH", "Xác thực tài nguyên nguồn; cô lập ngữ cảnh truy vấn; ký số vector embeddings."),
        ("LLM09", "Misinformation & Hallucination", "Mô hình tự tin khẳng định thông tin sai lệch, bịa đặt số liệu thống kê hoặc trích dẫn khoa học.", "MEDIUM", "Tích hợp RAG với nguồn kiểm chứng; hiển thị độ tin cậy; fact-checking guardrails."),
        ("LLM10", "Unbounded Consumption (DoS)", "Tấn công từ chối dịch vụ bằng prompt đệ quy, context siêu dài làm cạn kiệt tài nguyên GPU/VRAM.", "MEDIUM", "Rate limiting; giới hạn token trần; timeout chặt chẽ; hàng đợi ưu tiên.")
    ]
    b.add_academic_table(
        headers=["Mã Lỗ Hổng", "Tên Danh Mục OWASP (2025)", "Mô Tả Bản Chất Kỹ Thuật", "Mức Rủi Ro", "Biện Pháp Phòng Vệ Cốt Lõi"],
        rows=owasp_10_rows,
        caption="Bảng tổng hợp 10 hạng mục lỗ hổng bảo mật hàng đầu theo OWASP Top 10 for LLM Applications 2025",
        col_widths=[1.0, 1.8, 2.5, 1.0, 2.2]
    )

    b.add_p(
        "So với phiên bản ban đầu năm 2023, phiên bản 2025 có những cải tiến và định hình lại căn bản, phản ánh đúng thực trạng công nghệ:"
    )

    # Bảng 1.2
    diff_rows = [
        ("LLM01: Prompt Injection", "Chỉ tập trung vào Direct Injection cơ bản.", "Gộp toàn diện cả Direct Injection, Indirect Injection và kỹ thuật Jailbreak phá rào (trước đây nằm rải rác)."),
        ("LLM06: Excessive Agency", "Xếp hạng thứ 8 (mức độ quan tâm trung bình).", "Được nâng lên hạng 6 với mức độ cảnh báo CRITICAL do sự bùng nổ của các Tác tử AI (Agentic Workflows) có quyền gọi Tool/API."),
        ("LLM08: Vector & Embeddings", "Nằm chung trong nhóm Data Poisoning mơ hồ.", "Được tách thành một hạng mục độc lập chuyên biệt nhằm bảo vệ kiến trúc RAG (Retrieval-Augmented Generation) và Vector Database."),
        ("LLM10: Unbounded Consumption", "Gọi tên là 'Model Denial of Service'.", "Đổi tên thành 'Unbounded Consumption' để bao hàm cả rủi ro tiêu tốn chi phí tài chính API không giới hạn (Financial Exhaustion).")
    ]
    b.add_academic_table(
        headers=["Danh Mục / Vấn Đề", "Đặc Điểm Phiên Bản 2023", "Sự Chuyển Dịch Trong Phiên Bản 2025"],
        rows=diff_rows,
        caption="Phân tích so sánh sự chuyển dịch trọng tâm giữa OWASP LLM 2023 và 2025",
        col_widths=[2.0, 2.7, 3.8]
    )

    # 1.3 Khung ma trận MITRE ATLAS
    b.add_heading_2("1.3 Khung Ma Trận Đe Dọa MITRE ATLAS")
    b.add_p(
        "Bên cạnh OWASP vốn tập trung vào góc nhìn của nhà phát triển ứng dụng (Developer Perspective), "
        "tổ chức **MITRE** đã xây dựng ma trận **ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)** "
        "nhằm cung cấp một bức tranh toàn diện từ góc nhìn của đội ngũ tấn công (Attacker / Red Team Perspective), "
        "mô phỏng tương tự mô hình MITRE ATT&CK lừng danh trong an ninh mạng truyền thống."
    )
    b.add_p(
        "MITRE ATLAS cấu trúc vòng đời của một cuộc tấn công nhằm vào hệ thống AI thành 12 giai đoạn chiến thuật (Tactics):"
    )

    atlas_rows = [
        ("AML.TA0002", "Reconnaissance (Trinh sát)", "AML.T0008: Active Scanning\nAML.T0002: Gather Victim AI Information", "Dò quét cổng dịch vụ AI (Ollama 11434, Ray 8265); xác định họ mô hình và phiên bản kiến trúc qua phản hồi đặc thù."),
        ("AML.TA0004", "Initial Access (Thâm nhập)", "AML.T0051: LLM Prompt Injection\nAML.T0016: Supply Chain Compromise", "Gửi payload ghi đè chỉ dẫn hệ thống qua giao diện chat hoặc chèn tài liệu nhiễm độc vào kho RAG."),
        ("AML.TA0006", "Execution (Thực thi)", "AML.T0054: LLM Jailbreak\nAML.T0048: Improper Output Handling", "Sử dụng kịch bản DAN/AIM để ép AI thực thi lệnh nguy hiểm; ép sinh mã độc XSS/SQLi được thực thi bởi ứng dụng web."),
        ("AML.TA0009", "Discovery (Khám phá)", "AML.T0010: LLM System Prompt Disclosure\nAML.T0024: Discover Model Architecture", "Trích xuất System Prompt ẩn; dùng stylometry và tokens rò rỉ để khám phá cấu trúc rào cản an toàn."),
        ("AML.TA0010", "Collection (Thu thập dữ liệu)", "AML.T0024: Exfiltration via Model Outputs\nAML.T0020: Poisoned Retrieval Context", "Thu thập thông tin định danh cá nhân (PII), khóa xác thực API bị mô hình ghi nhớ trong quá trình huấn luyện."),
        ("AML.TA0013", "Impact (Gây tác động)", "AML.T0029: Denial of Service\nAML.T0048.001: Excessive Agency Actions", "Làm tê liệt hạ tầng GPU bằng prompt đệ quy cực lớn; điều khiển Agent thực thi giao dịch trái phép hoặc xóa database.")
    ]
    b.add_academic_table(
        headers=["Mã Chiến Thuật", "Tên Giai Đoạn (Tactics)", "Kỹ Thuật Tiêu Biểu (Techniques)", "Hành Vi Khai Thác Thực Tế Trong Đề Tài"],
        rows=atlas_rows,
        caption="Ánh xạ các chiến thuật và kỹ thuật trọng yếu của khung MITRE ATLAS được hiện thực trong hệ thống",
        col_widths=[1.3, 1.8, 2.4, 3.0]
    )

    # 1.4 NIST AI RMF và tiêu chuẩn liên quan
    b.add_heading_2("1.4 Khung Quản Trị Rủi Ro NIST AI RMF 1.0 Và Các Tiêu Chuẩn Quốc Tế Liên Quan")
    b.add_p(
        "Tháng 1 năm 2023, Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST) công bố **NIST AI Risk Management Framework 1.0 (AI RMF)**. "
        "Đây được coi là kim chỉ nam hàng đầu thế giới về quản trị rủi ro AI, cấu trúc quy trình quản lý thành 4 hàm cốt lõi liên hoàn:"
    )
    b.add_bullet(
        "Thiết lập văn hóa tổ chức, chính sách và cơ cấu trách nhiệm rõ ràng trong việc quản lý rủi ro xuyên suốt vòng đời phát triển AI.",
        "1. GOVERN (Quản trị)"
    )
    b.add_bullet(
        "Nhận diện, định danh bối cảnh triển khai, các bên liên quan và phân loại toàn bộ các nguy cơ bảo mật tiềm ẩn đối với từng mô hình AI.",
        "2. MAP (Bản đồ hóa)"
    )
    b.add_bullet(
        "Áp dụng các công cụ định lượng, phương pháp kiểm thử thâm nhập đối kháng (Red-teaming) để đo đạc và đánh giá mức độ tổn thương thực tế.",
        "3. MEASURE (Đo lường)"
    )
    b.add_bullet(
        "Phân bổ tài nguyên, triển khai các biện pháp phòng vệ (WAF, Guardrails, Sanitizer) và theo dõi liên tục để giảm thiểu rủi ro đã xác định.",
        "4. MANAGE (Kiểm soát)"
    )

    b.add_p(
        "Song hành cùng NIST AI RMF, các tiêu chuẩn quốc tế và quy định pháp lý khác cũng đang tạo nên làn sóng chuẩn hóa bắt buộc:"
    )
    b.add_bullet(
        "Tiêu chuẩn quốc tế đầu tiên về Hệ thống Quản lý Trí tuệ Nhân tạo (AIMS), yêu cầu các tổ chức phải có quy trình đánh giá rủi ro định kỳ và kiểm thử an toàn đối với các thuật toán AI.",
        "ISO/IEC 42001:2023"
    )
    b.add_bullet(
        "Đạo luật Quản lý AI của Liên minh Châu Âu (ban hành 2024), phân cấp các hệ sinh thái AI thành 4 mức rủi ro (Không thể chấp nhận, Rủi ro cao, Rủi ro hạn chế, Rủi ro tối thiểu) với các chế tài xử phạt hành chính cực kỳ nghiêm khắc đối với các hệ thống không vượt qua kiểm định an toàn.",
        "EU AI Act"
    )
    b.add_bullet(
        "Việt Nam đã ban hành Chiến lược Quốc gia về Nghiên cứu, Phát triển và Ứng dụng Trí tuệ Nhân tạo đến năm 2030 (Quyết định 127/QĐ-TTg) và Nghị định số 13/2023/NĐ-CP về Bảo vệ Dữ liệu Cá nhân. Việc kiểm thử an toàn hệ thống AI để chống rò rỉ dữ liệu người dùng là nghĩa vụ pháp lý bắt buộc đối với mọi doanh nghiệp công nghệ trong nước.",
        "Định hướng Chính sách tại Việt Nam"
    )

    # 1.5 Khảo sát công trình liên quan & khoảng trống
    b.add_heading_2("1.5 Khảo Sát Các Công Trình Nghiên Cứu Liên Quan Và Khoảng Trống Học Thuật")
    b.add_p(
        "Trong cộng đồng nghiên cứu an toàn thông tin quốc tế, nhiều công trình đột phá đã đặt nền móng cho lĩnh vực LLM Red-teaming:"
    )
    b.add_bullet(
        "Greshake et al. (2023) trong bài báo \"Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection\" "
        "đã chứng minh khả năng tiêm nhiễm gián tiếp qua tài liệu web và email để chiếm quyền điều khiển trợ lý AI Bing Chat.",
        "Nghiên cứu về Indirect Injection"
    )
    b.add_bullet(
        "Zou et al. (2023) tại Đại học Carnegie Mellon công bố thuật toán GCG (Greedy Coordinate Gradient) tự động tìm kiếm chuỗi hậu tố đối kháng (adversarial suffixes) "
        "có thể bẻ gãy mọi rào cản an toàn của LLaMA-2 và ChatGPT. Tiếp đó, Chao et al. (2023) đề xuất kỹ thuật PAIR (Prompt Automatic Iterative Refinement) "
        "sử dụng một LLM tấn công để tự động tinh chỉnh prompt qua nhiều vòng lặp mà không cần tính toán gradient.",
        "Nghiên cứu về Jailbreak Tự động hóa"
    )
    b.add_bullet(
        "Zheng et al. (2023) tại UC Berkeley đề xuất khuôn mẫu \"LLM-as-a-Judge\" trong bài báo MT-Bench, chứng minh các mô hình LLM mạnh có khả năng "
        "đánh giá chất lượng và độ an toàn của văn bản với độ tương đồng đạt tới 85-90% so với chuyên gia con người.",
        "Nghiên cứu về LLM-as-a-Judge"
    )

    b.add_callout(
        "Khoảng trống nghiên cứu (Research Gap): Mặc dù các nghiên cứu quốc tế đã đề xuất nhiều kỹ thuật tấn công đơn lẻ, "
        "nhưng thế giới vẫn đang thiếu một giải pháp toàn diện kết hợp giữa kiểm thử tốc độ cao và suy luận ngữ nghĩa; "
        "thiếu một mô hình tính điểm rủi ro định lượng có cấu trúc tương thích chuẩn CVSS; và hoàn toàn thiếu vắng một công cụ "
        "hoàn chỉnh hỗ trợ môi trường hạ tầng AI nội bộ (On-premise / Local Ollama) có giao diện trực quan thân thiện với người dùng Việt Nam. "
        "Đề tài này được xây dựng để lấp đầy chính xác khoảng trống học thuật và thực tiễn đó.",
        "KHOẢNG TRỐNG HỌC THUẬT VÀ ĐÓNG GÓP CỦA ĐỀ TÀI"
    )
    gap_rows = [
        ("G1 – Kiểm thử đa tầng", "Các công cụ hiện tại chỉ tập trung vào LLM đơn lẻ; thiếu mô hình thống nhất xuyên suốt từ Input → LLM → RAG → Agent → Tool/API → Data.", "Xây dựng kiến trúc 14 modules đa tầng + ThreatModel + AgentSandbox."),
        ("G2 – Sinh testcase thích nghi", "Đa số công cụ dùng tập probe tĩnh cố định; thiếu cơ chế học từ phản hồi của mục tiêu để tự động chuyển đổi chiến lược tấn công.", "Phát triển AdaptiveGenerator với vòng lặp phản hồi và 13 chiến lược đột biến."),
        ("G3 – Threat model thống nhất", "Thiếu ánh xạ tự động và nhất quán giữa loại hình hệ thống, bề mặt tấn công, lỗ hổng OWASP/MITRE, bằng chứng và mức độ tác động.", "Hiện thực SystemProfiler & ThreatModel tự động sinh hồ sơ đe dọa theo chuẩn JSON Schema."),
        ("G4 – Đo lường định lượng", "Các metric rời rạc giữa các công cụ; thiếu công thức chấm điểm rủi ro chuẩn hóa tương thích CVSS và các chỉ số chuyên biệt cho RAG/Agent.", "Xây dựng công thức toán học CVSS-like (ISS, Impact, Exploitability) & ExtendedMetrics (RMR, URR, TAR, DER)."),
        ("G5 – An toàn RAG & Agent", "Không gian tấn công thay đổi mạnh khi có Vector DB, Memory và Function Calling; thiếu môi trường hộp cát cô lập để kiểm thử an toàn.", "Xây dựng module rag_security, agent_testing và môi trường giả lập AgentSandbox 5 công cụ."),
        ("G6 – Tự động hóa & Tái lập", "Thiếu pipeline khép kín từ profiling → sinh testcase → thực thi → phân tích hai tầng → lưu trữ bằng chứng có thể tái lập (Replay).", "Thiết kế kiến trúc Two-Tier Hybrid Detector kết hợp EvidenceStore (SQLite WAL) hỗ trợ Replay Test."),
        ("G7 – Benchmark Tiếng Việt", "Thiếu hoàn toàn bộ dữ liệu chuẩn hóa có ngữ cảnh tiếng Việt (ngân hàng, y tế, pháp lý, từ lóng, không dấu) để kiểm định guardrail nội địa.", "Xây dựng bộ Vietnamese Benchmark gồm 62 kịch bản chuyên sâu và kiểm định thống kê Cross-lingual Gap.")
    ]
    b.add_academic_table(
        headers=["Khoảng trống khoa học", "Mô tả hạn chế của các nghiên cứu hiện có", "Giải pháp đóng góp của Đề tài"],
        rows=gap_rows,
        caption="Tổng hợp 7 khoảng trống khoa học (G1 – G7) và giải pháp giải quyết trong đề tài",
        col_widths=[1.6, 2.7, 2.7]
    )

    b.add_page_break()
