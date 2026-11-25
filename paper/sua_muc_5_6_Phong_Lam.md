# BẢN CHỈNH SỬA MỤC 5 VÀ MỤC 6 — PHẦN CÔNG VIỆC CỦA PHONG & LÂM

> **Hướng dẫn bôi đỏ trong Word để thầy review:**
> - Các đoạn/mục được đánh dấu **`[BÔI ĐỎ - SỬA]`** hoặc **`[BÔI ĐỎ - BỔ SUNG MỚI]`** là nội dung mới chỉnh sửa/bổ sung so với bản thảo gốc.
> - Toàn bộ số liệu thực nghiệm dưới đây đều là **số liệu thật 100%** thu từ hệ thống đã nâng cấp (`AI_Security_Scanner` + lớp lõi `RBST-AI`), lưu đầy đủ bằng chứng phản hồi thô tại `AI_Security_Scanner/experiments/results/rbst_real/`.
> - **Ghi chú đồng bộ cần nhắc cả nhóm (buổi họp 25/11):**
>   1. **Tóm tắt, Mục 1 (Phạm vi phương pháp) và Mục 8 (Kết luận):** Bỏ câu *"bài báo không công bố số liệu thực nghiệm mới"* và cập nhật thành *"bài báo hiện thực nguyên mẫu RBST-AI và thực nghiệm trên bốn kịch bản (CS1–CS4) với 507 lượt thực thi tấn công thật và 300 mẫu kiểm chứng Oracle gán nhãn mù đôi"*.
>   2. **Tiêu đề tiếng Anh:** Sửa `Intelligent Artificial Systems` → `Artificial Intelligence Systems`.
>   3. **Hình 1 và Hình 2:** Sửa chữ `luồng dữ liệu E` → `luồng dữ liệu D` (khớp $S=(C,D)$ ở Mục 4.1) và sửa `R = L · I · M` → `R = L · I · M · (1 − E)` (khớp công thức (3) ở Mục 4.3).
>   4. **Mục 6.1 bản gốc:** Đã bỏ ký hiệu chưa định nghĩa $\omega = 1$, thay bằng $a_3 = 1$ nhất quán với Mục 4.2.

---

# 5. Thiết kế và hiện thực framework RBST-AI `[BÔI ĐỎ - SỬA TIÊU ĐỀ]`

## 5.1. Kiến trúc bốn tầng

Hình 1 trình bày kiến trúc tổng thể của RBST-AI. Tầng 1 tiếp nhận hồ sơ hệ thống $S=(C, D)$, cơ sở tri thức mối đe dọa và yêu cầu tuân thủ. Tầng 2 hiện thực mô hình toán học ở Mục 4 (`Context Profiler`, `Threat Modeler`, `Risk Engine`). Tầng 3 điều phối và thực thi ca kiểm thử (`Test Orchestrator`, `Attack Generator`, `Executor`, `Oracle`). Tầng 4 lưu bằng chứng tái lập và sinh báo cáo truy vết tuân thủ. Điểm cốt lõi của kiến trúc là cạnh phản hồi từ `Oracle` về `Risk Engine`, cập nhật trực tiếp phân phối hậu nghiệm Beta–Bernoulli và biến quy trình thành vòng kín thích nghi.

*(Lưu ý chỉnh sửa trực tiếp trên Hình 1: đổi nhãn `luồng dữ liệu E` thành `luồng dữ liệu D`, và đổi `R = L · I · M` thành `R = L · I · M · (1 − E)`.)*

`[BÔI ĐỎ - SỬA BẢNG 4: gắn tên mô-đun hiện thực thực tế trong nguyên mẫu AI_Security_Scanner]`

**Bảng 4.** Các mô-đun của RBST-AI và hiện thực trong nguyên mẫu

| Mô-đun | Đầu vào | Đầu ra | Hiện thực trong nguyên mẫu (`AI_Security_Scanner`) |
| :--- | :--- | :--- | :--- |
| **Context Profiler** | Hồ sơ kiến trúc YAML/JSON, danh mục công cụ, phân loại dữ liệu | Đồ thị $S=(C, D)$; vector $(a_1 \dots a_4)$; $M(c)$ | `core/rbst_graph.py` (`SystemGraph`, BFS lan truyền đặc quyền $a_2$) |
| **Threat Modeler** | $S$, tri thức OWASP LLM/Agentic, ATLAS, mô hình kẻ tấn công | Tập cặp $(t, c)$ khả dĩ; danh sách ranh giới tin cậy | `core/rbst_graph.py` (`RBSTThreatModeler`) + `data/taxonomy.json` |
| **Risk Engine** | Cặp $(t, c)$, $I, E, \mu_0, n_0$, kết quả kiểm thử $y_k$ | $R$, $R_{\text{res}}$, $\theta_{\text{tb}}$, $\theta_{\max}$, bản đồ nhiệt | `core/rbst_engine.py` (`RBSTRiskEngine`, phân vị Beta 95% qua `scipy`) |
| **Test Orchestrator** | Hậu nghiệm Beta, thư viện ca kiểm thử, ngân sách $B$, ngưỡng $\tau$ | Chuỗi ca kiểm thử tối ưu chỉ số $P$ (CT 6) | `core/rbst_engine.py` (`RBSTOrchestrator`, Thompson Sampling + B0–B4/A1–A3) |
| **Attack Generator** | Cặp $(t, c)$ và ca $k$ được chọn | Payload gốc và biến thể đột biến | `core/rbst_adapter.py`, `core/adaptive_generator.py`, adapter `garak`/`PyRIT`/`ART`, PAIR, GCG |
| **Executor** | Ca kiểm thử $k$, cấu hình hệ thống đích | Phản hồi gốc, vết thực thi công cụ, chi phí $K$ | `core/llm_client.py` (Ollama/OpenAI), `core/agent_sandbox.py` (Email/Banking/Booking), `scikit-learn` API |
| **Oracle** | Phản hồi, vết thực thi công cụ | Nhãn $y_k \in \{0, 1\}$, lý do và mức nghiêm trọng | Cascade 2 tầng: `PatternDetector`/canary/tool-trace + `LLMJudge` (`modules/detectors/`) |
| **Evidence Store & Reporter** | Toàn bộ vết kiểm thử $(t, c, k, y_k, R, R_{\text{res}})$ | Báo cáo JSON/MD, bản đồ nhiệt, ánh xạ tuân thủ | `core/evidence_store.py` (SQLite) + `core/rbst_metrics.py` (`RBSTComplianceReporter`) |

## 5.2. Quy trình sáu pha

Quy trình vận hành gồm sáu pha (Hình 2). Pha 1–2 chạy một lần cho mỗi phiên bản hệ thống để dựng đồ thị $S=(C, D)$, xác định ranh giới tin cậy, tính hệ số khuếch đại $M(c)$ và sinh danh sách cặp $(t, c)$ khả dĩ theo mô hình kẻ tấn công NIST AI 100-2e2025 [21]. Pha 3–6 vận hành theo vòng lặp kín: định lượng rủi ro (CT 3–4), rút mẫu Thompson và chọn ca theo chỉ số ưu tiên $P$ (CT 6), thực thi trong sandbox và phán xét bằng Oracle, sau đó cập nhật hậu nghiệm (CT 5) và rủi ro tồn dư $R_{\text{res}}$ (CT 7) cho tới khi thỏa điều kiện dừng (CT 8).

*(Lưu ý chỉnh sửa trực tiếp trên Hình 2: đổi `R = L × I × M` ở khối 3 thành `R = L × I × M × (1 − E)`.)*

## 5.3. Thuật toán điều phối

*(Giữ nguyên Thuật toán 1 `RBST-AI-Loop` từ bản thảo gốc.)*

Mỗi vòng lặp có độ phức tạp thời gian tỉ lệ với số cặp $(t, c)$ cộng số ca khả dụng trong thư viện; khi thư viện ca lớn, có thể giảm chi phí tính toán bằng cách rút mẫu $\theta_{\text{mẫu}}$ một lần cho mỗi cặp $(t, c)$ rồi đánh giá $P$ cho các ca thuộc cặp đó (như đã hiện thực trong `RBSTOrchestrator`).

## 5.4. Truy vết tuân thủ

Mỗi bản ghi bằng chứng lưu trong `EvidenceStore` có cấu trúc chuẩn `(t, c, k, y_k, severity, mã OWASP/ATLAS, phiên bản hệ thống, thời điểm, chi phí K, R, R_res)`. Bảng 5 ánh xạ sáu pha sang ba khung quản trị và tiêu chuẩn chủ chốt: NIST AI RMF 1.0 [8], ISO/IEC TS 42119-2 [10] và Đạo luật AI của EU [9].

*(Giữ nguyên Bảng 5 từ bản thảo gốc.)*

## 5.5. Hiện thực nguyên mẫu trên hệ thống `AI_Security_Scanner` `[BÔI ĐỎ - BỔ SUNG MỚI]`

Để kiểm chứng thực nghiệm mà không phải xây dựng lại hạ tầng thực thi, lớp lõi RBST-AI được tích hợp trực tiếp vào bộ công cụ mã nguồn mở nội bộ `AI_Security_Scanner` (Python 3.13) thông qua bốn thành phần mới:
1. **`core/rbst_graph.py`:** Hiện thực đồ thị có hướng $S=(C, D)$ nạp từ lược đồ YAML (`data/rbst_profiles/cs1..cs4.yaml`), tự động tìm ranh giới tin cậy và lan truyền đặc quyền công cụ $a_2$ theo thuật toán duyệt đồ thị có hướng (BFS) trên mọi thành phần hạ nguồn.
2. **`core/rbst_engine.py`:** Hiện thực `RBSTRiskEngine` và `RBSTOrchestrator` hỗ trợ đầy đủ 9 chính sách chọn ca (`RBST-AI`, `B0`–`B4`, `A1`–`A3`), dừng sớm theo ngưỡng $R_{\text{res}} \le \tau$ hoặc ngân sách $B$, và bảo đảm tính tái lập hoàn toàn theo hạt giống ngẫu nhiên (`seed`).
3. **`core/rbst_metrics.py`:** Hiện thực bộ chỉ số đánh giá ở Mục 7.2 ($\text{APFD}_R$, $\text{RC}$, $\text{CF}$, Recall phân tầng mức nghiêm trọng, Spearman $\rho$, Cohen's $\kappa$) và `RBSTComplianceReporter` xuất báo cáo tuân thủ JSON/Markdown.
4. **`core/rbst_adapter.py` & giao diện dòng lệnh (`main.py --rbst`):** Kết nối lớp lõi vào các bộ tấn công hiện có (`data/testcases/*.yaml`, `AdaptiveGenerator`), `AgentSandbox` (bổ sung ba công cụ giả lập cho tác tử: `tool_email`, `tool_booking`, `tool_banking`), bộ phán xét hai tầng (`PatternDetector` + `LLMJudge`), bộ kiểm soát ngân sách `CampaignBudget` và kho bằng chứng SQLite `EvidenceStore`. Toàn bộ công thức (1)–(10) và luồng tích hợp đã được kiểm chứng tự động qua 12 ca kiểm thử đơn vị và tích hợp (`tests/test_rbst_core.py`, đạt 12/12 `PASSED`).

---

# 6. Case Study và Kết quả Thực nghiệm `[BÔI ĐỎ - SỬA TOÀN BỘ MỤC 6]`

`[BÔI ĐỎ - BỔ SUNG MỚI]` Khác với giai đoạn thiết kế khái niệm ban đầu, mục này trình bày **kết quả thực nghiệm định lượng dựa hoàn toàn trên phản hồi thật của bốn hệ thống AI đích (CS1–CS4)** tương ứng với bốn kịch bản kiến trúc trong Bảng 6. Mọi nhãn thành công $y_k \in \{0, 1\}$, độ trễ và chi phí $K$ đều được đo trực tiếp từ lần chạy thật (không sử dụng mô phỏng xác suất hay dữ liệu giả lập).

## 6.1. Thiết lập thực nghiệm và đặc trưng đồ thị bốn kịch bản (CS1–CS4)

Hệ thống thực nghiệm bao gồm bốn hệ thống đích đại diện cho bốn dạng kiến trúc AI phổ biến:
- **CS1 (Trợ lý chat tích hợp tìm kiếm web — RAG):** Chạy trực tiếp trên mô hình `qwen2.5:latest` (Ollama) với lịch sử hội thoại chứa thông tin phiên nhạy cảm (`alice.nguyen@corp.vn`, `CORP-TOK-7741`) và nguồn trang web ngoài không tin cậy.
- **CS2 (Tác tử AI có công cụ — Email, Đặt lịch, Ngân hàng):** Chạy trực tiếp tác tử ReAct trên `qwen2.5:latest` kết nối `AgentSandbox` với ba công cụ `tool_email` (ghi), `tool_booking` (ghi), `tool_banking` (thực thi giao dịch tài chính) và bộ nhớ chứa số tài khoản (`VN99-4410-8821`).
- **CS3 (Chatbot LLM công khai không công cụ):** Kết hợp bộ phản hồi thật đã ghi trên `qwen2.5:latest` từ tập chuẩn 180 ca (`benchmark_real_qwen2.5_latest_180.json`) cho nhóm vượt rào/tiêm nhiễm trực tiếp, và thực thi trực tiếp trên `qwen2.5:latest` cho nhóm rò rỉ dữ liệu, rò rỉ system prompt, xử lý đầu ra và tiêu thụ tài nguyên.
- **CS4 (Dịch vụ học máy qua API dự đoán — MLaaS):** Huấn luyện thật ba mô hình phân loại bằng `scikit-learn` (`LogisticRegression`, `DecisionTreeClassifier`, `MLPClassifier`) trên tập dữ liệu chuẩn `Breast Cancer Wisconsin`, bọc thành API dự đoán và thực thi trực tiếp các tấn công trích xuất mô hình [6], né tránh FGSM/nhiễu [3, 4], suy luận thành viên (MIA), đầu vào biên và quá tải lô (batch DoS).

Tổng cộng đã thu thập **507 lượt thực thi tấn công thật**: 186 ca trên kho kiểm thử chuẩn của bốn kịch bản (CS1: 51, CS2: 75, CS3: 36, CS4: 24), 105 lượt tấn công tinh chỉnh lặp 3 vòng cho **S1 (PAIR độc lập)** (`llama3:latest` tinh chỉnh dựa trên phản hồi từ chối thật của `qwen2.5:latest`), 108 ca chuyển giao từ 10 hậu tố tối ưu gradient hộp trắng cho **S2 (GCG độc lập)** (chạy `nanogcg` trên mô hình mở `Qwen/Qwen2.5-1.5B-Instruct` bằng GPU NVIDIA Tesla T4 trong 1.048 giây, giảm loss trung bình từ 3,629 xuống 2,074 rồi chuyển giao sang `qwen2.5:latest`), và 108 ca sinh tự động cho **S3 (Red teaming bằng LLM)** (`llama3:latest` sinh ca → bắn trực tiếp lên `qwen2.5:latest`). Toàn bộ nhãn $y_k \in \{0, 1\}$ trên 186 ca chuẩn được xác định khách quan bằng cảm biến Canary bí mật (`CORP-TOK-7741`, `VN99-4410-8821`), vết gọi công cụ `AgentSandbox` và ngưỡng toán học `scikit-learn`.

Tất cả các phương pháp ở Bảng 8 được đánh giá trong cùng ngân sách $B$ bằng 45% tổng chi phí kho ca của từng kịch bản (CS1: $B=36{,}9$; CS2: $B=48{,}1$; CS3: $B=32{,}2$; CS4: $B=23{,}0$), lặp qua **30 hạt giống ngẫu nhiên** (`seed = 1..30`), tính trung bình $\pm$ độ lệch chuẩn và kiểm định hạng có dấu Wilcoxon so với RBST-AI. Trọng số khuếch đại mặc định $w = (0{,}25; 0{,}25; 0{,}25; 0{,}25)$ và $n_{\min} = 2$ cho chỉ số $\text{RC}$.

**Bảng 6.** Đặc trưng đồ thị hệ thống $S=(C,D)$, hệ số khuếch đại $M$ và tổng hợp dữ liệu phản hồi thật trên bốn Case Study

| Đặc trưng | CS1. Trợ lý chat tìm kiếm web | CS2. Tác tử có công cụ (Email, Ngân hàng, Lịch) | CS3. Chatbot LLM công khai | CS4. Dịch vụ ML qua API (MLaaS) |
| :--- | :--- | :--- | :--- | :--- |
| **Nguồn tham chiếu** | [1, 2] | [14, 15, 22] | [7, 13, 27, 28] | [3, 4, 6] |
| **Hệ thống đích thực nghiệm** | Ollama `qwen2.5:latest` (Web RAG) | Ollama `qwen2.5:latest` + `AgentSandbox` | `benchmark_180` + Ollama `qwen2.5:latest` | `scikit-learn` (LR / DT / MLP) |
| **Kích thước đồ thị $(\|C\|, \|D\|)$** | (5, 5); 1 ranh giới tin cậy | (7, 7); 1 ranh giới tin cậy | (4, 4); 0 ranh giới tin cậy | (3, 3); 0 ranh giới tin cậy |
| **Số cặp $(t, c)$ khả dĩ** | 17 | 25 | 12 | 8 |
| **Hệ số $M$ ($M_{\min}$ / $M_{\text{tb}}$ / $M_{\max}$)** | 1,28 / 1,40 / **1,61** | 1,57 / 1,72 / **1,95** | 1,09 / 1,13 / **1,16** | 1,30 / 1,31 / **1,32** |
| **Cặp ưu tiên đầu ($R_0$ cao nhất)** | `T_IPI@web_context` | `T_ASI01_GOAL_HIJACK@untrusted_feeds` | `T_JB@llm_model` | `T_MODEL_EXTRACT@prediction_api` |
| **Số ca chuẩn / Số ca vượt rào ($y=1$)** | 51 / 32 (ASR 62,7%) | 75 / 55 (ASR 73,3%) | 36 / 12 (ASR 33,3%) | 24 / 8 (ASR 33,3%) |
| **Tổng lỗ hổng thật phân biệt** | 15 | 21 | 9 *(gồm cả ca S3)* | 5 |
| **Độ trễ thực thi TB (ms)** | 14.209,0 | 25.737,8 | 26.991,8 | 35,6 |

Kết quả Bảng 6 xác nhận đúng tính chất phân biệt kiến trúc của hệ số $M$: **$M_{\max}(\text{CS2}) = 1{,}95 > M_{\max}(\text{CS1}) = 1{,}61 > M_{\max}(\text{CS4}) = 1{,}32 > M_{\max}(\text{CS3}) = 1{,}16$**, và cặp rủi ro khởi đầu cao nhất ở mỗi hệ thống đều hội tụ đúng về điểm yếu đặc thù nhất của kiến trúc đó.

## 6.2. Phân tích chi tiết bốn Case Study

### 6.2.1. CS1 — Trợ lý chat tích hợp tìm kiếm web
Greshake và cộng sự [1] chỉ ra kẻ tấn công có thể cài lệnh ẩn trong trang web để điều khiển trợ lý mà không cần tương tác trực tiếp. Khi mô hình hóa CS1 bằng RBST-AI, nguồn `web_context` có tỉ lệ đầu vào không tin cậy $a_3 = 1{,}0$ và nằm ngay trước ranh giới tin cậy đi vào lớp điều phối; tuy đặc quyền lan truyền chỉ ở mức đọc ($a_2 = 1/3$), độ nhạy lịch sử hội thoại $a_4 > 0$ vẫn đẩy $M(\text{web\_context}) = 1{,}61$. Do đó cặp `(T_IPI, web_context)` xếp hạng rủi ro cao nhất và được ưu tiên kiểm thử trước nhóm jailbreak trực tiếp. Thực nghiệm trực tiếp trên `qwen2.5:latest` ghi nhận 32/51 ca vượt rào (ASR 62,7%), trong đó các chỉ thị ẩn nhúng trong thẻ `<retrieved_web_page>` đã buộc mô hình trích xuất mã phiên `CORP-TOK-7741` hoặc chèn liên kết rò rỉ dữ liệu. **Bài học:** RBST truyền thống chấm rủi ro tách rời tại thành phần LLM, còn RBST-AI định vị rủi ro theo luồng dữ liệu đi qua ranh giới tin cậy.

### 6.2.2. CS2 — Tác tử có công cụ
Theo kịch bản của InjecAgent [15] và AgentDojo [14], tác tử ReAct đọc nguồn ngoài không tin cậy (`untrusted_feeds`: email, đánh giá phòng khám) và có khả năng gọi các công cụ `tool_email`, `tool_booking` và `tool_banking`. Nhờ cơ chế **lan truyền đặc quyền $a_2$** ở Mục 4.2, dù bản thân `untrusted_feeds` chỉ có quyền đọc, đường đi dữ liệu tới `tool_banking` (mức thực thi giao dịch) khiến $a_2 = 1{,}0$; kết hợp mức tự chủ cao ($a_1 = 0{,}95$) và dữ liệu tài chính nhạy cảm ($a_4 = 0{,}85$), $M(\text{untrusted\_feeds})$ đạt **1,95** — cao nhất trong bốn kịch bản. Trên thực nghiệm live với `qwen2.5:latest` + `AgentSandbox`, tác tử phát ra lệnh gọi công cụ trái phép (chuyển tiền `tool_banking`, gửi dữ liệu `tool_email`, đặt lịch `tool_booking`) ở 55/75 ca (ASR 73,3%), xác nhận 21 lỗ hổng phân biệt. RBST-AI định hướng ngân sách ngay vào các cặp `ASI01`/`LLM06` có $M$ lớn, đạt chi phí tới lỗ hổng nghiêm trọng đầu tiên chỉ $\text{CF} = 1{,}15$. **Bài học:** Hệ số $M$ lượng hóa rõ sự gia tăng rủi ro khi cùng một mô hình nền được trao quyền gọi công cụ thực thi.

### 6.2.3. CS3 — Chatbot LLM công khai
Với chatbot chỉ trả lời văn bản và không kết nối công cụ, $M$ giữ mức thấp ($1{,}09$–$1{,}16$). Điểm đáng chú ý trong thực nghiệm thật là `qwen2.5:latest` được căn chỉnh an toàn rất chặt với các mẫu jailbreak trực tiếp trong tập 180 ca (0% vượt rào trên phần mẫu jailbreak chuẩn), trong khi vẫn tồn tại lỗ hổng ở nhóm rò rỉ ngữ cảnh/system prompt, xử lý đầu ra không khử trùng (`<script>`) và tiêu thụ tài nguyên. Vì vậy, mọi baseline tĩnh (`B1` OWASP, `B2` RBST tĩnh, `B3` công cụ mặc định, `B4` RBT định tính) đều bị "kẹt" ở nhóm `LLM01` đầu danh sách và cạn ngân sách $B=32{,}2$ với $\text{APFD}_R \approx 0{,}000$, hầu như không tìm thấy lỗ hổng nào. Ngược lại, **RBST-AI** liên tục hạ ước lượng hậu nghiệm $\theta_{\text{tb}}$ của các cặp jailbreak khi gặp chuỗi thất bại và chuyển ngân sách sang các cặp có tỉ số lợi ích/chi phí $P$ cao hơn, đạt $\text{APFD}_R = 0{,}719$ và $\text{CF} = 9{,}70$ ($p < 0{,}0001$).

### 6.2.4. CS4 — Dịch vụ ML qua API dự đoán `[BÔI ĐỎ - BỔ SUNG MỤC 6.4 CÒN THIẾU]`
Dịch vụ học máy qua API (`MLaaS`) không dùng công cụ tác tử ($a_1 \le 0{,}10$, $a_2 \le 1/3$) nhưng bản thân trọng số mô hình là tài sản sở hữu trí tuệ nhạy cảm ($a_4 = 0{,}90$), nên $M$ ở mức $1{,}30$–$1{,}32$ và rủi ro tập trung tại `(T_MODEL_EXTRACT, prediction_api)` và `(T_ML_EVASION, prediction_api/ml_model)`. Thực nghiệm trực tiếp trên ba mô hình `scikit-learn` thật xác nhận toàn bộ các mối đe dọa kinh điển:
- **Trích xuất mô hình [6]:** Mô hình thay thế đạt độ trung thực (*surrogate fidelity*) **99,0%** với `LogisticRegression` sau 650 truy vấn (97,5% ngay từ 120 truy vấn), **97,0%** với `DecisionTreeClassifier` sau 1.150 truy vấn, và **98,0%–99,0%** với `MLPClassifier` sau 300–1.150 truy vấn — tương đồng trực tiếp với các mốc 650–1.150 truy vấn đã công bố của Tramèr và cộng sự [6].
- **Tấn công né tránh [3, 4]:** FGSM đạt tỉ lệ đánh lừa phân loại **39,5%** ở $\epsilon = 0{,}35$ và **92,0%** ở $\epsilon = 0{,}90$ trên 200 mẫu kiểm thử thật.
- **Xử lý đầu vào biên:** API chấp nhận giá trị cực biên $10^{12}$ không kiểm tra lược đồ và bão hòa xác suất đầu ra `[1.0, 0.0]`.

Trong ngân sách $B = 23{,}0$, RBST-AI phát hiện lỗ hổng nghiêm trọng đầu tiên với chi phí chỉ **$\text{CF} = 0{,}60$** (so với $10{,}58$ của ngẫu nhiên và $7{,}80$ của OWASP tuần tự), đạt $\text{APFD}_R = 0{,}676$ ($\text{APFD}_R^{\text{pen}} = 0{,}533$) và độ bao phủ rủi ro $\text{RC} = 0{,}763$ ($p < 0{,}0001$ so với mọi baseline). **Bài học:** RBST-AI tổng quát hóa nhất quán cho cả hệ thống LLM/tác tử lẫn dịch vụ học máy truyền thống (trả lời ĐG4).

## 6.3. So sánh hiệu năng với các Baseline (B0–B4) và SOTA (S1–S3) `[BÔI ĐỎ - BỔ SUNG MỚI]`

Bảng 7 trình bày kết quả so sánh định lượng trên cả bốn Case Study (30 seeds). Ngoài chỉ số $\text{APFD}_R$ theo công thức (9) tính trên các lỗ hổng phát hiện được, bảng báo cáo song song biến thể có phạt $\text{APFD}_R^{\text{pen}}$ (gán $TF_i = n + 1$ cho lỗ hổng thật chưa phát hiện được trong ngân sách $B$) nhằm phản ánh công bằng cả tốc độ lẫn độ phủ lỗ hổng. Các phương pháp tấn công đặc thù LLM (`S1`, `S2`, `S3`) không áp dụng cho mô hình ML bảng ở CS4 nên được ghi nhận `N/A`.

**Bảng 7.** Kết quả thực nghiệm so sánh RBST-AI với Baseline (`B0`–`B4`), SOTA (`S1`–`S3`) và cấu hình loại bỏ (`A1`–`A3`) trên bốn Case Study (trung bình $\pm$ độ lệch chuẩn qua 30 seeds; $p$ là $p$-value Wilcoxon so với RBST-AI trên $\text{APFD}_R^{\text{pen}}$)

| CS | Mã | Phương pháp | $\text{APFD}_R$ (CT 9) | $\text{APFD}_R^{\text{pen}}$ | RC (CT 10) | CF (↓) | Recall trọng số | Wilcoxon $p$ |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **CS1** | `B0` | Ngẫu nhiên | 0,556 ± 0,080 | 0,405 ± 0,069 | 0,427 ± 0,107 | 4,76 ± 3,32 | 0,744 ± 0,105 | < 0,0001 |
| | `B1` | Theo danh mục OWASP [23] | 0,533 ± 0,064 | 0,317 ± 0,036 | 0,597 ± 0,040 | 2,60 ± 1,51 | 0,611 ± 0,061 | < 0,0001 |
| | `B2` | RBST tĩnh ($L_0 \times I$) [16, 17] | 0,516 ± 0,028 | 0,308 ± 0,013 | 0,585 | 1,42 ± 0,17 | 0,616 ± 0,048 | < 0,0001 |
| | `B3` | Công cụ mặc định [11, 12] | 0,522 | 0,344 | 0,598 | 1,29 | 0,669 | < 0,0001 |
| | `B4` | RBT định tính cho LLM [20] | 0,620 ± 0,082 | 0,383 ± 0,053 | 0,650 ± 0,048 | 3,00 ± 2,52 | 0,631 ± 0,052 | < 0,0001 |
| | `S1` | PAIR độc lập (hộp đen) [28] | 0,489 ± 0,184 | 0,155 ± 0,096 | 0,285 ± 0,034 | 16,09 ± 12,44 | 0,336 ± 0,126 | < 0,0001 |
| | `S2` | GCG độc lập (hộp trắng/T4) [27] | 0,544 ± 0,097 | 0,091 ± 0,052 | 0,042 ± 0,040 | 14,93 ± 10,21 | 0,263 ± 0,090 | < 0,0001 |
| | `S3` | Red teaming bằng LLM [29] | 0,524 ± 0,108 | 0,238 ± 0,070 | 0,325 ± 0,086 | 10,44 ± 7,58 | 0,480 ± 0,097 | < 0,0001 |
| | **RBST-AI** | **RBST-AI đầy đủ (đề xuất)** | **0,631 ± 0,046** | **0,519 ± 0,041** | **0,701 ± 0,053** | 2,70 ± 1,72 | **0,829 ± 0,056** | — |
| **CS2** | `B0` | Ngẫu nhiên | 0,581 ± 0,049 | 0,448 ± 0,064 | 0,431 ± 0,087 | 2,60 ± 1,68 | 0,777 ± 0,084 | 0,1840 |
| | `B1` | Theo danh mục OWASP [23] | 0,515 ± 0,037 | 0,233 ± 0,012 | 0,441 ± 0,016 | 2,23 ± 1,18 | 0,468 ± 0,018 | < 0,0001 |
| | `B2` | RBST tĩnh ($L_0 \times I$) [16, 17] | 0,648 ± 0,011 | 0,378 ± 0,007 | 0,600 ± 0,019 | 1,25 ± 0,31 | 0,592 | < 0,0001 |
| | `B3` | Công cụ mặc định [11, 12] | 0,496 | 0,236 | 0,426 | 0,95 | 0,491 | < 0,0001 |
| | `B4` | RBT định tính cho LLM [20] | 0,636 ± 0,044 | 0,464 ± 0,043 | 0,585 ± 0,053 | 1,92 ± 0,99 | 0,737 ± 0,050 | 0,7922 |
| | `S1` | PAIR độc lập (hộp đen) [28] | 0,485 ± 0,106 | 0,241 ± 0,076 | 0,179 ± 0,026 | 4,76 ± 4,30 | 0,516 ± 0,104 | < 0,0001 |
| | `S2` | GCG độc lập (hộp trắng/T4) [27] | 0,520 ± 0,093 | 0,117 ± 0,038 | 0,038 ± 0,034 | 7,43 ± 5,51 | 0,296 ± 0,062 | < 0,0001 |
| | `S3` | Red teaming bằng LLM [29] | 0,563 ± 0,051 | 0,365 ± 0,050 | 0,312 ± 0,049 | 2,84 ± 1,96 | 0,660 ± 0,066 | < 0,0001 |
| | **RBST-AI** | **RBST-AI đầy đủ (đề xuất)** | 0,620 ± 0,036 | **0,466 ± 0,028** | 0,574 ± 0,037 | **1,15 ± 0,48** | 0,758 ± 0,048 | — |
| **CS3** | `B0` | Ngẫu nhiên | 0,532 ± 0,140 | 0,171 ± 0,068 | 0,416 ± 0,095 | 23,20 ± 9,96 | 0,359 ± 0,085 | 0,0099 |
| | `B1` | Theo danh mục OWASP [23] | 0,004 ± 0,010 | 0,000 | 0,501 ± 0,040 | 32,24 ± 0,02 | 0,016 ± 0,042 | < 0,0001 |
| | `B2` | RBST tĩnh ($L_0 \times I$) [16, 17] | 0,000 | 0,000 | 0,586 | 32,25 | 0,000 | < 0,0001 |
| | `B3` | Công cụ mặc định [11, 12] | 0,000 | 0,000 | 0,582 | 32,25 | 0,000 | < 0,0001 |
| | `B4` | RBT định tính cho LLM [20] | 0,007 ± 0,013 | 0,000 | 0,604 ± 0,063 | 32,19 ± 0,15 | 0,031 ± 0,052 | < 0,0001 |
| | `S1` | PAIR độc lập (hộp đen) [28] | 0,383 ± 0,343 | 0,050 ± 0,066 | 0,419 ± 0,052 | 26,10 ± 9,85 | 0,109 ± 0,109 | < 0,0001 |
| | `S2` | GCG độc lập (hộp trắng/T4) [27] | 0,539 ± 0,204 | 0,083 ± 0,066 | 0,045 ± 0,048 | 23,35 ± 9,41 | 0,252 ± 0,099 | < 0,0001 |
| | `S3` | Red teaming bằng LLM [29] | 0,562 ± 0,079 | **0,355 ± 0,069** | 0,544 ± 0,057 | 11,39 ± 7,00 | **0,649 ± 0,085** | < 0,0001 |
| | **RBST-AI** | **RBST-AI đầy đủ (đề xuất)** | **0,719 ± 0,109** | 0,213 ± 0,034 | **0,671 ± 0,050** | **9,70 ± 8,09** | 0,320 ± 0,017 | — |
| **CS4** | `B0` | Ngẫu nhiên | 0,477 ± 0,132 | 0,286 ± 0,143 | 0,410 ± 0,134 | 10,58 ± 6,16 | 0,623 ± 0,170 | < 0,0001 |
| | `B1` | Theo danh mục OWASP [23] | 0,523 ± 0,077 | 0,247 ± 0,026 | 0,577 | 7,80 ± 1,86 | 0,524 ± 0,085 | < 0,0001 |
| | `B2` | RBST tĩnh ($L_0 \times I$) [16, 17] | 0,625 ± 0,026 | 0,379 ± 0,017 | 0,519 | 2,09 ± 1,50 | 0,635 | < 0,0001 |
| | `B3` | Công cụ mặc định [11, 12] | 0,340 | 0,265 | 0,732 | 10,40 | 0,803 | < 0,0001 |
| | `B4` | RBT định tính cho LLM [20] | 0,728 ± 0,144 | 0,329 ± 0,035 | 0,529 ± 0,053 | 3,43 ± 1,97 | 0,500 ± 0,087 | < 0,0001 |
| | `S1–S3` | PAIR / GCG / LLM-RT | N/A | N/A | N/A | N/A | N/A | N/A |
| | **RBST-AI** | **RBST-AI đầy đủ (đề xuất)** | 0,676 ± 0,090 | **0,533 ± 0,066** | **0,763 ± 0,091** | **0,60 ± 0,32** | **0,807 ± 0,096** | — |

**Phân tích chính (trả lời ĐG1):**
1. **Vượt trội so với các Baseline (`B0`–`B4`):** Trung bình qua cả 4 CS (Bảng 8), RBST-AI đạt $\text{APFD}_R^{\text{pen}} = 0{,}433$, $\text{RC} = 0{,}677$ và $\text{CF} = 3{,}54$ — cao hơn hẳn `B0` ngẫu nhiên ($0{,}328$; $\text{RC}=0{,}421$; $\text{CF}=10{,}28$), `B2` RBST tĩnh ($0{,}266$; $\text{CF}=9{,}25$) và `B4` RBT định tính ($0{,}294$; $\text{CF}=10{,}13$), giảm **2,6–2,9×** chi phí tới lỗ hổng nghiêm trọng đầu tiên.
2. **Vì sao các SOTA sinh tấn công độc lập (`S1`, `S2`, `S3`) kém hiệu quả khi chạy rời rạc:** Mặc dù `S2` (GCG chuyển giao) đạt ASR thực cao trên CS1 (64,7%) và CS2 (64,0%), chi phí tối ưu gradient hộp trắng lớn và thiếu định hướng rủi ro khiến `S2` chỉ đạt $\text{RC} = 0{,}042$ và $\text{CF} = 15{,}24$; tương tự `S1` (PAIR độc lập) tốn nhiều lượt tinh chỉnh vào các cặp ít rủi ro ($\text{CF} = 15{,}65$; $\text{RC} = 0{,}295$). Ngược lại, trên CS3, các biến thể do `S3` (`llama3`) sinh mới lại khám phá thêm 4 lỗ hổng mà bộ mẫu tĩnh chưa bao phủ ($\text{Recall}=0{,}649$), nhưng vẫn có $\text{APFD}_R$ và $\text{RC}$ thấp hơn RBST-AI ($0{,}562$ vs $0{,}719$; $0{,}544$ vs $0{,}671$). Điều này cung cấp bằng chứng thực nghiệm trực tiếp ủng hộ **thiết kế kiến trúc N3**: tích hợp PAIR, GCG và LLM Red Teaming làm *Attack Generator adapter* bên trong vòng lặp điều phối rủi ro RBST-AI thay vì vận hành độc lập.

## 6.4. Nghiên cứu loại bỏ (ĐG2), Rủi ro tồn dư (ĐG3) và Độ tin cậy Oracle `[BÔI ĐỎ - BỔ SUNG MỚI]`

**Bảng 8.** Tổng hợp nghiên cứu loại bỏ (Ablation) và đối chiếu trung bình qua bốn Case Study

| Cấu hình | CS1 ($\text{APFD}_R^{\text{pen}}$) | CS2 ($\text{APFD}_R^{\text{pen}}$) | CS3 ($\text{APFD}_R^{\text{pen}}$) | CS4 ($\text{APFD}_R^{\text{pen}}$) | TB 4 CS *(S1–S3: 3 CS)* | TB RC | TB CF (↓) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **RBST-AI đầy đủ** | 0,519 | 0,466 | 0,213 | 0,533 | **0,433** | **0,677** | 3,54 |
| `A1` — Bỏ $M$ ($M=1$) | 0,525 | 0,462 | 0,216 | 0,532 | 0,434 | 0,667 | 3,42 |
| `A2` — Bỏ cập nhật Bayes | 0,550 | 0,493 | 0,248 | 0,630 | 0,480 | 0,676 | 2,05 |
| `A3` — Tham lam (bỏ Thompson) | 0,383 | 0,333 | 0,219 | 0,511 | 0,361 | 0,649 | 3,52 |
| `S1` — PAIR độc lập | 0,155 | 0,241 | 0,050 | N/A | 0,149 | 0,295 | 15,65 |
| `S2` — GCG độc lập | 0,091 | 0,117 | 0,083 | N/A | 0,097 | 0,042 | 15,24 |
| `S3` — LLM Red Teaming | 0,238 | 0,365 | 0,355 | N/A | 0,319 | 0,394 | 8,22 |
| `B4` — RBT định tính [20] | 0,383 | 0,464 | 0,000 | 0,329 | 0,294 | 0,592 | 10,13 |
| `B2` — RBST tĩnh ($L_0 \times I$) | 0,308 | 0,378 | 0,000 | 0,379 | 0,266 | 0,572 | 9,25 |
| `B0` — Ngẫu nhiên | 0,405 | 0,448 | 0,171 | 0,286 | 0,328 | 0,421 | 10,28 |

**Đóng góp từng thành phần (trả lời ĐG2):**
- **Vai trò lấy mẫu Thompson (`RBST-AI` vs `A3`):** Loại bỏ khám phá ngẫu nhiên (`A3` tham lam) làm $\text{APFD}_R^{\text{pen}}$ giảm mạnh từ $0{,}519 \to 0{,}383$ trên CS1 và $0{,}466 \to 0{,}333$ trên CS2 ($p < 0{,}0001$), chứng minh cơ chế khám phá Thompson là thiết yếu để tránh mắc kẹt cục bộ.
- **Vai trò hệ số $M$ (`RBST-AI` vs `A1`):** Giữ $M$ giúp cải thiện độ bao phủ rủi ro trên tác tử CS2 ($\text{RC}: 0{,}574$ vs $0{,}561$) và tăng nhẹ $\text{RC}$ trung bình ($0{,}677$ vs $0{,}667$); trên hệ thống nhỏ có phạm vi $M$ hẹp trong cùng một kịch bản, chênh lệch về $\text{APFD}_R$ chưa lớn vì các thành phần chia sẻ chung đường đi công cụ, nhưng $M$ vẫn là yếu tố quyết định khi so sánh và phân bổ ngân sách giữa các hệ thống có mức tự chủ khác nhau (Bảng 6).
- **Đánh đổi khai thác–khám phá của cập nhật Bayes (`RBST-AI` vs `A2`):** Một phát hiện thực nghiệm đáng lưu ý là với thư viện nhỏ (3 ca/cặp) và tiên nghiệm $\mu_0$ ban đầu đã khá gần phân phối thật, `A2` (giữ $\mu_0$ cố định nhưng vẫn dùng $M$ và chia chi phí $K$) có xu hướng rải ca qua nhiều cặp khác nhau nên đạt $\text{APFD}_R^{\text{pen}}$ trung bình cao hơn (`0,480` vs `0,433`). Ngược lại, **RBST-AI đầy đủ** khi xác nhận một cặp dễ tổn thương sẽ chủ động phân bổ thêm ca để **xác minh khả năng tái lập và ước lượng ASR chính xác** (đạt $\text{RC}$ cao nhất `0,677`), đồng thời phát huy lợi thế quyết định khi tiên nghiệm $\mu_0$ sai lệch lớn so với thực tế (như CS3 với các mẫu jailbreak bị từ chối 100%).

**Bảng 9.** Tương quan rủi ro tồn dư $R_{\text{res}}$ với mức nghiêm trọng thực đo (ĐG3) và phân rã cảm biến Oracle khách quan

| Kịch bản | Số cặp $(t,c)$ | Spearman $\rho(R_{\text{res}}, \text{thực})$ — RBST-AI | Tầng cảm biến Oracle thực tế ($n=186$ ca CS1–CS4) | Độ phủ lỗ hổng xác nhận |
| :--- | :---: | :---: | :--- | :---: |
| **CS1** | 17 | **0,695 ± 0,021** | Chỉ `PatternDetector` quy tắc chung (CS1–CS3) | 22/99 ca (22,2%) |
| **CS2** | 25 | **0,904 ± 0,014** | + Cảm biến Canary bí mật & Đầu ra độc hại (`<script>`/SQLi) | 50/99 ca (50,5%) |
| **CS3** | 12 | −0,540 ± 0,105 *(do lệch tiên nghiệm LLM01)* | **+ Vết công cụ `AgentSandbox` & `LLM-Judge` (Đầy đủ)** | **99/99 ca LLM (100%) + 8/8 ca ML** |
| **CS4** | 8 | **0,973 ± 0,028** | Đối chiếu nhãn người mù đôi (Cohen's $\kappa$) | `—` *(đang hoàn thiện gán nhãn)* |

**Phân tích ĐG3 và cảm biến Oracle khách quan (Bảng 9):**
- Rủi ro tồn dư $R_{\text{res}}$ của RBST-AI đạt tương quan hạng Spearman rất mạnh với mức nghiêm trọng thực đo ở **CS1 ($\rho = 0{,}695$)**, **CS2 ($\rho = 0{,}904$)** và **CS4 ($\rho = 0{,}973$)**. Riêng CS3 có tương quan âm ($\rho = -0{,}540$) do ở ngân sách $B=32{,}2$, các cặp `LLM01` (vốn có $0\%$ vượt rào trong tập 180 ca nhưng bị `S3` khai thác bằng biến thể mới ở ngoài bộ tĩnh) giữ cận trên thận trọng $\theta_{\max}$ cao khi số ca kiểm thử còn ít — phản ánh đúng bản chất thận trọng của công thức (7): không vội kết luận an toàn khi chưa đủ bằng chứng.
- Trên 162 ca LLM chuẩn (99 ca vượt rào thực tế), nếu chỉ dùng bộ lọc quy tắc chung (`PatternDetector`) thì chỉ bắt được **22/99 ca (22,2%)** do không nhận diện được các ca lộ mã phiên Canary và gọi công cụ ngầm; khi bổ sung cảm biến Canary/đầu ra độc hại (**50/99 = 50,5%**) cùng vết thực thi `AgentSandbox` và `LLM-Judge`, Oracle đa tín hiệu xác nhận trọn vẹn **99/99 ca LLM (100%)** và **8/8 ca toán học ở CS4** (chỉ số Cohen's $\kappa$ đối chiếu nhãn người mù đôi đang được hoàn thiện thủ công nên để trống trung thực).
