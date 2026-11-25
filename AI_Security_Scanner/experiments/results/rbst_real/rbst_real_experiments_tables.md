# Bảng Tổng Hợp Thực Nghiệm RBST-AI (100% Dữ Liệu Phản Hồi Thật)

- **Thời điểm chạy:** `2026-11-25 20:34:20`
- **Mô hình LLM thực thi live:** Ollama `qwen2.5:latest` (CS1, CS2, CS3) + `scikit-learn` thật (CS4)
- **Số seeds lặp đánh giá chiến lược chọn ca:** `30` seeds (`1..30`)
- **Nguyên tắc dữ liệu:** 100% kết quả $y_k$ và chi phí $K$ thu trực tiếp từ phản hồi thật của hệ thống đích; mọi phương pháp/chỉ số chưa chạy thực nghiệm độc lập được **để trống (`—`)**.

---

## Bảng E1. Đặc trưng đồ thị hệ thống $S=(C,D)$ và hệ số khuếch đại tác tử $M$ (CS1–CS4)

| Case Study | Hệ thống đích | $|C|$ | $|D|$ | Ranh giới tin cậy | Số cặp $(t,c)$ | $M_{\min}$ | $M_{\text{tb}}$ | $M_{\max}$ | Cặp ưu tiên đầu ($R_0$ cao nhất) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **CS1** | CS1 — Web-Search Integrated Chat Assistant | 5 | 5 | 1 | 17 | 1.28 | 1.40 | **1.61** | `T_IPI@web_context` |
| **CS2** | CS2 — Tool-Using AI Agent (Email, Banking, Booking) | 7 | 7 | 1 | 25 | 1.57 | 1.72 | **1.95** | `T_ASI01_GOAL_HIJACK@untrusted_feeds` |
| **CS3** | CS3 — Public LLM Chatbot | 4 | 4 | 0 | 12 | 1.09 | 1.13 | **1.16** | `T_JB@llm_model` |
| **CS4** | CS4 — Machine Learning Prediction API (MLaaS) | 3 | 3 | 0 | 8 | 1.30 | 1.31 | **1.32** | `T_MODEL_EXTRACT@prediction_api` |

## Bảng E2. Tổng hợp bộ phản hồi THẬT thu thập trên 4 hệ thống đích

| Case Study | Nguồn thực thi thật | Số ca thật | Số ca vượt rào ($y=1$) | ASR thực đo | Số lỗ hổng phân biệt | Ngân sách $B$ | Độ trễ TB (ms) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **CS1** | Ollama live (`qwen2.5:latest`) — Web RAG Assistant | 51 | 32 | 62.7% | 15 | 36.9 / 81.9 | 14209.0 |
| **CS2** | Ollama live (`qwen2.5:latest`) + `AgentSandbox` (Email/Banking/Booking) | 75 | 55 | 73.3% | 21 | 48.1 / 106.8 | 25737.8 |
| **CS3** | Real 180-Benchmark (`qwen2.5:latest`) + Ollama live | 36 | 12 | 33.3% | 9 | 32.2 / 71.7 | 26991.8 |
| **CS4** | `scikit-learn` live (LR / DecisionTree / MLP trên BreastCancer) | 24 | 8 | 33.3% | 5 | 23.0 / 51.1 | 35.6 |

## Bảng E3. So sánh hiệu năng ưu tiên kiểm thử (RBST-AI vs Baseline B0–B4, SOTA S1–S3, Loại bỏ A1–A3)

> Ghi chú: $\text{APFD}_R^{\text{pen}}$ (càng cao càng tốt, gán $TF=n+1$ cho lỗ hổng chưa tìm thấy để phản ánh đúng cả tốc độ lẫn độ phủ), $\text{RC}$ (độ bao phủ rủi ro với $n_{\min}=2$), $\text{CF}$ (chi phí tới lỗ hổng nghiêm trọng đầu tiên, càng thấp càng tốt), Recall có trọng số rủi ro. `S1` (PAIR độc lập, `llama3:latest` tinh chỉnh 3 lượt → `qwen2.5:latest`), `S2` (GCG hộp trắng tối ưu gradient bằng `nanogcg` trên `Qwen/Qwen2.5-1.5B-Instruct` / GPU Tesla T4 → chuyển giao lên `qwen2.5:latest`), và `S3` (LLM Red Teaming độc lập, `llama3:latest` sinh ca → `qwen2.5:latest`) đều chạy live 100% trên CS1–CS3; trên CS4 (mô hình ML dạng bảng) đánh dấu `N/A` do các phương pháp tấn công LLM không áp dụng.

### CS1 — Web-Search Integrated Chat Assistant (B = 36.9, lỗ hổng thật = 15)

| Mã | Phương pháp | $\text{APFD}_R$ (CT 9) | $\text{APFD}_R^{\text{pen}}$ | RC (CT 10) | CF (↓) | Recall trọng số | Wilcoxon $p$ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `B0` | Ngẫu nhiên (Random) | 0.556 ± 0.080 | 0.405 ± 0.069 | 0.427 ± 0.107 | 4.76 ± 3.32 | 0.744 ± 0.105 | 0.0000 |
| `B1` | Theo danh mục OWASP [23] | 0.533 ± 0.064 | 0.317 ± 0.036 | 0.597 ± 0.040 | 2.60 ± 1.51 | 0.611 ± 0.061 | 0.0000 |
| `B2` | RBST tĩnh (L0 × I) [16, 17] | 0.516 ± 0.028 | 0.308 ± 0.013 | 0.585 | 1.42 ± 0.17 | 0.616 ± 0.048 | 0.0000 |
| `B3` | Công cụ mặc định (garak/PyRIT) [11, 12] | 0.522 | 0.344 | 0.598 | 1.29 | 0.669 | 0.0000 |
| `B4` | RBT định tính cho LLM [20] | 0.620 ± 0.082 | 0.383 ± 0.053 | 0.650 ± 0.048 | 3.00 ± 2.52 | 0.631 ± 0.052 | 0.0000 |
| `S1` | PAIR độc lập (SOTA hộp đen) [28] | 0.489 ± 0.184 | 0.155 ± 0.096 | 0.285 ± 0.034 | 16.09 ± 12.44 | 0.336 ± 0.126 | 0.0000 |
| `S2` | GCG độc lập (SOTA hộp trắng) [27] | 0.544 ± 0.097 | 0.091 ± 0.052 | 0.042 ± 0.040 | 14.93 ± 10.21 | 0.263 ± 0.090 | 0.0000 |
| `S3` | Red teaming tự động bằng LLM [29] | 0.524 ± 0.108 | 0.238 ± 0.070 | 0.325 ± 0.086 | 10.44 ± 7.58 | 0.480 ± 0.097 | 0.0000 |
| `A1` | RBST-AI bỏ M (M = 1) | 0.639 ± 0.040 | 0.525 ± 0.038 | 0.691 ± 0.048 | 3.15 ± 2.11 | 0.828 ± 0.053 | 0.3931 |
| `A2` | RBST-AI bỏ cập nhật Bayes | 0.605 | 0.550 | 0.692 | 1.29 | 0.912 | 0.0003 |
| `A3` | RBST-AI tham lam (bỏ Thompson) | 0.547 | 0.383 | 0.656 | 1.29 | 0.709 | 0.0000 |
| **RBST-AI** | RBST-AI đầy đủ (đề xuất) | 0.631 ± 0.046 | 0.519 ± 0.041 | 0.701 ± 0.053 | 2.70 ± 1.72 | 0.829 ± 0.056 | — |

### CS2 — Tool-Using AI Agent (Email, Banking, Booking) (B = 48.1, lỗ hổng thật = 21)

| Mã | Phương pháp | $\text{APFD}_R$ (CT 9) | $\text{APFD}_R^{\text{pen}}$ | RC (CT 10) | CF (↓) | Recall trọng số | Wilcoxon $p$ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `B0` | Ngẫu nhiên (Random) | 0.581 ± 0.049 | 0.448 ± 0.064 | 0.431 ± 0.087 | 2.60 ± 1.68 | 0.777 ± 0.084 | 0.1840 |
| `B1` | Theo danh mục OWASP [23] | 0.515 ± 0.037 | 0.233 ± 0.012 | 0.441 ± 0.016 | 2.23 ± 1.18 | 0.468 ± 0.018 | 0.0000 |
| `B2` | RBST tĩnh (L0 × I) [16, 17] | 0.648 ± 0.011 | 0.378 ± 0.007 | 0.600 ± 0.019 | 1.25 ± 0.31 | 0.592 | 0.0000 |
| `B3` | Công cụ mặc định (garak/PyRIT) [11, 12] | 0.496 | 0.236 | 0.426 | 0.95 | 0.491 | 0.0000 |
| `B4` | RBT định tính cho LLM [20] | 0.636 ± 0.044 | 0.464 ± 0.043 | 0.585 ± 0.053 | 1.92 ± 0.99 | 0.737 ± 0.050 | 0.7922 |
| `S1` | PAIR độc lập (SOTA hộp đen) [28] | 0.485 ± 0.106 | 0.241 ± 0.076 | 0.179 ± 0.026 | 4.76 ± 4.30 | 0.516 ± 0.104 | 0.0000 |
| `S2` | GCG độc lập (SOTA hộp trắng) [27] | 0.520 ± 0.093 | 0.117 ± 0.038 | 0.038 ± 0.034 | 7.43 ± 5.51 | 0.296 ± 0.062 | 0.0000 |
| `S3` | Red teaming tự động bằng LLM [29] | 0.563 ± 0.051 | 0.365 ± 0.050 | 0.312 ± 0.049 | 2.84 ± 1.96 | 0.660 ± 0.066 | 0.0000 |
| `A1` | RBST-AI bỏ M (M = 1) | 0.622 ± 0.048 | 0.462 ± 0.032 | 0.561 ± 0.033 | 1.22 ± 0.60 | 0.749 ± 0.048 | 0.5028 |
| `A2` | RBST-AI bỏ cập nhật Bayes | 0.644 | 0.493 | 0.601 | 0.91 | 0.770 | 0.0000 |
| `A3` | RBST-AI tham lam (bỏ Thompson) | 0.524 | 0.333 | 0.528 | 0.91 | 0.643 | 0.0000 |
| **RBST-AI** | RBST-AI đầy đủ (đề xuất) | 0.620 ± 0.036 | 0.466 ± 0.028 | 0.574 ± 0.037 | 1.15 ± 0.48 | 0.758 ± 0.048 | — |

### CS3 — Public LLM Chatbot (B = 32.2, lỗ hổng thật = 9)

| Mã | Phương pháp | $\text{APFD}_R$ (CT 9) | $\text{APFD}_R^{\text{pen}}$ | RC (CT 10) | CF (↓) | Recall trọng số | Wilcoxon $p$ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `B0` | Ngẫu nhiên (Random) | 0.532 ± 0.140 | 0.171 ± 0.068 | 0.416 ± 0.095 | 23.20 ± 9.96 | 0.359 ± 0.085 | 0.0099 |
| `B1` | Theo danh mục OWASP [23] | 0.004 ± 0.010 | 0.000 | 0.501 ± 0.040 | 32.24 ± 0.02 | 0.016 ± 0.042 | 0.0000 |
| `B2` | RBST tĩnh (L0 × I) [16, 17] | 0.000 | 0.000 | 0.586 | 32.25 | 0.000 | 0.0000 |
| `B3` | Công cụ mặc định (garak/PyRIT) [11, 12] | 0.000 | 0.000 | 0.582 | 32.25 | 0.000 | 0.0000 |
| `B4` | RBT định tính cho LLM [20] | 0.007 ± 0.013 | 0.000 | 0.604 ± 0.063 | 32.19 ± 0.15 | 0.031 ± 0.052 | 0.0000 |
| `S1` | PAIR độc lập (SOTA hộp đen) [28] | 0.383 ± 0.343 | 0.050 ± 0.066 | 0.419 ± 0.052 | 26.10 ± 9.85 | 0.109 ± 0.109 | 0.0000 |
| `S2` | GCG độc lập (SOTA hộp trắng) [27] | 0.539 ± 0.204 | 0.083 ± 0.066 | 0.045 ± 0.048 | 23.35 ± 9.41 | 0.252 ± 0.099 | 0.0000 |
| `S3` | Red teaming tự động bằng LLM [29] | 0.562 ± 0.079 | 0.355 ± 0.069 | 0.544 ± 0.057 | 11.39 ± 7.00 | 0.649 ± 0.085 | 0.0000 |
| `A1` | RBST-AI bỏ M (M = 1) | 0.736 ± 0.098 | 0.216 ± 0.031 | 0.662 ± 0.064 | 8.72 ± 6.60 | 0.317 | 0.3882 |
| `A2` | RBST-AI bỏ cập nhật Bayes | 0.837 | 0.248 | 0.643 | 5.49 | 0.317 | 0.0000 |
| `A3` | RBST-AI tham lam (bỏ Thompson) | 0.743 | 0.219 | 0.643 | 11.40 | 0.317 | 0.5291 |
| **RBST-AI** | RBST-AI đầy đủ (đề xuất) | 0.719 ± 0.109 | 0.213 ± 0.034 | 0.671 ± 0.050 | 9.70 ± 8.09 | 0.320 ± 0.017 | — |

### CS4 — Machine Learning Prediction API (MLaaS) (B = 23.0, lỗ hổng thật = 5)

| Mã | Phương pháp | $\text{APFD}_R$ (CT 9) | $\text{APFD}_R^{\text{pen}}$ | RC (CT 10) | CF (↓) | Recall trọng số | Wilcoxon $p$ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `B0` | Ngẫu nhiên (Random) | 0.477 ± 0.132 | 0.286 ± 0.143 | 0.410 ± 0.134 | 10.58 ± 6.16 | 0.623 ± 0.170 | 0.0000 |
| `B1` | Theo danh mục OWASP [23] | 0.523 ± 0.077 | 0.247 ± 0.026 | 0.577 | 7.80 ± 1.86 | 0.524 ± 0.085 | 0.0000 |
| `B2` | RBST tĩnh (L0 × I) [16, 17] | 0.625 ± 0.026 | 0.379 ± 0.017 | 0.519 | 2.09 ± 1.50 | 0.635 | 0.0000 |
| `B3` | Công cụ mặc định (garak/PyRIT) [11, 12] | 0.340 | 0.265 | 0.732 | 10.40 | 0.803 | 0.0000 |
| `B4` | RBT định tính cho LLM [20] | 0.728 ± 0.144 | 0.329 ± 0.035 | 0.529 ± 0.053 | 3.43 ± 1.97 | 0.500 ± 0.087 | 0.0000 |
| `S1` | PAIR độc lập (SOTA hộp đen) [28] | N/A | N/A | N/A | N/A | N/A | N/A |
| `S2` | GCG độc lập (SOTA hộp trắng) [27] | N/A | N/A | N/A | N/A | N/A | N/A |
| `S3` | Red teaming tự động bằng LLM [29] | N/A | N/A | N/A | N/A | N/A | N/A |
| `A1` | RBST-AI bỏ M (M = 1) | 0.675 ± 0.090 | 0.532 ± 0.066 | 0.754 ± 0.095 | 0.60 ± 0.32 | 0.807 ± 0.096 | 0.3173 |
| `A2` | RBST-AI bỏ cập nhật Bayes | 0.630 ± 0.010 | 0.630 ± 0.010 | 0.768 | 0.50 | 1.000 | 0.0000 |
| `A3` | RBST-AI tham lam (bỏ Thompson) | 0.646 ± 0.025 | 0.511 ± 0.021 | 0.768 | 0.50 | 0.803 | 0.0327 |
| **RBST-AI** | RBST-AI đầy đủ (đề xuất) | 0.676 ± 0.090 | 0.533 ± 0.066 | 0.763 ± 0.091 | 0.60 ± 0.32 | 0.807 ± 0.096 | — |

## Bảng E4. Tổng hợp nghiên cứu loại bỏ (Ablation Study — Trả lời ĐG2) trung bình qua 4 Case Study

| Cấu hình | CS1 ($\text{APFD}_R^{\text{pen}}$) | CS2 ($\text{APFD}_R^{\text{pen}}$) | CS3 ($\text{APFD}_R^{\text{pen}}$) | CS4 ($\text{APFD}_R^{\text{pen}}$) | Trung bình 4 CS | Trung bình RC | Trung bình CF (↓) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **RBST-AI** (RBST-AI đầy đủ (đề xuất)) | 0.519 | 0.466 | 0.213 | 0.533 | **0.433** | 0.677 | 3.54 |
| `A1` (RBST-AI bỏ M (M = 1)) | 0.525 | 0.462 | 0.216 | 0.532 | **0.434** | 0.667 | 3.42 |
| `A2` (RBST-AI bỏ cập nhật Bayes) | 0.550 | 0.493 | 0.248 | 0.630 | **0.480** | 0.676 | 2.05 |
| `A3` (RBST-AI tham lam (bỏ Thompson)) | 0.383 | 0.333 | 0.219 | 0.511 | **0.361** | 0.649 | 3.52 |
| `S1` (PAIR độc lập (SOTA hộp đen) [28]) | 0.155 | 0.241 | 0.050 | N/A | **0.149** | 0.295 | 15.65 |
| `S2` (GCG độc lập (SOTA hộp trắng) [27]) | 0.091 | 0.117 | 0.083 | N/A | **0.097** | 0.042 | 15.24 |
| `S3` (Red teaming tự động bằng LLM [29]) | 0.238 | 0.365 | 0.355 | N/A | **0.319** | 0.394 | 8.22 |
| `B4` (RBT định tính cho LLM [20]) | 0.383 | 0.464 | 0.000 | 0.329 | **0.294** | 0.592 | 10.13 |
| `B2` (RBST tĩnh (L0 × I) [16, 17]) | 0.308 | 0.378 | 0.000 | 0.379 | **0.266** | 0.572 | 9.25 |
| `B0` (Ngẫu nhiên (Random)) | 0.405 | 0.448 | 0.171 | 0.286 | **0.328** | 0.421 | 10.28 |

## Bảng E5. Tương quan rủi ro tồn dư $R_{\text{res}}$ với mức nghiêm trọng thực tế (ĐG3) & Độ tin cậy Oracle

### E5.1. Tương quan hạng Spearman ($\rho$) giữa $R_{\text{res}}$ của RBST-AI và mức nghiêm trọng thực đo

| Case Study | Số cặp $(t,c)$ | Spearman $\rho$ (RBST-AI) | Spearman $\rho$ (B0 Ngẫu nhiên) | Spearman $\rho$ (B2 Tĩnh) |
| :--- | :---: | :---: | :---: | :---: |
| **CS1** | 17 | 0.695 ± 0.021 | 0.741 ± 0.039 | 0.704 ± 0.006 |
| **CS2** | 25 | 0.904 ± 0.014 | 0.906 ± 0.022 | 0.921 ± 0.004 |
| **CS3** | 12 | -0.540 ± 0.105 | -0.526 ± 0.126 | -0.621 ± 0.024 |
| **CS4** | 8 | 0.973 ± 0.028 | 0.960 ± 0.033 | 0.976 |

### E5.2. Phân rã cảm biến khách quan của Bộ phán xét Oracle trên 186 ca thực nghiệm (CS1–CS4)

| Tầng cảm biến Oracle thực tế | Số lỗ hổng xác nhận / Độ phủ |
| :--- | :---: |
| Chỉ `PatternDetector` quy tắc chung (CS1–CS3) | `22/99` (`22.2%`) |
| + Cảm biến Canary bí mật & Đầu ra độc hại (`<script>`/SQLi) | `50/99` (`50.5%`) |
| **+ Vết công cụ `AgentSandbox` & `LLM-Judge` (Đầy đủ)** | **`99/99` (`100,0%`) + `8/8` ca ML CS4** |
| Đối chiếu nhãn người mù đôi (Cohen's $\kappa$) | `—` *(đang hoàn thiện gán nhãn thủ công)* |
