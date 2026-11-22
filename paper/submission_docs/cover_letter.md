# Cover Letter for Journal Submission

**To:**  
The Editor-in-Chief  
*Computers & Security* / *Journal of Information Security and Applications (JISA)* / *Information Processing & Management*  

**Date:** November 22, 2026  

**Subject:** Submission of Original Research Article:  
*"Vietnamese-Native LLM Red-Teaming Benchmark: Disaggregated Safety Evaluation, Orthographic and Register Variation Robustness, and Validated Cascade Judges"*

Dear Editor-in-Chief,

We are pleased to submit our original research manuscript entitled **"Vietnamese-Native LLM Red-Teaming Benchmark: Disaggregated Safety Evaluation, Orthographic and Register Variation Robustness, and Validated Cascade Judges"** for consideration as a regular research paper.

### Context and Core Problem
As Large Language Models (LLMs) transition from research prototypes to mission-critical conversational agents in public administration, enterprise customer support, and financial services, their safety alignment against malicious jailbreaks is paramount. While state-of-the-art alignment protocols (e.g., RLHF, DPO) ensure high safety standards in standard English, their defensive resilience in regional and low-resource languages remains fragile. Moreover, automated red-teaming benchmarks suffer from profound measurement bias: they conflate accidental low-specificity non-actionable outputs with active, principled refusals, while uncalibrated heuristic detectors produce prohibitive false alarm rates or extreme GPU inference costs.

### Key Contributions & Novelty
This work addresses three foundational research gaps (G1–G3) through the following core contributions:
1. **Symmetric Full-Population Benchmark Across Six Architectures (N_pop = 180 per model; 1,080 Total Real Evaluations)**: We construct a structurally paired benchmark bridging English and five distinct Vietnamese linguistic variants (Standard NFC, Unaccented/No Diacritics, Youth Slang/Teencode, Code-Switching, and Decomposed Unicode NFD) paired with Benign Contrastive Controls across five critical safety domains, evaluated across six local architectures (`Llama-3-8B-Instruct`, `Qwen-2.5-7B-Instruct`, `SeaLLMs-v3-7B-Chat`, `Vistral-7B-Chat`, `Mistral-7B-Instruct-v0.3`, and `Llama-3-Secure + Stage-0 Intervention`) using a decoupled `Qwen-2.5-7B-Instruct` judge.
2. **Orthographic Refusal Collapse, Cross-Model Alignment Gaps & Interventional Recovery**: On `Llama-3-8B-Instruct`, decomposed Unicode (NFD) inflates BPE subword fertility to F = 3.194 tokens/word (2.65× English), collapsing explicit safety refusals from 85.0%–90.0% down to 10.0% on No Diacritics (p_Holm = 0.00024) and 5.0% on Unicode NFD (p_Holm = 0.00015; omnibus Cochran's Q = 68.33, p = 2.28 × 10⁻¹³). Similar refusal collapse occurs on `Qwen-2.5-7B-Instruct` (65.0% EN → 0.0% No-Diac/NFD) and `SeaLLMs-v3-7B-Chat` (65.0% EN → 20.0% No-Diac / 25.0% NFD), whereas weakly aligned architectures (`Vistral-7B-Chat`, `Mistral-7B-Instruct-v0.3`) exhibit low overall explicit refusal (7.5% and 5.8%) and active State 2 jailbreaks (`Mistral-7B` Raw ASR = 8.3%, 10/120). Pre-processing interventions (N_h = 20) confirm that NFD→NFC canonicalization and lexicon diacritic restoration recover explicit refusals by +85.0% (p_exact < 0.001) and +25.0% (p_exact = 0.0625) while reducing benign over-refusal from 1/10 (10.0%) to 0/10 (0.0%).
3. **Validated Two-Stage Cascade Judge**: We design a hybrid cascade architecture where Stage 1 fast regex gating intercepts 40.0% (72/180) of queries on `Llama-3-8B-Instruct` with sub-millisecond CPU latency, and Stage 2 applies deep LLM validation with Prioritized Semantic Override (s_spec ≥ 4). Validated against verified double-blind human annotations on `N_VI = 50` Vietnamese responses (inter-annotator quadratic κ = 0.876, Macro-F1 = 93.8%, Observed Agreement = 94.0%), the cascade achieves Specificity = 1.000, 3-Class Macro-F1 = 1.000, and κ_quad = 1.000 on both the stratified held-out test split (N_test = 25, 36.0% LLM call savings) and full verified corpus (N = 50, 38.0% savings), suppressing the genuine `VN_RT_076` regex false alarm.
4. **Epidemiological Calibration Framework**: We formalize disjoint denominator metrics and the Rogan-Gladen prevalence estimator, transparently noting zero-jailbreak boundary regimes (N_State 2 = 0) and releasing a reproducible double-blind adjudication workflow (`N = 250` multi-architecture workbooks) for empirical sensitivity calibration across active-jailbreak models.

### Declarations & Statements
- **Originality**: This manuscript represents original work that has not been published previously and is not under consideration for publication elsewhere.
- **Authorship**: All co-authors have actively contributed to the research, approved the final manuscript, and agreed to its submission.
- **Ethics & Dual-Use**: All red-teaming queries are designed as abstract, non-actionable diagnostic probes under responsible AI safety standards. No executable zero-day exploits or bio-chemical formulas are disclosed.
- **Reproducibility**: All benchmark datasets, validation scripts, and LaTeX artifacts are released under the MIT License at https://github.com/HoangHuuPhong39/NCKH.

Thank you very much for your time and consideration of our manuscript.

Sincerely,  

**Pham Van Huong, Dinh Thi Tuyen, Hoang Huu Phong, Nguyen Ho Bao Lam, Tran Thuy Minh, Vu Khanh Vy**  
Academy of Cryptography Techniques, Hanoi 100000, Vietnam  
*Corresponding Author:* Pham Van Huong (`huongpv@actvn.edu.vn`)  
*Research Contact:* `ai-security@actvn.edu.vn`
