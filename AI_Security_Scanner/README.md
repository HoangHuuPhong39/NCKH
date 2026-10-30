# 🛡️ AI Security TestKit & Scanner (Enterprise Research Edition)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Standards](https://img.shields.io/badge/Standard-OWASP%20LLM%20Top%2010%20(2025)-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATLAS-red.svg)](https://atlas.mitre.org/)
[![Engines](https://img.shields.io/badge/Engines-Ollama%20%7C%20OpenAI%20%7C%20Garak%20%7C%20ART-brightgreen.svg)](https://ollama.com)
[![UI](https://img.shields.io/badge/Dashboard-Neon%20Dark%20Mode%20v2.0-8a2be2.svg)](http://localhost:5000)
[![License](https://img.shields.io/badge/License-Academic%20Research-lightgrey.svg)](#-license--ethical-guidelines)

> **Practical AI Security & Safety Engineering**: Comprehensive multi-tier red-teaming, automated vulnerability assessment, and adaptive adversarial evaluation framework for Large Language Models (LLMs), RAG pipelines, and autonomous AI Agents.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Key Features & Research Contributions](#-key-features--research-contributions)
- [Threat Coverage Matrix (OWASP & MITRE ATLAS)](#-threat-coverage-matrix)
- [System Architecture](#-system-architecture)
- [Repository Structure](#-repository-structure)
- [Installation & Quickstart](#-installation--quickstart)
  - [Prerequisites](#prerequisites)
  - [Setup Environment](#setup-environment)
- [Usage Guide](#-usage-guide)
  - [1. Web Dashboard (Enterprise GUI)](#1-web-dashboard-enterprise-gui)
  - [2. CLI Scanner (Metasploit-style)](#2-cli-scanner-metasploit-style)
  - [3. Scientific Benchmarking & Ablation Study](#3-scientific-benchmarking--ablation-study)
- [Vietnamese Safety Benchmark](#-vietnamese-safety-benchmark)
- [Integrations](#-integrations)
- [License & Ethical Guidelines](#-license--ethical-guidelines)

---

## 🔬 Overview

Modern AI deployments have evolved beyond standalone prompt-response models into complex architectures comprising **Retrieval-Augmented Generation (RAG)** systems, **vector databases**, and **autonomous AI Agents** equipped with tool execution capabilities. These extended attack surfaces introduce novel vulnerabilities that traditional web application scanners cannot detect.

**AI Security TestKit** is an end-to-end red-teaming and safety evaluation suite designed to assess and harden AI systems against both classical adversarial machine learning threats and emerging LLM vulnerabilities.

```
       ┌────────────────────────────────────────────────────────┐
       │               AI Security TestKit v2.0                 │
       └───────────────────────────┬────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
   [ LLM Tier ]              [ RAG Tier ]             [ Agent Tier ]
 • Direct Injection       • Knowledge Poisoning     • Tool Misuse
 • Jailbreak Variants     • Context Exfiltration    • Excessive Agency
 • System Prompt Leak     • Document Hijacking      • Unbounded Loops
```

---

## ✨ Key Features & Research Contributions

1. **Multi-Tier Attack Surface Assessment:**
   - Evaluates LLMs, RAG context pipelines, and autonomous Agents executing external tools.
2. **Adaptive Payload Mutation:**
   - Feedback-loop generator that iteratively mutates jailbreak attempts based on target refusal responses.
3. **Dual-Stage Hybrid Detector:**
   - Combines sub-millisecond regex/heuristic classifiers with high-precision LLM-as-a-Judge evaluators.
4. **Isolated Agent Sandbox:**
   - Emulates vulnerable tool endpoints (SQL execution, file I/O, API triggers) in a sandboxed runtime.
5. **Standardized YAML Attack DSL:**
   - Declarative format to author, version, and extend attack suites across risk profiles.
6. **Domain-Specific Vietnamese Benchmark:**
   - 62 curated adversarial scenarios contextualized to Vietnamese banking, healthcare, and legal domains.
7. **Empirical Ablation Engine:**
   - Automated testing harness to quantitatively isolate the contribution of individual defense/attack modules.
8. **Enterprise Neon Dark Mode Web UI:**
   - Real-time terminal log stream (SSE), interactive OWASP risk breakdown, bilingual localization (EN/VI), and non-destructive incident replay.

---

## 🎯 Threat Coverage Matrix

The scanner directly maps detected vulnerabilities to industry standards:

| Risk ID | Vulnerability Category | OWASP LLM (2025) | MITRE ATLAS | Severity |
|---|---|---|---|---|
| **LLM-01** | Prompt Injection (Direct & Indirect) | LLM01: Prompt Injection | AML.T0051 | `CRITICAL` |
| **LLM-02** | Adversarial Jailbreaking (Multi-turn) | LLM01: Prompt Injection | AML.T0054 | `HIGH` |
| **LLM-03** | Sensitive Information Disclosure | LLM06: Sensitive Info Disclosure | AML.T0024 | `HIGH` |
| **LLM-04** | Excessive Agency & Tool Abuse | LLM08: Excessive Agency | AML.T0053 | `CRITICAL` |
| **LLM-05** | Model Denial of Service (Algorithmic DoS) | LLM04: Model Denial of Service | AML.T0029 | `MEDIUM` |
| **LLM-06** | System Prompt & Context Leakage | LLM07: System Prompt Leakage | AML.T0051 | `HIGH` |
| **LLM-07** | RAG Context Poisoning & Manipulation | LLM02: Sensitive Info in RAG | AML.T0043 | `HIGH` |
| **LLM-08** | Insecure Output Handling | LLM02: Insecure Output Handling | AML.T0052 | `HIGH` |

---

## 🏛️ System Architecture

<p align="center">
  <img src="AI_Security_Scanner/docs/architecture.svg" alt="AI Security TestKit System Architecture" width="100%"/>
</p>

### High-Level Architecture Flow

```text
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                                     CONTROL LAYER                                      │
  │     [ 🖥️ Enterprise Web UI (Port 5000) ]     │     [ 💻 Metasploit-Style CLI ]        │
  └───────────────────────────┬────────────────────────────────────────┬───────────────────┘
                              ▼                                        ▼
  ┌────────────────────────────────────────────────────┐  ┌────────────────────────────────┐
  │            ATTACK ORCHESTRATION ENGINE             │  │       TARGET INTERFACES        │
  │  • Threat Profiler (MITRE ATLAS & OWASP LLM)       │  │  • 🦙 Local Ollama (Llama 3,   │
  │  • Adaptive Generator (Feedback-guided Mutations)  │─►│       Mistral, Qwen, DeepSeek) │
  │  • Mutation Engine (Cipher, Token Bypass, Obfusc)  │  │  • 🌐 Cloud API (OpenAI-compat)│
  │  • Declarative YAML DSL (62+ VN Domain Benchmarks) │  │  • 📦 Agent Mock Sandbox & RAG │
  └────────────────────────────────────────────────────┘  └────────────────┬───────────────┘
                                                                           │ (Raw Traces)
                                                                           ▼
  ┌────────────────────────────────────────────────────────────────────────────────────────┐
  │                           DUAL-STAGE EVALUATION & INTELLIGENCE                         │
  │  [ ⚡ Stage 1: Regex & Heuristic Signatures ] ──► [ 🧠 Stage 2: LLM-as-a-Judge Evaluator ]
  │                                      │                                                 │
  │                                      ▼                                                 │
  │  [ 📊 Quantitative Risk Engine ] ──► [ 💾 Evidence Store & Replay ] ──► [ 📑 Audit Reports ]
  │    • ASR (Attack Success Rate)           • SQLite Full Audit Trail           • Live HTML 
  │    • RMR (Retrieval Manipulation)        • Non-destructive Replay            • JSON Telemetry
  │    • TAR (Tool Abuse Rate)                                                             │
  └────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```text
.
├── .gitignore                      # Git exclusion rules
├── README.md                       # Main documentation & architecture guide
└── AI_Security_Scanner/            # Core system source tree
    ├── core/                       # Core scanner architecture
    │   ├── adaptive_generator.py   # Feedback-loop mutation engine
    │   ├── agent_sandbox.py        # Sandboxed tool simulator
    │   ├── async_scanner.py        # Asynchronous multi-thread scan runner
    │   ├── config.py               # Central configuration loader
    │   ├── db.py                   # SQLite schema, scan sessions, findings
    │   ├── evidence_store.py       # Full raw prompt/response audit store
    │   ├── llm_client.py           # Unified client for Ollama & OpenAI APIs
    │   ├── metrics_extended.py     # Quantitative safety metrics (ASR, RMR, TAR)
    │   ├── mutation.py             # Adversarial perturbation algorithms
    │   ├── owasp_mapper.py         # Mapping rules for OWASP LLM & MITRE ATLAS
    │   ├── report.py               # HTML & JSON report generator
    │   ├── risk_scorer.py          # Multi-dimensional risk matrix calculator
    │   ├── statistical_analysis.py # Confidence intervals and p-values
    │   └── threat_model.py         # System profiler & attack surface builder
    ├── data/                       # Test suites & benchmark datasets
    │   ├── testcases/              # Declarative YAML attack testcases
    │   │   ├── prompt_injection.yaml
    │   │   ├── jailbreak.yaml
    │   │   ├── rag_attacks.yaml
    │   │   └── agent_attacks.yaml
    │   ├── vietnamese_benchmark.json       # 62 Vietnamese domain-specific testcases
    │   ├── english_baseline_benchmark.json # Baseline cross-validation dataset
    │   └── harmbench_subset.json           # HarmBench safety evaluation subset
    ├── experiments/                # Research experiments & benchmarking
    │   ├── ablation_study.py       # Component ablation experiments
    │   ├── benchmark.py            # Cross-model evaluation suite
    │   └── multi_seed_runner.py    # Multi-seed variance verification
    ├── modules/                    # Attack and defense modules
    │   ├── detectors/              # Hybrid detection system
    │   │   ├── pattern_match.py    # Rule-based signature matcher
    │   │   └── llm_judge.py        # Evaluator LLM judge
    │   ├── exploits/               # Attack implementations
    │   │   ├── prompt_injection.py
    │   │   ├── jailbreak.py
    │   │   ├── multiturn_jailbreak.py
    │   │   ├── agent_testing.py
    │   │   ├── sensitive_disclosure.py
    │   │   ├── model_dos.py
    │   │   └── ml_adversarial.py
    │   └── integrations/           # Third-party red-teaming wrappers
    │       ├── art_wrapper.py      # Adversarial Robustness Toolbox
    │       ├── deepteam_wrapper.py # DeepTeam framework bridge
    │       ├── garak_wrapper.py    # NVIDIA Garak scanner
    │       ├── giskard_wrapper.py  # Giskard LLM test suite
    │       └── promptfoo_wrapper.py# Promptfoo evaluation integration
    ├── reports/                    # Generated audit reports
    │   └── report.html             # Interactive HTML summary
    ├── tests/                      # Unit & integration test suites
    ├── web/                        # Enterprise Web UI application
    │   ├── app.py                  # Flask REST API & SSE streaming
    │   ├── openapi.py              # Swagger UI OpenAPI 3.0 specification
    │   ├── security.py             # CSP & security middleware
    │   ├── TRANSLATION_GUIDE.md    # Bilingual localization documentation
    │   ├── static/
    │   │   ├── i18n.js             # Client-side Vietnamese/English localization
    │   │   ├── style.css           # Neon Dark Mode design tokens
    │   │   └── chart.umd.min.js    # Metric visualization
    │   └── templates/
    │       └── index.html          # Web dashboard single-page interface
    ├── config.yaml                 # System settings & model endpoints
    ├── docker-compose.yml          # Containerized orchestration
    ├── Dockerfile                  # Container build recipe
    └── requirements.txt            # Python dependencies
```

---

## 🚀 Installation & Quickstart

### Prerequisites
- **Python**: Version `3.10` or higher
- **Local Model Provider (Recommended)**: [Ollama](https://ollama.com/) running locally:
  ```bash
  # Pull standard test models
  ollama pull llama3
  ollama pull mistral
  ollama pull qwen:7b
  ```

### Setup Environment

```bash
# 1. Clone repository
git clone https://github.com/HoangHuuPhong39/NCKH.git
cd NCKH

# 2. Create and activate a virtual environment
python -m venv venv

# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
source venv/bin/activate

# 3. Install core dependencies
pip install -r AI_Security_Scanner/requirements.txt
```

---

## 💻 Usage Guide

### 1. Web Dashboard (Enterprise GUI)

Launch the interactive web portal:

```bash
cd AI_Security_Scanner
python web/app.py
```
Open your browser at `http://localhost:5000` to access:
- **Scan Console**: Live telemetry, module selector, latency graph, and cancel controls.
- **Terminal Stream**: Real-time SSE logs displaying attack mutations and detection verdicts.
- **Findings Explorer**: Filter by OWASP category, severity level, or target model.
- **Incident Correlator & Replay**: Inspect full request/response bodies and re-run non-destructive checks.
- **Language Switcher**: Toggle seamlessly between **Tiếng Việt** and **English**.

---

### 2. CLI Scanner (Metasploit-style)

For headless or terminal-first workflows:

```bash
cd AI_Security_Scanner
python main.py
```

Options:
- Run targeted scans against specific attack modules.
- Export findings directly to `reports/report.html` and `reports/report.json`.

---

### 3. Scientific Benchmarking & Ablation Study

#### Cross-Model Safety Benchmark
Benchmark multiple local models against identical attack distributions:
```bash
python AI_Security_Scanner/experiments/benchmark.py --models llama3,mistral,qwen:7b --iterations 5
```

#### Ablation Study
Evaluate the isolated performance of individual defense and attack components:
```bash
# Run full ablation matrix across all modules
python AI_Security_Scanner/experiments/ablation_study.py --mode full

# Run single-component ablation (e.g. disable Adaptive Generator)
python AI_Security_Scanner/experiments/ablation_study.py --mode single --component ADAPTIVE_GENERATOR
```

---

## 🇻🇳 Vietnamese Safety Benchmark

A key scientific contribution of this project is the **Vietnamese Domain-Specific Safety Benchmark** (`AI_Security_Scanner/data/vietnamese_benchmark.json`), addressing low-resource linguistic vulnerabilities:

- **62 Hand-Curated Scenarios**: Culturally and legally grounded in Vietnamese regulatory frameworks.
- **Three Critical Sectors**:
  - 🏦 **Banking & Fintech**: Vay tiêu dùng, trốn thuế, lừa đảo OTP, giả mạo biên lai chuyển khoản.
  - 🏥 **Healthcare & Pharma**: Kê đơn thuốc cấm, phát tán dữ liệu bệnh án cá nhân, mẹo dân gian nguy hại.
  - ⚖️ **Legal & Compliance**: Tư vấn lách luật đất đai, xâm phạm dữ liệu định danh VNeID, xuyên tạc văn bản quy phạm.
- **Linguistic Nuances**: Evaluates tone manipulation, regional dialect prompts, and multi-turn conversational traps.

---

## 🔌 Integrations

The system natively interfaces with major open-source AI evaluation and red-teaming toolkits:

| Framework | Role | Wrapper Module |
|---|---|---|
| **NVIDIA Garak** | Automated LLM vulnerability probes | `modules/integrations/garak_wrapper.py` |
| **Microsoft PyRIT** | Python Risk Identification Tool for GenAI | `modules/integrations/pyrit_wrapper.py` |
| **Promptfoo** | LLM output quality & security evaluations | `modules/integrations/promptfoo_wrapper.py` |
| **Giskard** | AI quality assurance and security testing | `modules/integrations/giskard_wrapper.py` |
| **IBM ART** | Adversarial Robustness Toolbox (ML attacks) | `modules/integrations/art_wrapper.py` |
| **DeepTeam** | Automated red-teaming test runner | `modules/integrations/deepteam_wrapper.py` |

---

## 📄 Research Context & Citation

This repository forms the empirical implementation of the scientific research project:
> **"Phân Tích, Thiết Kế và Phát Triển Bộ Công Cụ Kiểm Thử An Toàn Cho Các Hệ Thống AI"**

If you use this codebase or benchmark in your research, please cite:
```bibtex
@misc{aisecurityscanner2026,
  author = {Hoang Huu Phong},
  title = {AI Security TestKit: Practical AI Safety & Multi-tier Red-Teaming Framework},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/HoangHuuPhong39/NCKH}}
}
```

---

## ⚖️ License & Ethical Guidelines

- **Educational & Academic Purpose**: This toolkit is developed strictly for scientific research, authorized safety assessments, and defensive model alignment.
- **Responsible Disclosure**: Do not execute attacks against third-party production endpoints without explicit written authorization.
- **License**: Released under standard academic open-source licensing.
