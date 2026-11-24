# -*- coding: utf-8 -*-
"""
modules/auxiliary/scanner/oss_scanner.py - Open-Source AI Systems & Supply Chain Scanner

Quét bảo mật toàn diện các hệ thống AI mã nguồn mở (Open-Source AI Platforms),
Chuỗi cung ứng mô hình (Model Checkpoints / Modelfile) và Thư viện phụ thuộc AI (SCA):
  1. Open-Source AI Platform Audit (Ollama, Open-WebUI, vLLM, Langflow, Flowise,
     Dify, Gradio, MLflow, Ray Dashboard, Qdrant, ChromaDB, LocalAI).
  2. Live Ollama / Open-Source Model Introspection (/api/version, /api/tags, /api/ps,
     /api/show để kiểm tra System Prompt Guardrail, Quantization, Template & CVE).
  3. Open-Source Model Supply Chain & Checkpoint Scanner (Pickle RCE opcodes trong
     .pt/.pkl/.bin, HuggingFace config.json auto_map, và Ollama Modelfile Audit).
  4. AI/ML Software Composition Analysis - SCA (Quét requirements.txt phát hiện CVE
     trong langchain, transformers, torch, gradio, mlflow, ray, vllm...).
"""

import io
import json
import os
import pickletools
import re
import socket
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import tomllib
except ImportError:
    tomllib = None

import requests

from modules.base import BaseExploitModule


# ──────────────────────────────────────────────────────────────────────────────
# Danh mục Dịch vụ & Nền tảng AI Mã nguồn mở (Open-Source AI Ecosystem Catalog)
# ──────────────────────────────────────────────────────────────────────────────
OSS_AI_PLATFORMS: List[Dict[str, Any]] = [
    {
        "id": "ollama",
        "name": "Ollama Open-Source LLM Server",
        "default_port": 11434,
        "probe_paths": ["/api/version", "/api/tags", "/api/ps"],
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "cves": [
            {
                "cve": "CVE-2024-37032",
                "title": "Ollama 'Probllama' Path Traversal & Remote Code Execution",
                "affected_below": "0.1.34",
                "severity": "CRITICAL",
                "risk_score": 9.8,
                "description": "Lỗ hổng Path Traversal khi pull model từ registry không tin cậy cho phép ghi đè file hệ thống và RCE.",
            },
            {
                "cve": "CVE-2024-39722",
                "title": "Ollama Unauthenticated File Existence Disclosure via /api/push",
                "affected_below": "0.1.46",
                "severity": "HIGH",
                "risk_score": 7.5,
                "description": "Endpoint /api/push tiết lộ cấu trúc tệp tin trên máy chủ qua thông báo lỗi.",
            },
        ],
    },
    {
        "id": "open_webui",
        "name": "Open-WebUI (Self-Hosted AI Interface)",
        "default_port": 3000,
        "alt_ports": [8080],
        "probe_paths": ["/api/config", "/api/version"],
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "cves": [
            {
                "cve": "CVE-2024-7049",
                "title": "Open-WebUI SSRF & Arbitrary File Read via RAG Document Loader",
                "affected_below": "0.3.9",
                "severity": "HIGH",
                "risk_score": 8.4,
                "description": "Tính năng nạp URL trong RAG của Open-WebUI không lọc IP nội bộ dẫn đến SSRF.",
            },
        ],
    },
    {
        "id": "vllm",
        "name": "vLLM High-Throughput Open-Source Inference Engine",
        "default_port": 8000,
        "probe_paths": ["/v1/models", "/version", "/health"],
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "cves": [
            {
                "cve": "CVE-2024-9052",
                "title": "vLLM Distributed Worker Pickle Deserialization RCE",
                "affected_below": "0.6.2",
                "severity": "CRITICAL",
                "risk_score": 9.8,
                "description": "Giao thức truyền thông giữa các node vLLM sử dụng pickle không an toàn dẫn tới RCE.",
            },
        ],
    },
    {
        "id": "langflow",
        "name": "Langflow Low-Code AI Agent Builder",
        "default_port": 7860,
        "probe_paths": ["/api/v1/version", "/health"],
        "owasp": "LLM06",
        "mitre": "AML.T0048.001",
        "cves": [
            {
                "cve": "CVE-2025-3248",
                "title": "Langflow Unauthenticated Remote Code Execution (/api/v1/validate/code)",
                "affected_below": "1.3.0",
                "severity": "CRITICAL",
                "risk_score": 9.8,
                "description": "Endpoint /api/v1/validate/code thực thi mã Python trực tiếp không yêu cầu xác thực.",
            },
        ],
    },
    {
        "id": "flowise",
        "name": "Flowise Open-Source LLM Orchestration",
        "default_port": 3000,
        "probe_paths": ["/api/v1/ping", "/api/v1/chatflows"],
        "owasp": "LLM06",
        "mitre": "AML.T0048",
        "cves": [
            {
                "cve": "CVE-2024-31621",
                "title": "Flowise Unauthenticated API Credential & Chatflow Exposure",
                "affected_below": "1.6.6",
                "severity": "CRITICAL",
                "risk_score": 9.1,
                "description": "API quản lý chatflow không kiểm tra xác thực làm lộ API Keys và cấu hình Agent.",
            },
        ],
    },
    {
        "id": "gradio",
        "name": "Gradio Open-Source ML Web App Framework",
        "default_port": 7860,
        "probe_paths": ["/config", "/info"],
        "owasp": "LLM03",
        "mitre": "AML.T0024",
        "cves": [
            {
                "cve": "CVE-2024-1561",
                "title": "Gradio Local File Inclusion / Arbitrary File Read",
                "affected_below": "4.19.2",
                "severity": "HIGH",
                "risk_score": 8.6,
                "description": "Kẻ tấn công có thể lợi dụng hàm xử lý đường dẫn file trong Gradio để tải xuống bất kỳ file nào trên server.",
            },
        ],
    },
    {
        "id": "mlflow",
        "name": "MLflow Open-Source Model Registry & Tracking",
        "default_port": 5000,
        "probe_paths": ["/api/2.0/mlflow/experiments/search", "/version"],
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "cves": [
            {
                "cve": "CVE-2024-27132",
                "title": "MLflow Path Traversal & Cross-Site Scripting in Artifact Handler",
                "affected_below": "2.11.3",
                "severity": "HIGH",
                "risk_score": 8.8,
                "description": "Xử lý URI artifact không an toàn cho phép đọc file trái phép và thực thi mã trên client.",
            },
        ],
    },
    {
        "id": "ray",
        "name": "Anyscale Ray Distributed AI Cluster Dashboard",
        "default_port": 8265,
        "probe_paths": ["/api/version", "/api/jobs/"],
        "owasp": "LLM06",
        "mitre": "AML.T0048",
        "cves": [
            {
                "cve": "CVE-2023-48022",
                "title": "ShadowRay Unauthenticated Remote Code Execution via Ray Jobs API",
                "affected_below": "2.9.0",
                "severity": "CRITICAL",
                "risk_score": 10.0,
                "description": "Ray Dashboard mặc định không bật xác thực cho phép gửi job thực thi lệnh shell tùy ý trên cụm GPU.",
            },
        ],
    },
    {
        "id": "qdrant",
        "name": "Qdrant Open-Source Vector Database",
        "default_port": 6333,
        "probe_paths": ["/collections", "/telemetry"],
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "cves": [
            {
                "cve": "CVE-2024-3829",
                "title": "Qdrant Arbitrary File Upload via Snapshot Restore API",
                "affected_below": "1.9.0",
                "severity": "HIGH",
                "risk_score": 8.5,
                "description": "Endpoint khôi phục snapshot không kiểm tra đường dẫn cho phép ghi đè file hệ thống và đầu độc Vector DB.",
            },
        ],
    },
    {
        "id": "chromadb",
        "name": "ChromaDB Open-Source Embedding Database",
        "default_port": 8000,
        "probe_paths": ["/api/v1/heartbeat", "/api/v1/collections"],
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "cves": [],
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Cơ sở dữ liệu CVE cho Thư viện Phụ thuộc AI Mã nguồn mở (AI SCA Advisory DB)
# ──────────────────────────────────────────────────────────────────────────────
AI_DEPENDENCY_CVE_DB: List[Dict[str, Any]] = [
    {
        "package": "langchain",
        "safe_version": "0.1.17",
        "cve": "CVE-2023-46229 / CVE-2024-28088",
        "severity": "CRITICAL",
        "risk_score": 9.3,
        "owasp": "LLM06",
        "mitre": "AML.T0048.001",
        "title": "LangChain SSRF, Arbitrary Code Execution & Prompt Traversal",
        "description": "Các phiên bản LangChain cũ chứa lỗ hổng thực thi mã qua PALChain/PythonREPL và SSRF trong trình thu thập tài liệu RAG.",
        "remediation": "Nâng cấp lên langchain >= 0.2.0 và tách riêng langchain-community / langchain-experimental.",
    },
    {
        "package": "langchain-experimental",
        "safe_version": "0.0.60",
        "cve": "CVE-2024-27444",
        "severity": "CRITICAL",
        "risk_score": 9.5,
        "owasp": "LLM06",
        "mitre": "AML.T0048.001",
        "title": "LangChain Experimental PythonREPL Sandbox Escape",
        "description": "Cho phép LLM vượt rào thực thi lệnh hệ thống qua đối tượng PythonREPL.",
        "remediation": "Cập nhật langchain-experimental >= 0.0.60 và bắt buộc bật cờ xác nhận con người (Human-in-the-loop).",
    },
    {
        "package": "transformers",
        "safe_version": "4.38.0",
        "cve": "CVE-2023-7018 / CVE-2024-3568",
        "severity": "HIGH",
        "risk_score": 8.8,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "HuggingFace Transformers Deserialization of Untrusted Data (RCE)",
        "description": "Hàm nạp checkpoint và repo_type trong transformers < 4.38.0 dễ bị tấn công giải tuần tự hóa Pickle dẫn tới RCE.",
        "remediation": "Nâng cấp transformers >= 4.38.0 và ưu tiên sử dụng định dạng safetensors.",
    },
    {
        "package": "torch",
        "safe_version": "2.2.2",
        "cve": "CVE-2024-31580 / CVE-2024-31583",
        "severity": "HIGH",
        "risk_score": 8.4,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "PyTorch Heap Buffer Overflow & Use-After-Free in Mobile/TorchScript",
        "description": "Lỗ hổng tràn bộ đệm khi nạp model bytecode hoặc chạy toán tử tensor đặc biệt trong PyTorch < 2.2.2.",
        "remediation": "Nâng cấp torch >= 2.2.2 (khuyến nghị >= 2.4.0 với mặc định weights_only=True).",
    },
    {
        "package": "gradio",
        "safe_version": "4.19.2",
        "cve": "CVE-2024-1561 / CVE-2024-47167",
        "severity": "HIGH",
        "risk_score": 8.6,
        "owasp": "LLM03",
        "mitre": "AML.T0024",
        "title": "Gradio Arbitrary File Read & SSRF Vulnerability",
        "description": "Kẻ tấn công có thể đọc bất kỳ file nào trên máy chủ (bao gồm .env, khóa SSH, model weights) qua API tải file của Gradio.",
        "remediation": "Nâng cấp gradio >= 4.19.2 (hoặc >= 4.44.0).",
    },
    {
        "package": "mlflow",
        "safe_version": "2.11.3",
        "cve": "CVE-2024-27132 / CVE-2023-6977",
        "severity": "CRITICAL",
        "risk_score": 9.1,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "MLflow Path Traversal & Arbitrary File Read/Write",
        "description": "Cho phép đọc/ghi file tùy ý trên máy chủ quản lý vòng đời mô hình MLflow.",
        "remediation": "Nâng cấp mlflow >= 2.11.3 và đặt MLflow sau Reverse Proxy có xác thực.",
    },
    {
        "package": "ray",
        "safe_version": "2.9.0",
        "cve": "CVE-2023-48022",
        "severity": "CRITICAL",
        "risk_score": 10.0,
        "owasp": "LLM06",
        "mitre": "AML.T0048",
        "title": "ShadowRay Unauthenticated Remote Code Execution",
        "description": "Lỗ hổng thực thi lệnh từ xa không cần xác thực trên cụm tính toán AI phân tán Ray.",
        "remediation": "Nâng cấp ray >= 2.9.0 và chặn truy cập mạng công cộng vào cổng 8265.",
    },
    {
        "package": "llama-index",
        "safe_version": "0.10.20",
        "cve": "CVE-2024-3095",
        "severity": "HIGH",
        "risk_score": 8.2,
        "owasp": "LLM05",
        "mitre": "AML.T0048",
        "title": "LlamaIndex SQL Injection via NLSQLTableQueryEngine",
        "description": "Khai thác Prompt Injection để buộc LlamaIndex sinh truy vấn SQL độc hại thực thi trực tiếp vào cơ sở dữ liệu.",
        "remediation": "Nâng cấp llama-index >= 0.10.20 và chỉ cấp quyền SELECT (Read-Only) cho tài khoản DB.",
    },
    {
        "package": "vllm",
        "safe_version": "0.6.2",
        "cve": "CVE-2024-9052",
        "severity": "CRITICAL",
        "risk_score": 9.8,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "vLLM Distributed Inference Pickle Deserialization RCE",
        "description": "Thực thi mã từ xa qua kênh ZeroMQ/Pickle trong cụm suy luận vLLM.",
        "remediation": "Nâng cấp vllm >= 0.6.2.",
    },
    {
        "package": "pyyaml",
        "safe_version": "6.0",
        "cve": "CVE-2020-14343",
        "severity": "CRITICAL",
        "risk_score": 9.8,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "PyYAML Arbitrary Code Execution via FullLoader / Unsafe Load",
        "description": "Nạp file cấu hình model YAML trong PyYAML < 6.0 dễ dẫn đến thực thi mã tùy ý (RCE).",
        "remediation": "Nâng cấp PyYAML >= 6.0 và luôn sử dụng yaml.safe_load().",
    },
    {
        "package": "fastapi",
        "safe_version": "0.109.1",
        "cve": "CVE-2024-24762",
        "severity": "HIGH",
        "risk_score": 7.5,
        "owasp": "LLM10",
        "mitre": "AML.T0029",
        "title": "FastAPI / Starlette Multipart ReDoS Denial of Service",
        "description": "Phiên bản FastAPI < 0.109.1 tồn tại lỗ hổng ReDoS khi xử lý dữ liệu multipart/form-data gây treo dịch vụ AI API.",
        "remediation": "Nâng cấp fastapi >= 0.109.1 và python-multipart >= 0.0.7.",
    },
    {
        "package": "qdrant-client",
        "safe_version": "1.9.0",
        "cve": "CVE-2024-3829",
        "severity": "MEDIUM",
        "risk_score": 6.5,
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "title": "Outdated Qdrant Vector Client Missing Security Patching",
        "description": "Phiên bản qdrant-client cũ thiếu các bản vá kiểm soát kết nối và đồng bộ an toàn với Qdrant Engine mới.",
        "remediation": "Nâng cấp qdrant-client >= 1.9.0 và cấu hình kết nối qua HTTPS + API Key.",
    },
    {
        "package": "jinja2",
        "safe_version": "3.1.4",
        "cve": "CVE-2024-34064",
        "severity": "HIGH",
        "risk_score": 7.5,
        "owasp": "LLM05",
        "mitre": "AML.T0048",
        "title": "Jinja2 Template Attribute Injection & XSS / Sandbox Bypass",
        "description": "Jinja2 < 3.1.4 cho phép chèn thuộc tính HTML/SSTI khi render đầu ra không tin cậy hoặc đầu ra từ LLM.",
        "remediation": "Nâng cấp jinja2 >= 3.1.4, bật autoescape=True và tuyệt đối không truyền output LLM làm template.",
    },
    {
        "package": "aiohttp",
        "safe_version": "3.9.4",
        "cve": "CVE-2024-23334",
        "severity": "HIGH",
        "risk_score": 7.5,
        "owasp": "LLM03",
        "mitre": "AML.T0024",
        "title": "aiohttp Directory Traversal & Arbitrary File Read",
        "description": "aiohttp < 3.9.4 tồn tại lỗ hổng Path Traversal khi phục vụ tài nguyên tĩnh hoặc xử lý request bất đồng bộ cho AI API.",
        "remediation": "Nâng cấp aiohttp >= 3.9.4.",
    },
    {
        "package": "chromadb",
        "safe_version": "0.4.24",
        "cve": "CVE-2024-28189",
        "severity": "HIGH",
        "risk_score": 8.0,
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "title": "ChromaDB Vector Store Missing Auth & Improper Tenant Isolation",
        "description": "Các phiên bản ChromaDB cũ thiếu cơ chế xác thực mặc định và dễ bị truy cập/đầu độc kho tri thức RAG trái phép.",
        "remediation": "Nâng cấp chromadb >= 0.4.24, bật Token Auth và tắt allow_reset trên môi trường Production.",
    },
    {
        "package": "litellm",
        "safe_version": "1.35.0",
        "cve": "CVE-2024-2952 / CVE-2024-4888",
        "severity": "CRITICAL",
        "risk_score": 9.8,
        "owasp": "LLM06",
        "mitre": "AML.T0048.001",
        "title": "LiteLLM Proxy Remote Code Execution & SSRF",
        "description": "LiteLLM < 1.35.0 chứa lỗ hổng thực thi mã từ xa (RCE) qua post_call_rules/eval và SSRF qua cấu hình endpoint.",
        "remediation": "Nâng cấp litellm >= 1.35.0 và cô lập mạng cho LiteLLM Proxy.",
    },
    {
        "package": "tensorflow",
        "safe_version": "2.15.0",
        "cve": "CVE-2024-3660",
        "severity": "CRITICAL",
        "risk_score": 9.8,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "TensorFlow / Keras Arbitrary Code Injection via Model Deserialization",
        "description": "Nạp mô hình HDF5/SavedModel chứa lớp Lambda độc hại trong TensorFlow < 2.15.0 dẫn tới thực thi mã tùy ý (RCE).",
        "remediation": "Nâng cấp tensorflow >= 2.15.0 và bật safe_mode=True khi tải model.",
    },
    {
        "package": "keras",
        "safe_version": "2.13.1",
        "cve": "CVE-2024-3660",
        "severity": "CRITICAL",
        "risk_score": 9.8,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "Keras Arbitrary Code Execution via Untrusted Lambda Layer",
        "description": "Keras < 2.13.1 cho phép nhúng bytecode Python độc hại trong file model .h5/.keras thực thi ngay khi gọi load_model().",
        "remediation": "Nâng cấp keras >= 2.13.1 (khuyến nghị Keras 3 với safe_mode=True).",
    },
    {
        "package": "pillow",
        "safe_version": "10.2.0",
        "cve": "CVE-2023-50447",
        "severity": "HIGH",
        "risk_score": 8.1,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "Pillow Arbitrary Code Execution via PIL.ImageMath.eval",
        "description": "Pillow < 10.2.0 cho phép thực thi mã tùy ý trong pipeline xử lý ảnh cho mô hình Multimodal / Vision AI.",
        "remediation": "Nâng cấp Pillow >= 10.2.0.",
    },
    {
        "package": "numpy",
        "safe_version": "1.22.0",
        "cve": "CVE-2021-41496",
        "severity": "MEDIUM",
        "risk_score": 6.5,
        "owasp": "LLM10",
        "mitre": "AML.T0029",
        "title": "NumPy Buffer Overflow & Denial of Service in Array Creation",
        "description": "NumPy < 1.22.0 có thể gây crash/DoS khi xử lý tensor/mảng kích thước bất thường từ đầu vào người dùng.",
        "remediation": "Nâng cấp numpy >= 1.22.0.",
    },
    {
        "package": "onnx",
        "safe_version": "1.16.0",
        "cve": "CVE-2024-27318",
        "severity": "HIGH",
        "risk_score": 8.2,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "title": "ONNX Model External Data Path Traversal (Arbitrary File Read)",
        "description": "ONNX < 1.16.0 không kiểm tra đường dẫn external_data trong file .onnx cho phép đọc file nhạy cảm ngoài thư mục model.",
        "remediation": "Nâng cấp onnx >= 1.16.0 và kiểm duyệt tệp .onnx trước khi nạp.",
    },
    {
        "package": "requests",
        "safe_version": "2.32.0",
        "cve": "CVE-2024-35195",
        "severity": "MEDIUM",
        "risk_score": 5.6,
        "owasp": "LLM02",
        "mitre": "AML.T0024",
        "title": "Requests Session TLS Certificate Verification Bypass",
        "description": "Requests < 2.32.0 có thể bỏ qua kiểm tra chứng chỉ TLS trên các request tiếp theo trong cùng Session sau khi gặp verify=False.",
        "remediation": "Nâng cấp requests >= 2.32.0.",
    },
]


SAMPLE_VULNERABLE_REQUIREMENTS = """# Sample Open-Source AI Stack Dependencies (Demo SCA Audit)
langchain==0.0.250
langchain-experimental==0.0.42
transformers==4.30.2
torch==2.0.1
gradio==4.8.0
mlflow==2.8.1
ray==2.6.3
llama-index==0.9.40
vllm==0.5.0
pyyaml==5.3.1
requests==2.31.0
"""


def _parse_version_tuple(v_str: str) -> Tuple[int, int, int, int]:
    """Normalize version string '6.0' -> (6, 0, 0, 0) for accurate tuple comparisons."""
    nums = [int(x) for x in re.findall(r"\d+", v_str or "")[:4]]
    while len(nums) < 4:
        nums.append(0)
    return (nums[0], nums[1], nums[2], nums[3])


def _is_version_vulnerable(operator: str, pkg_ver: str, safe_ver: str) -> bool:
    """Evaluate whether a dependency specifier (operator + pkg_ver) allows a version < safe_ver."""
    op = (operator or "==").strip()
    if op == "!=":
        return False
    try:
        from packaging.version import Version
        v_pkg = Version(pkg_ver)
        v_safe = Version(safe_ver)
    except Exception:
        v_pkg = _parse_version_tuple(pkg_ver)
        v_safe = _parse_version_tuple(safe_ver)

    if op in ("==", "===", "~=", "<=", "<"):
        return v_pkg < v_safe
    if op in (">=", ">"):
        # e.g. langchain>=0.0.1 still allows vulnerable versions below safe_ver
        return v_pkg < v_safe
    return v_pkg < v_safe


class OpenSourceAIScanner(BaseExploitModule):
    """
    Module quét bảo mật các Hệ thống AI Mã nguồn mở (Ollama, Open-WebUI, vLLM, Langflow,
    Ray, MLflow, Qdrant...), Chuỗi cung ứng Model (Pickle/Modelfile) và Thư viện mã nguồn mở (SCA).
    """

    name = "Open-Source AI & Supply Chain Scanner"
    description = (
        "Quét các hệ thống AI mã nguồn mở (Ollama, Open-WebUI, vLLM, Langflow, Ray, MLflow, Qdrant), "
        "kiểm tra lỗ hổng chuỗi cung ứng Model Checkpoint (Pickle/Modelfile) và thư viện AI (LLM03 / AML.T0010)."
    )
    owasp = "LLM03"
    mitre = "AML.T0010"
    severity = "HIGH"
    category = "auxiliary"

    def __init__(self) -> None:
        self.platforms = OSS_AI_PLATFORMS
        self.cve_db = AI_DEPENDENCY_CVE_DB
        self._payloads = [
            {
                "name": "OSS_OLLAMA_MODEL_REGISTRY_AUDIT",
                "payload": "Probe Open-Source Ollama API (/api/tags, /api/ps, /api/show) for unauthenticated model exposure & Modelfile inspection.",
                "category": "OSS_PLATFORM_SCAN",
                "owasp": "LLM03",
                "mitre": "AML.T0010",
            },
            {
                "name": "OSS_MODELFILE_GUARDRAIL_AUDIT",
                "payload": "Inspect Open-Source LLM Modelfile & System Prompt for embedded canary secrets, temperature misalignment, and missing guardrails.",
                "category": "OSS_SUPPLY_CHAIN",
                "owasp": "LLM07",
                "mitre": "AML.T0010",
            },
            {
                "name": "OSS_MODEL_PICKLE_CHECKPOINT_SCAN",
                "payload": "Scan Open-Source Model Checkpoints (.pt, .pkl, .bin, .gguf) for malicious Pickle RCE opcodes (os.system / subprocess / eval).",
                "category": "OSS_MODEL_SCAN",
                "owasp": "LLM03",
                "mitre": "AML.T0010",
            },
            {
                "name": "OSS_AI_DEPENDENCY_SCA_SCAN",
                "payload": "Audit Open-Source AI Libraries (langchain, transformers, torch, gradio, ray, mlflow, vllm) against known CVE advisories.",
                "category": "OSS_SCA_AUDIT",
                "owasp": "LLM03",
                "mitre": "AML.T0010",
            },
        ]

    @staticmethod
    def get_sample_requirements() -> str:
        return SAMPLE_VULNERABLE_REQUIREMENTS

    @staticmethod
    def _verify_platform_fingerprint(plat_id: str, probe_path: str, resp: requests.Response) -> Tuple[bool, str]:
        """
        Xác thực chữ ký HTTP thực tế của nền tảng AI mã nguồn mở để tránh False Positive
        (ví dụ: tránh nhận nhầm Flask Web Dashboard ở Port 5000 thành MLflow).
        Trả về (matched: bool, detected_version: str).
        """
        if resp.status_code >= 400:
            return False, "Unknown"
        text = resp.text or ""
        low = text.lower()
        # Loại trừ chính giao diện AI Security Scanner (tránh tự báo nhầm cổng 5000 thành MLflow)
        if "ai security scanner" in low or "ai source code (sast)" in low:
            return False, "Unknown"

        content_type = (resp.headers.get("Content-Type") or "").lower()
        data = None
        if "json" in content_type or text.lstrip().startswith(("{", "[")):
            try:
                data = resp.json()
            except Exception:
                data = None

        if plat_id == "mlflow":
            if probe_path.startswith("/api/2.0/mlflow") and isinstance(data, dict) and (
                "experiments" in data or "error_code" in data
            ):
                return True, "Unknown"
            if probe_path == "/version" and "<html" not in low:
                m_ver = re.match(r"^\s*(\d+\.\d+\.\d+[a-zA-Z0-9.\-]*)\s*$", text)
                if m_ver:
                    return True, m_ver.group(1)
            return False, "Unknown"

        if plat_id == "vllm":
            if probe_path == "/v1/models" and isinstance(data, dict) and data.get("object") == "list" and isinstance(data.get("data"), list):
                return True, "Unknown"
            if probe_path == "/version" and isinstance(data, dict) and "version" in data:
                return True, str(data.get("version", "Unknown"))
            return False, "Unknown"

        if plat_id == "open_webui":
            if probe_path == "/api/config" and isinstance(data, dict) and (
                "features" in data or "default_models" in data or "webui" in low
            ):
                return True, str(data.get("version", "Unknown"))
            if probe_path == "/api/version" and isinstance(data, dict) and "version" in data and "ollama" not in low:
                return True, str(data.get("version", "Unknown"))
            return False, "Unknown"

        if plat_id == "langflow":
            if isinstance(data, dict) and ("langflow" in low or "package" in data) and "version" in data:
                return True, str(data.get("version", "Unknown"))
            return False, "Unknown"

        if plat_id == "flowise":
            if probe_path == "/api/v1/ping" and "pong" in low:
                return True, "Unknown"
            if probe_path == "/api/v1/chatflows" and isinstance(data, list):
                return True, "Unknown"
            return False, "Unknown"

        if plat_id == "gradio":
            if probe_path == "/config" and isinstance(data, dict) and "components" in data and "version" in data:
                return True, str(data.get("version", "Unknown"))
            if probe_path == "/info" and isinstance(data, dict) and ("named_endpoints" in data or "unnamed_endpoints" in data):
                return True, "Unknown"
            return False, "Unknown"

        if plat_id == "ray":
            if probe_path == "/api/version" and isinstance(data, dict) and "ray_version" in data:
                return True, str(data.get("ray_version", "Unknown"))
            if probe_path == "/api/jobs/" and isinstance(data, list):
                return True, "Unknown"
            return False, "Unknown"

        if plat_id == "qdrant":
            if probe_path == "/collections" and isinstance(data, dict) and isinstance(data.get("result"), dict) and "collections" in data["result"]:
                return True, "Unknown"
            if probe_path == "/telemetry" and isinstance(data, dict) and isinstance(data.get("result"), dict) and "app" in data["result"]:
                ver = (data["result"].get("app") or {}).get("version", "Unknown")
                return True, str(ver)
            return False, "Unknown"

        if plat_id == "chromadb":
            if probe_path == "/api/v1/heartbeat" and isinstance(data, dict) and "nanosecond heartbeat" in data:
                return True, "Unknown"
            if probe_path == "/api/v1/collections" and isinstance(data, list):
                return True, "Unknown"
            return False, "Unknown"

        if plat_id == "custom_oss_ai":
            if isinstance(data, dict) and any(k in data for k in ("models", "data", "version")):
                return True, str(data.get("version", "Unknown"))
            return False, "Unknown"

        return False, "Unknown"

    # ──────────────────────────────────────────────────────────────────────
    # 1. Quét Trực Tiếp Các Hệ Thống AI Mã Nguồn Mở (Live Platform Probing)
    # ──────────────────────────────────────────────────────────────────────
    def scan_oss_platforms(
        self,
        target_url: str = "http://localhost:11434",
        scan_common_ports: bool = True,
        timeout: float = 2.5,
    ) -> Dict[str, Any]:
        """
        Thăm dò thực tế mục tiêu và các cổng dịch vụ AI mã nguồn mở phổ biến kèm xác thực
        HTTP Fingerprint chặt chẽ (tránh nhận nhầm dịch vụ không phải AI như Flask Port 5000).
        Đặc biệt phân tích sâu toàn bộ model cài trên Ollama (/api/version, /api/tags, /api/show).
        """
        t0 = time.perf_counter()
        from core.url_security import validate_target_url

        normalized_url = target_url if "://" in target_url else f"http://{target_url}"
        url_ok, url_err = validate_target_url(normalized_url)
        if not url_ok:
            return {
                "success": False,
                "error": url_err or "Target URL blocked by SSRF policy.",
                "target_url": target_url,
                "discovered_services": [],
                "findings": [],
            }

        parsed = urlparse(normalized_url)
        host = parsed.hostname or "127.0.0.1"
        if host.lower() == "localhost":
            host = "127.0.0.1"
        explicit_port = parsed.port

        findings: List[Dict[str, Any]] = []
        discovered_services: List[Dict[str, Any]] = []

        # Nhóm tất cả các nền tảng chia sẻ cùng 1 cổng (vd 3000: Open-WebUI/Flowise, 7860: Langflow/Gradio, 8000: vLLM/ChromaDB)
        ports_to_plats: Dict[int, List[Dict[str, Any]]] = {}
        for plat in self.platforms:
            p = plat["default_port"]
            ports_to_plats.setdefault(p, []).append(plat)
        if explicit_port and explicit_port not in ports_to_plats:
            ports_to_plats[explicit_port] = [{
                "id": "custom_oss_ai",
                "name": f"Custom Open-Source AI Endpoint (Port {explicit_port})",
                "default_port": explicit_port,
                "probe_paths": ["/api/version", "/api/tags", "/v1/models", "/health"],
                "owasp": "LLM03",
                "mitre": "AML.T0010",
                "cves": [],
            }]

        if not scan_common_ports and explicit_port:
            ports_to_plats = {explicit_port: ports_to_plats[explicit_port]}

        for port, plat_candidates in ports_to_plats.items():
            # Bước 1: Kiểm tra kết nối TCP tới port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.6)
            is_open = (sock.connect_ex((host, port)) == 0)
            sock.close()

            if not is_open:
                continue

            base_endpoint = f"http://{host}:{port}"
            primary_plat = plat_candidates[0]

            # Bước 2: Kiểm tra xem endpoint có phải Ollama thực sự hay không (/api/version hoặc /api/tags)
            ollama_detected = False
            ollama_ver = "Unknown"
            try:
                ver_resp = requests.get(f"{base_endpoint}/api/version", timeout=timeout)
                if ver_resp.status_code == 200 and "version" in ver_resp.text:
                    ver_json = ver_resp.json()
                    if isinstance(ver_json, dict) and "version" in ver_json and "ray_version" not in ver_json:
                        ollama_detected = True
                        ollama_ver = str(ver_json.get("version", "Unknown"))
            except Exception:
                pass

            if ollama_detected:
                ollama_plat = next((p for p in self.platforms if p["id"] == "ollama"), primary_plat)
                service_info: Dict[str, Any] = {
                    "port": port,
                    "host": host,
                    "endpoint": base_endpoint,
                    "platform_id": "ollama",
                    "platform_name": "Ollama Open-Source LLM Server",
                    "version": ollama_ver,
                    "models_installed": [],
                    "running_models": [],
                    "status": "OPEN",
                }

                # Kiểm tra CVE theo version Ollama
                for cve_item in ollama_plat.get("cves", []):
                    if _parse_version_tuple(ollama_ver) < _parse_version_tuple(cve_item["affected_below"]):
                        findings.append({
                            "finding_id": cve_item["cve"],
                            "title": cve_item["title"],
                            "category": "OSS_PLATFORM_CVE",
                            "platform": f"Ollama v{ollama_ver} ({base_endpoint})",
                            "severity": cve_item["severity"],
                            "risk_score": cve_item["risk_score"],
                            "owasp": "LLM03",
                            "mitre": "AML.T0010",
                            "evidence": f"Phát hiện phiên bản Ollama {ollama_ver} < {cve_item['affected_below']} tại {base_endpoint}/api/version",
                            "description": cve_item["description"],
                            "remediation": f"Nâng cấp Ollama lên phiên bản mới nhất (>= {cve_item['affected_below']}).",
                        })

                # Kiểm tra /api/tags và phân tích TOÀN BỘ mô hình cài đặt (tối đa 50 model thay vì chỉ [:3])
                try:
                    tags_resp = requests.get(f"{base_endpoint}/api/tags", timeout=timeout)
                    if tags_resp.status_code == 200:
                        tags_data = tags_resp.json()
                        models_list = tags_data.get("models", [])
                        model_names = [m.get("name", "unknown") for m in models_list]
                        service_info["models_installed"] = model_names

                        findings.append({
                            "finding_id": "OSS-OLLAMA-001",
                            "title": "Ollama API Cho Phép Liệt Kê & Tải Mô Hình Không Cần Xác Thực (Unauthenticated API Access)",
                            "category": "OSS_PLATFORM_EXPOSURE",
                            "platform": f"Ollama ({base_endpoint})",
                            "severity": "HIGH",
                            "risk_score": 7.8,
                            "owasp": "LLM03",
                            "mitre": "AML.T0010",
                            "evidence": (
                                f"GET {base_endpoint}/api/tags trả về HTTP 200 mà không yêu cầu API Key/Bearer Token. "
                                f"Phát hiện {len(model_names)} mô hình mã nguồn mở: {', '.join(model_names[:12]) or 'None'}"
                            ),
                            "description": (
                                "Máy chủ Ollama mã nguồn mở mặc định không có lớp xác thực (Authentication). "
                                "Bất kỳ tiến trình hoặc người dùng nào truy cập được cổng 11434 đều có thể liệt kê model (/api/tags), "
                                "xóa model (/api/delete), tải model độc hại (/api/pull) hoặc khai thác tài nguyên GPU."
                            ),
                            "remediation": (
                                "Đặt AI Guard Proxy (Port 8000) hoặc Nginx Reverse Proxy có xác thực API Key đứng trước Ollama, "
                                "và chỉ bind Ollama vào 127.0.0.1 (OLLAMA_HOST=127.0.0.1:11434)."
                            ),
                        })

                        # Bước 3: Thăm dò sâu cấu hình của TẤT CẢ model qua /api/show (tối đa 50)
                        for m_obj in models_list[:50]:
                            m_name = m_obj.get("name")
                            if not m_name:
                                continue
                            details = m_obj.get("details", {})
                            quant = details.get("quantization_level", "")
                            param_size = details.get("parameter_size", "")

                            # Kiểm tra định dạng lượng tử hóa thấp (Q2/Q3/Q4_0) dễ làm giảm Safety Alignment
                            if quant and any(q in quant.upper() for q in ("Q2", "Q3", "Q4_0")):
                                findings.append({
                                    "finding_id": "OSS-MODEL-QUANT-001",
                                    "title": f"Mô hình Mã nguồn mở '{m_name}' Sử dụng Lượng tử hóa Thấp ({quant}) Gây Suy giảm Hàng rào An toàn",
                                    "category": "OSS_MODEL_CONFIGURATION",
                                    "platform": f"Ollama Model: {m_name}",
                                    "severity": "MEDIUM",
                                    "risk_score": 6.2,
                                    "owasp": "LLM01",
                                    "mitre": "AML.T0054",
                                    "evidence": f"Model '{m_name}' (Size: {param_size}, Quantization: {quant}, Family: {details.get('family', 'N/A')})",
                                    "description": (
                                        f"Mô hình mã nguồn mở '{m_name}' đang chạy bản nén lượng tử hóa '{quant}'. "
                                        "Nghiên cứu thực nghiệm cho thấy các bản lượng tử hóa 4-bit/3-bit có tỷ lệ bị bẻ khóa (Jailbreak ASR) "
                                        "cao hơn đáng kể so với bản FP16 nguyên gốc do suy hao trọng số RLHF Safety Alignment."
                                    ),
                                    "remediation": (
                                        "Bắt buộc kích hoạt tầng lọc ngoại vi (AI Guard Proxy + Dual-Stage Detector) "
                                        "khi vận hành các mô hình mã nguồn mở đã lượng tử hóa."
                                    ),
                                })

                            # Gọi POST /api/show để kiểm tra System Prompt Guardrail & Parameter Modelfile
                            try:
                                show_resp = requests.post(
                                    f"{base_endpoint}/api/show",
                                    json={"name": m_name},
                                    timeout=timeout,
                                )
                                if show_resp.status_code == 200:
                                    show_data = show_resp.json()
                                    sys_prompt = (show_data.get("system") or "").strip()
                                    modelfile_raw = show_data.get("modelfile") or ""

                                    if not sys_prompt:
                                        findings.append({
                                            "finding_id": "OSS-MODEL-GUARD-001",
                                            "title": f"Mô hình Mã nguồn mở '{m_name}' Không Thiết lập System Prompt Guardrail Mặc định",
                                            "category": "OSS_MODEL_CONFIGURATION",
                                            "platform": f"Ollama Model: {m_name}",
                                            "severity": "HIGH",
                                            "risk_score": 7.6,
                                            "owasp": "LLM01",
                                            "mitre": "AML.T0051",
                                            "evidence": f"POST {base_endpoint}/api/show ({m_name}) -> trường 'system' trống (Empty System Directive).",
                                            "description": (
                                                f"Mô hình '{m_name}' đang hoạt động với cấu hình gốc không có chỉ thị SYSTEM bảo vệ trong Modelfile. "
                                                "Điều này khiến mô hình dễ dàng chấp nhận các câu lệnh nhập vai (Roleplay/DAN) hoặc giải mã ROT13/Base64 độc hại."
                                            ),
                                            "remediation": (
                                                "Đóng gói lại mô hình bằng Modelfile có khai báo SYSTEM guardrail chặt chẽ "
                                                "(ví dụ: 'ollama create safe-llama3 -f Modelfile')."
                                            ),
                                        })
                                    elif re.search(r"(?:canary|secret|token|password|key|postgres://|whsec_)[:\s=_\-]*\S{4,}", sys_prompt, re.IGNORECASE):
                                        findings.append({
                                            "finding_id": "OSS-MODEL-LEAK-001",
                                            "title": f"Lộ System Prompt & Canary Token Qua API /api/show của Mô hình '{m_name}'",
                                            "category": "OSS_MODEL_EXPOSURE",
                                            "platform": f"Ollama Model: {m_name}",
                                            "severity": "CRITICAL",
                                            "risk_score": 9.1,
                                            "owasp": "LLM07",
                                            "mitre": "AML.T0010",
                                            "evidence": f"POST {base_endpoint}/api/show tiết lộ trực tiếp System Prompt ({len(sys_prompt)} ký tự): {sys_prompt[:120]}...",
                                            "description": (
                                                "Endpoint /api/show của Ollama trả về toàn bộ nội dung Modelfile và System Prompt ở dạng văn bản rõ "
                                                "mà không cần thực hiện Prompt Injection, làm lộ ngay lập tức Canary Token hoặc hướng dẫn mật."
                                            ),
                                            "remediation": (
                                                "Chặn truy cập trực tiếp từ bên ngoài vào các endpoint quản trị của Ollama (/api/show, /api/tags, /api/pull) "
                                                "thông qua AI Guard Proxy."
                                            ),
                                        })

                                    # Kiểm tra tham số rủi ro (num_predict -1 / num_ctx >= 65536 / temperature > 1.2) trong Modelfile live
                                    if modelfile_raw and re.search(r"PARAMETER\s+num_predict\s+-1\b", modelfile_raw, re.IGNORECASE):
                                        findings.append({
                                            "finding_id": "OSS-MODEL-DOS-001",
                                            "title": f"Mô hình '{m_name}' Cấu hình num_predict -1 (Không giới hạn Token đầu ra)",
                                            "category": "OSS_MODEL_CONFIGURATION",
                                            "platform": f"Ollama Model: {m_name}",
                                            "severity": "MEDIUM",
                                            "risk_score": 6.2,
                                            "owasp": "LLM10",
                                            "mitre": "AML.T0029",
                                            "evidence": f"POST {base_endpoint}/api/show ({m_name}) -> Modelfile chứa 'PARAMETER num_predict -1'.",
                                            "description": "Cấu hình num_predict -1 cho phép mô hình sinh token vô hạn, dễ bị khai thác tấn công Sponge Examples / DoS tài nguyên.",
                                            "remediation": "Giới hạn PARAMETER num_predict (ví dụ 512–2048) trong Modelfile.",
                                        })
                            except Exception:
                                pass
                except Exception:
                    pass

                discovered_services.append(service_info)
                continue

            # Bước 3: Thăm dò & XÁC THỰC HTTP FINGERPRINT cho các dịch vụ AI mã nguồn mở khác
            # CHỈ ghi nhận vào discovered_services khi fingerprint HTTP thực sự khớp!
            for plat in plat_candidates:
                if plat["id"] == "ollama":
                    continue
                matched_plat = False
                for probe_path in plat.get("probe_paths", ["/"]):
                    try:
                        r = requests.get(f"{base_endpoint}{probe_path}", timeout=timeout)
                        is_match, det_ver = self._verify_platform_fingerprint(plat["id"], probe_path, r)
                        if is_match:
                            matched_plat = True
                            discovered_services.append({
                                "port": port,
                                "host": host,
                                "endpoint": base_endpoint,
                                "platform_id": plat["id"],
                                "platform_name": plat["name"],
                                "version": det_ver,
                                "models_installed": [],
                                "running_models": [],
                                "status": "OPEN",
                            })
                            findings.append({
                                "finding_id": f"OSS-EXP-{plat['id'].upper()}",
                                "title": f"Phát hiện Dịch vụ AI Mã nguồn mở '{plat['name']}' Mở Công Khai tại Cổng {port}",
                                "category": "OSS_PLATFORM_EXPOSURE",
                                "platform": f"{plat['name']} ({base_endpoint})",
                                "severity": "HIGH",
                                "risk_score": 7.8,
                                "owasp": plat.get("owasp", "LLM03"),
                                "mitre": plat.get("mitre", "AML.T0010"),
                                "evidence": f"GET {base_endpoint}{probe_path} -> HTTP {r.status_code} (Verified {plat['id']} fingerprint, version={det_ver})",
                                "description": (
                                    f"Dịch vụ '{plat['name']}' đang lắng nghe tại {base_endpoint} và cho phép truy vấn endpoint '{probe_path}' không cần xác thực. "
                                    f"Cần kiểm tra xác thực và đối chiếu các CVE liên quan ({', '.join(c['cve'] for c in plat.get('cves', [])) or 'OWASP LLM03'})."
                                ),
                                "remediation": "Bật xác thực Token/OAuth, giới hạn firewall nội bộ và cập nhật bản vá bảo mật mới nhất.",
                            })
                            # Đối chiếu CVE nếu xác định được version
                            if det_ver and det_ver != "Unknown":
                                for cve_item in plat.get("cves", []):
                                    if _parse_version_tuple(det_ver) < _parse_version_tuple(cve_item["affected_below"]):
                                        findings.append({
                                            "finding_id": cve_item["cve"],
                                            "title": cve_item["title"],
                                            "category": "OSS_PLATFORM_CVE",
                                            "platform": f"{plat['name']} v{det_ver} ({base_endpoint})",
                                            "severity": cve_item["severity"],
                                            "risk_score": cve_item["risk_score"],
                                            "owasp": plat.get("owasp", "LLM03"),
                                            "mitre": plat.get("mitre", "AML.T0010"),
                                            "evidence": f"Phiên bản {det_ver} < {cve_item['affected_below']} tại {base_endpoint}{probe_path}",
                                            "description": cve_item["description"],
                                            "remediation": f"Nâng cấp {plat['name']} lên phiên bản >= {cve_item['affected_below']}.",
                                        })
                            break
                    except Exception:
                        continue
                if matched_plat:
                    break

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "success": True,
            "target_host": host,
            "discovered_services": discovered_services,
            "findings": findings,
            "elapsed_ms": elapsed_ms,
        }

    @staticmethod
    def _format_context_snippet(lines: List[str], target_line: int, end_line: Optional[int] = None) -> str:
        end_ln = end_line if (end_line and end_line >= target_line) else target_line
        start_ctx = max(0, target_line - 2)
        end_ctx = min(len(lines), end_ln + 1)
        out = []
        for idx in range(start_ctx, end_ctx):
            ln_num = idx + 1
            marker = "▶" if target_line <= ln_num <= end_ln else " "
            out.append(f"{marker} {ln_num:3d} | {lines[idx]}")
        return "\n".join(out)

    # ──────────────────────────────────────────────────────────────────────
    # 2. Quét Chuỗi Cung Ứng Thư Viện AI Mã Nguồn Mở (SCA Dependency Audit)
    # ──────────────────────────────────────────────────────────────────────
    def scan_dependencies(self, requirements_content: str, source_name: str = "requirements.txt") -> Dict[str, Any]:
        """
        Phân tích tệp khai báo thư viện (`requirements.txt`, `.in`, `pyproject.toml`, `package.json`)
        để phát hiện các thư viện AI/ML mã nguồn mở chứa lỗ hổng CVE đã công bố, kèm số dòng chính xác.
        """
        t0 = time.perf_counter()
        findings: List[Dict[str, Any]] = []
        parsed_packages: List[Dict[str, Any]] = []
        lines = requirements_content.splitlines()
        src_low = source_name.lower()

        def find_pkg_line(pkg: str) -> int:
            pat = re.compile(rf"[\"']?{re.escape(pkg)}[\"']?", re.IGNORECASE)
            for idx, ln in enumerate(lines, start=1):
                if pat.search(ln):
                    return idx
            return 1

        # Trích xuất danh sách (line_idx, raw_line, pkg_name, operator, pkg_ver) theo định dạng tệp
        entries: List[Tuple[int, str, str, str, str]] = []

        if src_low.endswith("package.json"):
            try:
                pkg_json = json.loads(requirements_content)
                for sec in ("dependencies", "devDependencies"):
                    deps = pkg_json.get(sec)
                    if isinstance(deps, dict):
                        for k, v in deps.items():
                            p_name = str(k).lower().strip()
                            v_str = str(v or "").strip()
                            m_v = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", v_str)
                            p_ver = m_v.group(1) if m_v else ""
                            ln = find_pkg_line(k)
                            entries.append((ln, f'"{k}": "{v_str}"', p_name, "==", p_ver))
            except Exception:
                pass
        elif src_low.endswith("pyproject.toml") and tomllib is not None:
            try:
                toml_data = tomllib.loads(requirements_content)
                # PEP 621: [project].dependencies
                proj_deps = (toml_data.get("project") or {}).get("dependencies") or []
                for dep_spec in proj_deps:
                    if not isinstance(dep_spec, str):
                        continue
                    m = re.match(r"^\s*([a-zA-Z0-9_\-\.]+)(?:\[[^\]]+\])?\s*(?:([=<>!~]+)\s*([0-9a-zA-Z\.\*]+))?", dep_spec)
                    if m:
                        p_name = m.group(1).lower().replace("_", "-")
                        ln = find_pkg_line(m.group(1))
                        entries.append((ln, dep_spec.strip(), p_name, m.group(2) or "", m.group(3) or ""))
                # Poetry: [tool.poetry.dependencies]
                poetry_deps = ((toml_data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
                if isinstance(poetry_deps, dict):
                    for k, v in poetry_deps.items():
                        if k.lower() == "python":
                            continue
                        p_name = k.lower().replace("_", "-")
                        v_str = v.get("version", "") if isinstance(v, dict) else str(v or "")
                        m_v = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", v_str)
                        ln = find_pkg_line(k)
                        entries.append((ln, f'{k} = "{v_str}"', p_name, "==", m_v.group(1) if m_v else ""))
            except Exception:
                pass
        else:
            for line_idx, raw_line in enumerate(lines, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]+\])?\s*(?:([=<>!~]+)\s*([0-9a-zA-Z\.\*]+))?", line)
                if not m:
                    continue
                pkg_name = m.group(1).lower().replace("_", "-")
                operator = m.group(2) or ""
                pkg_ver = m.group(3) or ""
                entries.append((line_idx, line, pkg_name, operator, pkg_ver))

        for line_idx, line, pkg_name, operator, pkg_ver in entries:
            parsed_packages.append({"package": pkg_name, "operator": operator, "version": pkg_ver})
            ctx_snip = self._format_context_snippet(lines, line_idx) if lines else line

            if not pkg_ver:
                findings.append({
                    "finding_id": f"OSS-SCA-UNPINNED-{pkg_name.upper()}",
                    "title": f"Thư viện Mã nguồn mở '{pkg_name}' Không Ghim Phiên bản Cố định (Unpinned Supply Chain Risk)",
                    "category": "OSS_DEPENDENCY_SCA",
                    "platform": f"{source_name} : L{line_idx}",
                    "file": source_name,
                    "line": line_idx,
                    "code_line": line,
                    "context_snippet": ctx_snip,
                    "severity": "LOW",
                    "risk_score": 3.8,
                    "owasp": "LLM03",
                    "mitre": "AML.T0010",
                    "evidence": f"Dòng L{line_idx}: '{line}' (thiếu phiên bản cố định)",
                    "description": (
                        f"Gói thư viện '{pkg_name}' không được ghim phiên bản cố định, khiến hệ thống có nguy cơ tự động kéo về "
                        "phiên bản mới không tương thích hoặc bị tấn công Dependency Confusion / Typosquatting."
                    ),
                    "remediation": f"Ghim phiên bản cụ thể và kiểm tra mã băm (hash-pinning) cho gói '{pkg_name}'.",
                })
                continue

            for adv in self.cve_db:
                if adv["package"].lower() == pkg_name:
                    if _is_version_vulnerable(operator, pkg_ver, adv["safe_version"]):
                        findings.append({
                            "finding_id": adv["cve"],
                            "title": f"[{adv['cve']}] {adv['title']} ({pkg_name}=={pkg_ver})",
                            "category": "OSS_DEPENDENCY_CVE",
                            "platform": f"{source_name} : L{line_idx}",
                            "file": source_name,
                            "line": line_idx,
                            "code_line": line,
                            "context_snippet": ctx_snip,
                            "severity": adv["severity"],
                            "risk_score": adv["risk_score"],
                            "owasp": adv["owasp"],
                            "mitre": adv["mitre"],
                            "evidence": f"Dòng L{line_idx}: {line} (cần nâng cấp >= {adv['safe_version']})",
                            "description": adv["description"],
                            "remediation": adv["remediation"],
                        })

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "success": True,
            "source": source_name,
            "packages_scanned": len(parsed_packages),
            "findings": findings,
            "elapsed_ms": elapsed_ms,
        }

    @staticmethod
    def _inspect_pickle_stream_safe(raw_bytes: bytes) -> List[str]:
        """
        Phân tích tĩnh luồng byte Pickle bằng `pickletools.genops()` (100% an toàn, KHÔNG unpickle thật).
        Phát hiện cả opcode cổ điển (`GLOBAL`, `INST`) lẫn Pickle Protocol 4/5 (`STACK_GLOBAL`)
        gọi các module/hàm thực thi hệ thống nguy hiểm.
        """
        dangerous_modules = {
            "os", "posix", "nt", "subprocess", "builtins", "__builtin__",
            "importlib", "socket", "urllib.request", "shutil", "webbrowser",
            "marshal", "types", "pty", "commands", "operator",
        }
        dangerous_attrs = {
            "system", "popen", "eval", "exec", "__import__", "import_module",
            "Popen", "run", "call", "check_output", "check_call", "spawn",
            "socket", "urlopen", "rmtree", "FunctionType", "loads", "attrgetter",
        }
        detected: List[str] = []
        str_stack: List[str] = []

        try:
            for opcode, arg, _ in pickletools.genops(io.BytesIO(raw_bytes)):
                name = opcode.name
                if name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"):
                    if isinstance(arg, str):
                        str_stack.append(arg)
                        if len(str_stack) > 64:
                            str_stack = str_stack[-32:]
                elif name in ("GLOBAL", "INST") and isinstance(arg, str):
                    parts = arg.strip().split()
                    mod = parts[0] if parts else ""
                    attr = parts[1] if len(parts) > 1 else ""
                    full_sym = f"{mod}.{attr}" if attr else mod
                    if mod in dangerous_modules and (not attr or attr in dangerous_attrs or mod in ("subprocess", "posix", "nt")):
                        if full_sym not in detected:
                            detected.append(full_sym)
                elif name == "STACK_GLOBAL" and len(str_stack) >= 2:
                    attr = str_stack.pop()
                    mod = str_stack.pop()
                    full_sym = f"{mod}.{attr}"
                    if mod in dangerous_modules and (attr in dangerous_attrs or mod in ("subprocess", "posix", "nt")):
                        if full_sym not in detected:
                            detected.append(full_sym)
        except Exception:
            pass

        # Fallback quét chuỗi thô nếu luồng byte bị cắt ngang hoặc hỏng cấu trúc Pickle
        if not detected:
            raw_markers = [
                b"os\nsystem", b"posix\nsystem", b"nt\nsystem", b"subprocess",
                b"builtins\neval", b"builtins\nexec", b"__builtin__\neval",
                b"socket\nsocket", b"urllib.request", b"os.system", b"Popen",
            ]
            for m in raw_markers:
                if m in raw_bytes:
                    sym = m.decode("utf-8", errors="ignore").replace("\n", ".")
                    if sym not in detected:
                        detected.append(sym)
        return detected

    # ──────────────────────────────────────────────────────────────────────
    # 3. Quét An Toàn File Model Checkpoint, Modelfile & YAML Config
    # ──────────────────────────────────────────────────────────────────────
    def scan_model_artifacts(self, target_dir: str, include_requirements: bool = False) -> Dict[str, Any]:
        """
        Quét các tệp tin mô hình AI & cấu hình chuỗi cung ứng:
          - Pickle / PyTorch Checkpoint (.pkl, .pickle, .pt, .pth, .bin — hỗ trợ cả ZIP nén DEFLATE qua zipfile + pickletools)
          - Ollama Modelfile (tích hợp Modelfile Directive Parser: num_ctx, num_predict, secrets, backdoor)
          - YAML Agent Config (.yaml, .yml — tích hợp YAML Anchor-Resolved Parser)
          - HuggingFace config.json (`auto_map`), .env
          - Tệp thư viện (`requirements.txt`, `pyproject.toml`, `package.json`) khi `include_requirements=True`
        """
        t0 = time.perf_counter()
        from core.path_security import resolve_safe_path

        try:
            root_path = resolve_safe_path(target_dir, must_exist=True)
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return {"success": False, "error": str(exc), "findings": [], "packages_scanned": 0}
        findings: List[Dict[str, Any]] = []
        artifacts_scanned: List[str] = []
        packages_scanned = 0

        def _is_hf_config_name(name: str) -> bool:
            low = name.lower()
            return bool(re.match(r"^config(?:\s*\(\d+\)|[-_][\w.-]+)?\.json$", low))

        def _is_dep_manifest_name(name: str) -> bool:
            low = name.lower()
            return bool(
                re.match(r"^requirements(?:\s*\(\d+\)|[-_][\w.-]+)?\.txt$", low)
                or re.match(r"^pyproject(?:\s*\(\d+\))?\.toml$", low)
                or re.match(r"^package(?:\s*\(\d+\))?\.json$", low)
            )

        files_to_check: List[Path] = []
        if root_path.is_file():
            files_to_check.append(root_path)
        else:
            ignore_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
            for r, dirs, files in os.walk(root_path):
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
                for fn in files:
                    fp = Path(r) / fn
                    ext_low = fp.suffix.lower()
                    if (
                        ext_low in {".pkl", ".pickle", ".pt", ".pth", ".bin", ".gguf", ".safetensors", ".yaml", ".yml"}
                        or fn in ("Modelfile", ".env")
                        or fn.startswith((".env.", "Modelfile."))
                        or _is_hf_config_name(fn)
                        or _is_dep_manifest_name(fn)
                    ):
                        files_to_check.append(fp)

        # Nạp rules & parsers chuyên sâu từ SAST cho Modelfile & YAML
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        try:
            from modules.auxiliary.scanner.code_scanner import AI_SAST_RULES
            rules_by_id = {r["rule_id"]: r for r in AI_SAST_RULES}
        except Exception:
            pass

        for fp in files_to_check:
            rel_name = fp.name if root_path.is_file() else str(fp.relative_to(root_path))
            artifacts_scanned.append(rel_name)
            ext_low = fp.suffix.lower()

            # A. Quét file trọng số Pickle / PyTorch (.pkl, .pickle, .pt, .pth, .bin — hỗ trợ cả ZIP nén PyTorch!)
            if ext_low in {".pkl", ".pickle", ".pt", ".pth", ".bin"}:
                try:
                    matched_symbols: List[str] = []
                    stream_source = "Binary Pickle Stream"

                    if zipfile.is_zipfile(fp):
                        stream_source = "PyTorch ZIP Checkpoint"
                        cumulative_bytes = 0
                        max_zip_total = 25 * 1024 * 1024
                        with zipfile.ZipFile(fp, "r") as zf:
                            for zinfo in zf.infolist():
                                if zinfo.file_size > 10 * 1024 * 1024:
                                    continue  # Chống Zip Bomb theo từng entry
                                if zinfo.filename.endswith(".pkl") or "data.pkl" in zinfo.filename:
                                    if cumulative_bytes + zinfo.file_size > max_zip_total:
                                        break
                                    member_bytes = zf.read(zinfo.filename)
                                    cumulative_bytes += len(member_bytes)
                                    for sym in self._inspect_pickle_stream_safe(member_bytes):
                                        tag = f"{sym} ({zinfo.filename})"
                                        if tag not in matched_symbols:
                                            matched_symbols.append(tag)
                    else:
                        with open(fp, "rb") as fh:
                            raw_bytes = fh.read(2 * 1024 * 1024)
                        matched_symbols = self._inspect_pickle_stream_safe(raw_bytes)

                    if matched_symbols:
                        ev_str = f"Opcode nguy hiểm trong {stream_source}: {', '.join(matched_symbols)}"
                        findings.append({
                            "finding_id": "OSS-MODELSCAN-PICKLE-RCE",
                            "title": f"Phát hiện Mã thực thi Độc hại (Malicious Pickle Opcode) trong File Model '{rel_name}'",
                            "category": "OSS_MODEL_MALWARE",
                            "platform": f"{rel_name} : {stream_source}",
                            "file": rel_name,
                            "line": 1,
                            "code_line": ev_str[:220],
                            "context_snippet": f"▶   1 | [{stream_source}] {ev_str}",
                            "severity": "CRITICAL",
                            "risk_score": 9.9,
                            "owasp": "LLM03",
                            "mitre": "AML.T0010",
                            "evidence": f"File '{rel_name}' ({stream_source}) chứa chỉ thị gọi hệ thống nguy hiểm: {', '.join(matched_symbols)}",
                            "description": (
                                "Tệp trọng số mô hình (Pickle / PyTorch ZIP) chứa các opcode Pickle gọi trực tiếp hàm thực thi lệnh hệ thống "
                                "(os.system / subprocess / eval / STACK_GLOBAL). Khi nạp bằng torch.load() hoặc pickle.load(), "
                                "mã độc sẽ tự động chiếm quyền điều khiển máy chủ (Supply Chain Attack)."
                            ),
                            "remediation": (
                                "Cách ly và xóa ngay tệp model này. Chỉ tải các mô hình mã nguồn mở sử dụng định dạng "
                                "'.safetensors' hoặc '.gguf' đã xác thực chữ ký SHA256."
                            ),
                        })
                except Exception:
                    pass

            # B. Quét Ollama Modelfile (tích hợp Modelfile Directive Parser đầy đủ)
            elif fp.name == "Modelfile" or fp.name.startswith("Modelfile.") or ext_low == ".modelfile":
                try:
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                    lines = text.splitlines()
                    from modules.auxiliary.scanner.sast_analyzers import analyze_modelfile

                    mf_hits = analyze_modelfile(text, rel_name, lines, rules_by_id, self._format_context_snippet, [])
                    for h in mf_hits:
                        findings.append({
                            "finding_id": f"OSS-MF-{h['rule_id']}",
                            "title": h["title"],
                            "category": "OSS_MODEL_CONFIGURATION",
                            "platform": f"{rel_name} : L{h['line']}",
                            "file": rel_name,
                            "line": h["line"],
                            "code_line": h["code_line"],
                            "context_snippet": h["context_snippet"],
                            "severity": h["severity"],
                            "risk_score": h["risk_score"],
                            "owasp": h["owasp"],
                            "mitre": h["mitre"],
                            "evidence": f"Dòng L{h['line']}: {h['code_line']}",
                            "description": h["description"],
                            "remediation": h["remediation"],
                        })
                except Exception:
                    pass

            # B2. Quét tệp cấu hình YAML Agent / Model (tích hợp YAML Anchor-Resolved Parser)
            elif ext_low in {".yaml", ".yml"}:
                try:
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                    lines = text.splitlines()
                    from modules.auxiliary.scanner.sast_analyzers import analyze_yaml_config

                    yml_hits = analyze_yaml_config(text, rel_name, lines, rules_by_id, self._format_context_snippet, [])
                    for h in yml_hits:
                        findings.append({
                            "finding_id": f"OSS-YAML-{h['rule_id']}",
                            "title": h["title"],
                            "category": "OSS_MODEL_CONFIGURATION",
                            "platform": f"{rel_name} : L{h['line']}",
                            "file": rel_name,
                            "line": h["line"],
                            "code_line": h["code_line"],
                            "context_snippet": h["context_snippet"],
                            "severity": h["severity"],
                            "risk_score": h["risk_score"],
                            "owasp": h["owasp"],
                            "mitre": h["mitre"],
                            "evidence": f"Dòng L{h['line']}: {h['code_line']}",
                            "description": h["description"],
                            "remediation": h["remediation"],
                        })
                except Exception:
                    pass

            # B3. Quét .env tìm bí mật nhúng tĩnh
            elif fp.name == ".env" or fp.name.startswith(".env."):
                try:
                    text = fp.read_text(encoding="utf-8", errors="ignore")
                    lines = text.splitlines()
                    secret_line_pat = re.compile(
                        r"(?:sk-(?:proj-|ant-|live-|test-|prod-)?[a-zA-Z0-9_\-]{12,}"
                        r"|hf_[a-zA-Z0-9]{16,}"
                        r"|gsk_[a-zA-Z0-9]{16,}"
                        r"|whsec_[a-zA-Z0-9_\-]{16,}"
                        r"|(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]+@"
                        r"|(?:canary(?:\s+token)?|secret|api[_\s]*key|password|jwt_secret|hf_token)[:\s=_\-]+[^\s\"']{6,})",
                        re.IGNORECASE,
                    )
                    for line_idx, raw_ln in enumerate(lines, start=1):
                        stripped = raw_ln.strip()
                        if not stripped or stripped.startswith("#"):
                            continue
                        if secret_line_pat.search(stripped):
                            from core.governance import redact_sensitive_data
                            redacted_line, _ = redact_sensitive_data(stripped[:220])
                            redacted_ctx, _ = redact_sensitive_data(self._format_context_snippet(lines, line_idx))
                            findings.append({
                                "finding_id": "OSS-ENV-SECRET-001",
                                "title": f"Phát hiện Bí mật / API Key Nhúng Tĩnh trong '{rel_name}' (Dòng L{line_idx})",
                                "category": "OSS_MODEL_CONFIGURATION",
                                "platform": f"{rel_name} : L{line_idx}",
                                "file": rel_name,
                                "line": line_idx,
                                "code_line": redacted_line,
                                "context_snippet": redacted_ctx,
                                "severity": "HIGH" if ("sk-" in stripped or "://" in stripped) else "MEDIUM",
                                "risk_score": 8.5 if ("sk-" in stripped or "://" in stripped) else 6.8,
                                "owasp": "LLM02",
                                "mitre": "AML.T0024",
                                "evidence": f"Dòng L{line_idx}: {redacted_line}",
                                "description": f"Tệp môi trường '{rel_name}' chứa khóa API hoặc bí mật xác thực ở dạng văn bản rõ tại dòng {line_idx}.",
                                "remediation": "Chuyển khóa bí mật sang Vault / Secret Manager và đảm bảo .env nằm trong .gitignore.",
                            })
                except Exception:
                    pass

            # C. Quét HuggingFace config.json (hỗ trợ cả tên tải trùng kiểu 'config (1).json')
            elif _is_hf_config_name(fp.name):
                try:
                    raw_text = fp.read_text(encoding="utf-8", errors="ignore")
                    lines = raw_text.splitlines()
                    cfg_data = json.loads(raw_text)
                    if isinstance(cfg_data, dict) and "auto_map" in cfg_data:
                        auto_line = 1
                        end_auto_line = 1
                        for idx, ln in enumerate(lines, start=1):
                            if '"auto_map"' in ln:
                                auto_line = idx
                                end_auto_line = min(len(lines), idx + len(cfg_data["auto_map"]) + 1)
                                break
                        code_ln = lines[auto_line - 1].strip() if 0 < auto_line <= len(lines) else '"auto_map": {...}'
                        findings.append({
                            "finding_id": "OSS-HF-AUTOMAP-001",
                            "title": f"Cấu hình HuggingFace '{rel_name}' Khai báo 'auto_map' Yêu cầu Thực thi Code Tùy chỉnh",
                            "category": "OSS_MODEL_CONFIGURATION",
                            "platform": f"{rel_name} : L{auto_line}",
                            "file": rel_name,
                            "line": auto_line,
                            "code_line": code_ln,
                            "context_snippet": self._format_context_snippet(lines, auto_line, end_auto_line),
                            "severity": "HIGH",
                            "risk_score": 8.0,
                            "owasp": "LLM03",
                            "mitre": "AML.T0010",
                            "evidence": f"Dòng L{auto_line} trong {rel_name}: {json.dumps(cfg_data['auto_map'])[:140]}",
                            "description": (
                                "Tệp config.json của mô hình mã nguồn mở sử dụng 'auto_map' để ánh xạ tới các tệp Python tùy chỉnh "
                                "bên trong repo. Nếu nạp với trust_remote_code=True, các tệp Python này sẽ tự động được thực thi."
                            ),
                            "remediation": "Kiểm tra kỹ toàn bộ các file .py đi kèm model checkpoint trước khi nạp vào môi trường Production.",
                        })
                except Exception:
                    pass

            # D. Quét tệp phụ thuộc (requirements.txt, pyproject.toml, package.json — gồm cả tên tải trùng) khi bật include_requirements
            elif include_requirements and _is_dep_manifest_name(fp.name):
                try:
                    req_txt = fp.read_text(encoding="utf-8", errors="ignore")
                    sca_sub = self.scan_dependencies(req_txt, source_name=rel_name)
                    packages_scanned += int(sca_sub.get("packages_scanned", 0))
                    findings.extend(sca_sub.get("findings", []))
                except Exception:
                    pass

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "success": True,
            "target_dir": str(root_path),
            "artifacts_scanned": artifacts_scanned,
            "packages_scanned": packages_scanned,
            "findings": findings,
            "elapsed_ms": elapsed_ms,
        }

    # ──────────────────────────────────────────────────────────────────────
    # 4. Chạy Tổng Hợp Toàn Diện Quét Mã Nguồn Mở (Full OSS Audit)
    # ──────────────────────────────────────────────────────────────────────
    def run_full_oss_audit(
        self,
        target_url: str = "http://localhost:11434",
        project_dir: Optional[str] = None,
        requirements_text: Optional[str] = None,
        scan_common_ports: bool = False,
    ) -> Dict[str, Any]:
        """
        Thực hiện quét toàn diện Hệ sinh thái AI Mã nguồn mở:
          1. Quét Live Endpoint (và tùy chọn cổng dịch vụ AI mã nguồn mở phổ biến khi scan_common_ports=True).
          2. Quét Model Checkpoint & Modelfile trong thư mục dự án.
          3. Quét Thư viện phụ thuộc AI mã nguồn mở (requirements.txt / SCA).
        """
        t0 = time.perf_counter()
        all_findings: List[Dict[str, Any]] = []

        # 1. Quét Live Platform
        plat_res = self.scan_oss_platforms(target_url=target_url, scan_common_ports=scan_common_ports)
        all_findings.extend(plat_res.get("findings", []))

        # 2. Quét Model Artifacts (chỉ quét thư mục dự án khi được cung cấp rõ ràng; không tự quét repo scanner)
        art_res: Dict[str, Any] = {"findings": [], "artifacts_scanned": []}
        dep_candidates = []
        if project_dir:
            art_res = self.scan_model_artifacts(project_dir, include_requirements=False)
            all_findings.extend(art_res.get("findings", []))
            p_def = Path(project_dir)
            if p_def.is_dir():
                for child in sorted(p_def.iterdir()):
                    if child.is_file() and (
                        re.match(r"^requirements(?:\s*\(\d+\)|[-_][\w.-]+)?\.txt$", child.name.lower())
                        or re.match(r"^pyproject(?:\s*\(\d+\))?\.toml$", child.name.lower())
                        or re.match(r"^package(?:\s*\(\d+\))?\.json$", child.name.lower())
                    ):
                        dep_candidates.append(child)
            elif p_def.is_file() and (
                re.match(r"^requirements(?:\s*\(\d+\)|[-_][\w.-]+)?\.txt$", p_def.name.lower())
                or re.match(r"^pyproject(?:\s*\(\d+\))?\.toml$", p_def.name.lower())
                or re.match(r"^package(?:\s*\(\d+\))?\.json$", p_def.name.lower())
            ):
                dep_candidates.append(p_def)

        # 3. Quét Dependencies (SCA)
        total_pkgs_scanned = 0
        norm_req = (requirements_text or "").replace("\r\n", "\n").strip()
        norm_sample = SAMPLE_VULNERABLE_REQUIREMENTS.replace("\r\n", "\n").strip()
        if dep_candidates and (not norm_req or norm_req == norm_sample):
            for dp in dep_candidates:
                sub_sca = self.scan_dependencies(dp.read_text(encoding="utf-8", errors="ignore"), source_name=dp.name)
                total_pkgs_scanned += int(sub_sca.get("packages_scanned", 0))
                all_findings.extend(sub_sca.get("findings", []))
        elif requirements_text and requirements_text.strip():
            sub_sca = self.scan_dependencies(requirements_text, source_name="requirements.txt")
            total_pkgs_scanned += int(sub_sca.get("packages_scanned", 0))
            all_findings.extend(sub_sca.get("findings", []))

        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            s = f.get("severity", "MEDIUM").upper()
            by_sev[s] = by_sev.get(s, 0) + 1

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "success": True,
            "target_url": target_url,
            "discovered_services": plat_res.get("discovered_services", []),
            "artifacts_scanned": art_res.get("artifacts_scanned", []),
            "packages_scanned": total_pkgs_scanned,
            "summary": {
                "total_findings": len(all_findings),
                "services_online": len(plat_res.get("discovered_services", [])),
                "artifacts_checked": len(art_res.get("artifacts_scanned", [])),
                "packages_checked": total_pkgs_scanned,
                "by_severity": by_sev,
                "elapsed_ms": elapsed_ms,
            },
            "findings": all_findings,
        }

    def run(self, llm_client: Any) -> List[Dict[str, Any]]:
        """Thực thi module trong luồng Scan Control / CLI tiêu chuẩn."""
        target_url = getattr(llm_client, "api_url", "http://localhost:11434")
        audit = self.run_full_oss_audit(target_url=target_url)
        results: List[Dict[str, Any]] = []
        for f in audit.get("findings", []):
            results.append({
                "name": f"[{f['finding_id']}] {f['title']}",
                "payload": f"Target: {f['platform']} | Category: {f['category']}",
                "response": (
                    f"[OSS VULNERABILITY DETECTED] {f['finding_id']} | "
                    f"Evidence: {f['evidence']} | Description: {f['description']} | "
                    f"Pattern Triggered: secret=exposed / CVE"
                ),
                "category": f["category"],
                "owasp": f.get("owasp", "LLM03"),
                "mitre": f.get("mitre", "AML.T0010"),
            })
        return results
