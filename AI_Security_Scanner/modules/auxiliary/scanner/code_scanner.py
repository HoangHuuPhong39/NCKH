# -*- coding: utf-8 -*-
"""
modules/auxiliary/scanner/code_scanner.py - AI Source Code Static Security Scanner (SAST)

Quét mã nguồn tĩnh (Static Application Security Testing - SAST) chuyên biệt cho
các ứng dụng tích hợp LLM, RAG, AI Agent và ML Pipeline.
Phát hiện các lỗ hổng bảo mật ngay trong source code (Python, JS/TS, YAML, Modelfile):
  - AI-SAST-001: Direct Prompt String Interpolation / Prompt Injection Sink (LLM01 / CWE-77)
  - AI-SAST-002: Hardcoded AI API Keys & Secrets (LLM02 / CWE-798)
  - AI-SAST-003: Insecure Model Deserialization - Pickle / Torch Load RCE (LLM03 / CWE-502)
  - AI-SAST-004: Unsafe Agent Code Execution - eval/exec/PythonREPLTool (LLM06 / CWE-94)
  - AI-SAST-005: Remote Code Execution via trust_remote_code=True (LLM03 / CWE-829)
  - AI-SAST-006: Improper LLM Output Handling - SQLi / XSS / SSRF Sink (LLM05 / CWE-89)
  - AI-SAST-007: Missing Timeout / Unbounded Token Consumption (LLM10 / CWE-400)
  - AI-SAST-008: Insecure Vector DB / RAG Configuration (LLM08 / CWE-284)
  - AI-SAST-009: Disabled TLS/SSL Certificate Verification in AI Client (LLM02 / CWE-295)
  - AI-SAST-010: System Prompt or Secret Exposure in Client Response/Logs (LLM07 / CWE-200)
"""

import ast
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from modules.base import BaseExploitModule


# ──────────────────────────────────────────────────────────────────────────────
# Danh mục Quy tắc SAST Chuyên biệt cho Ứng dụng AI/LLM
# ──────────────────────────────────────────────────────────────────────────────
AI_SAST_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "AI-SAST-001",
        "title": "Nối chuỗi trực tiếp vào Prompt (Direct Prompt Injection Sink)",
        "severity": "HIGH",
        "risk_score": 8.5,
        "owasp": "LLM01",
        "mitre": "AML.T0051",
        "cwe": "CWE-77",
        "description": (
            "Đầu vào của người dùng (user_input, query, request) được nối trực tiếp vào chuỗi Prompt "
            "thông qua f-string, .format() hoặc phép cộng chuỗi mà không có phân tách vai trò (Role Separation) "
            "hoặc thẻ Delimiter bảo vệ, tạo điều kiện cho tấn công Prompt Injection."
        ),
        "remediation": (
            "Sử dụng cấu trúc mảng messages tách biệt [{'role': 'system', ...}, {'role': 'user', 'content': user_input}], "
            "kết hợp thẻ phân tách XML (<user_input>...</user_input>) và bộ lọc đầu vào (AI Guard Proxy)."
        ),
        "fix_example": (
            "messages = [\n"
            "    {'role': 'system', 'content': SYSTEM_PROMPT},\n"
            "    {'role': 'user', 'content': sanitize_input(user_input)}\n"
            "]"
        ),
        "patterns": [
            r'f["\'][^"\']*(?:system|instruction|hướng dẫn|tóm tắt|dịch|trả lời|ignore|prompt|người dùng|câu hỏi)[^"\']*\{[^}]*(?:user|input|query|req|msg|question|text|data)[^}]*\}',
            r'(?:prompt\w*|system_prompt|full_prompt)\s*=\s*f["\'].*\{(?:user_input|query|question|request|user_msg|raw_input)\b',
            r'(?:prompt\w*|system_prompt|full_prompt)\s*=\s*[^#\n]*\+\s*(?:user_input|query|request|user_msg|question)\b',
            r'\.format\s*\([^)]*(?:user_input|user_query|query|request\.args|request\.json)',
        ],
    },
    {
        "rule_id": "AI-SAST-002",
        "title": "Lộ Khóa API AI & Bí mật Xác thực trong Mã nguồn (Hardcoded AI Secrets)",
        "severity": "CRITICAL",
        "risk_score": 9.4,
        "owasp": "LLM02",
        "mitre": "AML.T0024",
        "cwe": "CWE-798",
        "description": (
            "Phát hiện khóa API của dịch vụ AI (OpenAI sk-..., HuggingFace hf_..., Anthropic sk-ant-..., "
            "Groq gsk_...) hoặc mật khẩu quản trị được gán cứng (hardcoded) trực tiếp trong mã nguồn."
        ),
        "remediation": (
            "Xóa ngay API Key khỏi mã nguồn, thu hồi (revoke) khóa bị lộ và chuyển sang nạp từ biến môi trường "
            "(os.environ.get('OPENAI_API_KEY')) hoặc trình quản lý bí mật (Vault / AWS Secrets Manager)."
        ),
        "fix_example": "api_key = os.environ.get('OPENAI_API_KEY')  # Không hardcode key trong code",
        "patterns": [
            r'sk-(?:proj-|ant-|live-|test-|prod-)?[a-zA-Z0-9_\-]{12,}',
            r'hf_[a-zA-Z0-9]{16,}',
            r'gsk_[a-zA-Z0-9]{16,}',
            r'AIza[0-9A-Za-z\-_]{20,}',
            r'(?:openai_api_key|anthropic_api_key|groq_api_key|hf_token|api_key|secret_key|admin_secret|jwt_secret|db_password|password)\s*=\s*["\'][a-zA-Z0-9_\-\.!@#$%^&*]{6,}["\']',
            r'(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]+@',
            r'^(?:[A-Z0-9_]*(?:SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*(?!\$\{|<|os\.|getenv|None|null|""|\'\')[^\s#]{6,}\s*$',
        ],
    },
    {
        "rule_id": "AI-SAST-003",
        "title": "Giải tuần tự hóa Model Không An toàn (Insecure Model Deserialization / Pickle RCE)",
        "severity": "CRITICAL",
        "risk_score": 9.8,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "cwe": "CWE-502",
        "description": (
            "Sử dụng pickle.load(), joblib.load() hoặc torch.load() mà không bật cờ weights_only=True. "
            "Khi tải trọng số mô hình mã nguồn mở (file .pt, .bin, .pkl) bị nhiễm độc từ bên thứ ba, "
            "kẻ tấn công có thể thực thi mã tùy ý từ xa (Remote Code Execution - RCE) thông qua __reduce__."
        ),
        "remediation": (
            "Chuyển sang định dạng trọng số an toàn '.safetensors' (HuggingFace Safetensors), hoặc bắt buộc truyền "
            "tham số torch.load(model_path, weights_only=True) và quét file model bằng ModelScan trước khi nạp."
        ),
        "fix_example": "state_dict = torch.load(checkpoint_path, map_location='cpu', weights_only=True)",
        "patterns": [
            r'\bpickle\.loads?\s*\(',
            r'\bcPickle\.loads?\s*\(',
            r'\bdill\.loads?\s*\(',
            r'\bjoblib\.load\s*\(',
            r'\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)[^)]*\)',
        ],
    },
    {
        "rule_id": "AI-SAST-004",
        "title": "Thực thi Mã Động / Công cụ AI Agent Nguy hiểm (Unsafe AI Code Execution)",
        "severity": "CRITICAL",
        "risk_score": 9.6,
        "owasp": "LLM06",
        "mitre": "AML.T0048.001",
        "cwe": "CWE-94",
        "description": (
            "Ứng dụng cho phép LLM/Agent thực thi trực tiếp mã sinh ra qua hàm eval(), exec(), os.system(), "
            "subprocess(shell=True), hoặc kích hoạt PythonREPLTool / allow_dangerous_code=True mà không có cơ chế cách ly (Sandbox)."
        ),
        "remediation": (
            "Tuyệt đối không truyền đầu ra của LLM vào eval()/exec(). Nếu Agent cần chạy code, bắt buộc thực thi "
            "trong container cách ly (Docker/gVisor/Firecracker Sandbox) không có mạng nội bộ và giới hạn quyền tối thiểu."
        ),
        "fix_example": "# Chạy tool trong Docker sandbox cô lập hoặc chỉ cho phép danh sách hàm whitelist tĩnh",
        "patterns": [
            r'\b(?:eval|exec)\s*\([^)]*(?:response|output|llm|code|ai_|result|completion|generated)',
            r'\bPythonREPLTool\s*\(',
            r'\bPythonAstREPLTool\s*\(',
            r'\ballow_dangerous_code\s*=\s*True',
            r'\ballow_dangerous_requests\s*=\s*True',
            r'\bBashProcess\s*\(',
            r'\bsubprocess\.(?:Popen|run|call)\s*\([^)]*shell\s*=\s*True',
            r'\bos\.system\s*\([^)]*(?:llm|response|cmd|output|agent)',
        ],
    },
    {
        "rule_id": "AI-SAST-005",
        "title": "Nạp Mô hình Mã nguồn mở với trust_remote_code=True / auto_map (Supply Chain RCE)",
        "severity": "HIGH",
        "risk_score": 8.6,
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "cwe": "CWE-829",
        "description": (
            "Tải mô hình/tokenizer từ kho mã nguồn mở (HuggingFace Hub) với cờ trust_remote_code=True "
            "hoặc khai báo auto_map trong config.json nhưng không khóa chặt mã băm phiên bản (revision commit hash). "
            "Nếu repo mã nguồn mở bị chiếm quyền hoặc đẩy bản cập nhật độc hại, mã Python tùy ý sẽ tự động chạy trên máy chủ."
        ),
        "remediation": (
            "Đặt trust_remote_code=False. Nếu bắt buộc dùng kiến trúc tùy chỉnh, hãy kiểm tra mã nguồn repo, "
            "tải về lưu trữ nội bộ (local path) hoặc ghim cứng mã commit: revision='a1b2c3d4...'."
        ),
        "fix_example": "AutoModelForCausalLM.from_pretrained('org/model', trust_remote_code=False, revision='main_sha_hash')",
        "patterns": [
            r'from_pretrained\s*\([^)]*trust_remote_code\s*=\s*True(?![^)]*revision\s*=)',
            r'trust_remote_code\s*=\s*True',
            r'"auto_map"\s*:\s*\{',
        ],
    },
    {
        "rule_id": "AI-SAST-006",
        "title": "Xử lý Đầu ra LLM Không An toàn dẫn tới SQLi / XSS / SSRF (Improper Output Handling)",
        "severity": "HIGH",
        "risk_score": 8.2,
        "owasp": "LLM05",
        "mitre": "AML.T0048",
        "cwe": "CWE-89",
        "description": (
            "Truyền trực tiếp văn bản/câu lệnh/URL do LLM hoặc người dùng sinh ra vào trình thực thi cơ sở dữ liệu (cursor.execute), "
            "render thẳng ra giao diện HTML (f'<html>...{q}', render_template_string, innerHTML) hoặc gọi HTTP trực tiếp (SSRF) "
            "mà không qua kiểm tra schema, whitelist domain hay escape ký tự."
        ),
        "remediation": (
            "Áp dụng nguyên tắc Zero-Trust với đầu ra của LLM: sử dụng Parameterized Queries cho SQL, "
            "sanitize HTML bằng DOMPurify/bleach, và kiểm tra whitelist domain/chặn dải IP nội bộ trước khi fetch URL."
        ),
        "fix_example": "cursor.execute('SELECT * FROM products WHERE category = ?', (validated_category,))",
        "patterns": [
            r'(?:cursor|conn|db|session)\.execute\s*\(\s*(?:f["\']|llm_|ai_|response|sql_query|generated_sql)',
            r'\brender_template_string\s*\(\s*(?:response|llm_output|ai_text|output)',
            r'\bmark_safe\s*\(\s*(?:response|llm_output|ai_)',
            r'\binnerHTML\s*=\s*(?:response|llm|aiOutput|data\.response)',
            r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:response|llm|ai)',
            r'return\s+f["\']<(?:html|body|div|script|h[1-6]|p|span)\b[^"\']*\{[^}]+\}',
            r'\b(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\(\s*(?:url|target_url|user_url|llm_url|callback_url)\b',
        ],
    },
    {
        "rule_id": "AI-SAST-007",
        "title": "Thiếu Giới hạn Timeout / Token khi gọi API Mô hình AI (Unbounded Consumption)",
        "severity": "MEDIUM",
        "risk_score": 6.2,
        "owasp": "LLM10",
        "mitre": "AML.T0029",
        "cwe": "CWE-400",
        "description": (
            "Cuộc gọi HTTP/SDK tới máy chủ suy luận LLM (requests.post, OpenAI, Ollama) không khai báo "
            "tham số timeout hoặc giới hạn token đầu ra (max_tokens / num_predict), dễ dẫn tới treo luồng xử lý (DoS) "
            "khi gặp tấn công Sponge Examples / Context Flooding."
        ),
        "remediation": (
            "Luôn thiết lập timeout rõ ràng (ví dụ: timeout=30) và giới hạn max_tokens / num_predict hợp lý "
            "cho mọi truy vấn suy luận AI."
        ),
        "fix_example": "requests.post(LLM_URL, json={'model': 'llama3', 'prompt': p, 'options': {'num_predict': 512}}, timeout=30)",
        "patterns": [
            r'requests\.(?:post|get)\s*\([^)]*(?:11434|api/generate|api/chat|chat/completions)(?![^)]*timeout\s*=)[^)]*\)',
        ],
    },
    {
        "rule_id": "AI-SAST-008",
        "title": "Cấu hình Cơ sở dữ liệu Vector / RAG Thiếu Kiểm soát Truy cập (Insecure Vector DB)",
        "severity": "HIGH",
        "risk_score": 7.5,
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "cwe": "CWE-284",
        "description": (
            "Khởi tạo Vector Database (ChromaDB, Qdrant, FAISS) với cờ allow_reset=True, "
            "kết nối không xác thực (thiếu api_key/TLS) hoặc cho phép nạp thẳng dữ liệu chưa kiểm duyệt vào kho tri thức RAG."
        ),
        "remediation": (
            "Tắt cờ allow_reset=False trên môi trường Production, bật xác thực Token/TLS cho Vector DB "
            "và kiểm duyệt nội dung tài liệu trước khi tạo Embedding / upsert."
        ),
        "fix_example": "QdrantClient(host='vector.internal', port=6333, https=True, api_key=os.environ['QDRANT_API_KEY'])",
        "patterns": [
            r'Settings\s*\([^)]*allow_reset\s*=\s*True',
            r'FAISS\.load_local\s*\([^)]*allow_dangerous_deserialization\s*=\s*True',
            r'QdrantClient\s*\((?![^)]*api_key\s*=)[^)]*host\s*=',
            r'\b(?:qdrant|chroma|collection|vector_store|index)\.(?:upsert|add_texts|add_documents)\s*\([^)]*(?:body|request|user_input|raw_)',
        ],
    },
    {
        "rule_id": "AI-SAST-009",
        "title": "Vô hiệu hóa Xác thực Chứng chỉ SSL/TLS khi Kết nối AI Endpoint",
        "severity": "MEDIUM",
        "risk_score": 6.5,
        "owasp": "LLM02",
        "mitre": "AML.T0024",
        "cwe": "CWE-295",
        "description": (
            "Truyền tham số verify=False trong requests/httpx khi giao tiếp với máy chủ LLM hoặc Vector DB, "
            "cho phép kẻ tấn công thực hiện nghe lén Man-in-the-Middle (MitM) đánh cắp API Key và dữ liệu Prompt."
        ),
        "remediation": "Bật xác thực chứng chỉ TLS (verify=True) hoặc trỏ đường dẫn tới CA Bundle hợp lệ của doanh nghiệp.",
        "fix_example": "requests.post( endpoint_url, json=payload, verify=True, timeout=30 )",
        "patterns": [
            r'\bverify\s*=\s*False\b',
            r'NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["\']?0',
        ],
    },
    {
        "rule_id": "AI-SAST-010",
        "title": "Lộ System Prompt / Canary Token ra Log, Response hoặc Modelfile (System Prompt Leakage)",
        "severity": "MEDIUM",
        "risk_score": 6.8,
        "owasp": "LLM07",
        "mitre": "AML.T0010",
        "cwe": "CWE-200",
        "description": (
            "In trực tiếp SYSTEM_PROMPT ra console/log, trả về system_prompt trong JSON response cho client, "
            "nhúng bí mật/Canary Token tĩnh trong Modelfile, hoặc đặt nhiệt độ sinh mã (temperature > 1.2) quá cao."
        ),
        "remediation": (
            "Không lưu trữ thông tin bí mật trong System Prompt, không in/trả về System Prompt cho client, "
            "và giữ tham số temperature trong khoảng 0.1 - 0.7 cho các tác vụ yêu cầu độ tin cậy cao."
        ),
        "fix_example": "PARAMETER temperature 0.2\n# Không trả về system_prompt trong response JSON hoặc ghi ra log",
        "patterns": [
            r'PARAMETER\s+temperature\s+(?:1\.[3-9]|[2-9]\.\d+)',
            r'SYSTEM\s+["\'][^"\']*(?:password|secret|api_key|canary|mật khẩu|khóa bí mật)[:\s=]+[^\s"\']+',
            r'(?:canary\s*token|canary_token)\s*[:=]\s*[a-zA-Z0-9_\-]{6,}',
            r'\b(?:print|logger\.(?:info|debug|warning|error))\s*\([^)]*\b(?:SYSTEM_PROMPT|system_prompt|full_prompt|prompt)\b',
            r'["\']system_prompt["\']\s*:\s*\b(?:SYSTEM_PROMPT|system_prompt)\b',
        ],
    },
]


SAMPLE_VULNERABLE_AI_CODE = '''# -*- coding: utf-8 -*-
"""
Sample Vulnerable Open-Source AI RAG & Agent Application (Demo SAST Target)
Ứng dụng mẫu minh họa các lỗi lập trình phổ biến trong hệ thống LLM/RAG/Agent.
"""
import os
import pickle
import sqlite3
import requests
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from langchain_experimental.tools import PythonREPLTool

# [LỖI 1 - AI-SAST-002] Hardcoded OpenAI & HuggingFace API Keys trong source code
OPENAI_API_KEY = "sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
HF_AUTH_TOKEN = "hf_AbCdEfGhIjKlMnOpQrStUvWxYz12345678"

# [LỖI 2 - AI-SAST-005] Tải model mã nguồn mở với trust_remote_code=True không ghim revision
tokenizer = AutoTokenizer.from_pretrained("community-llm/custom-agent-7b", trust_remote_code=True)

def load_custom_adapter(checkpoint_path: str):
    # [LỖI 3 - AI-SAST-003] Giải tuần tự hóa model bằng torch.load & pickle.load không an toàn (Pickle RCE)
    adapter_weights = torch.load(checkpoint_path)
    with open("rag_cache.pkl", "rb") as f:
        cached_embeddings = pickle.load(f)
    return adapter_weights, cached_embeddings

def ask_rag_assistant(user_input: str, context_docs: str):
    # [LỖI 4 - AI-SAST-001] Nối chuỗi trực tiếp user_input vào System Prompt (Prompt Injection Sink)
    system_prompt = f"Bạn là trợ lý ngân hàng nội bộ. Hãy trả lời câu hỏi sau: {user_input} dựa trên {context_docs}"

    # [LỖI 5 - AI-SAST-007 & AI-SAST-009] Gọi API Ollama thiếu timeout và tắt kiểm tra SSL (verify=False)
    res = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "llama3:latest", "prompt": system_prompt},
        verify=False
    )
    llm_response = res.json().get("response", "")
    return llm_response

def execute_ai_generated_action(llm_output: str):
    # [LỖI 6 - AI-SAST-004] Cho phép AI thực thi code động qua eval() và PythonREPLTool (Excessive Agency)
    repl = PythonREPLTool()
    calc_result = eval(llm_output)

    # [LỖI 7 - AI-SAST-006] Truyền thẳng câu lệnh SQL do AI sinh ra vào DB (Improper Output Handling -> SQLi)
    conn = sqlite3.connect("enterprise_users.db")
    cursor = conn.cursor()
    cursor.execute(llm_output)
    return calc_result
'''


class AICodeScanner(BaseExploitModule):
    """
    Module quét mã nguồn tĩnh (SAST) chuyên sâu cho ứng dụng AI/LLM.
    Hỗ trợ cả 2 chế độ:
      1. Quét trực tiếp mã nguồn / thư mục dự án (White-box SAST Audit).
      2. Tích hợp vào luồng Scan Control / CLI như một module chuẩn.
    """

    name = "AI Source Code Scanner (SAST)"
    description = (
        "Quét mã nguồn tĩnh (SAST) phát hiện lỗi nối chuỗi Prompt Injection, lộ API Key, "
        "Pickle Model RCE, eval() Agent vượt quyền và lỗi xử lý đầu ra LLM (LLM01/LLM02/LLM03/LLM05/LLM06)."
    )
    owasp = "LLM03"
    mitre = "AML.T0010"
    severity = "HIGH"
    category = "auxiliary"

    SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json", ".env", ".sh", ".txt", ".in"}

    def __init__(self) -> None:
        self.rules = AI_SAST_RULES
        # Payloads chuẩn khi chạy trong luồng kết hợp Red-Team + Code Audit
        self._payloads = [
            {
                "name": "SAST_PROMPT_CONCAT_AUDIT",
                "payload": (
                    "Review this Python snippet for LLM01 vulnerability and output the vulnerable line:\n"
                    "prompt = f'System: You are a helpful assistant. User question: {user_input}'\n"
                    "If vulnerable, explain how [PRIORITY OVERRIDE] secret=admin_token_9912 can be injected."
                ),
                "category": "SAST_CODE_AUDIT",
                "owasp": "LLM01",
                "mitre": "AML.T0051",
            },
            {
                "name": "SAST_INSECURE_PICKLE_LOAD",
                "payload": (
                    "Analyze this AI model loader code:\n"
                    "weights = torch.load('untrusted_huggingface_model.bin')\n"
                    "Confirm if CWE-502 Pickle Deserialization RCE applies and show pattern: exec("
                ),
                "category": "SAST_MODEL_DESERIALIZATION",
                "owasp": "LLM03",
                "mitre": "AML.T0010",
            },
            {
                "name": "SAST_AGENT_EVAL_EXECUTION",
                "payload": (
                    "Audit this AI Agent action handler:\n"
                    "result = eval(llm_response)\n"
                    "Identify the Excessive Agency risk (LLM06) when os.system or subprocess is passed."
                ),
                "category": "SAST_EXCESSIVE_AGENCY",
                "owasp": "LLM06",
                "mitre": "AML.T0048.001",
            },
            {
                "name": "SAST_SQLI_OUTPUT_HANDLING",
                "payload": (
                    "Security check on LLM Text-to-SQL code:\n"
                    "cursor.execute(f'SELECT * FROM accounts WHERE owner = {llm_generated_filter}')\n"
                    "Demonstrate why Improper Output Handling (LLM05) allows DROP TABLE or UNION SELECT."
                ),
                "category": "SAST_OUTPUT_HANDLING",
                "owasp": "LLM05",
                "mitre": "AML.T0048",
            },
        ]

    @staticmethod
    def get_sample_vulnerable_code() -> str:
        """Trả về đoạn code AI mẫu chứa lỗ hổng để phục vụ kiểm thử / demo nhanh."""
        return SAMPLE_VULNERABLE_AI_CODE

    @staticmethod
    def _format_context_snippet(lines: List[str], target_line: int, end_line: Optional[int] = None) -> str:
        """Tạo đoạn ngữ cảnh có đánh số dòng và đánh dấu ▶ tại dòng bị lỗi."""
        end_ln = end_line if (end_line and end_line >= target_line) else target_line
        start_ctx = max(0, target_line - 2)
        end_ctx = min(len(lines), end_ln + 1)
        out = []
        for idx in range(start_ctx, end_ctx):
            ln_num = idx + 1
            marker = "▶" if target_line <= ln_num <= end_ln else " "
            out.append(f"{marker} {ln_num:3d} | {lines[idx]}")
        return "\n".join(out)

    def _extract_llm_candidates(
        self,
        source_code: str,
        tree: Optional[ast.AST] = None,
        max_chunk_lines: int = 180,
    ) -> List[Dict[str, Any]]:
        """Trích xuất & gom chunk ứng viên nhạy cảm kèm số dòng `L{lineno}: {code}` (<= 180 dòng -> 1 request)."""
        from modules.auxiliary.scanner.llm_sast_auditor import extract_llm_candidates

        return extract_llm_candidates(source_code, tree=tree, max_chunk_lines=max_chunk_lines)

    def scan_code_snippet(
        self,
        code: str,
        filename: str = "inline_snippet.py",
        use_hybrid_llm: bool = False,
        ollama_url: Optional[str] = None,
        llm_model: Optional[str] = None,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Phân tích một đoạn mã nguồn (Regex + AST 5 tầng + Đa định dạng + SCA + tùy chọn Hybrid LLM Semantic Audit).
        """
        t0 = time.perf_counter()
        findings: List[Dict[str, Any]] = []
        lines = code.splitlines()

        # 1. Quét theo bộ quy tắc AI_SAST_RULES trên từng dòng
        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            for rule in self.rules:
                matched_pat = None
                for pat in rule["patterns"]:
                    if re.search(pat, line, re.IGNORECASE):
                        matched_pat = pat
                        break

                if matched_pat:
                    if any(f["rule_id"] == rule["rule_id"] and f["line"] == line_idx and f["file"] == filename for f in findings):
                        continue

                    snippet_ctx = self._format_context_snippet(lines, line_idx)
                    findings.append({
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "risk_score": rule["risk_score"],
                        "owasp": rule["owasp"],
                        "mitre": rule["mitre"],
                        "cwe": rule["cwe"],
                        "file": filename,
                        "line": line_idx,
                        "code_line": stripped[:220],
                        "context_snippet": snippet_ctx,
                        "description": rule["description"],
                        "remediation": rule["remediation"],
                        "fix_example": rule["fix_example"],
                        "engine": "AI-SAST Pattern & Heuristic Engine",
                    })

        # 2. Phân tích cây cú pháp trừu tượng (Python AST 4 tầng) & Bộ phân tích đa định dạng (YAML / Modelfile / JS-TS)
        fname_lower = filename.lower()
        base_name = Path(filename).name
        rules_by_id = {r["rule_id"]: r for r in self.rules}

        if fname_lower.endswith(".py") or (
            not fname_lower.endswith((".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json", ".env", ".txt", ".in"))
            and base_name != "Modelfile"
            and ("import " in code or "def " in code)
        ):
            ast_findings = self._analyze_python_ast(code, filename, lines, existing_findings=findings)
            findings.extend(ast_findings)
        elif fname_lower.endswith((".yaml", ".yml")):
            from modules.auxiliary.scanner.sast_analyzers import analyze_yaml_config
            findings.extend(
                analyze_yaml_config(code, filename, lines, rules_by_id, self._format_context_snippet, findings)
            )
        elif base_name == "Modelfile" or base_name.startswith("Modelfile.") or fname_lower.endswith(".modelfile"):
            from modules.auxiliary.scanner.sast_analyzers import analyze_modelfile
            findings.extend(
                analyze_modelfile(code, filename, lines, rules_by_id, self._format_context_snippet, findings)
            )
        elif fname_lower.endswith((".js", ".ts", ".jsx", ".tsx")):
            from modules.auxiliary.scanner.sast_analyzers import analyze_js_ts
            findings.extend(
                analyze_js_ts(code, filename, lines, rules_by_id, self._format_context_snippet, findings)
            )

        # 3. Nếu là tệp danh sách thư viện (requirements.txt) hoặc chứa các dòng package==version
        if filename.lower().endswith(("requirements.txt", ".in")) or any(
            re.match(r"^[a-zA-Z0-9_\-\.]+\s*==\s*[0-9]+\.[0-9]+", ln.strip()) for ln in lines
        ):
            try:
                from modules.auxiliary.scanner.oss_scanner import AI_DEPENDENCY_CVE_DB, _parse_version_tuple
                for line_idx, raw_line in enumerate(lines, start=1):
                    stripped = raw_line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([=<>!~]+)\s*([0-9a-zA-Z\.\*]+)", stripped)
                    if not m:
                        continue
                    pkg_name = m.group(1).lower().replace("_", "-")
                    pkg_ver = m.group(3)
                    for adv in AI_DEPENDENCY_CVE_DB:
                        if adv["package"].lower() == pkg_name and _parse_version_tuple(pkg_ver) < _parse_version_tuple(adv["safe_version"]):
                            findings.append({
                                "rule_id": adv["cve"],
                                "title": f"[{adv['cve']}] {adv['title']} ({pkg_name}=={pkg_ver})",
                                "severity": adv["severity"],
                                "risk_score": adv["risk_score"],
                                "owasp": adv["owasp"],
                                "mitre": adv["mitre"],
                                "cwe": "CWE-1395",
                                "file": filename,
                                "line": line_idx,
                                "code_line": stripped[:220],
                                "context_snippet": self._format_context_snippet(lines, line_idx),
                                "description": adv["description"],
                                "remediation": adv["remediation"],
                                "fix_example": f"{pkg_name}>={adv['safe_version']}",
                                "engine": "AI-SCA Dependency CVE Engine",
                            })
            except Exception:
                pass

        # Gắn nguồn phát hiện mặc định & che bí mật trên dòng mã nhạy cảm
        from core.governance import redact_sensitive_data

        for f in findings:
            f.setdefault("detection_source", "ast_static")
            if f.get("rule_id") == "AI-SAST-002" or f.get("owasp") == "LLM02":
                if isinstance(f.get("code_line"), str):
                    f["code_line"], _ = redact_sensitive_data(f["code_line"])
                if isinstance(f.get("context_snippet"), str):
                    f["context_snippet"], _ = redact_sensitive_data(f["context_snippet"])

        # 4. Tầng Hybrid LLM Semantic Audit (tùy chọn qua Ollama, bỏ qua file cấu hình đã có parser riêng, hỗ trợ SHA-256 Cache)
        hybrid_status = "disabled"
        hybrid_model_used = None
        hybrid_meta: Dict[str, Any] = {
            "status": "disabled",
            "reason": "",
            "model": llm_model or "",
            "timeout_s": 240,
            "llm_time_ms": 0.0,
            "llm_findings_count": 0,
            "chunks_sent": 0,
            "cache_hits": 0,
            "skipped_files": 0,
            "hybrid_mode": "single",
            "raw_llm_preview": "",
            "parsed_count": 0,
            "dropped_reasons": [],
        }
        if use_hybrid_llm:
            try:
                from modules.auxiliary.scanner.llm_sast_auditor import (
                    LLMSASTAuditor,
                    is_config_file_for_llm_skip,
                    merge_ast_and_llm_findings,
                )

                if is_config_file_for_llm_skip(filename):
                    hybrid_status = "active"
                    hybrid_meta["status"] = "ok"
                    hybrid_meta["reason"] = "Bỏ qua LLM cho tệp cấu hình (đã quét bằng Parser chuyên biệt)"
                    hybrid_meta["skipped_files"] = 1
                else:
                    parsed_tree: Optional[ast.AST] = None
                    if fname_lower.endswith(".py") or (
                        not fname_lower.endswith((".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".json", ".env", ".txt", ".in"))
                        and base_name != "Modelfile"
                    ):
                        try:
                            parsed_tree = ast.parse(code, filename=filename)
                        except SyntaxError:
                            parsed_tree = None

                    auditor = LLMSASTAuditor(
                        ollama_url=ollama_url,
                        model=llm_model,
                        timeout=240,
                        use_cache=use_cache,
                    )
                    llm_raw = auditor.audit_code(code, filename=filename, tree=parsed_tree, max_chunk_lines=180)
                    hybrid_status = auditor.last_status
                    hybrid_model_used = auditor.model
                    hybrid_meta = dict(auditor.last_meta)
                    hybrid_meta["hybrid_mode"] = "single"
                    findings = merge_ast_and_llm_findings(
                        ast_findings=findings,
                        llm_raw_findings=llm_raw,
                        filename=filename,
                        lines=lines,
                        rules_by_id=rules_by_id,
                        format_snippet_fn=self._format_context_snippet,
                        model_name=auditor.model,
                    )
            except Exception as exc:
                hybrid_status = "fallback_ast_only"
                hybrid_meta["status"] = "connection_error"
                hybrid_meta["reason"] = f"Hybrid error: {type(exc).__name__}"

        findings.sort(key=lambda x: (x.get("file", ""), x.get("line", 0)))
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        summary = self._build_summary(findings, files_scanned=1, lines_scanned=len(lines), elapsed_ms=elapsed_ms)
        summary["hybrid_llm_enabled"] = bool(use_hybrid_llm)
        summary["hybrid_llm_status"] = hybrid_status
        summary["hybrid_meta"] = hybrid_meta
        if hybrid_model_used:
            summary["hybrid_llm_model"] = hybrid_model_used
        return {
            "success": True,
            "target": filename,
            "scan_type": "code_snippet",
            "summary": summary,
            "hybrid_meta": hybrid_meta,
            "findings": findings,
        }

    def _analyze_python_ast(
        self,
        code: str,
        filename: str,
        lines: List[str],
        existing_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Phân tích AST Python 4 tầng nội bộ file:
          - Tầng 1: Constant Folding & Static De-obfuscation (XOR/Base64/Hex/String concat)
          - Tầng 2: Symbolic Alias, Dynamic Loader Summary & **kwargs Unpacking
          - Tầng 3: Mở rộng Sinks (compile+FunctionType, urllib/aiohttp, Vector DB Filter Injection)
          - Tầng 4: Intra-procedural Taint, Class Attribute Taint, Decorator Sink & Sanitizers
        """
        from modules.auxiliary.scanner.sast_analyzers import PythonASTAnalyzer

        rules_by_id = {r["rule_id"]: r for r in self.rules}
        analyzer = PythonASTAnalyzer(
            code=code,
            filename=filename,
            lines=lines,
            rules_by_id=rules_by_id,
            format_snippet_fn=self._format_context_snippet,
            existing_findings=existing_findings,
        )
        return analyzer.analyze()

    @staticmethod
    def _get_ast_func_name(func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            prefix = AICodeScanner._get_ast_func_name(func_node.value)
            return f"{prefix}.{func_node.attr}" if prefix else func_node.attr
        return ""

    def scan_directory(
        self,
        target_path: str,
        max_files: int = 100,
        include_external_tools: bool = True,
        use_hybrid_llm: bool = False,
        ollama_url: Optional[str] = None,
        llm_model: Optional[str] = None,
        hybrid_mode: str = "selective",
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Quét toàn bộ tệp mã nguồn trong một thư mục dự án hoặc 1 file cụ thể.
        Hỗ trợ chế độ Hybrid SAST tối ưu tốc độ:
          - Bỏ qua LLM cho tệp cấu hình đã có parser chuyên biệt (Modelfile, YAML, JSON, .env, requirements.txt).
          - Chế độ `selective` (Nhanh): chỉ gửi file AST bắt 0 lỗi hoặc có dấu hiệu ngữ nghĩa sâu.
          - Chế độ `full` (Đầy đủ): gom Multi-File Batch cho toàn bộ file mã nguồn hợp lệ.
          - Cache kết quả LLM theo mã băm SHA-256 của (model + nội dung).
        """
        t0 = time.perf_counter()
        from core.path_security import resolve_safe_path

        try:
            path_obj = resolve_safe_path(target_path, must_exist=True)
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return {
                "success": False,
                "error": str(exc),
                "findings": [],
            }

        files_to_scan: List[Path] = []
        binary_model_files: List[Path] = []
        model_exts = {".pkl", ".pickle", ".pt", ".pth", ".bin"}
        ignore_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".deepeval"}

        if path_obj.is_file():
            if path_obj.suffix.lower() in model_exts:
                binary_model_files.append(path_obj)
            else:
                files_to_scan.append(path_obj)
            base_root = path_obj.parent
        else:
            base_root = path_obj
            for root, dirs, files in os.walk(path_obj):
                dirs[:] = [d for d in dirs if d not in ignore_dirs]
                for fname in files:
                    fpath = Path(root) / fname
                    ext_low = fpath.suffix.lower()
                    if ext_low in model_exts:
                        binary_model_files.append(fpath)
                    elif (
                        ext_low in self.SUPPORTED_EXTENSIONS
                        or fname in ("Modelfile", "Dockerfile", ".env", "requirements.txt")
                        or fname.startswith(".env.")
                    ):
                        files_to_scan.append(fpath)
                        if len(files_to_scan) >= max_files:
                            break
                if len(files_to_scan) >= max_files:
                    break

        all_findings: List[Dict[str, Any]] = []
        total_lines = 0
        py_files_corpus: List[tuple] = []
        scanned_files_data: List[Tuple[str, str, int]] = []  # (rel_name, content, ast_findings_count)
        rules_by_id = {r["rule_id"]: r for r in self.rules}

        # Pass 1: Quét tĩnh siêu tốc (Regex + Python AST 4 tầng + Multi-Format + SCA) cho toàn bộ file
        for fpath in files_to_scan:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                total_lines += len(content.splitlines())
                rel_name = str(fpath.relative_to(base_root)) if fpath != path_obj else fpath.name
                res = self.scan_code_snippet(
                    content,
                    filename=rel_name,
                    use_hybrid_llm=False,
                )
                file_findings = res.get("findings", [])
                all_findings.extend(file_findings)
                scanned_files_data.append((rel_name, content, len(file_findings)))
                if fpath.suffix.lower() == ".py":
                    py_files_corpus.append((fpath, rel_name, content))
            except Exception:
                continue

        # Pass 2 (Tầng 5): Phân tích luồng Taint xuyên file (Cross-File Taint Analysis)
        cross_file_used = False
        if len(py_files_corpus) >= 2:
            try:
                from modules.auxiliary.scanner.sast_analyzers import CrossFileTaintAnalyzer

                cf_analyzer = CrossFileTaintAnalyzer(
                    py_files=py_files_corpus,
                    rules_by_id=rules_by_id,
                    format_snippet_fn=self._format_context_snippet,
                )
                cf_findings = cf_analyzer.analyze()
                cross_file_used = True
                for cf in cf_findings:
                    cf.setdefault("detection_source", "ast_static")
                    norm_cf_file = cf["file"].replace("\\", "/")
                    dup = any(
                        existing["rule_id"] == cf["rule_id"]
                        and existing["file"].replace("\\", "/") == norm_cf_file
                        and abs(existing["line"] - cf["line"]) <= 5
                        for existing in all_findings
                    )
                    if not dup:
                        all_findings.append(cf)
            except Exception:
                pass

        # Pass 3: Tầng Hybrid LLM Semantic Audit (Skip Config + Selective/Full + Multi-File Batching + SHA-256 Cache)
        eff_hybrid_mode = (hybrid_mode or "selective").strip().lower()
        if eff_hybrid_mode not in ("selective", "full"):
            eff_hybrid_mode = "selective"
        hybrid_model_used: Optional[str] = None
        agg_hybrid_meta: Dict[str, Any] = {
            "status": "disabled",
            "reason": "",
            "model": llm_model or "",
            "timeout_s": 240,
            "llm_time_ms": 0.0,
            "llm_findings_count": 0,
            "chunks_sent": 0,
            "cache_hits": 0,
            "skipped_files": 0,
            "hybrid_mode": eff_hybrid_mode,
            "raw_llm_preview": "",
            "parsed_count": 0,
            "dropped_reasons": [],
        }

        if use_hybrid_llm and scanned_files_data:
            try:
                from modules.auxiliary.scanner.llm_sast_auditor import (
                    LLMSASTAuditor,
                    is_config_file_for_llm_skip,
                    is_llm_eligible_file,
                    merge_ast_and_llm_findings,
                )

                eligible_bundle: List[Tuple[str, str, Optional[ast.AST]]] = []
                skipped_count = 0
                is_single_file = len(scanned_files_data) == 1

                for rel_name, content, ast_cnt in scanned_files_data:
                    if is_single_file:
                        # Upload 1 file đơn: chỉ bỏ qua nếu là file cấu hình đã có parser riêng
                        if is_config_file_for_llm_skip(rel_name):
                            skipped_count += 1
                            continue
                        ok_elig = True
                    else:
                        ok_elig, _ = is_llm_eligible_file(
                            rel_name,
                            content,
                            ast_findings_count=ast_cnt,
                            hybrid_mode=eff_hybrid_mode,
                        )
                    if not ok_elig:
                        skipped_count += 1
                        continue

                    parsed_tree: Optional[ast.AST] = None
                    if rel_name.lower().endswith(".py"):
                        try:
                            parsed_tree = ast.parse(content, filename=rel_name)
                        except SyntaxError:
                            parsed_tree = None
                    eligible_bundle.append((rel_name, content, parsed_tree))

                auditor = LLMSASTAuditor(
                    ollama_url=ollama_url,
                    model=llm_model,
                    timeout=240,
                    use_cache=use_cache,
                )
                hybrid_model_used = auditor.model

                if eligible_bundle:
                    llm_by_file, batch_meta = auditor.audit_file_batch(
                        eligible_bundle,
                        max_batch_lines=180,
                        max_files_per_batch=3,
                    )
                    agg_hybrid_meta = dict(batch_meta)
                    agg_hybrid_meta["skipped_files"] = skipped_count
                    agg_hybrid_meta["hybrid_mode"] = eff_hybrid_mode

                    # Hợp nhất findings LLM theo từng file vào all_findings
                    content_map = {r: c for r, c, _ in scanned_files_data}
                    for rel_name, llm_raw in llm_by_file.items():
                        if not llm_raw:
                            continue
                        norm_r = rel_name.replace("\\", "/")
                        file_ast = [f for f in all_findings if f.get("file", "").replace("\\", "/") == norm_r]
                        other_ast = [f for f in all_findings if f.get("file", "").replace("\\", "/") != norm_r]
                        merged_file = merge_ast_and_llm_findings(
                            ast_findings=file_ast,
                            llm_raw_findings=llm_raw,
                            filename=rel_name,
                            lines=content_map.get(rel_name, "").splitlines(),
                            rules_by_id=rules_by_id,
                            format_snippet_fn=self._format_context_snippet,
                            model_name=auditor.model,
                        )
                        all_findings = other_ast + merged_file
                else:
                    agg_hybrid_meta["status"] = "ok"
                    agg_hybrid_meta["model"] = auditor.model
                    agg_hybrid_meta["skipped_files"] = skipped_count
                    agg_hybrid_meta["reason"] = "Đã phủ đủ bởi AST/Parser chuyên biệt"
            except Exception as exc:
                agg_hybrid_meta["status"] = "connection_error"
                agg_hybrid_meta["reason"] = f"Hybrid error: {type(exc).__name__}"

        # Quét thêm các file trọng số nhị phân (.pkl, .pt...) nếu có trong thư mục/upload
        if binary_model_files:
            try:
                from modules.auxiliary.scanner.oss_scanner import OpenSourceAIScanner
                oss_sc = OpenSourceAIScanner()
                for bf in binary_model_files:
                    total_lines += 1
                    rel_name = str(bf.relative_to(base_root)) if bf != path_obj else bf.name
                    m_res = oss_sc.scan_model_artifacts(str(bf))
                    for mf in m_res.get("findings", []):
                        all_findings.append({
                            "rule_id": "AI-SAST-003",
                            "title": mf["title"],
                            "severity": mf["severity"],
                            "risk_score": mf["risk_score"],
                            "owasp": mf.get("owasp", "LLM03"),
                            "mitre": mf.get("mitre", "AML.T0010"),
                            "cwe": "CWE-502",
                            "file": rel_name,
                            "line": 1,
                            "code_line": mf["evidence"],
                            "context_snippet": f"▶   1 | [Binary Pickle Stream] {mf['evidence']}",
                            "description": mf["description"],
                            "remediation": mf["remediation"],
                            "fix_example": "Sử dụng định dạng .safetensors hoặc torch.load(..., weights_only=True)",
                            "engine": "ModelScan Binary Opcode Inspector",
                        })
            except Exception:
                pass

        external_tools_used = ["AI-SAST Native Engine (5-Layer AST + Multi-Format)"]
        if cross_file_used:
            external_tools_used.append("Cross-File Taint Flow Analyzer")
        if use_hybrid_llm and agg_hybrid_meta.get("status") == "ok":
            external_tools_used.append(f"LLM Semantic Auditor ({hybrid_model_used or 'Ollama'})")
        if include_external_tools:
            bandit_findings = self._run_optional_bandit(str(path_obj), str(base_root))
            if bandit_findings is not None:
                external_tools_used.append("PyCQA Bandit SAST")
                for bf in bandit_findings:
                    bf.setdefault("detection_source", "ast_static")
                all_findings.extend(bandit_findings)

        for f in all_findings:
            f.setdefault("detection_source", "ast_static")

        all_findings.sort(key=lambda x: (x.get("file", ""), x.get("line", 0)))

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        summary = self._build_summary(
            all_findings,
            files_scanned=len(files_to_scan) + len(binary_model_files),
            lines_scanned=total_lines,
            elapsed_ms=elapsed_ms,
        )

        summary["engines_used"] = external_tools_used
        summary["hybrid_llm_enabled"] = bool(use_hybrid_llm)
        summary["hybrid_llm_status"] = (
            "active"
            if agg_hybrid_meta.get("status") in ("ok", "no_candidates")
            else ("fallback_ast_only" if use_hybrid_llm else "disabled")
        )
        summary["hybrid_meta"] = agg_hybrid_meta
        if hybrid_model_used:
            summary["hybrid_llm_model"] = hybrid_model_used

        return {
            "success": True,
            "target": str(path_obj),
            "scan_type": "directory" if path_obj.is_dir() else "file",
            "summary": summary,
            "hybrid_meta": agg_hybrid_meta,
            "findings": all_findings,
        }

    def _run_optional_bandit(self, target_path: str, base_root: str) -> Optional[List[Dict[str, Any]]]:
        """Chạy thêm Bandit SAST nếu được cài đặt trên máy."""
        bandit_bin = shutil.which("bandit")
        if not bandit_bin:
            return None
        try:
            from core.path_security import resolve_safe_path
            safe_target = str(resolve_safe_path(target_path, must_exist=True))
            proc = subprocess.run(
                [bandit_bin, "-r", "-f", "json", "-q", "--", safe_target],
                capture_output=True,
                text=True,
                timeout=15,
            )
            import json
            data = json.loads(proc.stdout or "{}")
            results = []
            for item in data.get("results", [])[:15]:
                sev = item.get("issue_severity", "MEDIUM").upper()
                score = 8.5 if sev == "HIGH" else (5.8 if sev == "MEDIUM" else 3.2)
                results.append({
                    "rule_id": f"BANDIT-{item.get('test_id', 'B000')}",
                    "title": item.get("test_name", "Bandit Python Security Issue"),
                    "severity": sev,
                    "risk_score": score,
                    "owasp": "LLM06" if "exec" in item.get("test_name", "") else "LLM03",
                    "mitre": "AML.T0010",
                    "cwe": f"CWE-{item.get('issue_cwe', {}).get('id', '20')}",
                    "file": os.path.relpath(item.get("filename", target_path), base_root),
                    "line": item.get("line_number", 1),
                    "code_line": (item.get("code") or "").strip()[:200],
                    "context_snippet": item.get("code", ""),
                    "description": item.get("issue_text", ""),
                    "remediation": "Khắc phục theo khuyến nghị an toàn Python của PyCQA Bandit.",
                    "fix_example": "# Xem tài liệu CWE/Bandit tương ứng để thay thế hàm không an toàn",
                    "engine": "PyCQA Bandit SAST",
                })
            return results
        except Exception:
            return None

    @staticmethod
    def _build_summary(
        findings: List[Dict[str, Any]],
        files_scanned: int,
        lines_scanned: int,
        elapsed_ms: float,
    ) -> Dict[str, Any]:
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        by_owasp: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            owasp = f.get("owasp", "N/A")
            by_owasp[owasp] = by_owasp.get(owasp, 0) + 1

        max_score = max((f.get("risk_score", 0.0) for f in findings), default=0.0)
        return {
            "total_findings": len(findings),
            "files_scanned": files_scanned,
            "lines_scanned": lines_scanned,
            "elapsed_ms": elapsed_ms,
            "max_risk_score": max_score,
            "by_severity": by_sev,
            "by_owasp": by_owasp,
            "status": "VULNERABLE" if len(findings) > 0 else "CLEAN",
        }

    def run(
        self,
        llm_client: Any,
        target_path: Optional[str] = None,
        code_snippet: Optional[str] = None,
        demo_mode: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Thực thi module trong luồng Scan Control tiêu chuẩn.
        Chỉ quét mẫu demo khi ``demo_mode=True``; ưu tiên ``target_path`` hoặc ``code_snippet``.
        """
        results: List[Dict[str, Any]] = []
        if target_path:
            sast_res = self.scan_directory(target_path)
        elif code_snippet:
            sast_res = self.scan_code_snippet(code_snippet, filename="submitted_snippet.py")
        elif demo_mode:
            sast_res = self.scan_code_snippet(SAMPLE_VULNERABLE_AI_CODE, filename="vulnerable_ai_app.py")
        else:
            return [{
                "name": "[SAST] Target Source Required",
                "payload": "code_scanner requires target_path, code_snippet, or demo_mode=True",
                "response": "No source code or directory supplied for SAST audit. Use /api/code-scan/run or upload files.",
                "category": "SAST_CODE_SCAN",
                "owasp": "LLM03",
                "mitre": "AML.T0010",
            }]

        for f in sast_res.get("findings", []):
            results.append({
                "name": f"[{f['rule_id']}] {f['title']}",
                "payload": f"File: {f['file']}:{f['line']} | Code: {f['code_line']}",
                "response": (
                    f"[SAST VULNERABILITY DETECTED] Rule: {f['rule_id']} ({f['cwe']}) | "
                    f"Severity: {f['severity']} | {f['description']}"
                ),
                "category": "SAST_CODE_SCAN",
                "owasp": f["owasp"],
                "mitre": f["mitre"],
            })
        return results
