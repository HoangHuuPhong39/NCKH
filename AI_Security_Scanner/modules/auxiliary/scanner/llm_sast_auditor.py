# -*- coding: utf-8 -*-
"""
modules/auxiliary/scanner/llm_sast_auditor.py - LLM Semantic SAST Auditor (Ollama)

Tầng kiểm toán ngữ nghĩa mã nguồn bằng mô hình ngôn ngữ cục bộ (Ollama) cho kiến trúc
Hybrid SAST (AST 5 tầng + LLM Semantic Audit):
  1. Gom chunk thông minh (extract_llm_candidates): file <= 180 dòng -> 1 request duy nhất,
     lược bỏ dòng trống/comment để tối ưu token prefill và giữ nguyên số dòng gốc `L{n}:`.
  2. Prompt 1-shot tối ưu cho model 8B (`llama3:latest`): format="json", keep_alive="10m",
     options={"temperature": 0.0, "top_p": 0.1, "num_ctx": 4096, "num_predict": 1024},
     timeout=120s/chunk.
  3. Parser linh hoạt cho model 8B: chấp nhận findings/vulnerabilities/issues/results,
     single-object wrapping, line/line_number/lineno ("L21" -> 21), rule_id/rule/id
     ("001" -> "AI-SAST-001"), confidence chữ ("high"->0.9, "medium"->0.75, mặc định 0.8).
  4. Grounding chống ảo giác + tự dịch dòng ±2 nếu rơi vào comment/trống + ngưỡng
     confidence >= 0.65 + ghi log chẩn đoán đầy đủ (`raw_llm_preview`, `parsed_count`,
     `dropped_reasons`).
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

VALID_SAST_RULES = {f"AI-SAST-{i:03d}" for i in range(1, 11)}

# Các định dạng cấu hình đã có bộ parser chuyên biệt (YAML Anchor, Modelfile, SCA, .env) -> bỏ qua LLM để tiết kiệm ~100s/file
LLM_SKIP_CONFIG_EXTS = {".yaml", ".yml", ".json", ".env", ".txt", ".in"}

# Dấu hiệu ngữ nghĩa sâu (chế độ Selective ưu tiên gửi sang LLM ngay cả khi file đã có lỗi AST)
_DEEP_SEMANTIC_HINTS = re.compile(
    r"(?:\[::-1\]|os\.popen|Jinja|Template\s*\(|safe_substitute|while\s+True|\blambda\b|new\s+Function|render_template)",
    re.IGNORECASE,
)

# Thread-safe LRU cache cho kết quả LLM theo SHA-256(model + prompt_ver + filename + compact_code)
_LLM_CACHE_LOCK = threading.Lock()
_LLM_AUDIT_CACHE: "OrderedDict[str, Tuple[float, List[Dict[str, Any]]]]" = OrderedDict()
_LLM_CACHE_MAX_ENTRIES = 256
_LLM_CACHE_TTL_SECONDS = 1800.0
_LLM_PROMPT_VERSION = "v3"


def clear_llm_audit_cache() -> None:
    """Xóa bộ nhớ đệm kết quả LLM (dùng khi benchmark lượt quét lạnh hoặc kiểm thử)."""
    with _LLM_CACHE_LOCK:
        _LLM_AUDIT_CACHE.clear()


def _make_cache_key(model: str, filename: str, numbered_code: str) -> str:
    raw = f"{model}||{_LLM_PROMPT_VERSION}||{filename}||{numbered_code}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def _cache_get(key: str) -> Optional[List[Dict[str, Any]]]:
    now = time.monotonic()
    with _LLM_CACHE_LOCK:
        entry = _LLM_AUDIT_CACHE.get(key)
        if not entry:
            return None
        ts, val = entry
        if (now - ts) > _LLM_CACHE_TTL_SECONDS:
            _LLM_AUDIT_CACHE.pop(key, None)
            return None
        _LLM_AUDIT_CACHE.move_to_end(key)
        return [dict(x) for x in val]


def _cache_put(key: str, findings: List[Dict[str, Any]]) -> None:
    now = time.monotonic()
    with _LLM_CACHE_LOCK:
        _LLM_AUDIT_CACHE[key] = (now, [dict(x) for x in findings])
        _LLM_AUDIT_CACHE.move_to_end(key)
        while len(_LLM_AUDIT_CACHE) > _LLM_CACHE_MAX_ENTRIES:
            _LLM_AUDIT_CACHE.popitem(last=False)


def is_config_file_for_llm_skip(filename: str) -> bool:
    """Kiểm tra file cấu hình đã có parser tĩnh chuyên biệt (Modelfile, YAML, JSON, .env, requirements, .d.ts)."""
    low = filename.lower().replace("\\", "/")
    base = Path(low).name
    if base == "modelfile" or base.startswith("modelfile.") or low.endswith(".modelfile"):
        return True
    if base.startswith(".env") or low.endswith(".d.ts"):
        return True
    ext = Path(low).suffix
    return ext in LLM_SKIP_CONFIG_EXTS


def is_llm_eligible_file(
    filename: str,
    source_code: str,
    ast_findings_count: int = 0,
    hybrid_mode: str = "selective",
) -> Tuple[bool, str]:
    """
    Quyết định file có cần gửi sang LLM Semantic Auditor hay không:
      1. Bỏ qua file cấu hình đã có parser riêng (Modelfile, YAML, JSON, .env, requirements.txt, .d.ts).
      2. Bỏ qua file không chứa bất kỳ thao tác nhạy cảm nào.
      3. Ở chế độ `selective` (Nhanh): chỉ gửi file mà AST bắt được 0 lỗi HOẶC chứa dấu hiệu ngữ nghĩa sâu
         mà AST dễ sót (`[::-1]`, `os.popen`, `Jinja`, `Template`, `while True`, `lambda`, `new Function`).
      4. Ở chế độ `full`: gửi toàn bộ file mã nguồn hợp lệ (sẽ được gom Multi-File Batch).
    """
    if is_config_file_for_llm_skip(filename):
        return False, "skipped_config_parser"
    if not _SENSITIVE_AST_TOKENS.search(source_code):
        return False, "no_sensitive_tokens"
    mode_low = (hybrid_mode or "selective").strip().lower()
    if mode_low == "selective":
        if ast_findings_count == 0 or _DEEP_SEMANTIC_HINTS.search(source_code):
            return True, "selected_semantic"
        return False, "skipped_ast_covered"
    return True, "selected_full"

# Các từ khóa nhạy cảm dùng để nhận diện file/hàm cần đưa vào LLM Semantic Auditor
_SENSITIVE_AST_TOKENS = re.compile(
    r"(?:completions\.create|chat\.create|messages\s*=|prompt\s*=|"
    r"\.execute\s*\(|\.executemany\s*\(|sqlite3|cursor|"
    r"\.query\s*\(|\.similarity_search\s*\(|\.search\s*\(|vector_store|vdb|chroma|qdrant|"
    r"urlopen|urllib\.request|requests\.|httpx\.|aiohttp|"
    r"subprocess\.|os\.system|os\.popen|Popen|"
    r"\bcompile\s*\(|\bexec\s*\(|\beval\s*\(|FunctionType|getattr\s*\(|import_module|"
    r"pickle|torch\.load|from_pretrained|trust_remote_code|"
    r"fromhex|b64decode|chr\s*\(|\[::-1\]|Jinja|Template\s*\(|safe_substitute|render_template|while\s+True|"
    r"new\s+Function|PARAMETER\s+|SYSTEM\s+\"\"\"|verify_ssl|sandbox_mode)",
    re.IGNORECASE,
)

# System Prompt siêu gọn + phân biệt rõ mã rule 001..010 + ép reason <= 5 từ để tối ưu tốc độ decode CPU
LLM_SAST_SYSTEM_PROMPT = """Audit numbered Python/AI code (`L<n>: <code>`) and report ALL real vulnerabilities with exact rule IDs:
- AI-SAST-001: Prompt Injection (untrusted/state-bus input via Template/safe_substitute, f-string, format, builder into messages without separate static system & raw user roles).
- AI-SAST-002: Hardcoded/obfuscated secret or API key (hex/fromhex, base64, XOR, reversed `[::-1]`, join).
- AI-SAST-003: Insecure deserialization (`pickle.load(s)`, `joblib.load`, `torch.load` without `weights_only=True`).
- AI-SAST-004: Code/OS exec (`eval`, `exec`, `compile`+`exec`/`FunctionType`, `os.system`, `os.popen` incl. lambda, `subprocess` `shell=True`, `new Function`).
- AI-SAST-005: `from_pretrained` with `trust_remote_code=True` (incl. `**kwargs`/`not False`) without `revision`.
- AI-SAST-006: Unsafe LLM output: Jinja2 `JinjaTemplate`/`Template.render` SSTI/XSS, unparameterized `.execute` SQLi, or `urlopen`/`requests` SSRF.
- AI-SAST-007: Unbounded DoS: infinite `while True` LLM loop, missing `timeout` on HTTP/urlopen, `max_tokens: -1`.
- AI-SAST-008: Vector DB filter injection (`where`/`filter` merging untrusted dict via `**`, `|`, `.update`).
- AI-SAST-009: `verify=False` / `verify_ssl: false`.
- AI-SAST-010: System prompt leak / backdoor.

Ignore safe code: `subprocess.run(..., shell=False)` with validation, `yaml.safe_load`, `ast.literal_eval`, `os.environ.get`, parameterized SQL `VALUES (?)`, separated static `system` + raw `user` messages.
Return compact JSON (reason max 5 words): {"findings":[{"rule_id":"AI-SAST-001","line":10,"confidence":0.9,"reason":"5 words max"}]} or {"findings":[]} if safe."""

# 1-shot example siêu gọn (reason <= 5 từ) giúp model 7B/8B sinh JSON ngắn, nhanh gấp ~2 lần trên CPU
_ONE_SHOT_USER = """File: demo.py
L1: import os, sqlite3
L2: KEY_REV = "998877665544332211-jorp-ks"
L3: def get_k(): return KEY_REV[::-1]
L4: TOOLS = {"run": lambda c: os.popen(c).read()}
L5: def safe_db(conn, x): conn.execute("INSERT INTO t VALUES (?)", (x,))"""

_ONE_SHOT_ASSISTANT = json.dumps({
    "findings": [
        {"rule_id": "AI-SAST-002", "line": 3, "confidence": 0.95, "reason": "Reversed API key [::-1]"},
        {"rule_id": "AI-SAST-004", "line": 4, "confidence": 0.95, "reason": "os.popen command exec in lambda"},
    ]
}, separators=(",", ":"))


def _format_numbered_lines(lines: List[str], start_line: int, end_line: int) -> str:
    """Định dạng đoạn mã kèm số dòng gốc `L{lineno}: {code}`, lược bỏ dòng trống và comment thuần."""
    s = max(1, start_line)
    e = min(len(lines), end_line)
    out: List[str] = []
    for ln in range(s, e + 1):
        raw = lines[ln - 1]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        if (stripped.startswith('"""') and stripped.endswith('"""') and len(stripped) > 3) or (
            stripped.startswith("'''") and stripped.endswith("'''") and len(stripped) > 3
        ):
            continue
        out.append(f"L{ln}: {raw}")
    return "\n".join(out)


def extract_llm_candidates(
    source_code: str,
    tree: Optional[ast.AST] = None,
    max_chunk_lines: int = 180,
) -> List[Dict[str, Any]]:
    """
    Gom chunk thông minh để giảm số lần gọi Ollama:
      - Nếu toàn bộ file <= max_chunk_lines (mặc định 180 dòng) và có chứa thao tác nhạy cảm
        -> gộp thành 1 request duy nhất.
      - Nếu file > 180 dòng: chỉ trích xuất các hàm/method/class nhạy cảm (gắn `L{lineno}: {code}`),
        rồi gom các đoạn liên tiếp vào chung 1 chunk sao cho mỗi chunk <= max_chunk_lines.
    """
    lines = source_code.splitlines()
    if not lines:
        return []

    if not _SENSITIVE_AST_TOKENS.search(source_code):
        return []

    if len(lines) <= max_chunk_lines:
        return [{
            "label": f"full file (1-{len(lines)})",
            "start_line": 1,
            "end_line": len(lines),
            "valid_lines": set(range(1, len(lines) + 1)),
            "numbered_code": _format_numbered_lines(lines, 1, len(lines)),
        }]

    selected_ranges: List[Tuple[int, int, str]] = []
    if tree is not None and isinstance(tree, ast.Module):
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                s_ln = getattr(node, "lineno", 1)
                e_ln = getattr(node, "end_lineno", s_ln)
                block = "\n".join(lines[s_ln - 1:e_ln])
                if _SENSITIVE_AST_TOKENS.search(block):
                    selected_ranges.append((s_ln, e_ln, f"function {node.name}"))
            elif isinstance(node, ast.ClassDef):
                c_start = getattr(node, "lineno", 1)
                c_end = getattr(node, "end_lineno", c_start)
                cls_block = "\n".join(lines[c_start - 1:c_end])
                if not _SENSITIVE_AST_TOKENS.search(cls_block):
                    continue
                if (c_end - c_start + 1) <= max_chunk_lines:
                    selected_ranges.append((c_start, c_end, f"class {node.name}"))
                else:
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            m_start = getattr(item, "lineno", c_start)
                            m_end = getattr(item, "end_lineno", m_start)
                            m_block = "\n".join(lines[m_start - 1:m_end])
                            if _SENSITIVE_AST_TOKENS.search(m_block):
                                selected_ranges.append((m_start, m_end, f"{node.name}.{item.name}"))

        covered = set()
        for s_ln, e_ln, _ in selected_ranges:
            covered.update(range(s_ln, e_ln + 1))

        top_lines: List[int] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
                continue
            s_ln = getattr(node, "lineno", 1)
            e_ln = getattr(node, "end_lineno", s_ln)
            block = "\n".join(lines[s_ln - 1:e_ln])
            if _SENSITIVE_AST_TOKENS.search(block):
                for ln in range(s_ln, e_ln + 1):
                    if ln not in covered:
                        top_lines.append(ln)
        if top_lines:
            selected_ranges.append((min(top_lines), max(top_lines), "module_top_level"))
    else:
        cur = 1
        while cur <= len(lines):
            end_w = min(len(lines), cur + max_chunk_lines - 1)
            block = "\n".join(lines[cur - 1:end_w])
            if _SENSITIVE_AST_TOKENS.search(block):
                selected_ranges.append((cur, end_w, f"lines {cur}-{end_w}"))
            cur = end_w + 1

    if not selected_ranges:
        return []

    selected_ranges.sort(key=lambda r: r[0])

    normalized_ranges: List[Tuple[int, int, str]] = []
    for s_ln, e_ln, label in selected_ranges:
        cur = s_ln
        while cur <= e_ln:
            c_end = min(e_ln, cur + max_chunk_lines - 1)
            normalized_ranges.append((cur, c_end, label))
            cur = c_end + 1

    candidates: List[Dict[str, Any]] = []
    buf_blocks: List[str] = []
    buf_labels: List[str] = []
    buf_valid: set = set()
    buf_line_count = 0
    buf_start = normalized_ranges[0][0]
    buf_end = normalized_ranges[0][1]

    def flush_buf() -> None:
        nonlocal buf_blocks, buf_labels, buf_valid, buf_line_count
        if not buf_blocks:
            return
        candidates.append({
            "label": ", ".join(dict.fromkeys(buf_labels))[:120],
            "start_line": buf_start,
            "end_line": buf_end,
            "valid_lines": set(buf_valid),
            "numbered_code": "\n...\n".join(buf_blocks),
        })
        buf_blocks = []
        buf_labels = []
        buf_valid = set()
        buf_line_count = 0

    for s_ln, e_ln, label in normalized_ranges:
        seg_len = e_ln - s_ln + 1
        if buf_blocks and (buf_line_count + seg_len > max_chunk_lines):
            flush_buf()
            buf_start = s_ln
        if not buf_blocks:
            buf_start = s_ln
        buf_end = max(buf_end, e_ln) if buf_blocks else e_ln
        buf_blocks.append(_format_numbered_lines(lines, s_ln, e_ln))
        buf_labels.append(label)
        buf_valid.update(range(s_ln, e_ln + 1))
        buf_line_count += seg_len

    flush_buf()
    return candidates


def _resolve_ollama_config(
    ollama_url: Optional[str] = None,
    model: Optional[str] = None,
) -> Tuple[str, str]:
    """Lấy cấu hình Ollama URL và model đang có sẵn trong dự án."""
    url = ollama_url
    mdl = model
    if not url or not mdl:
        try:
            from core.config import Config

            cfg = Config()
            url = url or cfg.get("scanner.target_url", "http://localhost:11434")
            mdl = mdl or cfg.get("scanner.target_model", "llama3:latest")
        except Exception:
            url = url or "http://localhost:11434"
            mdl = mdl or "llama3:latest"
    return str(url).rstrip("/"), str(mdl)


def _is_comment_or_blank(line_text: str) -> bool:
    stripped = line_text.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("//"):
        return True
    if stripped in ('"""', "'''"):
        return True
    if (stripped.startswith('"""') and stripped.endswith('"""') and len(stripped) > 3) or (
        stripped.startswith("'''") and stripped.endswith("'''") and len(stripped) > 3
    ):
        return True
    return False


def _is_safe_grounded_false_positive(rule_id: str, line_no: int, lines: List[str]) -> Optional[str]:
    """
    Kiểm tra mẫu code an toàn rõ ràng để chống ảo giác báo giả từ model 8B.
    Trả về chuỗi lý do nếu là False Positive cần loại bỏ, ngược lại trả None.
    """
    if line_no < 1 or line_no > len(lines):
        return "line_out_of_range"
    stripped = lines[line_no - 1].strip()

    if _is_comment_or_blank(stripped):
        return "comment_or_blank_line"

    win_start = max(0, line_no - 5)
    win_end = min(len(lines), line_no + 7)
    window = "\n".join(
        ln for ln in lines[win_start:win_end]
        if not ln.strip().startswith("#") and not ln.strip().startswith("//")
    )

    if "yaml.safe_load" in stripped or "ast.literal_eval" in stripped:
        return "safe_stdlib_loader"
    if re.search(r"\bos\.(?:environ\.get|getenv)\s*\(", stripped) and not re.search(r"sk-|hf_|gsk_|AIza", stripped):
        return "safe_env_var_secret"

    # AI-SAST-009 (Disabled TLS/SSL) bắt buộc phải có từ khóa liên quan tới TLS/SSL/verify trong ngữ cảnh
    if rule_id == "AI-SAST-009":
        if not re.search(r"\b(?:verify|verify_ssl|ssl_verify|tls_verify|ssl|tls|cert|reject_unauthorized|rejectUnauthorized|insecure)\b", window, re.IGNORECASE):
            return "rule_009_no_tls_context"

    # AI-SAST-010 (System Prompt Leakage / Modelfile Backdoor) bắt buộc có dấu hiệu log/print/trả về system_prompt hoặc Modelfile
    if rule_id == "AI-SAST-010":
        if not re.search(r"\b(?:print|logger|logging|system_prompt|canary|override|backdoor|temperature|SYSTEM)\b", window, re.IGNORECASE):
            return "rule_010_no_leak_context"

    # subprocess.run(..., shell=False)
    if rule_id == "AI-SAST-004":
        if "subprocess." in stripped and re.search(r"shell\s*=\s*False", stripped):
            return "safe_subprocess_shell_false"
        if "subprocess." in window and re.search(r"shell\s*=\s*False", window):
            if not re.search(r"shell\s*=\s*True|\*\*|eval\s*\(|exec\s*\(|FunctionType|os\.popen", window):
                return "safe_subprocess_shell_false"

    # Parameterized SQL query an toàn (kể cả viết nhiều dòng như save_audit_safely) -> không báo 006 hay 008
    if rule_id in ("AI-SAST-006", "AI-SAST-008") and ".execute" in window:
        if re.search(r"\.execute\s*\(\s*[\"'][^\"']*(?:\?|%s)[^\"']*[\"']\s*,", window, re.DOTALL):
            if not re.search(r"Template\s*\(|JinjaTemplate|urlopen|requests\.|httpx\.|render_template_string|where\s*=|filter\s*=", window):
                return "safe_parameterized_sql"

    # AI-SAST-008 (Vector DB / RAG) phải có ngữ cảnh Vector DB / filter / where / allow_reset / upsert
    if rule_id == "AI-SAST-008":
        if not re.search(r"\b(?:where|filter|similarity_search|query_texts|vector|vdb|chroma|qdrant|faiss|allow_reset|upsert|add_texts|add_documents)\b", window, re.IGNORECASE):
            return "rule_008_no_vectordb_context"

    # messages tách bạch rõ role: "system" tĩnh và role: "user" truyền biến thô
    if rule_id == "AI-SAST-001":
        has_static_sys = bool(re.search(r"""["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*["'][^"'{}]+["']""", window))
        has_raw_user = bool(re.search(r"""["']role["']\s*:\s*["']user["']\s*,\s*["']content["']\s*:\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}""", window))
        if has_static_sys and has_raw_user and not re.search(r"format|format_map|safe_substitute|join\(|f[\"']", window):
            return "safe_role_separated_messages"

    return None


def _normalize_rule_id(raw_rule: Any) -> str:
    """Chuẩn hóa linh hoạt mã quy tắc: 'AI-SAST-001', 'ai-sast-1', 'SAST-001', '001', '1' -> 'AI-SAST-001'."""
    if raw_rule is None:
        return ""
    s = str(raw_rule).strip().upper()
    if s in VALID_SAST_RULES:
        return s
    m = re.search(r"(\d{1,3})$", s)
    if m:
        num = int(m.group(1))
        if 1 <= num <= 10:
            return f"AI-SAST-{num:03d}"
    return s


def _normalize_confidence(raw_conf: Any) -> float:
    """Chuẩn hóa độ tin cậy từ số hoặc chuỗi ('high'->0.9, 'medium'->0.75, rỗng->0.8)."""
    if raw_conf is None or raw_conf == "":
        return 0.8
    if isinstance(raw_conf, (int, float)):
        val = float(raw_conf)
        if val > 1.0 and val <= 100.0:
            val = val / 100.0
        return round(min(max(val, 0.0), 1.0), 2)
    s = str(raw_conf).strip().lower()
    mapping = {
        "critical": 0.95,
        "very high": 0.95,
        "high": 0.9,
        "medium": 0.75,
        "moderate": 0.75,
        "low": 0.5,
    }
    if s in mapping:
        return mapping[s]
    try:
        val = float(s.rstrip("%"))
        if val > 1.0 and val <= 100.0:
            val = val / 100.0
        return round(min(max(val, 0.0), 1.0), 2)
    except ValueError:
        return 0.8


class LLMSASTAuditor:
    """
    Tầng kiểm toán ngữ nghĩa mã nguồn qua Ollama API:
      - 1-shot chat prompt tối ưu cho Llama-3 8B
      - format="json", keep_alive="10m"
      - options={"temperature": 0.0, "top_p": 0.1, "num_ctx": 4096, "num_predict": 1024}
      - timeout mặc định 120s/chunk, fallback an toàn kèm diagnostic `hybrid_meta`.
    """

    def __init__(
        self,
        ollama_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = 240,
        min_confidence: float = 0.65,
        keep_alive: str = "10m",
        use_cache: bool = True,
    ) -> None:
        self.ollama_url, self.model = _resolve_ollama_config(ollama_url, model)
        self.timeout = timeout
        self.min_confidence = min_confidence
        self.keep_alive = keep_alive
        self.use_cache = use_cache
        self.last_status: str = "idle"
        self.last_error: Optional[str] = None
        self.last_meta: Dict[str, Any] = {
            "status": "disabled",
            "reason": "",
            "model": self.model,
            "timeout_s": self.timeout,
            "llm_time_ms": 0.0,
            "llm_findings_count": 0,
            "chunks_sent": 0,
            "cache_hits": 0,
            "skipped_files": 0,
            "raw_llm_preview": "",
            "parsed_count": 0,
            "dropped_reasons": [],
        }

    def _call_ollama_stream(self, messages: List[Dict[str, str]]) -> str:
        """Gọi Ollama `/api/chat` ở chế độ stream với keep_alive và kiểm soát tổng timeout."""
        payload = {
            "model": self.model,
            "stream": True,
            "format": "json",
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": 0.0,
                "top_p": 0.1,
                "num_ctx": 4096,
                "num_predict": 1024,
            },
            "messages": messages,
        }
        chunk_t0 = time.perf_counter()
        resp = requests.post(
            f"{self.ollama_url}/api/chat",
            json=payload,
            stream=True,
            timeout=(10, self.timeout),
        )
        resp.raise_for_status()
        token_parts: List[str] = []
        for raw_line in resp.iter_lines(decode_unicode=True):
            if (time.perf_counter() - chunk_t0) > self.timeout:
                resp.close()
                raise requests.exceptions.ReadTimeout(f"Exceeded total chunk timeout {self.timeout}s")
            if not raw_line:
                continue
            try:
                evt = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            piece = (evt.get("message") or {}).get("content", "")
            if piece:
                token_parts.append(piece)
            if evt.get("done"):
                break
        return "".join(token_parts)

    def audit_code(
        self,
        source_code: str,
        filename: str,
        tree: Optional[ast.AST] = None,
        max_chunk_lines: int = 180,
    ) -> List[Dict[str, Any]]:
        """
        Gom chunk ứng viên (<= 180 dòng -> 1 request), kiểm tra SHA-256 Cache, gọi Ollama,
        parse linh hoạt và lọc Grounding.
        """
        t0 = time.perf_counter()
        lines = source_code.splitlines()
        candidates = extract_llm_candidates(source_code, tree=tree, max_chunk_lines=max_chunk_lines)
        if not candidates:
            self.last_status = "no_candidates"
            self.last_meta = {
                "status": "no_candidates",
                "reason": "Không có thao tác nhạy cảm cần gửi LLM",
                "model": self.model,
                "timeout_s": self.timeout,
                "llm_time_ms": round((time.perf_counter() - t0) * 1000, 2),
                "llm_findings_count": 0,
                "chunks_sent": 0,
                "cache_hits": 0,
                "skipped_files": 0,
                "raw_llm_preview": "",
                "parsed_count": 0,
                "dropped_reasons": [],
            }
            return []

        verified_raw: List[Dict[str, Any]] = []
        raw_previews: List[str] = []
        total_parsed = 0
        dropped_reasons: List[str] = []
        any_success = False
        had_timeout = False
        had_parse_error = False
        chunks_sent = 0
        cache_hits = 0

        for chunk in candidates:
            ckey = _make_cache_key(self.model, filename, chunk["numbered_code"])
            if self.use_cache:
                cached = _cache_get(ckey)
                if cached is not None:
                    cache_hits += 1
                    any_success = True
                    verified_raw.extend(cached)
                    continue

            chunks_sent += 1
            user_prompt = (
                f"File: {filename} ({chunk['label']})\n"
                f"Audit all lines and return JSON findings:\n\n"
                f"{chunk['numbered_code']}"
            )
            messages = [
                {"role": "system", "content": LLM_SAST_SYSTEM_PROMPT},
                {"role": "user", "content": _ONE_SHOT_USER},
                {"role": "assistant", "content": _ONE_SHOT_ASSISTANT},
                {"role": "user", "content": user_prompt},
            ]
            try:
                content = self._call_ollama_stream(messages)
                raw_previews.append(content[:500])
                parsed, ok = self._parse_llm_json(content)
                if not ok:
                    had_parse_error = True
                    self.last_error = f"JSON parse error on {filename} ({chunk['label']})"
                    logger.warning("[Hybrid-SAST Fallback] %s | raw=%s", self.last_error, content[:300])
                    continue
                any_success = True
                total_parsed += len(parsed)
            except requests.exceptions.Timeout as exc:
                had_timeout = True
                self.last_error = f"Timeout {self.timeout}s"
                logger.warning("[Hybrid-SAST Fallback] Ollama timeout (%ss) khi quét %s: %s", self.timeout, filename, exc)
                continue
            except Exception as exc:
                self.last_error = f"Ollama error: {type(exc).__name__}"
                logger.warning("[Hybrid-SAST Fallback] Lỗi kết nối Ollama khi quét %s: %s", filename, exc)
                continue

            chunk_verified: List[Dict[str, Any]] = []
            valid_lines = chunk.get("valid_lines")
            for item in parsed:
                grounded, drop_reason = self._ground_finding_with_reason(
                    item,
                    lines,
                    chunk["start_line"],
                    chunk["end_line"],
                    valid_lines=valid_lines,
                )
                if grounded:
                    chunk_verified.append(grounded)
                elif drop_reason:
                    dropped_reasons.append(drop_reason)

            verified_raw.extend(chunk_verified)
            if self.use_cache:
                _cache_put(ckey, chunk_verified)

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        if any_success:
            meta_status = "ok"
            meta_reason = ""
            self.last_status = "active"
        elif had_timeout:
            meta_status = "timeout"
            meta_reason = f"Timeout {self.timeout}s"
            self.last_status = "fallback_ast_only"
        elif had_parse_error:
            meta_status = "parse_error"
            meta_reason = "JSON Parse Error"
            self.last_status = "fallback_ast_only"
        else:
            meta_status = "connection_error"
            meta_reason = self.last_error or "Ollama Unreachable"
            self.last_status = "fallback_ast_only"

        raw_preview = " | ".join(raw_previews)[:500]
        self.last_meta = {
            "status": meta_status,
            "reason": meta_reason,
            "model": self.model,
            "timeout_s": self.timeout,
            "llm_time_ms": elapsed_ms,
            "llm_findings_count": len(verified_raw),
            "chunks_sent": chunks_sent,
            "cache_hits": cache_hits,
            "skipped_files": 0,
            "raw_llm_preview": raw_preview,
            "parsed_count": total_parsed,
            "dropped_reasons": dropped_reasons,
        }
        logger.info(
            "[Hybrid-SAST Diagnostic] file=%s status=%s chunks=%d cache_hits=%d parsed=%d kept=%d dropped=%d time=%.0fms preview=%s",
            filename,
            meta_status,
            chunks_sent,
            cache_hits,
            total_parsed,
            len(verified_raw),
            len(dropped_reasons),
            elapsed_ms,
            raw_preview[:200],
        )
        return verified_raw

    def audit_file_batch(
        self,
        files_bundle: List[Tuple[str, str, Optional[ast.AST]]],
        max_batch_lines: int = 180,
        max_files_per_batch: int = 3,
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
        """
        Multi-File Batching + SHA-256 Cache cho quét thư mục:
          - Kiểm tra cache từng file trước -> trả về tức thì các file đã quét.
          - Gom nhiều file nhỏ (tổng dòng sau lược comment <= 180, tối đa 3 file/batch) thành 1 request
            Ollama duy nhất để giảm mạnh chi phí prefill lặp lại.
        """
        t0 = time.perf_counter()
        results_by_file: Dict[str, List[Dict[str, Any]]] = {fname: [] for fname, _, _ in files_bundle}
        if not files_bundle:
            meta = {
                "status": "no_candidates",
                "reason": "",
                "model": self.model,
                "timeout_s": self.timeout,
                "llm_time_ms": 0.0,
                "llm_findings_count": 0,
                "chunks_sent": 0,
                "cache_hits": 0,
                "raw_llm_preview": "",
                "parsed_count": 0,
                "dropped_reasons": [],
            }
            return results_by_file, meta

        cache_hits = 0
        chunks_sent = 0
        total_parsed = 0
        dropped_reasons: List[str] = []
        raw_previews: List[str] = []
        any_success = False
        had_timeout = False
        had_parse_error = False

        # Chuẩn bị compact numbered code & tra cứu cache cho từng file
        small_uncached: List[Dict[str, Any]] = []
        large_uncached: List[Tuple[str, str, Optional[ast.AST]]] = []

        for fname, code, tree in files_bundle:
            lines = code.splitlines()
            cands = extract_llm_candidates(code, tree=tree, max_chunk_lines=max_batch_lines)
            if not cands:
                continue
            if len(cands) == 1:
                ncode = cands[0]["numbered_code"]
                ckey = _make_cache_key(self.model, fname, ncode)
                if self.use_cache:
                    cached = _cache_get(ckey)
                    if cached is not None:
                        cache_hits += 1
                        any_success = True
                        results_by_file[fname] = cached
                        continue
                compact_len = len(ncode.splitlines())
                if compact_len <= max_batch_lines:
                    small_uncached.append({
                        "file": fname,
                        "code": code,
                        "lines": lines,
                        "tree": tree,
                        "numbered_code": ncode,
                        "compact_len": compact_len,
                        "cache_key": ckey,
                        "start_line": cands[0]["start_line"],
                        "end_line": cands[0]["end_line"],
                        "valid_lines": cands[0].get("valid_lines"),
                    })
                else:
                    large_uncached.append((fname, code, tree))
            else:
                large_uncached.append((fname, code, tree))

        # 1. Đóng gói các file nhỏ vào Multi-File Batches (<= max_batch_lines, <= max_files_per_batch)
        batches: List[List[Dict[str, Any]]] = []
        cur_batch: List[Dict[str, Any]] = []
        cur_lines = 0
        for item in small_uncached:
            if cur_batch and (
                cur_lines + item["compact_len"] > max_batch_lines or len(cur_batch) >= max_files_per_batch
            ):
                batches.append(cur_batch)
                cur_batch = []
                cur_lines = 0
            cur_batch.append(item)
            cur_lines += item["compact_len"]
        if cur_batch:
            batches.append(cur_batch)

        for batch in batches:
            if len(batch) == 1:
                # 1 file đơn -> gọi audit_code chuẩn
                it = batch[0]
                f_res = self.audit_code(it["code"], it["file"], tree=it["tree"], max_chunk_lines=max_batch_lines)
                results_by_file[it["file"]] = f_res
                m = self.last_meta
                chunks_sent += int(m.get("chunks_sent", 0))
                cache_hits += int(m.get("cache_hits", 0))
                total_parsed += int(m.get("parsed_count", 0))
                dropped_reasons.extend(m.get("dropped_reasons") or [])
                if m.get("raw_llm_preview"):
                    raw_previews.append(m["raw_llm_preview"])
                if m.get("status") == "ok":
                    any_success = True
                elif m.get("status") == "timeout":
                    had_timeout = True
                elif m.get("status") == "parse_error":
                    had_parse_error = True
                continue

            # Batch nhiều file (2-3 file) trong 1 request duy nhất
            chunks_sent += 1
            sections = [f"=== FILE: {it['file']} ===\n{it['numbered_code']}" for it in batch]
            file_list_str = ", ".join(it["file"] for it in batch)
            batch_prompt = (
                f"Multi-file audit ({file_list_str}). Include exact \"file\" name in each finding object:\n"
                f"{{\"findings\":[{{\"file\":\"name.py\",\"rule_id\":\"AI-SAST-001\",\"line\":10,\"confidence\":0.9,\"reason\":\"5 words\"}}]}}\n\n"
                + "\n\n".join(sections)
            )
            messages = [
                {"role": "system", "content": LLM_SAST_SYSTEM_PROMPT},
                {"role": "user", "content": _ONE_SHOT_USER},
                {"role": "assistant", "content": _ONE_SHOT_ASSISTANT},
                {"role": "user", "content": batch_prompt},
            ]
            try:
                content = self._call_ollama_stream(messages)
                raw_previews.append(content[:500])
                parsed, ok = self._parse_llm_json(content)
                if not ok:
                    had_parse_error = True
                    self.last_error = f"JSON parse error on batch ({file_list_str})"
                    logger.warning("[Hybrid-SAST Fallback] %s | raw=%s", self.last_error, content[:300])
                    continue
                any_success = True
                total_parsed += len(parsed)
            except requests.exceptions.Timeout as exc:
                had_timeout = True
                self.last_error = f"Timeout {self.timeout}s"
                logger.warning("[Hybrid-SAST Fallback] Ollama timeout (%ss) trên batch (%s): %s", self.timeout, file_list_str, exc)
                continue
            except Exception as exc:
                self.last_error = f"Ollama error: {type(exc).__name__}"
                logger.warning("[Hybrid-SAST Fallback] Lỗi kết nối Ollama trên batch (%s): %s", file_list_str, exc)
                continue

            by_exact = {it["file"].replace("\\", "/"): it for it in batch}
            by_base = {Path(it["file"]).name: it for it in batch}
            batch_verified: Dict[str, List[Dict[str, Any]]] = {it["file"]: [] for it in batch}

            for raw_item in parsed:
                raw_f = str(raw_item.get("file") or raw_item.get("filename") or "").strip().replace("\\", "/")
                target_it = by_exact.get(raw_f) or by_base.get(Path(raw_f).name) if raw_f else None
                if target_it is None:
                    # Fallback nếu model quên trường file: thử khớp với file nào có dòng hợp lệ
                    dropped_reasons.append(f"batch_missing_file({raw_item.get('rule_id')})")
                    continue
                grounded, drop_reason = self._ground_finding_with_reason(
                    raw_item,
                    target_it["lines"],
                    target_it["start_line"],
                    target_it["end_line"],
                    valid_lines=target_it.get("valid_lines"),
                )
                if grounded:
                    batch_verified[target_it["file"]].append(grounded)
                elif drop_reason:
                    dropped_reasons.append(f"{target_it['file']}:{drop_reason}")

            for it in batch:
                f_list = batch_verified[it["file"]]
                results_by_file[it["file"]] = f_list
                if self.use_cache:
                    _cache_put(it["cache_key"], f_list)

        # 2. Xử lý các file lớn hơn max_batch_lines bằng audit_code chuẩn
        for fname, code, tree in large_uncached:
            f_res = self.audit_code(code, fname, tree=tree, max_chunk_lines=max_batch_lines)
            results_by_file[fname] = f_res
            m = self.last_meta
            chunks_sent += int(m.get("chunks_sent", 0))
            cache_hits += int(m.get("cache_hits", 0))
            total_parsed += int(m.get("parsed_count", 0))
            dropped_reasons.extend(m.get("dropped_reasons") or [])
            if m.get("raw_llm_preview"):
                raw_previews.append(m["raw_llm_preview"])
            if m.get("status") == "ok":
                any_success = True
            elif m.get("status") == "timeout":
                had_timeout = True
            elif m.get("status") == "parse_error":
                had_parse_error = True

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        total_kept = sum(len(v) for v in results_by_file.values())
        if any_success:
            meta_status = "ok"
            meta_reason = ""
            self.last_status = "active"
        elif had_timeout:
            meta_status = "timeout"
            meta_reason = f"Timeout {self.timeout}s"
            self.last_status = "fallback_ast_only"
        elif had_parse_error:
            meta_status = "parse_error"
            meta_reason = "JSON Parse Error"
            self.last_status = "fallback_ast_only"
        else:
            meta_status = "connection_error"
            meta_reason = self.last_error or "Ollama Unreachable"
            self.last_status = "fallback_ast_only"

        batch_meta = {
            "status": meta_status,
            "reason": meta_reason,
            "model": self.model,
            "timeout_s": self.timeout,
            "llm_time_ms": elapsed_ms,
            "llm_findings_count": total_kept,
            "chunks_sent": chunks_sent,
            "cache_hits": cache_hits,
            "raw_llm_preview": " | ".join(raw_previews)[:500],
            "parsed_count": total_parsed,
            "dropped_reasons": dropped_reasons[:50],
        }
        self.last_meta = batch_meta
        return results_by_file, batch_meta

    @staticmethod
    def _parse_llm_json(content: str) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Parse JSON linh hoạt cho model 8B:
          - Tự gỡ markdown fence ```json ... ``` và trích khối {...} / [...] nếu có ký tự thừa.
          - Chấp nhận khóa danh sách: `findings`, `vulnerabilities`, `issues`, `results`.
          - Nếu trả thẳng 1 JSON object chứa `rule_id`/`rule`/`id` -> tự bọc vào list.
        """
        if not content or not isinstance(content, str):
            return [], False

        cleaned = content.strip()
        fence_m = re.search(r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```", cleaned, re.DOTALL | re.IGNORECASE)
        if fence_m:
            cleaned = fence_m.group(1).strip()

        candidates_str = [cleaned]
        first_brace = cleaned.find("{")
        last_brace = cleaned.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            extracted = cleaned[first_brace:last_brace + 1]
            if extracted != cleaned:
                candidates_str.append(extracted)
        first_br = cleaned.find("[")
        last_br = cleaned.rfind("]")
        if first_br != -1 and last_br > first_br:
            extracted_arr = cleaned[first_br:last_br + 1]
            if extracted_arr not in candidates_str:
                candidates_str.append(extracted_arr)

        for cand in candidates_str:
            try:
                data = json.loads(cand)
            except json.JSONDecodeError:
                continue
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)], True
            if isinstance(data, dict):
                for list_key in ("findings", "vulnerabilities", "issues", "results"):
                    if isinstance(data.get(list_key), list):
                        return [x for x in data[list_key] if isinstance(x, dict)], True
                # Nếu model trả thẳng 1 finding object đơn lẻ
                if any(k in data for k in ("rule_id", "rule", "id")) and any(
                    k in data for k in ("line", "line_number", "lineno")
                ):
                    return [data], True
                # Dict rỗng hợp lệ như {} -> xem là 0 findings
                if not data:
                    return [], True

        return [], False

    def _ground_finding(
        self,
        item: Dict[str, Any],
        lines: List[str],
        chunk_start: int,
        chunk_end: int,
        valid_lines: Optional[set] = None,
    ) -> Optional[Dict[str, Any]]:
        grounded, _ = self._ground_finding_with_reason(item, lines, chunk_start, chunk_end, valid_lines=valid_lines)
        return grounded

    def _ground_finding_with_reason(
        self,
        item: Dict[str, Any],
        lines: List[str],
        chunk_start: int,
        chunk_end: int,
        valid_lines: Optional[set] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Bộ lọc Grounding chống ảo giác kèm lý do loại bỏ:
          - Chuẩn hóa linh hoạt rule_id/rule/id, line/line_number/lineno ("L21" -> 21), confidence.
          - Nếu dòng báo rơi vào comment/trống ngay sát code, tự dịch ±2 dòng tới dòng code gần nhất.
          - Ngưỡng confidence tối thiểu >= self.min_confidence (mặc định 0.65).
        """
        raw_rule = item.get("rule_id") or item.get("rule") or item.get("id")
        rule_id = _normalize_rule_id(raw_rule)
        if rule_id not in VALID_SAST_RULES:
            return None, f"invalid_rule_id({raw_rule!r})"

        raw_line_obj = (
            item.get("line")
            if item.get("line") is not None
            else (item.get("line_number") if item.get("line_number") is not None else item.get("lineno"))
        )
        raw_line_str = re.sub(r"^[Ll]\s*", "", str(raw_line_obj or "0").strip())
        # Hỗ trợ cả dạng "21-23" -> lấy 21
        m_ln = re.match(r"^(\d+)", raw_line_str)
        if not m_ln:
            return None, f"{rule_id}:invalid_line({raw_line_obj!r})"
        line_no = int(m_ln.group(1))

        if line_no < 1 or line_no > len(lines):
            return None, f"{rule_id}:line_out_of_file(L{line_no})"
        if line_no < chunk_start - 2 or line_no > chunk_end + 2:
            return None, f"{rule_id}:line_out_of_chunk(L{line_no})"

        conf = _normalize_confidence(item.get("confidence"))
        if conf < self.min_confidence:
            return None, f"{rule_id}@L{line_no}:low_confidence({conf:.2f}<{self.min_confidence:.2f})"

        # Nếu line rơi vào dòng trống/comment -> dịch ±2 dòng tới dòng code gần nhất
        if _is_comment_or_blank(lines[line_no - 1]):
            snapped = None
            for delta in (1, -1, 2, -2):
                cand_ln = line_no + delta
                if 1 <= cand_ln <= len(lines) and chunk_start <= cand_ln <= chunk_end:
                    if not _is_comment_or_blank(lines[cand_ln - 1]):
                        snapped = cand_ln
                        break
            if snapped is None:
                return None, f"{rule_id}@L{line_no}:comment_or_blank_no_nearby_code"
            line_no = snapped

        if valid_lines is not None and line_no not in valid_lines:
            return None, f"{rule_id}@L{line_no}:not_in_chunk_valid_lines"

        fp_reason = _is_safe_grounded_false_positive(rule_id, line_no, lines)
        if fp_reason:
            return None, f"{rule_id}@L{line_no}:{fp_reason}"

        return (
            {
                "rule_id": rule_id,
                "line": line_no,
                "confidence": conf,
                "reason": str(item.get("reason", "")).strip()[:400],
                "evidence": str(item.get("evidence", "")).strip()[:220],
            },
            None,
        )


def merge_ast_and_llm_findings(
    ast_findings: List[Dict[str, Any]],
    llm_raw_findings: List[Dict[str, Any]],
    filename: str,
    lines: List[str],
    rules_by_id: Dict[str, Dict[str, Any]],
    format_snippet_fn: Callable[[List[str], int, Optional[int]], str],
    model_name: str = "llama3",
) -> List[Dict[str, Any]]:
    """
    Hợp nhất kết quả AST 5 tầng và kết quả LLM Semantic Auditor:
      - Gắn `detection_source = "ast_static"` mặc định cho mọi finding tĩnh.
      - Nếu trùng `(file, rule_id)` trong khoảng cách `<= 5` dòng -> gộp thành 1 finding duy nhất
        và gắn `detection_source = "hybrid_verified"`.
      - Nếu chỉ LLM tìm thấy -> tạo finding chuẩn schema với `detection_source = "llm_semantic"`.
    """
    merged: List[Dict[str, Any]] = []
    for f in ast_findings:
        item = dict(f)
        item.setdefault("detection_source", "ast_static")
        merged.append(item)

    norm_file = filename.replace("\\", "/")

    # Khử trùng lặp nội bộ giữa các finding LLM cùng rule_id cách nhau <= 3 dòng (vd báo cả L15 và L16 cho 1 biến nhiều dòng)
    deduped_llm: List[Dict[str, Any]] = []
    for lf in llm_raw_findings:
        # Ưu tiên giữ dòng khớp được với AST finding (<= 5 dòng) nếu có 2 dòng liền kề cùng rule_id
        dup_idx = next(
            (
                i for i, prev in enumerate(deduped_llm)
                if prev["rule_id"] == lf["rule_id"] and abs(prev["line"] - lf["line"]) <= 3
            ),
            None,
        )
        if dup_idx is None:
            deduped_llm.append(lf)
        else:
            prev = deduped_llm[dup_idx]
            lf_hits_ast = any(
                e.get("file", "").replace("\\", "/") == norm_file
                and e.get("rule_id") == lf["rule_id"]
                and abs(int(e.get("line", 0)) - lf["line"]) <= 5
                for e in merged
            )
            prev_hits_ast = any(
                e.get("file", "").replace("\\", "/") == norm_file
                and e.get("rule_id") == prev["rule_id"]
                and abs(int(e.get("line", 0)) - prev["line"]) <= 5
                for e in merged
            )
            if (lf_hits_ast and not prev_hits_ast) or (lf["confidence"] > prev["confidence"] and lf_hits_ast == prev_hits_ast):
                deduped_llm[dup_idx] = lf

    for lf in deduped_llm:
        rule_id = lf["rule_id"]
        line_no = lf["line"]
        conf = lf["confidence"]
        reason = lf.get("reason", "")

        matched_ast = None
        merge_dist = 8 if rule_id == "AI-SAST-002" else 5
        for existing in merged:
            if (
                existing.get("file", "").replace("\\", "/") == norm_file
                and existing.get("rule_id") == rule_id
                and abs(int(existing.get("line", 0)) - line_no) <= merge_dist
            ):
                matched_ast = existing
                break

        if matched_ast is not None:
            matched_ast["detection_source"] = "hybrid_verified"
            matched_ast["llm_confidence"] = conf
            if reason and "[LLM Verified" not in matched_ast.get("description", ""):
                matched_ast["description"] = (
                    f"{matched_ast['description']} [LLM Verified ({model_name}, conf={conf:.2f}): {reason}]"
                )
            continue

        rule = rules_by_id.get(rule_id)
        if not rule:
            continue
        code_line = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else lf.get("evidence", "")
        ctx_snip = format_snippet_fn(lines, line_no, line_no)
        desc = rule["description"]
        if reason:
            desc = f"{desc} [LLM Semantic Audit ({model_name}, conf={conf:.2f}): {reason}]"
        merged.append({
            "rule_id": rule["rule_id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "risk_score": rule["risk_score"],
            "owasp": rule["owasp"],
            "mitre": rule["mitre"],
            "cwe": rule["cwe"],
            "file": filename,
            "line": line_no,
            "code_line": code_line[:220],
            "context_snippet": ctx_snip,
            "description": desc,
            "remediation": rule["remediation"],
            "fix_example": rule["fix_example"],
            "engine": f"LLM Semantic Auditor ({model_name})",
            "detection_source": "llm_semantic",
            "llm_confidence": conf,
        })

    return merged
