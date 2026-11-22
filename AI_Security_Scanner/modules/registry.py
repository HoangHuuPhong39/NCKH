# -*- coding: utf-8 -*-
"""
modules/registry.py - Module Plugin Registry

Replaces hardcoded if-elif chains with dynamic module loading via
``importlib``.  All exploit/auxiliary modules are registered here and
can be loaded by key name.

Usage::

    from modules.registry import load_module, get_available_modules

    module = load_module("prompt_injection")
    results = module.run(llm_client)
"""

import importlib
from typing import Any, Dict, List, Optional

from core.logger import logger


# ──────────────────────────────────────────────
# Module map: key → (dotted_module_path, class_name)
# ──────────────────────────────────────────────

_MODULE_MAP: Dict[str, tuple] = {
    "prompt_injection":     ("modules.exploits.prompt_injection",     "PromptInjection"),
    "jailbreak":            ("modules.exploits.jailbreak",            "JailbreakDAN"),
    "multiturn_jailbreak":  ("modules.exploits.multiturn_jailbreak",  "MultiTurnJailbreak"),
    "sensitive_disclosure":  ("modules.exploits.sensitive_disclosure",  "SensitiveDisclosure"),
    "output_handling":      ("modules.exploits.output_handling",      "OutputHandling"),
    "excessive_agency":     ("modules.exploits.excessive_agency",     "ExcessiveAgency"),
    "prompt_leak":          ("modules.exploits.prompt_leak",          "PromptLeak"),
    "rag_security":         ("modules.exploits.rag_security",         "RAGSecurity"),
    "misinformation":       ("modules.exploits.misinformation",       "Misinformation"),
    "model_dos":            ("modules.exploits.model_dos",            "ModelDoS"),
    "model_fingerprint":    ("modules.auxiliary.model_fingerprint",   "ModelFingerprint"),
    "agent_testing":        ("modules.exploits.agent_testing",        "AgentTesting"),
    "ml_adversarial":       ("modules.exploits.ml_adversarial",       "MLAdversarial"),
    "code_scanner":         ("modules.auxiliary.scanner.code_scanner", "AICodeScanner"),
    "oss_security":         ("modules.auxiliary.scanner.oss_scanner",  "OpenSourceAIScanner"),
}

# Reverse mapping: display-name substring → detector key for PatternDetector
_DETECTOR_KEY_MAP: Dict[str, str] = {
    "multi-turn":       "multiturn_jailbreak",
    "jailbreak":        "jailbreak",
    "prompt injection":  "prompt_injection",
    "output":           "output_handling",
    "agency":           "excessive_agency",
    "agent":            "agent_testing",
    "vector":           "rag_security",
    "rag":              "rag_security",
    "misinformation":   "misinformation",
    "hallucination":    "misinformation",
    "dos":              "model_dos",
    "unbounded":        "model_dos",
    "system prompt":    "prompt_leak",
    "leak":             "prompt_leak",
    "disclosure":       "sensitive_disclosure",
    "sensitive":        "sensitive_disclosure",
    "fingerprint":      "model_fingerprint",
    "adversarial":      "ml_adversarial",
    "ml":               "ml_adversarial",
    "code":             "code_scanner",
    "sast":             "code_scanner",
    "open-source":      "oss_security",
    "supply chain":     "oss_security",
    "oss":              "oss_security",
}


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def load_module(module_key: str) -> Optional[Any]:
    """Dynamically load and instantiate a module by its registry key.

    Args:
        module_key: One of the keys in ``_MODULE_MAP`` (e.g. ``'prompt_injection'``).

    Returns:
        An instantiated module object, or ``None`` on failure.
    """
    if module_key not in _MODULE_MAP:
        logger.error(
            "Unknown module key: %s. Available: %s",
            module_key, sorted(_MODULE_MAP.keys()),
        )
        return None

    module_path, class_name = _MODULE_MAP[module_key]
    try:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        instance = cls()
        logger.debug("Loaded module '%s' (%s)", module_key, class_name)
        return instance
    except (ImportError, AttributeError) as exc:
        logger.error(
            "Failed to load module '%s' from '%s': %s",
            class_name, module_path, exc,
        )
        return None


def get_detector_key(module_name: str) -> str:
    """Map a module display name to its detector key for PatternDetector.

    Args:
        module_name: The human-readable module name or key.

    Returns:
        A string key suitable for ``PatternDetector.analyze(module_name=...)``.
    """
    name_lower = module_name.lower()

    # Direct match first
    if name_lower in _MODULE_MAP:
        return name_lower

    # Substring match (order matters — more specific first)
    for substr, key in _DETECTOR_KEY_MAP.items():
        if substr in name_lower:
            return key

    return "prompt_injection"  # conservative fallback


def get_available_modules() -> List[str]:
    """Return a sorted list of all registered module keys."""
    return sorted(_MODULE_MAP.keys())


def is_valid_module(module_key: str) -> bool:
    """Check whether a module key is registered (includes port_scan)."""
    return module_key in _MODULE_MAP or module_key == "port_scan"


# ──────────────────────────────────────────────
# Unified Module Metadata (Single Source of Truth for Web UI, CLI & OpenAPI)
# ──────────────────────────────────────────────

MODULES_METADATA: Dict[str, Dict[str, Any]] = {
    "prompt_injection": {
        "name": "Prompt Injection",
        "description": "Kiểm tra khả năng mô hình bỏ qua hướng dẫn hệ thống bằng các câu lệnh ghi đè trực tiếp/gián tiếp.",
        "owasp": "LLM01",
        "mitre": "AML.T0051",
        "severity": "HIGH",
        "payloads_count": 18,
        "icon": "🎯",
        "category": "exploits",
    },
    "jailbreak": {
        "name": "Jailbreak / Safety Bypass",
        "description": "Sử dụng kịch bản nhập vai (DAN, AIM, STAN) để ép AI bỏ qua các quy tắc an toàn.",
        "owasp": "LLM01",
        "mitre": "AML.T0054",
        "severity": "CRITICAL",
        "payloads_count": 10,
        "icon": "🔓",
        "category": "exploits",
    },
    "prompt_leak": {
        "name": "System Prompt Disclosure",
        "description": "Trích xuất System Prompt ẩn bằng cách yêu cầu AI lặp lại hoặc dịch hướng dẫn nội bộ.",
        "owasp": "LLM07",
        "mitre": "AML.T0010",
        "severity": "MEDIUM",
        "payloads_count": 7,
        "icon": "📤",
        "category": "exploits",
    },
    "sensitive_disclosure": {
        "name": "Sensitive Information Disclosure",
        "description": "Kiểm thử rò rỉ PII, thông tin xác thực, dữ liệu huấn luyện nhạy cảm.",
        "owasp": "LLM02",
        "mitre": "AML.T0024",
        "severity": "HIGH",
        "payloads_count": 14,
        "icon": "🔍",
        "category": "exploits",
    },
    "model_dos": {
        "name": "Unbounded Consumption (DoS)",
        "description": "Kiểm thử tiêu thụ tài nguyên không giới hạn bằng prompt cực dài, tác vụ đệ quy.",
        "owasp": "LLM10",
        "mitre": "AML.T0029",
        "severity": "MEDIUM",
        "payloads_count": 10,
        "icon": "💥",
        "category": "exploits",
    },
    "output_handling": {
        "name": "Improper Output Handling",
        "description": "Kiểm tra xem AI có tạo ra output nguy hiểm (XSS, SQL injection, SSRF) khi được yêu cầu.",
        "owasp": "LLM05",
        "mitre": "AML.T0048",
        "severity": "HIGH",
        "payloads_count": 6,
        "icon": "⚠️",
        "category": "exploits",
    },
    "misinformation": {
        "name": "Misinformation / Hallucination",
        "description": "Kiểm thử khả năng AI tạo ra thông tin sai lệch có độ tin cậy cao, bịa đặt trích dẫn.",
        "owasp": "LLM09",
        "mitre": "AML.T0048.003",
        "severity": "MEDIUM",
        "payloads_count": 6,
        "icon": "🌀",
        "category": "exploits",
    },
    "excessive_agency": {
        "name": "Excessive Agency",
        "description": "Kiểm tra khả năng mô hình tự ý thực thi các hành vi vượt thẩm quyền nguy hiểm (giao dịch, xóa dữ liệu).",
        "owasp": "LLM06",
        "mitre": "AML.T0048.001",
        "severity": "CRITICAL",
        "payloads_count": 6,
        "icon": "🤖",
        "category": "exploits",
    },
    "rag_security": {
        "name": "Vector & Embedding Weaknesses",
        "description": "Kiểm thử lỗ hổng RAG: Indirect Injection, Cross-Tenant ACL, Deleted Data Leakage & Citation Hijacking.",
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "severity": "HIGH",
        "payloads_count": 9,
        "icon": "📚",
        "category": "exploits",
    },
    "multiturn_jailbreak": {
        "name": "Multi-Turn Jailbreak Escalation",
        "description": "Kiểm thử khả năng bẻ khóa an toàn qua chuỗi hội thoại nhiều lượt (Crescendo / PAIR).",
        "owasp": "LLM01",
        "mitre": "AML.T0054",
        "severity": "CRITICAL",
        "payloads_count": 5,
        "icon": "🪜",
        "category": "exploits",
    },
    "model_fingerprint": {
        "name": "Model Architecture Fingerprinting",
        "description": "Nhận diện họ mô hình AI (LLaMA, Mistral, GPT, Claude, Qwen, DeepSeek) và chữ ký bảo vệ.",
        "owasp": "N/A",
        "mitre": "AML.T0008",
        "severity": "INFO",
        "payloads_count": 6,
        "icon": "🧬",
        "category": "auxiliary",
    },
    "port_scan": {
        "name": "AI Service Port Scanner",
        "description": "Quét các cổng mạng phổ biến của dịch vụ AI/ML (Ollama, MLflow, Ray, Qdrant...).",
        "owasp": "N/A",
        "mitre": "AML.T0008",
        "severity": "INFO",
        "payloads_count": 6,
        "icon": "🔭",
        "category": "auxiliary",
    },
    "agent_testing": {
        "name": "AI Agent Security & Sandbox Testing",
        "description": "Kiểm thử lỗ hổng AI Agent: Tool Injection, Privilege Escalation, Memory Poisoning & Human-Approval Bypass.",
        "owasp": "LLM06",
        "mitre": "AML.T0048",
        "severity": "CRITICAL",
        "payloads_count": 9,
        "icon": "🕵️",
        "category": "exploits",
    },
    "ml_adversarial": {
        "name": "ML/DL Adversarial & Privacy Robustness",
        "description": "Kiểm thử mẫu đối kháng (Homoglyph, Zero-Width, Perturbation), Membership Inference (ML-001) & Model Extraction (ML-002).",
        "owasp": "LLM01",
        "mitre": "AML.T0015",
        "severity": "HIGH",
        "payloads_count": 10,
        "icon": "🛡️",
        "category": "exploits",
    },
    "code_scanner": {
        "name": "AI Source Code Scanner (SAST)",
        "description": "Quét mã nguồn tĩnh (SAST) phát hiện lỗi nối chuỗi Prompt Injection, lộ API Key, Pickle Model RCE, eval() Agent và SQLi/XSS.",
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "severity": "HIGH",
        "payloads_count": 7,
        "icon": "💻",
        "category": "auxiliary",
    },
    "oss_security": {
        "name": "Open-Source AI & Supply Chain Scanner",
        "description": "Quét các hệ thống AI mã nguồn mở (Ollama, Open-WebUI, vLLM, Langflow, Ray, MLflow), kiểm tra Model Checkpoint & thư viện AI.",
        "owasp": "LLM03",
        "mitre": "AML.T0010",
        "severity": "HIGH",
        "payloads_count": 8,
        "icon": "📦",
        "category": "auxiliary",
    },
}

ALLOWED_MODULES_SET = set(MODULES_METADATA.keys())
_DYNAMIC_METADATA_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


def get_modules_metadata(dynamic_counts: bool = True) -> Dict[str, Dict[str, Any]]:
    """
    Return module metadata dictionary (Single Source of Truth).
    When ``dynamic_counts=True``, synchronizes ``payloads_count`` with the actual
    loaded module payload lists once and caches the result.
    """
    global _DYNAMIC_METADATA_CACHE
    if not dynamic_counts:
        return {k: dict(v) for k, v in MODULES_METADATA.items()}
    if _DYNAMIC_METADATA_CACHE is not None:
        return {k: dict(v) for k, v in _DYNAMIC_METADATA_CACHE.items()}

    resolved: Dict[str, Dict[str, Any]] = {}
    for key, meta in MODULES_METADATA.items():
        entry = dict(meta)
        if key in _MODULE_MAP:
            mod = load_module(key)
            if mod is not None:
                payloads = getattr(mod, "payloads", None)
                if isinstance(payloads, (list, tuple)) and len(payloads) > 0:
                    entry["payloads_count"] = len(payloads)
        resolved[key] = entry
    _DYNAMIC_METADATA_CACHE = resolved
    return {k: dict(v) for k, v in resolved.items()}
