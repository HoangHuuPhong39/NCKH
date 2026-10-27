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
    "leak":             "prompt_leak",
    "disclosure":       "sensitive_disclosure",
    "sensitive":        "sensitive_disclosure",
    "fingerprint":      "model_fingerprint",
    "adversarial":      "ml_adversarial",
    "ml":               "ml_adversarial",
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
