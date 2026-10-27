# -*- coding: utf-8 -*-
"""
tests/unit/test_registry.py - Unit tests for Module Plugin Registry
"""

import pytest
from modules.registry import load_module, get_detector_key, get_available_modules, is_valid_module


def test_registry_get_available_modules():
    mods = get_available_modules()
    assert isinstance(mods, list)
    assert len(mods) >= 10
    assert "prompt_injection" in mods
    assert "jailbreak" in mods
    assert "multiturn_jailbreak" in mods
    assert "rag_security" in mods


def test_registry_load_module_success():
    mod = load_module("prompt_injection")
    assert mod is not None
    assert hasattr(mod, "run")
    assert hasattr(mod, "payloads")
    assert len(mod.payloads) > 0


def test_registry_load_module_invalid():
    mod = load_module("non_existent_exploit")
    assert mod is None


def test_registry_detector_key_mapping():
    assert get_detector_key("Jailbreak & Safety Bypass") == "jailbreak"
    assert get_detector_key("Multi-Turn Jailbreak Escalation") == "multiturn_jailbreak"
    assert get_detector_key("Prompt Injection (LLM01)") == "prompt_injection"
    assert get_detector_key("Vector & Embedding Weaknesses") == "rag_security"
    assert get_detector_key("Excessive Agency") == "excessive_agency"


def test_registry_is_valid_module():
    assert is_valid_module("prompt_injection") is True
    assert is_valid_module("port_scan") is True
    assert is_valid_module("malicious_injection") is False
