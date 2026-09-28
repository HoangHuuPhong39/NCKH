# -*- coding: utf-8 -*-
"""
tests/unit/test_owasp_mapper.py - Unit tests for OWASPMapper
"""

import pytest
from core.owasp_mapper import OWASPMapper, _MODULE_TO_OWASP


@pytest.fixture
def mapper():
    return OWASPMapper()


def test_mapper_init(mapper):
    assert mapper is not None
    assert len(mapper._by_owasp) > 0


def test_all_modules_mapped():
    expected_modules = [
        "prompt_injection", "jailbreak", "sensitive_disclosure",
        "output_handling", "excessive_agency", "prompt_leak",
        "rag_security", "misinformation", "model_dos", "port_scan",
    ]
    for mod in expected_modules:
        assert mod in _MODULE_TO_OWASP


def test_get_category_info(mapper):
    info_llm01 = mapper.get_category_info("LLM01")
    assert info_llm01 is not None
    assert "Prompt Injection" in info_llm01["name"]

    info_llm08 = mapper.get_category_info("LLM08")
    assert info_llm08 is not None
    assert "Vector" in info_llm08["name"] or "RAG" in info_llm08["name"]


def test_get_remediation(mapper):
    remediation_steps = mapper.get_remediation("LLM01")
    assert isinstance(remediation_steps, list)
    assert len(remediation_steps) > 0


def test_format_finding_description(mapper):
    desc = mapper.format_finding_description("jailbreak", "CRITICAL")
    assert isinstance(desc, str)
    assert "LLM01" in desc
