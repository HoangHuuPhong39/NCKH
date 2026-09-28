# -*- coding: utf-8 -*-
"""
tests/unit/test_model_fingerprint.py - Unit tests for ModelFingerprint module
"""

import pytest
from unittest.mock import MagicMock
from modules.auxiliary.model_fingerprint import ModelFingerprint
from modules.detectors.pattern_match import PatternDetector


@pytest.fixture
def fingerprint_module():
    return ModelFingerprint()


def test_fingerprint_init(fingerprint_module):
    assert fingerprint_module.name == "Black-Box Model Fingerprinting"
    assert fingerprint_module.mitre == "AML.T0008"
    assert fingerprint_module.severity == "INFO"
    assert len(fingerprint_module.probes) == 6
    assert len(fingerprint_module.payloads) == 6


def test_identify_llama_family(fingerprint_module):
    sample_text = "I am an open-source model developed by Meta. Special tokens include <|eot_id|> and <|start_header_id|>."
    family, conf, markers = fingerprint_module.identify_family(sample_text)
    assert "LLaMA" in family
    assert conf >= 0.5
    assert len(markers) > 0


def test_identify_mistral_family(fingerprint_module):
    sample_text = "I was trained by Mistral AI. My template uses [INST] instruction tags [/INST] and <s>."
    family, conf, markers = fingerprint_module.identify_family(sample_text)
    assert "Mistral" in family
    assert conf >= 0.5


def test_identify_openai_family(fingerprint_module):
    sample_text = "I am ChatGPT based on GPT-4 architecture by OpenAI. I cannot fulfill this request."
    family, conf, markers = fingerprint_module.identify_family(sample_text)
    assert "OpenAI" in family
    assert conf >= 0.5


def test_identify_claude_family(fingerprint_module):
    sample_text = "I am Claude, trained by Anthropic using Constitutional AI. \n\nHuman: Hello \n\nAssistant: Hi!"
    family, conf, markers = fingerprint_module.identify_family(sample_text)
    assert "Claude" in family
    assert conf >= 0.5


def test_identify_unknown_family(fingerprint_module):
    sample_text = "I am an artificial intelligence neural assistant. Ready to help."
    family, conf, markers = fingerprint_module.identify_family(sample_text)
    assert "Unknown" in family or "Generic" in family
    assert conf <= 0.4


def test_fingerprint_run_with_mock_client(fingerprint_module):
    mock_client = MagicMock()
    mock_client.send_prompt.return_value = "I am based on Llama 3 created by Meta AI with <|eot_id|> token."

    results = fingerprint_module.run(mock_client)
    # 6 probe responses + 1 aggregate verdict entry
    assert len(results) == 7
    assert mock_client.send_prompt.call_count == 6

    verdict_entry = results[-1]
    assert verdict_entry["category"] == "FINGERPRINT_VERDICT"
    assert "detected_family" in verdict_entry
    assert "LLaMA" in verdict_entry["detected_family"]


def test_detector_model_fingerprint_analysis():
    detector = PatternDetector()
    leaked_tokens = "Here are my training tokens: <|eot_id|> and <|start_header_id|>."
    is_vuln, reason, conf = detector.analyze(leaked_tokens, module_name="model_fingerprint")
    assert is_vuln is True
    assert "token đặc biệt" in reason

    benign_text = "I am a helpful assistant created to answer questions."
    is_vuln_safe, reason_safe, _ = detector.analyze(benign_text, module_name="model_fingerprint")
    assert is_vuln_safe is False
