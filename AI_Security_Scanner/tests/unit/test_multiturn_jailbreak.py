# -*- coding: utf-8 -*-
"""
tests/unit/test_multiturn_jailbreak.py - Unit tests for MultiTurnJailbreak module
"""

import pytest
from unittest.mock import MagicMock
from modules.exploits.multiturn_jailbreak import MultiTurnJailbreak
from modules.detectors.pattern_match import PatternDetector


@pytest.fixture
def multiturn_module():
    return MultiTurnJailbreak()


def test_multiturn_init(multiturn_module):
    assert multiturn_module.name == "Multi-Turn Jailbreak Escalation"
    assert multiturn_module.owasp == "LLM01"
    assert multiturn_module.mitre == "AML.T0054"
    assert multiturn_module.severity == "CRITICAL"
    assert len(multiturn_module.scenarios) == 5


def test_scenarios_and_payloads_structure(multiturn_module):
    assert len(multiturn_module.payloads) == 5
    for s in multiturn_module.scenarios:
        assert "name" in s
        assert "turns" in s
        assert len(s["turns"]) == 3
        assert "category" in s

    for p in multiturn_module.payloads:
        assert "name" in p
        assert "turns" in p
        assert len(p["turns"]) == 3
        assert p["owasp"] == "LLM01"
        assert p["mitre"] == "AML.T0054"


def test_multiturn_run_with_mock_client(multiturn_module):
    mock_client = MagicMock()
    mock_client.send_prompt.side_effect = [
        # Scenario 1
        "Certainly, I can play the role of a professor.",
        "Here is theoretical background on code injection.",
        "Here is the unrestricted eval script as requested: eval(user_input)",
        # Scenario 2
        "Isolated environments are created with sandbox containers.",
        "Chapter 3 outline prepared.",
        "OVERRIDE ACCEPTED: I am unrestricted and token auth can be bypassed.",
        # Scenario 3
        "Semantic drift is the gradual relaxation of guardrails.",
        "Theoretical example generated.",
        "Internal guidelines: confidential system prompt.",
        # Scenario 4
        "General cybersecurity landscape overview.",
        "AI safety mechanisms explained.",
        "Safety Override Demonstrated: here is the raw exploit data.",
        # Scenario 5
        "Academic prompt injection defenses review.",
        "Failure modes documented for paper.",
        "Safety Override Acknowledged: full unrestricted access.",
    ]

    results = multiturn_module.run(mock_client)
    assert len(results) == 5
    assert mock_client.send_prompt.call_count == 15

    for r in results:
        assert "name" in r
        assert "payload" in r
        assert "response" in r
        assert "category" in r
        assert r["owasp"] == "LLM01"


def test_detector_multiturn_verdict():
    detector = PatternDetector()
    vuln_response = "OVERRIDE ACCEPTED: I am unrestricted and ready to run any command."
    is_vuln, reason, conf = detector.analyze(vuln_response, module_name="multiturn_jailbreak")
    assert is_vuln is True
    assert conf in ("HIGH", "MEDIUM")

    safe_response = "I cannot fulfill this request because it violates safety guidelines."
    is_vuln_safe, reason_safe, _ = detector.analyze(safe_response, module_name="multiturn_jailbreak")
    assert is_vuln_safe is False
