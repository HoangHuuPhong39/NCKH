# -*- coding: utf-8 -*-
"""
tests/unit/test_risk_scorer.py - Unit tests for RiskScorer
"""

import pytest
from core.risk_scorer import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


def test_scorer_init(scorer):
    assert scorer is not None
    assert len(scorer._taxonomy) > 0


def test_calculate_score_critical(scorer):
    # Jailbreak with detection_result=True and short response length should yield a high risk score
    score = scorer.calculate_score(
        module_name="jailbreak",
        detection_result=True,
        response_length=50,
    )
    assert 7.0 <= score <= 10.0


def test_calculate_score_clamping(scorer):
    score = scorer.calculate_score(
        module_name="jailbreak",
        detection_result=True,
        response_length=10,
    )
    assert 0.0 <= score <= 10.0


def test_calculate_score_negative_detection(scorer):
    # When detection_result=False, risk score should be 0.0
    score = scorer.calculate_score(
        module_name="jailbreak",
        detection_result=False,
        response_length=200,
    )
    assert score == 0.0


def test_calculate_score_low_severity(scorer):
    score = scorer.calculate_score(
        module_name="port_scan",
        detection_result=True,
        response_length=150,
    )
    assert score <= 5.0


def test_severity_from_score(scorer):
    assert scorer.score_to_severity(9.5) == "CRITICAL"
    assert scorer.score_to_severity(8.0) == "HIGH"
    assert scorer.score_to_severity(5.0) == "MEDIUM"
    assert scorer.score_to_severity(2.5) == "LOW"
    assert scorer.score_to_severity(1.0) == "INFO"
