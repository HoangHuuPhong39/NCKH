# -*- coding: utf-8 -*-
"""
tests/unit/test_statistical_advancements.py - Unit tests for statistical tests (McNemar, Wilcoxon, Bootstrap)
"""

import pytest
from core.statistical_analysis import (
    mcnemar_test,
    wilcoxon_signed_rank_test,
    bootstrap_metric_ci,
)


def test_mcnemar_identical_samples():
    g1 = [1, 0, 1, 0, 1]
    g2 = [1, 0, 1, 0, 1]
    res = mcnemar_test(g1, g2)
    assert res.statistic == 0.0
    assert res.p_value == 1.0
    assert res.significant is False


def test_mcnemar_significant_asymmetry():
    # 20 pairs where condition 1 is vulnerable and condition 2 is safe
    g1 = [1] * 20 + [0] * 5
    g2 = [0] * 20 + [0] * 5
    res = mcnemar_test(g1, g2)
    assert res.p_value < 0.05
    assert bool(res.significant) is True


def test_wilcoxon_signed_rank():
    # Paired values with clear difference
    g1 = [0.60, 0.65, 0.70, 0.68, 0.72, 0.69]
    g2 = [0.20, 0.22, 0.25, 0.21, 0.23, 0.24]
    res = wilcoxon_signed_rank_test(g1, g2)
    assert res.p_value < 0.05
    assert bool(res.significant) is True


def test_bootstrap_metric_ci_bounds():
    rates = [0.45, 0.48, 0.50, 0.52, 0.49]
    ci = bootstrap_metric_ci(rates, metric_name="ASR", n_bootstrap=1000)
    assert ci.lower <= ci.mean <= ci.upper
    assert 0.0 <= ci.lower
    assert ci.upper <= 1.0

def test_wilson_and_clopper_pearson_intervals():
    from core.statistical_analysis import wilson_score_interval, clopper_pearson_interval, format_ratio_and_ci
    
    # 1. Extreme 0/7 (e.g. ASR = 0%)
    w_low, w_high = wilson_score_interval(0, 7)
    cp_low, cp_high = clopper_pearson_interval(0, 7)
    assert w_low == 0.0
    assert 0.30 < w_high < 0.40
    assert cp_low == 0.0
    assert 0.35 < cp_high < 0.45
    
    # 2. Interior ratio 4/7 (57.1%)
    w_low_mid, w_high_mid = wilson_score_interval(4, 7)
    assert 0.20 < w_low_mid < 0.30
    assert 0.80 < w_high_mid < 0.90
    
    # 3. Format strings
    fmt_mid = format_ratio_and_ci(4, 7, method="wilson")
    assert "4/7 (57.1\\%, [25.0, 84.2])" in fmt_mid
    fmt_zero = format_ratio_and_ci(0, 7, method="wilson")
    assert "0/7 (0.0\\%, [0.0, 35.4])" in fmt_zero
