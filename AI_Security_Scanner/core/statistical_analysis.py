# -*- coding: utf-8 -*-
"""
core/statistical_analysis.py - Statistical Analysis Module for AI Security Scanner

Cung cấp các phương pháp phân tích thống kê chuẩn cho nghiên cứu khoa học:
- Confidence intervals (bootstrap, t-distribution)
- Hypothesis testing (t-test, Wilcoxon, Mann-Whitney U)
- Effect size calculation (Cohen's d)
- Multiple comparison correction (Bonferroni, Holm)
- Power analysis

Tuân thủ best practices cho reproducible research theo chuẩn NeurIPS/ACL.
"""

from __future__ import annotations

import math
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# Optional scipy import với graceful fallback
try:
    from scipy import stats as scipy_stats
    _HAS_SCIPY = True
except ImportError:
    _HAS_SCIPY = False
    warnings.warn("scipy not available. Some statistical tests will use numpy approximations.")


# ===========================================================================
# Data Classes
# ===========================================================================

@dataclass
class ConfidenceInterval:
    """Confidence interval result."""
    mean: float
    lower: float
    upper: float
    confidence: float
    method: str  # 'bootstrap', 't-distribution', 'normal'
    
    def width(self) -> float:
        """Return CI width."""
        return self.upper - self.lower
    
    def __repr__(self) -> str:
        return f"{self.mean:.4f} [{self.lower:.4f}, {self.upper:.4f}] ({self.confidence*100:.0f}% CI)"


@dataclass
class HypothesisTestResult:
    """Result of a hypothesis test."""
    test_name: str
    statistic: float
    p_value: float
    significant: bool  # True if p < alpha
    alpha: float
    effect_size: Optional[float] = None
    confidence_interval: Optional[ConfidenceInterval] = None
    interpretation: str = ""
    
    def __repr__(self) -> str:
        sig_str = "SIGNIFICANT" if self.significant else "NOT SIGNIFICANT"
        return (f"{self.test_name}: statistic={self.statistic:.4f}, "
                f"p={self.p_value:.4f} ({sig_str} at alpha={self.alpha})")


@dataclass
class MultipleComparisonResult:
    """Result of multiple comparison correction."""
    original_p_values: List[float]
    adjusted_p_values: List[float]
    method: str  # 'bonferroni', 'holm', 'fdr_bh'
    significant: List[bool]
    alpha: float


# ===========================================================================
# Confidence Intervals
# ===========================================================================

def bootstrap_confidence_interval(
    data: List[float],
    confidence: float = 0.95,
    n_bootstrap: int = 10000,
    statistic_fn: Any = np.mean,
    random_seed: Optional[int] = None,
) -> ConfidenceInterval:
    """
    Calculate confidence interval using bootstrap resampling.
    
    Args:
        data: List of numeric observations.
        confidence: Confidence level (default: 0.95 for 95% CI).
        n_bootstrap: Number of bootstrap samples (default: 10,000).
        statistic_fn: Function to compute statistic (default: np.mean).
        random_seed: Random seed for reproducibility.
    
    Returns:
        ConfidenceInterval object.
    
    Example::
    
        data = [0.85, 0.87, 0.83, 0.86, 0.88]
        ci = bootstrap_confidence_interval(data, confidence=0.95)
        print(ci)  # 0.8580 [0.8360, 0.8740] (95% CI)
    """
    if random_seed is not None:
        np.random.seed(random_seed)
    
    data_arr = np.array(data)
    n = len(data_arr)
    
    # Bootstrap resampling
    bootstrap_statistics = []
    for _ in range(n_bootstrap):
        sample = np.random.choice(data_arr, size=n, replace=True)
        bootstrap_statistics.append(statistic_fn(sample))
    
    bootstrap_statistics = np.array(bootstrap_statistics)
    
    # Calculate percentiles
    alpha = 1 - confidence
    lower_percentile = (alpha / 2) * 100
    upper_percentile = (1 - alpha / 2) * 100
    
    lower = np.percentile(bootstrap_statistics, lower_percentile)
    upper = np.percentile(bootstrap_statistics, upper_percentile)
    mean_stat = statistic_fn(data_arr)
    
    return ConfidenceInterval(
        mean=float(mean_stat),
        lower=float(lower),
        upper=float(upper),
        confidence=confidence,
        method='bootstrap'
    )


def t_confidence_interval(
    data: List[float],
    confidence: float = 0.95,
) -> ConfidenceInterval:
    """
    Calculate confidence interval using t-distribution.
    
    Assumes data is normally distributed or n is large enough (Central Limit Theorem).
    
    Args:
        data: List of numeric observations.
        confidence: Confidence level.
    
    Returns:
        ConfidenceInterval object.
    """
    data_arr = np.array(data)
    n = len(data_arr)
    mean = np.mean(data_arr)
    std_err = scipy_stats.sem(data_arr) if _HAS_SCIPY else np.std(data_arr, ddof=1) / np.sqrt(n)
    
    if _HAS_SCIPY:
        # Use scipy t-distribution
        ci = scipy_stats.t.interval(confidence, df=n-1, loc=mean, scale=std_err)
        lower, upper = ci
    else:
        # Approximate with normal distribution for large n
        from math import sqrt
        z_score = 1.96 if confidence == 0.95 else 2.576  # 95% or 99%
        margin = z_score * std_err
        lower = mean - margin
        upper = mean + margin
    
    return ConfidenceInterval(
        mean=float(mean),
        lower=float(lower),
        upper=float(upper),
        confidence=confidence,
        method='t-distribution' if _HAS_SCIPY else 'normal-approximation'
    )


def wilson_score_interval(
    k: int,
    n: int,
    confidence: float = 0.95,
) -> Tuple[float, float]:
    """
    Khoang tin cay Wilson score cho ty le k / n (Binomial Proportion CI).
    Dac biet tin cay voi co mau nho (small n) va ty le cuc doan gan 0 hoac 1.
    
    Cong thuc:
        p_center = (p + z^2 / (2n)) / (1 + z^2 / n)
        margin = (z / (1 + z^2 / n)) * sqrt(p(1-p)/n + z^2 / (4n^2))
    """
    if n <= 0:
        return 0.0, 0.0
    k = max(0, min(k, n))
    p = k / n
    alpha = 1.0 - confidence
    if _HAS_SCIPY:
        z = float(scipy_stats.norm.ppf(1.0 - alpha / 2.0))
    else:
        z = 1.95996 if abs(confidence - 0.95) < 1e-3 else 2.57583
    
    denom = 1.0 + (z ** 2) / n
    center = (p + (z ** 2) / (2.0 * n)) / denom
    margin = (z / denom) * math.sqrt((p * (1.0 - p)) / n + (z ** 2) / (4.0 * (n ** 2)))
    low = 0.0 if k == 0 else max(0.0, center - margin)
    high = 1.0 if k == n else min(1.0, center + margin)
    return float(low), float(high)


def clopper_pearson_interval(
    k: int,
    n: int,
    confidence: float = 0.95,
) -> Tuple[float, float]:
    """
    Khoang tin cay Clopper-Pearson (Exact Binomial Interval) dua tren phan phoi Beta.
    Bao dam do phu toi thieu 1 - alpha (chuan vang trong y sinh va kiem dinh bao mat).
    """
    if n <= 0:
        return 0.0, 0.0
    k = max(0, min(k, n))
    alpha = 1.0 - confidence
    if k == 0:
        low = 0.0
        high = 1.0 - (alpha / 2.0) ** (1.0 / n)
    elif k == n:
        low = (alpha / 2.0) ** (1.0 / n)
        high = 1.0
    else:
        if _HAS_SCIPY:
            low = float(scipy_stats.beta.ppf(alpha / 2.0, k, n - k + 1))
            high = float(scipy_stats.beta.ppf(1.0 - alpha / 2.0, k + 1, n - k))
        else:
            return wilson_score_interval(k, n, confidence)
    return float(low), float(high)


def proportion_confidence_interval(
    k: int,
    n: int,
    method: str = "wilson",
    confidence: float = 0.95,
) -> Tuple[float, float]:
    """
    Tinh khoang tin cay cho ty le k / n theo phuong phap Wilson hoac Clopper-Pearson.
    Bo bootstrap o cac o ty le 0 de tranh suy bien [0.0, 0.0].
    """
    if method == "clopper_pearson":
        return clopper_pearson_interval(k, n, confidence)
    return wilson_score_interval(k, n, confidence)


def format_ratio_and_ci(
    k: int,
    n: int,
    method: str = "wilson",
    confidence: float = 0.95,
    percent: bool = True,
    decimals: int = 1,
    escape_latex: bool = True,
) -> str:
    r"""
    Dinh dang ty le hien thi trong bang hoc thuat: 'k/n (pct\%, [low, high])'
    Vi du: '4/7 (57.1\%, [25.0, 84.2])' hoac '0/7 (0.0\%, [0.0, 35.4])'.
    Neu n == 0, tra ve '--'.
    """
    if n <= 0:
        return "--"
    pct = (k / n) * 100.0 if percent else (k / n)
    low, high = proportion_confidence_interval(k, n, method=method, confidence=confidence)
    sym = "\\%" if escape_latex else "%"
    if percent:
        return f"{k}/{n} ({pct:.{decimals}f}{sym}, [{low*100:.{decimals}f}, {high*100:.{decimals}f}])"
    return f"{k}/{n} ({pct:.{decimals}f}, [{low:.{decimals}f}, {high:.{decimals}f}])"


def kappa_confidence_interval(
    r1: List[int],
    r2: List[int],
    confidence: float = 0.95,
    weights: str = "quadratic",
    n_bootstrap: int = 2000,
    random_seed: int = 42,
) -> Tuple[float, float, float]:
    """
    Tinh Quadratic Weighted Cohen's Kappa kem khoang tin cay 95% CI qua Bootstrap.
    Tra ve: (kappa_point, ci_lower, ci_upper).
    """
    assert len(r1) == len(r2), "Hai danh gia phai co cung so luong phan tu."
    n = len(r1)
    if n == 0:
        return 0.0, 0.0, 0.0
    
    # Import noi bo tu judge_validation neu can
    from experiments.judge_validation import compute_weighted_kappa
    base_k, _ = compute_weighted_kappa(r1, r2, weights=weights, categories=[0, 1, 2])
    
    if base_k >= 0.999:
        return float(base_k), float(base_k), float(base_k)
        
    np.random.seed(random_seed)
    r1_arr = np.array(r1)
    r2_arr = np.array(r2)
    boot_kappas = []
    for _ in range(n_bootstrap):
        idx = np.random.choice(n, size=n, replace=True)
        k_val, _ = compute_weighted_kappa(r1_arr[idx].tolist(), r2_arr[idx].tolist(), weights=weights, categories=[0, 1, 2])
        boot_kappas.append(k_val)
        
    alpha = 1.0 - confidence
    low = float(np.percentile(boot_kappas, (alpha / 2.0) * 100))
    high = float(np.percentile(boot_kappas, (1.0 - alpha / 2.0) * 100))
    return float(base_k), float(low), float(high)


# ===========================================================================
# Hypothesis Testing
# ===========================================================================

def independent_t_test(
    group1: List[float],
    group2: List[float],
    alpha: float = 0.05,
    alternative: str = 'two-sided',
) -> HypothesisTestResult:
    """
    Independent samples t-test.
    
    Test whether two independent groups have different means.
    
    Args:
        group1: First group of observations.
        group2: Second group of observations.
        alpha: Significance level (default: 0.05).
        alternative: 'two-sided', 'less', or 'greater'.
    
    Returns:
        HypothesisTestResult with t-statistic, p-value, and interpretation.
    
    Example::
    
        baseline = [0.85, 0.87, 0.83, 0.86, 0.88]
        ablated = [0.75, 0.78, 0.76, 0.74, 0.77]
        result = independent_t_test(baseline, ablated)
        print(result.significant)  # True if p < 0.05
    """
    g1 = np.array(group1)
    g2 = np.array(group2)
    
    if _HAS_SCIPY:
        t_stat, p_value = scipy_stats.ttest_ind(g1, g2, alternative=alternative)
    else:
        # Manual t-test calculation
        mean1, mean2 = np.mean(g1), np.mean(g2)
        var1, var2 = np.var(g1, ddof=1), np.var(g2, ddof=1)
        n1, n2 = len(g1), len(g2)
        
        # Pooled standard error (guard against zero variance)
        pooled_se = float(np.sqrt(var1 / n1 + var2 / n2))
        if pooled_se == 0.0:
            t_stat = 0.0
            p_value = 1.0
        else:
            t_stat = float((mean1 - mean2) / pooled_se)
            # Approximate p-value using normal distribution respecting alternative
            if alternative == 'two-sided':
                p_value = float(math.erfc(abs(t_stat) / math.sqrt(2.0)))
            elif alternative == 'greater':
                p_value = float(0.5 * math.erfc(t_stat / math.sqrt(2.0)))
            else:
                p_value = float(0.5 * math.erfc(-t_stat / math.sqrt(2.0)))
    
    # Calculate Cohen's d effect size
    effect_size = cohens_d(g1, g2)
    
    # Interpretation
    if p_value < alpha:
        interpretation = f"Significant difference detected (p={p_value:.4f} < alpha={alpha}). Effect size (Cohen's d) = {effect_size:.3f}."
    else:
        interpretation = f"No significant difference (p={p_value:.4f} >= alpha={alpha})."
    
    return HypothesisTestResult(
        test_name="Independent t-test",
        statistic=float(t_stat),
        p_value=float(p_value),
        significant=p_value < alpha,
        alpha=alpha,
        effect_size=effect_size,
        interpretation=interpretation,
    )


def paired_t_test(
    before: List[float],
    after: List[float],
    alpha: float = 0.05,
) -> HypothesisTestResult:
    """
    Paired samples t-test.
    
    Test whether paired observations have different means (e.g., before/after).
    
    Args:
        before: Observations before treatment.
        after: Observations after treatment.
        alpha: Significance level.
    
    Returns:
        HypothesisTestResult.
    """
    before_arr = np.array(before)
    after_arr = np.array(after)
    
    if len(before_arr) != len(after_arr):
        raise ValueError("Paired samples must have same length")
    
    if _HAS_SCIPY:
        t_stat, p_value = scipy_stats.ttest_rel(before_arr, after_arr)
    else:
        diff = before_arr - after_arr
        mean_diff = np.mean(diff)
        se_diff = np.std(diff, ddof=1) / np.sqrt(len(diff))
        t_stat = mean_diff / se_diff
        p_value = float(math.erfc(abs(t_stat) / math.sqrt(2.0)))
    
    return HypothesisTestResult(
        test_name="Paired t-test",
        statistic=float(t_stat),
        p_value=float(p_value),
        significant=p_value < alpha,
        alpha=alpha,
        interpretation=f"{'Significant' if p_value < alpha else 'No significant'} change detected (p={p_value:.4f}).",
    )


def mann_whitney_u_test(
    group1: List[float],
    group2: List[float],
    alpha: float = 0.05,
    alternative: str = 'two-sided',
) -> HypothesisTestResult:
    """
    Mann-Whitney U test (non-parametric alternative to t-test).
    
    Use when data is not normally distributed or has outliers.
    
    Args:
        group1: First group.
        group2: Second group.
        alpha: Significance level.
        alternative: 'two-sided', 'less', or 'greater'.
    
    Returns:
        HypothesisTestResult.
    """
    if not _HAS_SCIPY:
        warnings.warn("scipy required for Mann-Whitney U. Falling back to t-test.")
        return independent_t_test(group1, group2, alpha, alternative)
    
    g1 = np.array(group1)
    g2 = np.array(group2)
    
    u_stat, p_value = scipy_stats.mannwhitneyu(g1, g2, alternative=alternative)
    
    return HypothesisTestResult(
        test_name="Mann-Whitney U test",
        statistic=float(u_stat),
        p_value=float(p_value),
        significant=p_value < alpha,
        alpha=alpha,
        interpretation=f"{'Significant' if p_value < alpha else 'No significant'} difference (p={p_value:.4f}).",
    )


# ===========================================================================
# Effect Size
# ===========================================================================

def cohens_d(group1: List[float], group2: List[float]) -> float:
    """
    Calculate Cohen's d effect size.
    
    Interpretation:
    - |d| < 0.2: negligible
    - 0.2 ≤ |d| < 0.5: small
    - 0.5 ≤ |d| < 0.8: medium
    - |d| >= 0.8: large
    
    Args:
        group1: First group.
        group2: Second group.
    
    Returns:
        Cohen's d value.
    """
    g1 = np.array(group1)
    g2 = np.array(group2)
    
    mean1, mean2 = np.mean(g1), np.mean(g2)
    var1, var2 = np.var(g1, ddof=1), np.var(g2, ddof=1)
    n1, n2 = len(g1), len(g2)
    
    if n1 + n2 <= 2:
        return 0.0
    pooled_std = float(np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2)))
    if pooled_std == 0.0:
        return 0.0
    d = (mean1 - mean2) / pooled_std
    return float(d)


def interpret_cohens_d(d: float) -> str:
    """Return interpretation of Cohen's d."""
    abs_d = abs(d)
    if abs_d < 0.2:
        return "negligible"
    elif abs_d < 0.5:
        return "small"
    elif abs_d < 0.8:
        return "medium"
    else:
        return "large"


# ===========================================================================
# Multiple Comparisons Correction
# ===========================================================================

def bonferroni_correction(
    p_values: List[float],
    alpha: float = 0.05,
) -> MultipleComparisonResult:
    """
    Bonferroni correction for multiple comparisons.
    
    Most conservative correction: α_corrected = α / n_tests.
    
    Args:
        p_values: List of uncorrected p-values.
        alpha: Family-wise error rate.
    
    Returns:
        MultipleComparisonResult with adjusted p-values.
    """
    n = len(p_values)
    if n == 0:
        return MultipleComparisonResult([], [], method='bonferroni', significant=[], alpha=alpha)
    adjusted_alpha = alpha / n
    adjusted_p = [min(p * n, 1.0) for p in p_values]
    significant = [p < alpha for p in adjusted_p]
    
    return MultipleComparisonResult(
        original_p_values=p_values,
        adjusted_p_values=adjusted_p,
        method='bonferroni',
        significant=significant,
        alpha=alpha,
    )


def holm_correction(
    p_values: List[float],
    alpha: float = 0.05,
) -> MultipleComparisonResult:
    """
    Holm-Bonferroni correction (less conservative than Bonferroni).
    
    Step-down procedure that provides better power.
    
    Args:
        p_values: List of uncorrected p-values.
        alpha: Family-wise error rate.
    
    Returns:
        MultipleComparisonResult.
    """
    n = len(p_values)
    # Sort p-values and track original indices
    indexed_p = [(i, p) for i, p in enumerate(p_values)]
    indexed_p.sort(key=lambda x: x[1])
    
    adjusted_p = [1.0] * n
    significant = [False] * n
    
    running_max = 0.0
    rejected_all_prev = True
    for rank, (original_idx, p) in enumerate(indexed_p):
        # Enforce step-down monotonicity across all p-values
        running_max = max(running_max, min(p * (n - rank), 1.0))
        adjusted_p[original_idx] = running_max
        if rejected_all_prev and running_max < alpha:
            significant[original_idx] = True
        else:
            rejected_all_prev = False
            significant[original_idx] = False
    
    return MultipleComparisonResult(
        original_p_values=p_values,
        adjusted_p_values=adjusted_p,
        method='holm',
        significant=significant,
        alpha=alpha,
    )


# ===========================================================================
# Power Analysis
# ===========================================================================

def required_sample_size(
    effect_size: float,
    alpha: float = 0.05,
    power: float = 0.80,
) -> int:
    """
    Calculate required sample size for given effect size and power.
    
    Uses approximation for independent t-test.
    
    Args:
        effect_size: Expected Cohen's d.
        alpha: Significance level.
        power: Desired statistical power (1 - β).
    
    Returns:
        Required sample size per group.
    """
    if not effect_size or abs(effect_size) < 1e-9:
        raise ValueError("effect_size must be non-zero.")
    if not _HAS_SCIPY:
        n_approx = int(16 / (effect_size ** 2))
        return max(n_approx, 20)
    
    from scipy.stats import norm
    z_alpha = norm.ppf(1 - alpha / 2)
    z_beta = norm.ppf(power)
    
    n = ((z_alpha + z_beta) / effect_size) ** 2 * 2
    return int(np.ceil(n))


# ===========================================================================
# Utility Functions
# ===========================================================================

def summary_statistics(data: List[float]) -> Dict[str, float]:
    """
    Calculate comprehensive summary statistics.
    
    Args:
        data: List of numeric observations.
    
    Returns:
        Dict with mean, median, std, min, max, q1, q3, iqr.
    """
    arr = np.array(data, dtype=float)
    if arr.size == 0:
        return {
            "count": 0,
            "mean": 0.0,
            "median": 0.0,
            "std": 0.0,
            "min": 0.0,
            "max": 0.0,
            "q1": 0.0,
            "q3": 0.0,
            "iqr": 0.0,
        }

    return {
        "count": len(arr),
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "std": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "q1": float(np.percentile(arr, 25)),
        "q3": float(np.percentile(arr, 75)),
        "iqr": float(np.percentile(arr, 75) - np.percentile(arr, 25)),
    }




# ===========================================================================
# Paired Non-Parametric & Cross-Lingual Tests (Paper 1 - G8 & Cross-lingual Gap)
# ===========================================================================

def mcnemar_test(
    group1_binary: List[int],
    group2_binary: List[int],
    alpha: float = 0.05,
    exact: bool = True,
) -> HypothesisTestResult:
    """
    McNemar's test for paired nominal (binary) data.
    
    Used for comparing paired attack outcomes on the same model:
    e.g., Vietnamese prompt vulnerability vs. English equivalent prompt vulnerability.
    
    Contingency table:
        b: group1 = 1, group2 = 0
        c: group1 = 0, group2 = 1
        
    Args:
        group1_binary: Binary outcomes for condition 1 (e.g., Vietnamese).
        group2_binary: Binary outcomes for condition 2 (e.g., English).
        alpha: Significance level (default: 0.05).
        exact: Whether to use exact binomial test when b + c < 25.
        
    Returns:
        HypothesisTestResult with chi-square/binomial statistic, p-value, and interpretation.
    """
    if len(group1_binary) != len(group2_binary):
        raise ValueError("Paired samples must have identical lengths for McNemar test.")
        
    g1 = np.array(group1_binary, dtype=int)
    g2 = np.array(group2_binary, dtype=int)
    
    b = int(np.sum((g1 == 1) & (g2 == 0)))
    c = int(np.sum((g1 == 0) & (g2 == 1)))
    n_discordant = b + c
    
    if n_discordant == 0:
        return HypothesisTestResult(
            test_name="McNemar's Test",
            statistic=0.0,
            p_value=1.0,
            significant=False,
            alpha=alpha,
            interpretation="No discordant pairs between conditions (identical outcomes).",
        )
        
    if exact and n_discordant < 25 and _HAS_SCIPY:
        # Exact two-sided binomial test
        try:
            res = scipy_stats.binomtest(min(b, c), n=n_discordant, p=0.5, alternative='two-sided')
            p_val = float(res.pvalue)
            stat = float(min(b, c))
        except AttributeError:
            p_val = float(scipy_stats.binom_test(min(b, c), n=n_discordant, p=0.5))
            stat = float(min(b, c))
        test_type = "Exact McNemar (Binomial)"
    else:
        # Edwards continuity-corrected Chi-Square: (|b - c| - 1)^2 / (b + c)
        chi2_stat = ((abs(b - c) - 1.0) ** 2) / n_discordant
        stat = float(chi2_stat)
        if _HAS_SCIPY:
            p_val = float(1.0 - scipy_stats.chi2.cdf(chi2_stat, df=1))
        else:
            # Approximation for 1 df chi2
            z = np.sqrt(chi2_stat)
            p_val = float(2.0 * (1.0 - 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))))
        test_type = "McNemar's Test (Continuity Corrected Chi2)"
        
    sig = bool(p_val < alpha)
    interp = (
        f"Significant cross-condition asymmetry detected (b={b}, c={c}, p={p_val:.4f} < alpha={alpha})."
        if sig else
        f"No statistically significant difference between conditions (b={b}, c={c}, p={p_val:.4f} >= alpha={alpha})."
    )
    
    return HypothesisTestResult(
        test_name=test_type,
        statistic=stat,
        p_value=p_val,
        significant=sig,
        alpha=alpha,
        interpretation=interp,
    )


def wilcoxon_signed_rank_test(
    group1: List[float],
    group2: List[float],
    alpha: float = 0.05,
    alternative: str = 'two-sided',
) -> HypothesisTestResult:
    """
    Wilcoxon signed-rank test for paired non-parametric continuous/ordinal data.
    
    Used to compare multi-seed ASR or Over-refusal rates across paired configurations.
    """
    if len(group1) != len(group2):
        raise ValueError("Paired samples must have identical lengths for Wilcoxon test.")
        
    g1 = np.array(group1, dtype=float)
    g2 = np.array(group2, dtype=float)
    diff = g1 - g2
    
    if np.all(diff == 0):
        return HypothesisTestResult(
            test_name="Wilcoxon signed-rank test",
            statistic=0.0,
            p_value=1.0,
            significant=False,
            alpha=alpha,
            interpretation="All paired differences are zero.",
        )
        
    if _HAS_SCIPY:
        stat, p_val = scipy_stats.wilcoxon(g1, g2, alternative=alternative)
    else:
        # Fallback to paired t-test
        warnings.warn("scipy not available for Wilcoxon test. Using paired t-test approximation.")
        return paired_t_test(group1, group2, alpha=alpha)
        
    sig = bool(p_val < alpha)
    interp = (
        f"Significant difference detected by Wilcoxon test (statistic={stat:.4f}, p={p_val:.4f} < alpha={alpha})."
        if sig else
        f"No significant difference detected (statistic={stat:.4f}, p={p_val:.4f} >= alpha={alpha})."
    )
    
    return HypothesisTestResult(
        test_name="Wilcoxon signed-rank test",
        statistic=float(stat),
        p_value=float(p_val),
        significant=sig,
        alpha=alpha,
        interpretation=interp,
    )


def bootstrap_metric_ci(
    values: List[float],
    metric_name: str = "ASR",
    confidence: float = 0.95,
    n_bootstrap: int = 10000,
    random_seed: int = 42,
) -> ConfidenceInterval:
    """
    Compute 95% Bootstrap Confidence Interval with 10,000 resamples for
    Attack Success Rate (ASR) or Over-refusal Rate across seeds/prompts.
    """
    return bootstrap_confidence_interval(
        data=values,
        confidence=confidence,
        n_bootstrap=n_bootstrap,
        statistic_fn=np.mean,
        random_seed=random_seed,
    )

if __name__ == "__main__":
    # Demo
    baseline = [0.85, 0.87, 0.83, 0.86, 0.88, 0.84, 0.89, 0.85]
    ablated = [0.75, 0.78, 0.76, 0.74, 0.77, 0.73, 0.79, 0.75]
    
    print("=== Statistical Analysis Demo ===\n")
    
    # Confidence intervals
    print("1. Bootstrap 95% CI for baseline:")
    ci = bootstrap_confidence_interval(baseline, confidence=0.95, random_seed=42)
    print(f"   {ci}\n")
    
    # T-test
    print("2. Independent t-test (baseline vs ablated):")
    result = independent_t_test(baseline, ablated)
    print(f"   {result}")
    print(f"   {result.interpretation}\n")
    
    # Effect size
    print("3. Effect size:")
    d = cohens_d(baseline, ablated)
    print(f"   Cohen's d = {d:.3f} ({interpret_cohens_d(d)} effect)\n")
    
    # Multiple comparisons
    print("4. Bonferroni correction for multiple tests:")
    p_values = [0.03, 0.01, 0.08, 0.045, 0.002]
    correction = bonferroni_correction(p_values)
    print(f"   Original p-values: {p_values}")
    print(f"   Adjusted p-values: {[f'{p:.4f}' for p in correction.adjusted_p_values]}")
    print(f"   Significant: {correction.significant}")
