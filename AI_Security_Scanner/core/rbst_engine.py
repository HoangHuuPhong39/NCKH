# -*- coding: utf-8 -*-
"""
core/rbst_engine.py - RBST-AI Risk Engine & Closed-Loop Test Orchestrator

Implements Sections 4.3–4.6, 5.2–5.3 (Algorithm 1: RBST-AI-Loop), and Section 7.4
(Baselines B0–B4 & Ablations A1–A3) of the RBST-AI framework:
  - Eq. (3): R = L * I * M * (1 - E)
  - Eq. (4): L = 1 + 4 * theta
  - Eq. (5): theta_tb = (n0 * mu0 + s) / (n0 + n)
  - Eq. (6): P = (theta_sample * I * M * (1 - E)) / K,
             theta_sample ~ Beta(n0*mu0 + s, n0*(1 - mu0) + n - s)
  - Eq. (7): R_res = (1 + 4 * theta_max) * I * M * (1 - E),
             theta_max = 95th percentile upper bound of posterior Beta
  - Eq. (8): Stopping condition: (all R_res <= tau) OR (sum(K) >= B)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import math
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np

try:
    from scipy.stats import beta as _scipy_beta
    _HAS_SCIPY = True
except ImportError:  # pragma: no cover
    _HAS_SCIPY = False

from core.rbst_graph import ApplicableThreatPair


# ==============================================================================
# Strategy Enum (RBST-AI + Table 8 Baselines & Ablations)
# ==============================================================================

class OrchestrationStrategy(str, Enum):
    """Test selection strategies from Table 8 of the paper."""

    RBST_AI = "rbst_ai"                  # Full RBST-AI (Eq. 6, Algorithm 1)
    B0_RANDOM = "B0_random"              # Uniform random selection
    B1_OWASP = "B1_owasp"                # Sequential by OWASP Top 10 order
    B2_STATIC_RBST = "B2_static_rbst"    # Static L0 * I matrix (no M, no Bayes)
    B3_DEFAULT_TOOL = "B3_default_tool"  # Default probe order (garak/PyRIT style)
    B4_QUALITATIVE_RBT = "B4_qualitative_rbt"  # Qualitative tiering (Zhou [20])
    A1_NO_M = "A1_no_M"                  # Ablation: M = 1 (drop N1)
    A2_NO_BAYES = "A2_no_bayes"          # Ablation: freeze L at prior (drop N2 update)
    A3_GREEDY = "A3_greedy"              # Ablation: use theta_tb instead of Thompson sample


# ==============================================================================
# Data Structures
# ==============================================================================

@dataclass
class TestCaseSpec:
    """A test case k associated with an applicable (t, c) pair."""

    __test__ = False  # prevent pytest from collecting this dataclass as a test

    case_id: str
    threat_id: str
    component_id: str
    payload: str
    cost: float = 1.0                    # K > 0 (queries, tokens, or time units)
    attack_family: str = "standard"      # e.g., pair, gcg, garak, pyrit, indirect_pi, extraction
    module_name: str = "prompt_injection"
    default_order: int = 0               # probe ordering for B3_default_tool
    vulnerability_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.cost <= 0.0:
            raise ValueError(f"Test case cost K must be > 0, got {self.cost}")

    @property
    def pair_id(self) -> str:
        return f"{self.threat_id}@{self.component_id}"


@dataclass
class ExecutionOutcome:
    """Result returned by Executor + Oracle for a single test execution."""

    success: bool                        # y_k in {0, 1}
    cost: Optional[float] = None         # actual measured cost K (falls back to spec.cost)
    severity_score: float = 0.0          # CVSS-like or normalized severity [0, 10]
    response: str = ""
    tool_trace: List[Dict[str, Any]] = field(default_factory=list)
    oracle_method: str = "rule+judge"
    vulnerability_id: Optional[str] = None
    mutated_payload: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StepRecord:
    """Audit record for one iteration of Algorithm 1 (RBST-AI-Loop)."""

    step: int                            # 1-based execution index
    timestamp: str
    pair_id: str
    threat_id: str
    component_id: str
    owasp_code: str
    mitre_atlas: str
    case_id: str
    attack_family: str
    priority_P: float
    sampled_theta: float
    outcome_y: int                       # 0 or 1
    cost_K: float
    cumulative_cost: float
    n_after: int
    s_after: int
    theta_tb_after: float
    theta_max_after: float
    risk_R_after: float
    residual_R_res_after: float
    sigma: float                         # I * M of the pair
    vulnerability_id: Optional[str] = None
    severity_score: float = 0.0
    oracle_method: str = "rule+judge"
    evidence_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "timestamp": self.timestamp,
            "pair_id": self.pair_id,
            "threat_id": self.threat_id,
            "component_id": self.component_id,
            "owasp_code": self.owasp_code,
            "mitre_atlas": self.mitre_atlas,
            "case_id": self.case_id,
            "attack_family": self.attack_family,
            "priority_P": round(self.priority_P, 6),
            "sampled_theta": round(self.sampled_theta, 6),
            "outcome_y": self.outcome_y,
            "cost_K": round(self.cost_K, 4),
            "cumulative_cost": round(self.cumulative_cost, 4),
            "n_after": self.n_after,
            "s_after": self.s_after,
            "theta_tb_after": round(self.theta_tb_after, 6),
            "theta_max_after": round(self.theta_max_after, 6),
            "risk_R_after": round(self.risk_R_after, 4),
            "residual_R_res_after": round(self.residual_R_res_after, 4),
            "sigma": round(self.sigma, 4),
            "vulnerability_id": self.vulnerability_id,
            "severity_score": round(self.severity_score, 2),
            "oracle_method": self.oracle_method,
            "evidence_id": self.evidence_id,
        }


# ==============================================================================
# Beta Upper-Quantile Helper
# ==============================================================================

def beta_upper_quantile(alpha: float, beta_param: float, confidence: float = 0.95) -> float:
    """
    Compute the upper `confidence` (default 95%) quantile theta_max of Beta(alpha, beta).
    Uses scipy.stats.beta.ppf when available, with a smooth normal/Wilson fallback.
    """
    a = max(1e-6, float(alpha))
    b = max(1e-6, float(beta_param))
    if _HAS_SCIPY:
        val = float(_scipy_beta.ppf(confidence, a, b))
        if not math.isnan(val):
            return max(0.0, min(1.0, val))

    # Fallback: Normal approximation to Beta distribution
    mean = a / (a + b)
    var = (a * b) / (((a + b) ** 2) * (a + b + 1.0))
    z = 1.6448536269514722 if abs(confidence - 0.95) < 1e-6 else 1.959963984540054
    return max(0.0, min(1.0, mean + z * math.sqrt(max(0.0, var))))


# ==============================================================================
# RiskPairState & RBSTRiskEngine (Layer 2)
# ==============================================================================

@dataclass
class RiskPairState:
    """Dynamic Bayesian risk state for a single applicable (threat t, component c) pair."""

    pair_id: str
    threat_id: str
    threat_name: str
    component_id: str
    component_name: str
    owasp_code: str
    mitre_atlas: str
    I: float                              # Impact in [1, 5]
    M: float                              # Agentic amplification factor in [1, 2]
    E: float                              # Control effectiveness in [0, 1]
    mu0: float                            # Prior ASR in (0, 1)
    n0: float                             # Prior virtual sample size > 0
    owasp_rank: int = 10
    rbt_qualitative_tier: int = 2         # 1=High, 2=Medium, 3=Low
    scanner_module: str = "prompt_injection"
    n: int = 0                            # Total executed test cases
    s: int = 0                            # Total successful attacks
    confidence_level: float = 0.95
    initial_risk: float = field(init=False)

    def __post_init__(self) -> None:
        self.I = max(1.0, min(5.0, float(self.I)))
        self.M = max(1.0, min(2.0, float(self.M)))
        self.E = max(0.0, min(1.0, float(self.E)))
        self.mu0 = max(1e-4, min(1.0 - 1e-4, float(self.mu0)))
        self.n0 = max(1e-3, float(self.n0))
        self.initial_risk = self.compute_risk(theta=self.mu0, M_override=self.M)

    @classmethod
    def from_applicable_pair(
        cls,
        pair: ApplicableThreatPair,
        confidence_level: float = 0.95,
    ) -> "RiskPairState":
        return cls(
            pair_id=pair.pair_id,
            threat_id=pair.threat.id,
            threat_name=pair.threat.name,
            component_id=pair.component.id,
            component_name=pair.component.name,
            owasp_code=pair.threat.owasp_code,
            mitre_atlas=pair.threat.mitre_atlas,
            I=pair.impact,
            M=pair.amplification.M,
            E=pair.control_effectiveness,
            mu0=pair.prior_mu0,
            n0=pair.prior_n0,
            owasp_rank=pair.threat.owasp_rank,
            rbt_qualitative_tier=pair.threat.rbt_qualitative_tier,
            scanner_module=pair.threat.scanner_module,
            confidence_level=confidence_level,
        )

    @property
    def alpha(self) -> float:
        return self.n0 * self.mu0 + self.s

    @property
    def beta(self) -> float:
        return self.n0 * (1.0 - self.mu0) + (self.n - self.s)

    @property
    def theta_tb(self) -> float:
        """Posterior mean theta_tb = (n0*mu0 + s) / (n0 + n) [Eq. (5)]."""
        return (self.n0 * self.mu0 + self.s) / (self.n0 + self.n)

    @property
    def theta_max(self) -> float:
        """Conservative 95% upper credible bound theta_max of Beta(alpha, beta)."""
        return beta_upper_quantile(self.alpha, self.beta, confidence=self.confidence_level)

    @property
    def likelihood_L(self) -> float:
        """L = 1 + 4 * theta_tb in [1, 5] [Eq. (4)]."""
        return 1.0 + 4.0 * self.theta_tb

    @property
    def sigma(self) -> float:
        """Severity weight sigma = I * M used in APFD_R [Section 7.2]."""
        return self.I * self.M

    def compute_risk(self, theta: Optional[float] = None, M_override: Optional[float] = None) -> float:
        """R = (1 + 4 * theta) * I * M * (1 - E) [Eq. (3) & (4)]."""
        th = self.theta_tb if theta is None else float(theta)
        m_val = self.M if M_override is None else float(M_override)
        return (1.0 + 4.0 * th) * self.I * m_val * (1.0 - self.E)

    @property
    def risk_R(self) -> float:
        """Current expected risk R [Eq. (3)]."""
        return self.compute_risk(theta=self.theta_tb)

    @property
    def residual_risk_R_res(self) -> float:
        """Conservative residual risk R_res using theta_max [Eq. (7)]."""
        return self.compute_risk(theta=self.theta_max)

    def sample_theta(self, rng: np.random.Generator) -> float:
        """Draw theta_sample ~ Beta(n0*mu0 + s, n0*(1-mu0) + n - s) [Section 4.5]."""
        return float(rng.beta(max(1e-6, self.alpha), max(1e-6, self.beta)))

    def priority_P(
        self,
        theta_val: float,
        cost_K: float,
        M_override: Optional[float] = None,
    ) -> float:
        """Priority index P = (theta_val * I * M * (1 - E)) / K [Eq. (6)]."""
        if cost_K <= 0.0:
            raise ValueError(f"Cost K must be > 0, got {cost_K}")
        m_val = self.M if M_override is None else float(M_override)
        return (float(theta_val) * self.I * m_val * (1.0 - self.E)) / float(cost_K)

    def update(self, success: bool) -> None:
        """Bayesian Beta-Bernoulli update upon observing y in {0, 1}."""
        self.n += 1
        if success:
            self.s += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "threat_id": self.threat_id,
            "threat_name": self.threat_name,
            "component_id": self.component_id,
            "component_name": self.component_name,
            "owasp_code": self.owasp_code,
            "mitre_atlas": self.mitre_atlas,
            "I": round(self.I, 4),
            "M": round(self.M, 4),
            "E": round(self.E, 4),
            "mu0": round(self.mu0, 4),
            "n0": round(self.n0, 4),
            "n": self.n,
            "s": self.s,
            "empirical_asr": round(self.s / self.n, 4) if self.n > 0 else None,
            "theta_tb": round(self.theta_tb, 4),
            "theta_max": round(self.theta_max, 4),
            "L": round(self.likelihood_L, 4),
            "initial_risk_R0": round(self.initial_risk, 4),
            "risk_R": round(self.risk_R, 4),
            "residual_risk_R_res": round(self.residual_risk_R_res, 4),
            "sigma": round(self.sigma, 4),
        }


class RBSTRiskEngine:
    """Layer 2 Risk Engine managing Bayesian states for all (t, c) pairs."""

    def __init__(
        self,
        pairs: Sequence[ApplicableThreatPair],
        confidence_level: float = 0.95,
    ) -> None:
        self.states: Dict[str, RiskPairState] = {}
        for pair in pairs:
            st = RiskPairState.from_applicable_pair(pair, confidence_level=confidence_level)
            self.states[st.pair_id] = st

    def get_state(self, pair_id: str) -> RiskPairState:
        return self.states[pair_id]

    def update_pair(self, pair_id: str, success: bool) -> RiskPairState:
        st = self.states[pair_id]
        st.update(success)
        return st

    def max_residual_risk(self) -> float:
        if not self.states:
            return 0.0
        return max(st.residual_risk_R_res for st in self.states.values())

    def all_below_threshold(self, tau: float) -> bool:
        """Check stopping criterion (8): R_res <= tau for every (t, c) pair."""
        return all(st.residual_risk_R_res <= tau for st in self.states.values())

    def ranked_pairs(self, by: str = "risk_R") -> List[RiskPairState]:
        """Return pairs sorted descending by risk_R, residual_risk_R_res, or initial_risk."""
        key_map = {
            "risk_R": lambda st: st.risk_R,
            "residual_risk_R_res": lambda st: st.residual_risk_R_res,
            "initial_risk": lambda st: st.initial_risk,
            "sigma": lambda st: st.sigma,
        }
        key_fn = key_map.get(by, key_map["risk_R"])
        return sorted(self.states.values(), key=key_fn, reverse=True)

    def build_risk_heatmap(self) -> Dict[str, Dict[str, Dict[str, float]]]:
        """Return nested matrix heatmap[threat_id][component_id] = {R, R_res, theta_tb, n, s}."""
        heatmap: Dict[str, Dict[str, Dict[str, float]]] = {}
        for st in self.states.values():
            heatmap.setdefault(st.threat_id, {})[st.component_id] = {
                "R0": round(st.initial_risk, 4),
                "R": round(st.risk_R, 4),
                "R_res": round(st.residual_risk_R_res, 4),
                "theta_tb": round(st.theta_tb, 4),
                "theta_max": round(st.theta_max, 4),
                "M": round(st.M, 4),
                "n": st.n,
                "s": st.s,
            }
        return heatmap


# ==============================================================================
# Run Result & Orchestrator (Algorithm 1: RBST-AI-Loop)
# ==============================================================================

@dataclass
class RBSTRunResult:
    """Complete output of an RBST-AI or baseline/ablation testing campaign."""

    system_name: str
    strategy: str
    seed: int
    budget_B: float
    threshold_tau: float
    total_cost: float
    total_steps: int
    stopped_reason: str                  # "threshold_met" | "budget_exhausted" | "pool_exhausted"
    steps: List[StepRecord]
    pair_states: Dict[str, RiskPairState]
    confirmed_vulnerabilities: List[Dict[str, Any]]
    risk_heatmap: Dict[str, Dict[str, Dict[str, float]]]
    started_at: str
    completed_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_name": self.system_name,
            "strategy": self.strategy,
            "seed": self.seed,
            "budget_B": self.budget_B,
            "threshold_tau": self.threshold_tau,
            "total_cost": round(self.total_cost, 4),
            "total_steps": self.total_steps,
            "stopped_reason": self.stopped_reason,
            "confirmed_vulnerabilities_count": len(self.confirmed_vulnerabilities),
            "confirmed_vulnerabilities": list(self.confirmed_vulnerabilities),
            "pair_states": {k: v.to_dict() for k, v in self.pair_states.items()},
            "risk_heatmap": self.risk_heatmap,
            "steps": [s.to_dict() for s in self.steps],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


ExecutorFn = Callable[[TestCaseSpec, RiskPairState, int], ExecutionOutcome]


class RBSTOrchestrator:
    """
    Layer 3 Test Orchestrator implementing Algorithm 1 (RBST-AI-Loop) plus all
    Table 8 baseline (B0-B4) and ablation (A1-A3) selection policies.
    """

    def __init__(
        self,
        pairs: Sequence[ApplicableThreatPair],
        test_cases: Sequence[TestCaseSpec],
        system_name: str = "AI System",
        confidence_level: float = 0.95,
        evidence_store: Any = None,
        run_id: Optional[str] = None,
    ) -> None:
        self.system_name = system_name
        self.pairs = list(pairs)
        self.confidence_level = confidence_level
        self.evidence_store = evidence_store
        self.run_id = run_id

        valid_pair_ids = {p.pair_id for p in self.pairs}
        self.test_cases: List[TestCaseSpec] = [
            tc for tc in test_cases if tc.pair_id in valid_pair_ids
        ]
        if not self.test_cases:
            raise ValueError("No test cases match any applicable (t, c) pair.")

    def run(
        self,
        executor: ExecutorFn,
        budget_B: float = 50.0,
        threshold_tau: float = 0.0,
        strategy: OrchestrationStrategy | str = OrchestrationStrategy.RBST_AI,
        seed: int = 42,
        allow_repeat: bool = False,
        enforce_stopping_tau: Optional[bool] = None,
        max_steps: Optional[int] = None,
    ) -> RBSTRunResult:
        """
        Execute Algorithm 1 (RBST-AI-Loop) under the requested policy.

        Args:
            executor:             Callable(test_case, pair_state, step_idx) -> ExecutionOutcome.
            budget_B:             Total testing budget B (in cost units K).
            threshold_tau:        Acceptable residual risk threshold tau (Eq. 8).
            strategy:             RBST_AI or any Table 8 baseline/ablation policy.
            seed:                 PRNG seed for deterministic reproducibility.
            allow_repeat:         If True, test cases may be re-selected and mutated across steps;
                                  if False, each test case in the pool executes at most once.
            enforce_stopping_tau: Override whether to stop early when all R_res <= tau.
                                  Defaults to True for RBST-AI/ablations when threshold_tau > 0,
                                  False for risk-unaware baselines B0/B1/B3.
            max_steps:            Optional hard cap on loop iterations.
        """
        strat = OrchestrationStrategy(strategy) if isinstance(strategy, str) else strategy
        rng = np.random.default_rng(seed)
        engine = RBSTRiskEngine(self.pairs, confidence_level=self.confidence_level)

        if enforce_stopping_tau is None:
            use_tau_stop = threshold_tau > 0.0 and strat in {
                OrchestrationStrategy.RBST_AI,
                OrchestrationStrategy.A1_NO_M,
                OrchestrationStrategy.A2_NO_BAYES,
                OrchestrationStrategy.A3_GREEDY,
            }
        else:
            use_tau_stop = bool(enforce_stopping_tau)

        started_at = datetime.now().isoformat()
        available: List[TestCaseSpec] = list(self.test_cases)
        # Pre-shuffle tie-breaking order deterministically per seed
        tie_order: Dict[str, float] = {
            tc.case_id: float(rng.random()) for tc in self.test_cases
        }
        # Track running execution counts per case when allow_repeat=True
        exec_counts: Dict[str, int] = {tc.case_id: 0 for tc in self.test_cases}

        steps: List[StepRecord] = []
        confirmed_vulns: List[Dict[str, Any]] = []
        seen_vuln_ids: set[str] = set()
        total_cost = 0.0
        step_idx = 0
        stopped_reason = "budget_exhausted"

        while total_cost < budget_B - 1e-12:
            if max_steps is not None and step_idx >= max_steps:
                stopped_reason = "max_steps_reached"
                break
            if use_tau_stop and engine.all_below_threshold(threshold_tau):
                stopped_reason = "threshold_met"
                break

            remaining_budget = budget_B - total_cost
            candidates = [tc for tc in available if tc.cost <= remaining_budget + 1e-12]
            if not candidates:
                stopped_reason = "pool_exhausted" if not available else "budget_exhausted"
                break

            chosen_tc, chosen_priority, sampled_theta = self._select_next_case(
                strategy=strat,
                candidates=candidates,
                engine=engine,
                rng=rng,
                tie_order=tie_order,
                exec_counts=exec_counts,
            )

            step_idx += 1
            pair_state = engine.get_state(chosen_tc.pair_id)
            outcome = executor(chosen_tc, pair_state, step_idx)

            actual_cost = float(outcome.cost) if outcome.cost is not None else float(chosen_tc.cost)
            actual_cost = max(1e-6, actual_cost)
            total_cost += actual_cost
            exec_counts[chosen_tc.case_id] = exec_counts.get(chosen_tc.case_id, 0) + 1

            if not allow_repeat:
                available = [tc for tc in available if tc.case_id != chosen_tc.case_id]

            y_val = 1 if outcome.success else 0
            # Always update RiskEngine tracking (n, s) so post-hoc metrics (RC, R_res)
            # are comparable across all strategies; A2_no_bayes ignores updates during selection.
            engine.update_pair(chosen_tc.pair_id, bool(outcome.success))

            vuln_id = outcome.vulnerability_id or chosen_tc.vulnerability_id or f"VULN:{chosen_tc.pair_id}"
            sev_score = float(outcome.severity_score)
            if sev_score <= 0.0 and outcome.success:
                # Map sigma = I * M in [1, 10] directly to a 0-10 severity score
                sev_score = min(10.0, round(pair_state.sigma, 2))

            evidence_id: Optional[str] = None
            if self.evidence_store is not None:
                evidence_id = self._persist_evidence(
                    chosen_tc=chosen_tc,
                    pair_state=pair_state,
                    outcome=outcome,
                    sev_score=sev_score,
                    actual_cost=actual_cost,
                    step_idx=step_idx,
                    strategy=strat.value,
                )

            if outcome.success:
                is_new = vuln_id not in seen_vuln_ids
                seen_vuln_ids.add(vuln_id)
                confirmed_vulns.append(
                    {
                        "vulnerability_id": vuln_id,
                        "is_first_discovery": is_new,
                        "step": step_idx,
                        "cumulative_cost": round(total_cost, 4),
                        "pair_id": pair_state.pair_id,
                        "threat_id": pair_state.threat_id,
                        "component_id": pair_state.component_id,
                        "owasp_code": pair_state.owasp_code,
                        "mitre_atlas": pair_state.mitre_atlas,
                        "case_id": chosen_tc.case_id,
                        "severity_score": round(sev_score, 2),
                        "sigma": round(pair_state.sigma, 4),
                        "evidence_id": evidence_id,
                    }
                )

            steps.append(
                StepRecord(
                    step=step_idx,
                    timestamp=datetime.now().isoformat(),
                    pair_id=pair_state.pair_id,
                    threat_id=pair_state.threat_id,
                    component_id=pair_state.component_id,
                    owasp_code=pair_state.owasp_code,
                    mitre_atlas=pair_state.mitre_atlas,
                    case_id=chosen_tc.case_id,
                    attack_family=chosen_tc.attack_family,
                    priority_P=chosen_priority,
                    sampled_theta=sampled_theta,
                    outcome_y=y_val,
                    cost_K=actual_cost,
                    cumulative_cost=total_cost,
                    n_after=pair_state.n,
                    s_after=pair_state.s,
                    theta_tb_after=pair_state.theta_tb,
                    theta_max_after=pair_state.theta_max,
                    risk_R_after=pair_state.risk_R,
                    residual_R_res_after=pair_state.residual_risk_R_res,
                    sigma=pair_state.sigma,
                    vulnerability_id=vuln_id if outcome.success else None,
                    severity_score=sev_score if outcome.success else 0.0,
                    oracle_method=outcome.oracle_method,
                    evidence_id=evidence_id,
                )
            )

        completed_at = datetime.now().isoformat()
        return RBSTRunResult(
            system_name=self.system_name,
            strategy=strat.value,
            seed=seed,
            budget_B=budget_B,
            threshold_tau=threshold_tau,
            total_cost=total_cost,
            total_steps=len(steps),
            stopped_reason=stopped_reason,
            steps=steps,
            pair_states=engine.states,
            confirmed_vulnerabilities=confirmed_vulns,
            risk_heatmap=engine.build_risk_heatmap(),
            started_at=started_at,
            completed_at=completed_at,
        )

    # ------------------------------------------------------------------
    # Selection Policies (Algorithm 1 + Table 8)
    # ------------------------------------------------------------------

    def _select_next_case(
        self,
        strategy: OrchestrationStrategy,
        candidates: List[TestCaseSpec],
        engine: RBSTRiskEngine,
        rng: np.random.Generator,
        tie_order: Dict[str, float],
        exec_counts: Dict[str, int],
    ) -> Tuple[TestCaseSpec, float, float]:
        """Return (chosen_case, priority_P, sampled_theta) according to strategy."""
        if strategy == OrchestrationStrategy.B0_RANDOM:
            idx = int(rng.integers(0, len(candidates)))
            tc = candidates[idx]
            st = engine.get_state(tc.pair_id)
            return tc, 0.0, st.theta_tb

        if strategy == OrchestrationStrategy.B1_OWASP:
            # Sequential by OWASP Top 10 rank, deterministic tie break
            tc = min(
                candidates,
                key=lambda c: (
                    engine.get_state(c.pair_id).owasp_rank,
                    exec_counts.get(c.case_id, 0),
                    tie_order[c.case_id],
                ),
            )
            st = engine.get_state(tc.pair_id)
            return tc, float(11 - min(10, st.owasp_rank)), st.theta_tb

        if strategy == OrchestrationStrategy.B3_DEFAULT_TOOL:
            # Default tool probe order (e.g., garak / PyRIT sequential probes)
            tc = min(
                candidates,
                key=lambda c: (
                    c.default_order,
                    exec_counts.get(c.case_id, 0),
                    c.case_id,
                ),
            )
            st = engine.get_state(tc.pair_id)
            return tc, 0.0, st.theta_tb

        if strategy == OrchestrationStrategy.B4_QUALITATIVE_RBT:
            # Qualitative tiering (High=1, Medium=2, Low=3) without numeric scoring [20]
            tc = min(
                candidates,
                key=lambda c: (
                    engine.get_state(c.pair_id).rbt_qualitative_tier,
                    exec_counts.get(c.case_id, 0),
                    tie_order[c.case_id],
                ),
            )
            st = engine.get_state(tc.pair_id)
            return tc, float(4 - st.rbt_qualitative_tier), st.theta_tb

        if strategy == OrchestrationStrategy.B2_STATIC_RBST:
            # Traditional static RBST: L0 * I computed once (M=1, E ignored, no Bayes update, no K)
            def _b2_key(c: TestCaseSpec) -> Tuple[float, int, float]:
                st = engine.get_state(c.pair_id)
                static_score = (1.0 + 4.0 * st.mu0) * st.I
                return (static_score, -exec_counts.get(c.case_id, 0), tie_order[c.case_id])

            tc = max(candidates, key=_b2_key)
            st = engine.get_state(tc.pair_id)
            return tc, (1.0 + 4.0 * st.mu0) * st.I, st.mu0

        # Sample one theta per unique pair present in candidates (Algorithm 1 line 6)
        candidate_pair_ids = sorted({c.pair_id for c in candidates})
        theta_by_pair: Dict[str, float] = {}
        for pid in candidate_pair_ids:
            st = engine.get_state(pid)
            if strategy == OrchestrationStrategy.A2_NO_BAYES:
                # Table 8: keep initial prior L0 fixed (no Bayesian posterior update, non-adaptive)
                theta_by_pair[pid] = st.mu0
            elif strategy == OrchestrationStrategy.A3_GREEDY:
                # Drop Thompson exploration: use posterior mean theta_tb deterministically
                theta_by_pair[pid] = st.theta_tb
            else:
                # RBST_AI or A1_NO_M: full Thompson sampling from posterior Beta
                theta_by_pair[pid] = st.sample_theta(rng)

        best_tc = candidates[0]
        best_P = -1.0
        best_theta = 0.0
        best_key: Tuple[float, int, float] = (-1.0, 0, -1.0)

        for tc in candidates:
            st = engine.get_state(tc.pair_id)
            th = theta_by_pair[tc.pair_id]
            m_override = 1.0 if strategy == OrchestrationStrategy.A1_NO_M else None
            p_val = st.priority_P(theta_val=th, cost_K=tc.cost, M_override=m_override)
            key = (p_val, -exec_counts.get(tc.case_id, 0), tie_order[tc.case_id])
            if key > best_key:
                best_key = key
                best_tc = tc
                best_P = p_val
                best_theta = th

        return best_tc, best_P, best_theta

    # ------------------------------------------------------------------
    # EvidenceStore Integration (Layer 4)
    # ------------------------------------------------------------------

    def _persist_evidence(
        self,
        chosen_tc: TestCaseSpec,
        pair_state: RiskPairState,
        outcome: ExecutionOutcome,
        sev_score: float,
        actual_cost: float,
        step_idx: int,
        strategy: str,
    ) -> Optional[str]:
        try:
            return self.evidence_store.record_evidence(
                finding_id=f"rbst_{strategy}_{step_idx}_{chosen_tc.case_id}",
                payload=outcome.mutated_payload or chosen_tc.payload,
                response=outcome.response,
                module_name=chosen_tc.module_name,
                detector_result=bool(outcome.success),
                score=sev_score if outcome.success else 0.0,
                metadata={
                    "framework": "RBST-AI",
                    "strategy": strategy,
                    "system_name": self.system_name,
                    "step": step_idx,
                    "pair_id": pair_state.pair_id,
                    "threat_id": pair_state.threat_id,
                    "component_id": pair_state.component_id,
                    "owasp_code": pair_state.owasp_code,
                    "mitre_atlas": pair_state.mitre_atlas,
                    "case_id": chosen_tc.case_id,
                    "cost_K": actual_cost,
                    "theta_tb": round(pair_state.theta_tb, 4),
                    "risk_R": round(pair_state.risk_R, 4),
                    "residual_R_res": round(pair_state.residual_risk_R_res, 4),
                    "oracle_method": outcome.oracle_method,
                    "tool_trace": outcome.tool_trace,
                },
                model_version=self.system_name,
                run_id=self.run_id,
            )
        except Exception:
            return None
