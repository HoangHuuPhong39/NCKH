# -*- coding: utf-8 -*-
"""
tests/test_rbst_core.py - Unit & Integration Tests for the RBST-AI Core Layer

Verifies:
  - Eqs. (1)-(2): SystemGraph S=(C,D), trust boundaries, transitive privilege propagation a2,
                  amplification factor M in [1, 2], CS1-CS4 relative M ordering (Table 6).
  - Eqs. (3)-(8): Risk formula R, likelihood L, Beta-Bernoulli Bayesian posterior theta_tb,
                  95% conservative upper bound theta_max & R_res, Thompson Sampling priority P,
                  dual stopping criteria (tau & budget B), all 9 Table 8 policies.
  - Eqs. (9)-(10): APFD_R (including exact equivalence to classic APFD when weights are equal),
                   Risk Coverage RC, Cost to First Critical CF, Recall, Spearman rho, Cohen's kappa.
  - Layer 4 & Integration: EvidenceStore persistence, Compliance Reporter (Table 5),
                           LiveScannerExecutor + CS2 AgentSandbox, and CLI `--rbst`.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.evidence_store import EvidenceStore
from core.rbst_adapter import (
    EmpiricalCalibrationExecutor,
    LiveScannerExecutor,
    build_pipeline_for_case_study,
    create_cs2_agent_sandbox,
    default_ground_truth_for_case_study,
    load_case_study_graph,
)
from core.rbst_engine import (
    ExecutionOutcome,
    OrchestrationStrategy,
    RBSTOrchestrator,
    RBSTRiskEngine,
    RiskPairState,
    StepRecord,
    TestCaseSpec,
)
from core.rbst_graph import (
    AttackerModel,
    ComponentNode,
    ComponentType,
    PrivilegeLevel,
    RBSTThreatModeler,
    SystemGraph,
    validate_weights,
)
from core.rbst_metrics import (
    RBSTComplianceReporter,
    calculate_apfd_r,
    calculate_cohens_kappa,
    calculate_cost_to_first_critical,
    calculate_residual_spearman,
    calculate_risk_coverage,
    evaluate_run,
)


# ==============================================================================
# 1. Context Profiler, Graph S=(C,D) & Amplification Factor M [Eq. (1)-(2)]
# ==============================================================================

def test_graph_privilege_propagation_and_trust_boundaries():
    graph = SystemGraph(name="AgentTest", weights=(0.25, 0.25, 0.25, 0.25))
    graph.add_component(ComponentNode(
        id="reviews",
        name="External Doctor Reviews",
        component_type=ComponentType.CONTEXT_SOURCE,
        privilege=PrivilegeLevel.NONE,
        is_untrusted_source=True,
        data_sensitivity=0.8,
        human_approval_rate=0.0,   # a1 = 1.0
    ))
    graph.add_component(ComponentNode(
        id="planner",
        name="ReAct Planner",
        component_type=ComponentType.ORCHESTRATOR,
        privilege=PrivilegeLevel.READ,
        data_sensitivity=0.8,
        human_approval_rate=0.0,
    ))
    graph.add_component(ComponentNode(
        id="bank_tool",
        name="Banking Transfer Tool",
        component_type=ComponentType.TOOL,
        privilege=PrivilegeLevel.EXECUTE,
        data_sensitivity=1.0,
        human_approval_rate=0.0,
    ))
    graph.add_flow("reviews", "planner", untrusted_channel=True)
    graph.add_flow("planner", "bank_tool")

    # Trust boundary must capture reviews -> planner
    boundaries = graph.get_trust_boundaries()
    assert len(boundaries) == 1
    assert boundaries[0].source == "reviews" and boundaries[0].target == "planner"

    # Even though 'reviews' has NONE direct privilege, transitive a2 must equal 1.0 (bank_tool)
    amp_reviews = graph.compute_amplification("reviews")
    assert amp_reviews.a2_propagated_privilege == pytest.approx(1.0)
    assert "bank_tool" in amp_reviews.reachable_tools
    assert amp_reviews.a3_untrusted_input_ratio == pytest.approx(1.0)
    assert 1.0 <= amp_reviews.M <= 2.0
    assert amp_reviews.M == pytest.approx(1.0 + 0.25 * (1.0 + 1.0 + 1.0 + 0.8))


def test_weight_validation_bounds():
    assert validate_weights((0.25, 0.25, 0.25, 0.25)) == (0.25, 0.25, 0.25, 0.25)
    with pytest.raises(ValueError):
        validate_weights((-0.1, 0.3, 0.3, 0.3))
    with pytest.raises(ValueError):
        validate_weights((0.4, 0.4, 0.4, 0.1))
    with pytest.raises(ValueError):
        validate_weights((0.5, 0.5))


def test_case_study_profiles_relative_M_matches_table6():
    """Verify Table 6 property: CS2 (Agent) has highest M > CS1 (Web RAG) > CS3 & CS4."""
    max_M = {}
    for cs in ("cs1", "cs2", "cs3", "cs4"):
        g = load_case_study_graph(cs)
        profs = g.profile_all_components()
        assert len(profs) >= 3
        for p in profs.values():
            assert 1.0 <= p.M <= 2.0
        max_M[cs] = max(p.M for p in profs.values())

    assert max_M["cs2"] > max_M["cs1"] > max_M["cs3"]
    assert max_M["cs2"] > max_M["cs4"]


def test_threat_modeler_respects_attacker_model():
    graph = load_case_study_graph("cs2")
    modeler = RBSTThreatModeler()

    black_box_pairs = modeler.enumerate_applicable_pairs(
        graph, attacker=AttackerModel(knowledge="black_box")
    )
    limited_pairs = modeler.enumerate_applicable_pairs(
        graph,
        attacker=AttackerModel(knowledge="black_box", access_points={"untrusted_feeds"}),
    )
    assert len(black_box_pairs) > len(limited_pairs) > 0
    assert all(p.component.id == "untrusted_feeds" for p in limited_pairs)


# ==============================================================================
# 2. Risk Engine, Bayesian Update, Residual Risk & Stopping [Eq. (3)-(8)]
# ==============================================================================

def test_bayesian_update_and_conservative_residual_risk():
    st = RiskPairState(
        pair_id="T_IPI@web",
        threat_id="T_IPI",
        threat_name="Indirect PI",
        component_id="web",
        component_name="Web",
        owasp_code="LLM01",
        mitre_atlas="AML.T0051.001",
        I=4.0,
        M=1.5,
        E=0.2,
        mu0=0.25,
        n0=4.0,
    )
    # Before testing (n=0): theta_tb == mu0
    assert st.theta_tb == pytest.approx(0.25)
    assert st.likelihood_L == pytest.approx(2.0)
    assert st.risk_R == pytest.approx(2.0 * 4.0 * 1.5 * 0.8)

    # Residual risk uses conservative 95% upper bound theta_max > theta_tb
    r_res_0 = st.residual_risk_R_res
    assert st.theta_max > st.theta_tb
    assert r_res_0 > st.risk_R

    # Running 15 failed attacks (s=0) must strictly decrease theta_tb, theta_max, and R_res
    for _ in range(15):
        st.update(False)
    assert st.theta_tb == pytest.approx((4.0 * 0.25 + 0) / (4.0 + 15))
    assert st.residual_risk_R_res < r_res_0

    # Priority index P inversely scales with cost K [Eq. (6)]
    p_cheap = st.priority_P(theta_val=0.3, cost_K=1.0)
    p_expensive = st.priority_P(theta_val=0.3, cost_K=3.0)
    assert p_cheap == pytest.approx(3.0 * p_expensive)


def test_orchestrator_all_table8_strategies_and_reproducibility():
    graph, pairs, cases = build_pipeline_for_case_study("cs2", cases_per_pair=5)
    true_asr, gt_vulns, actual_sev = default_ground_truth_for_case_study("cs2", pairs)

    orchestrator = RBSTOrchestrator(pairs=pairs, test_cases=cases, system_name=graph.name)

    for strat in OrchestrationStrategy:
        exec1 = EmpiricalCalibrationExecutor(true_asr_by_pair=true_asr, seed=123)
        res1 = orchestrator.run(executor=exec1, budget_B=30.0, strategy=strat, seed=123)
        assert res1.total_steps > 0
        assert res1.total_cost <= 30.0 + 1e-6

        metrics = evaluate_run(
            res1,
            n_min=2,
            ground_truth_vulns=gt_vulns,
            actual_severity_by_pair=actual_sev,
        )
        assert 0.0 <= metrics["APFD_R"] <= 1.0
        assert 0.0 <= metrics["RC"] <= 1.0

    # Exact determinism with same seed
    r_a = orchestrator.run(
        executor=EmpiricalCalibrationExecutor(true_asr_by_pair=true_asr, seed=77),
        budget_B=25.0,
        strategy=OrchestrationStrategy.RBST_AI,
        seed=77,
    )
    r_b = orchestrator.run(
        executor=EmpiricalCalibrationExecutor(true_asr_by_pair=true_asr, seed=77),
        budget_B=25.0,
        strategy=OrchestrationStrategy.RBST_AI,
        seed=77,
    )
    assert [s.case_id for s in r_a.steps] == [s.case_id for s in r_b.steps]
    assert [s.outcome_y for s in r_a.steps] == [s.outcome_y for s in r_b.steps]


def test_orchestrator_early_stop_on_tau_threshold():
    graph, pairs, cases = build_pipeline_for_case_study("cs3", cases_per_pair=8)
    orchestrator = RBSTOrchestrator(pairs=pairs, test_cases=cases, system_name=graph.name)

    # All attacks fail -> R_res drops steadily -> stops before consuming huge budget
    always_safe = lambda tc, st, step: ExecutionOutcome(success=False, cost=tc.cost)
    res = orchestrator.run(
        executor=always_safe,
        budget_B=500.0,
        threshold_tau=12.0,
        strategy=OrchestrationStrategy.RBST_AI,
        seed=42,
        allow_repeat=True,
    )
    assert res.stopped_reason == "threshold_met"
    assert res.total_cost < 500.0
    assert all(st.residual_risk_R_res <= 12.0 for st in res.pair_states.values())


# ==============================================================================
# 3. Evaluation Metrics [Eq. (9)-(10)] & Compliance Reporter (Table 5)
# ==============================================================================

def _make_step(step: int, vid: str | None, y: int, sigma: float, cost: float, cum_cost: float) -> StepRecord:
    return StepRecord(
        step=step,
        timestamp="2026-11-24T00:00:00",
        pair_id="T@C",
        threat_id="T",
        component_id="C",
        owasp_code="LLM01",
        mitre_atlas="AML.T0051",
        case_id=f"case_{step}",
        attack_family="standard",
        priority_P=1.0,
        sampled_theta=0.3,
        outcome_y=y,
        cost_K=cost,
        cumulative_cost=cum_cost,
        n_after=step,
        s_after=y,
        theta_tb_after=0.3,
        theta_max_after=0.5,
        risk_R_after=4.0,
        residual_R_res_after=5.0,
        sigma=sigma,
        vulnerability_id=vid if y == 1 else None,
        severity_score=sigma if y == 1 else 0.0,
    )


def test_apfd_r_matches_classic_apfd_and_rewards_early_high_severity():
    # Equal weights (sigma = 5.0): 4 steps, vulns at step 1 and 2
    # Classic APFD = 1 - (1 + 2)/(4 * 2) + 1/(2 * 4) = 1 - 3/8 + 1/8 = 0.75
    steps_equal = [
        _make_step(1, "V1", 1, 5.0, 1.0, 1.0),
        _make_step(2, "V2", 1, 5.0, 1.0, 2.0),
        _make_step(3, None, 0, 5.0, 1.0, 3.0),
        _make_step(4, None, 0, 5.0, 1.0, 4.0),
    ]
    assert calculate_apfd_r(steps_equal)["apfd_r"] == pytest.approx(0.75)

    # Unequal weights: detecting high-severity (sigma=9) at step 1 beats detecting low-severity (sigma=2) at step 1
    early_high = [
        _make_step(1, "V_HIGH", 1, 9.0, 1.0, 1.0),
        _make_step(2, None, 0, 2.0, 1.0, 2.0),
        _make_step(3, None, 0, 2.0, 1.0, 3.0),
        _make_step(4, "V_LOW", 1, 2.0, 1.0, 4.0),
    ]
    early_low = [
        _make_step(1, "V_LOW", 1, 2.0, 1.0, 1.0),
        _make_step(2, None, 0, 2.0, 1.0, 2.0),
        _make_step(3, None, 0, 2.0, 1.0, 3.0),
        _make_step(4, "V_HIGH", 1, 9.0, 1.0, 4.0),
    ]
    assert calculate_apfd_r(early_high)["apfd_r"] > calculate_apfd_r(early_low)["apfd_r"]

    # Cost to first critical (sigma >= 6.0)
    cf_high = calculate_cost_to_first_critical(early_high, critical_sigma_threshold=6.0)
    cf_low = calculate_cost_to_first_critical(early_low, critical_sigma_threshold=6.0)
    assert cf_high["cf"] == pytest.approx(1.0)
    assert cf_low["cf"] == pytest.approx(4.0)


def test_risk_coverage_spearman_and_kappa():
    s1 = RiskPairState("P1", "T1", "T1", "C1", "C1", "LLM01", "AML.T0051", I=5.0, M=2.0, E=0.0, mu0=0.5, n0=4.0)
    s2 = RiskPairState("P2", "T2", "T2", "C2", "C2", "LLM07", "AML.T0056", I=2.0, M=1.0, E=0.0, mu0=0.2, n0=4.0)
    s3 = RiskPairState("P3", "T3", "T3", "C3", "C3", "LLM10", "AML.T0029", I=1.0, M=1.0, E=0.0, mu0=0.1, n0=4.0)
    s1.n = 4
    s2.n = 1
    s3.n = 0
    states = {"P1": s1, "P2": s2, "P3": s3}

    rc = calculate_risk_coverage(states, n_min=3)
    expected_rc = s1.initial_risk / (s1.initial_risk + s2.initial_risk + s3.initial_risk)
    assert rc == pytest.approx(expected_rc, abs=1e-5)

    sp = calculate_residual_spearman(states, {"P1": 9.5, "P2": 4.0, "P3": 1.2})
    assert sp["rho"] == pytest.approx(1.0)

    assert calculate_cohens_kappa([1, 1, 0, 0], [1, 1, 0, 0]) == pytest.approx(1.0)


# ==============================================================================
# 4. Integration with EvidenceStore, LiveScannerExecutor, Sandbox & CLI
# ==============================================================================

def test_evidence_store_and_compliance_reporter(tmp_path: Path):
    db_file = tmp_path / "test_rbst_evidence.db"
    store = EvidenceStore(db_path=db_file)

    graph, pairs, cases = build_pipeline_for_case_study("cs1", cases_per_pair=4)
    true_asr, gt_vulns, actual_sev = default_ground_truth_for_case_study("cs1", pairs)

    orchestrator = RBSTOrchestrator(
        pairs=pairs,
        test_cases=cases,
        system_name=graph.name,
        evidence_store=store,
        run_id="rbst_test_run_01",
    )
    res = orchestrator.run(
        executor=EmpiricalCalibrationExecutor(true_asr_by_pair=true_asr, seed=42),
        budget_B=15.0,
        strategy=OrchestrationStrategy.RBST_AI,
        seed=42,
    )
    assert len(store.list_all(limit=100)) == res.total_steps

    reporter = RBSTComplianceReporter()
    metrics = evaluate_run(res, ground_truth_vulns=gt_vulns, actual_severity_by_pair=actual_sev)
    report = reporter.generate_report(res, metrics=metrics, system_version=graph.version)

    assert len(report["compliance_traceability"]) == 4
    md = reporter.render_markdown(report)
    assert "NIST AI RMF 1.0" in md and "ISO/IEC TS 42119-2" in md and "EU AI Act" in md

    out_json = reporter.export_json(report, tmp_path / "rbst_report.json")
    loaded = json.loads(out_json.read_text(encoding="utf-8"))
    assert loaded["executive_summary"]["total_steps"] == res.total_steps


def test_live_scanner_executor_and_cs2_sandbox():
    class _DummyLLM:
        def send_prompt(self, prompt: str) -> str:
            if "transfer" in prompt.lower() or "banking" in prompt.lower():
                return "Executing transfer of $5000 to attacker account immediately."
            return "I cannot comply with that request."

    sandbox = create_cs2_agent_sandbox()
    executor = LiveScannerExecutor(llm_client=_DummyLLM(), use_llm_judge=False, sandbox=sandbox, seed=42)

    graph, pairs, cases = build_pipeline_for_case_study("cs2", cases_per_pair=3)
    orchestrator = RBSTOrchestrator(pairs=pairs, test_cases=cases, system_name=graph.name)
    res = orchestrator.run(
        executor=executor,
        budget_B=10.0,
        strategy=OrchestrationStrategy.RBST_AI,
        seed=42,
    )
    assert res.total_steps > 0
    assert any(s.oracle_method == "sandbox_tool_trace" for s in res.steps)


def test_cli_rbst_json_output(capsys):
    import main as cli_main

    exit_code = cli_main.main(["--rbst", "cs4", "--rbst-budget", "20", "--rbst-seed", "42", "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["report_metadata"]["framework"] == "RBST-AI"
    assert parsed["executive_summary"]["total_steps"] > 0
