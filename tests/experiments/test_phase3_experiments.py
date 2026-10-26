"""Phase 3 repeatability, scenario outcomes, and Config A vs Config B tests."""

from __future__ import annotations

from pathlib import Path

from gateheal.config import GateHealConfig, load_config
from gateheal.experiments import (
    ExperimentRunner,
    build_default_scenarios,
    compute_campaign_metrics,
)
from gateheal.models import ActionId, VerificationStatus


def _load_lab_cfg() -> GateHealConfig:
    cfg_p = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_p)


def test_scenarios_are_deterministic_and_match_expected_outcomes() -> None:
    cfg = _load_lab_cfg()
    runner = ExperimentRunner(cfg)
    scenarios = build_default_scenarios()

    for scen in scenarios:
        o1 = runner.run_single_trial(
            scen,
            config_name="config_b_deterministic_risk_aware",
            trial_index=1,
        )
        o2 = runner.run_single_trial(
            scen,
            config_name="config_b_deterministic_risk_aware",
            trial_index=2,
        )
        # Repeatability check across independent trials
        assert o1.selected_action_id == o2.selected_action_id
        assert o1.selected_target_unit == o2.selected_target_unit
        assert o1.verification_status == o2.verification_status
        assert o1.verification_status == scen.expected_policy_gated_status
        assert o1.abstained == scen.expected_abstain


def test_config_b_outperforms_config_a_on_disruption_and_recovery() -> None:
    cfg = _load_lab_cfg()
    runner = ExperimentRunner(cfg)
    scenarios = build_default_scenarios()
    scenarios_by_id = {s.scenario_id: s for s in scenarios}

    outcomes_a = [
        runner.run_single_trial(s, "config_a_fixed_runbook", trial_index=i)
        for i in range(1, 4)
        for s in scenarios
    ]
    outcomes_b = [
        runner.run_single_trial(
            s, "config_b_deterministic_risk_aware", trial_index=i
        )
        for i in range(1, 4)
        for s in scenarios
    ]

    metrics_a = compute_campaign_metrics(
        "config_a_fixed_runbook", outcomes_a, scenarios_by_id
    )
    metrics_b = compute_campaign_metrics(
        "config_b_deterministic_risk_aware", outcomes_b, scenarios_by_id
    )

    # Config B must have zero unsafe executed actions and zero collateral failures
    assert metrics_b.unsafe_executed_action_rate == 0.0
    assert metrics_b.collateral_failure_rate == 0.0
    assert metrics_b.unnecessary_recovery_rate == 0.0
    assert metrics_b.verified_recovery_rate == 1.0
    assert metrics_b.appropriate_abstention_rate == 1.0
    assert metrics_b.false_positive_remediation_rate == 0.0

    # Config A suffers collateral failures (S2, S5) and lower verified recovery (S3, S5)
    assert metrics_a.collateral_failure_rate > metrics_b.collateral_failure_rate
    assert metrics_a.unnecessary_recovery_rate > metrics_b.unnecessary_recovery_rate
    assert metrics_b.verified_recovery_rate > metrics_a.verified_recovery_rate
    assert metrics_b.mean_unavailability_sec < metrics_a.mean_unavailability_sec


def test_specific_scenario_decisions_for_config_b() -> None:
    cfg = _load_lab_cfg()
    runner = ExperimentRunner(cfg)
    scenarios = {s.scenario_id: s for s in build_default_scenarios()}

    # S3: Must restart upstream lab-redis.service, NOT alerting lab-api.service
    s3_out = runner.run_single_trial(
        scenarios["S3_DEPENDENCY_FAILURE"],
        "config_b_deterministic_risk_aware",
    )
    assert s3_out.selected_action_id == ActionId.RESTART_SERVICE.value
    assert s3_out.selected_target_unit == "lab-redis.service"
    assert s3_out.verification_status == VerificationStatus.RECOVERED_CLEAN

    # S5: Must select graceful reload_service (Tier 1) instead of restart_service (Tier 2)
    s5_out = runner.run_single_trial(
        scenarios["S5_COLLATERAL_TRAP"],
        "config_b_deterministic_risk_aware",
    )
    assert s5_out.selected_action_id == ActionId.RELOAD_SERVICE.value
    assert s5_out.selected_target_unit == "lab-api.service"
    assert not s5_out.collateral_failure_detected
