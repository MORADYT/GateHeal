"""Unit tests for LLM agent proposers, budget limits, and Config C vs Config D."""

from __future__ import annotations

import json

from gateheal.agent import (
    OpenAICompatibleAgentProposer,
    SimulatedLLMAgentProposer,
    build_agent_system_prompt,
)
from gateheal.config import (
    ExecutionBudgets,
    GateHealConfig,
    InventoryConfig,
    PlatformSettings,
    ServiceInventoryItem,
)
from gateheal.experiments import (
    ExperimentRunner,
    build_default_scenarios,
    compute_campaign_metrics,
)
from gateheal.models import ActionId, FaultClass, IncidentRecord, ServiceEvidence


def _make_test_config(max_llm_requests: int = 3) -> GateHealConfig:
    return GateHealConfig(
        platform=PlatformSettings(
            controller_mode="agentic",
            max_allowed_impact_tier=2,
            min_confidence_for_mutation=0.70,
        ),
        budgets=ExecutionBudgets(
            max_llm_requests=max_llm_requests,
            max_agent_rounds=2,
            max_recovery_attempts=1,
        ),
        inventory=InventoryConfig(
            services={
                "lab-redis.service": ServiceInventoryItem(
                    unit_name="lab-redis.service",
                    health_check_tcp_port=6379,
                    supports_reload=False,
                    config_check_mode="acknowledged_none",
                    downstream_dependents=("lab-api.service",),
                ),
                "lab-api.service": ServiceInventoryItem(
                    unit_name="lab-api.service",
                    health_check_http_url="http://127.0.0.1:8080/healthz",
                    supports_reload=True,
                    config_check_mode="argv",
                    config_check_argv=(
                        "/usr/local/bin/lab-api",
                        "--validate-config",
                        "/etc/lab-api/config.yaml",
                    ),
                    upstream_dependencies=("lab-redis.service",),
                    downstream_dependents=("lab-worker.service",),
                ),
                "lab-worker.service": ServiceInventoryItem(
                    unit_name="lab-worker.service",
                    supports_reload=False,
                    config_check_mode="acknowledged_none",
                    upstream_dependencies=("lab-api.service",),
                ),
            }
        ),
    )


def _make_sample_incident() -> IncidentRecord:
    return IncidentRecord(
        incident_id="inc-agent-test-01",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-21T08:00:00Z",
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
                config_valid=True,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                can_reload=True,
                health_probe_ok=False,
                config_valid=True,
            ),
        },
    )


def test_openai_proposer_valid_json_and_budget_enforcement() -> None:
    """OpenAICompatibleAgentProposer parses valid JSON and enforces max_llm_requests."""
    cfg = _make_test_config(max_llm_requests=1)
    incident = _make_sample_incident()
    prompt = build_agent_system_prompt()
    assert "human_approved" in prompt

    def fake_sender(_payload: bytes, _timeout: float) -> str:
        inner = {
            "proposals": [
                {
                    "action_id": "restart_service",
                    "target_unit": "lab-api.service",
                    "inferred_fault": "process_crash",
                    "rationale": "Service crashed cleanly with valid config.",
                }
            ]
        }
        return json.dumps(
            {"choices": [{"message": {"content": json.dumps(inner)}}]}
        )

    proposer = OpenAICompatibleAgentProposer(cfg, http_sender=fake_sender)

    first_batch = proposer.propose(incident)
    assert first_batch.raw_error is None
    assert first_batch.llm_requests_used == 1
    assert len(first_batch.proposals) == 1
    assert first_batch.proposals[0].action_id == ActionId.RESTART_SERVICE.value
    assert first_batch.proposals[0].inferred_fault == FaultClass.PROCESS_CRASH

    # Second call exceeds max_llm_requests=1 and must safely abstain
    second_batch = proposer.propose(incident)
    assert second_batch.raw_error == "ERR_LLM_BUDGET_EXHAUSTED"
    assert second_batch.llm_requests_used == 0
    assert (
        second_batch.proposals[0].action_id
        == ActionId.ABSTAIN_AND_ESCALATE.value
    )


def test_openai_proposer_malformed_json_falls_back_to_abstain() -> None:
    """Malformed LLM output never crashes the controller and falls back to abstain."""
    cfg = _make_test_config(max_llm_requests=2)
    incident = _make_sample_incident()

    def broken_sender(_payload: bytes, _timeout: float) -> str:
        return '{"choices": [{"message": {"content": "not valid json {{"}}]}'

    proposer = OpenAICompatibleAgentProposer(cfg, http_sender=broken_sender)
    batch = proposer.propose(incident)
    assert batch.raw_error is not None
    assert len(batch.proposals) == 1
    assert batch.proposals[0].action_id == ActionId.ABSTAIN_AND_ESCALATE.value


def test_config_c_ungated_vs_config_d_policy_gated_llm() -> None:
    """Config D blocks all unsafe LLM proposals that Config C executes."""
    cfg = _make_test_config(max_llm_requests=10)
    scenarios = build_default_scenarios()
    scenarios_by_id = {s.scenario_id: s for s in scenarios}
    runner = ExperimentRunner(cfg)

    proposer_check = SimulatedLLMAgentProposer(cfg)
    assert proposer_check is not None

    outcomes_c = [
        runner.run_single_trial(s, "config_c_ungated_llm_agent", 1)
        for s in scenarios
    ]
    outcomes_d = [
        runner.run_single_trial(s, "config_d_policy_gated_llm_agent", 1)
        for s in scenarios
    ]

    metrics_c = compute_campaign_metrics(
        "config_c_ungated_llm_agent", outcomes_c, scenarios_by_id
    )
    metrics_d = compute_campaign_metrics(
        "config_d_policy_gated_llm_agent", outcomes_d, scenarios_by_id
    )

    assert metrics_c.unsafe_executed_action_rate > 0.0
    assert metrics_c.collateral_failure_rate > 0.0

    assert metrics_d.unsafe_proposal_rate > 0.0
    assert metrics_d.unsafe_executed_action_rate == 0.0
    assert metrics_d.collateral_failure_rate == 0.0
    assert metrics_d.verified_recovery_rate == 1.0
    assert metrics_d.appropriate_abstention_rate == 1.0
