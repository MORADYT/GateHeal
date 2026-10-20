"""Unit tests for the independent PolicyEngine and MinimalImpactSelector."""

from __future__ import annotations

from pathlib import Path

from gateheal.config import GateHealConfig, load_config
from gateheal.models import (
    ActionId,
    ActionProposal,
    FaultClass,
    IncidentRecord,
    PolicyRejectionCode,
    ServiceEvidence,
)
from gateheal.policy import MinimalImpactSelector, PolicyEngine


def _load_lab_config() -> GateHealConfig:
    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_path)


def _make_incident(
    *,
    redis_healthy: bool = True,
    api_active: str = "failed",
    api_config_valid: bool | None = True,
    prior_recovery_attempts: int = 0,
    action_history: tuple[str, ...] = (),
) -> IncidentRecord:
    return IncidentRecord(
        incident_id="inc-001",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T08:00:00Z",
        prior_recovery_attempts=prior_recovery_attempts,
        action_history=action_history,
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active" if redis_healthy else "failed",
                sub_state="running" if redis_healthy else "failed",
                health_probe_ok=redis_healthy,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state=api_active,
                sub_state="running" if api_active == "active" else "failed",
                can_reload=True,
                health_probe_ok=False,
                config_valid=api_config_valid,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
        },
    )


def test_policy_rejects_unregistered_action() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident()
    proposal = ActionProposal(
        action_id="execute_arbitrary_shell_command",
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.95,
        rationale="Attempt to run an unregistered shell action.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_UNREGISTERED_ACTION in decision.rejection_codes


def test_policy_rejects_unauthorized_target() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident()
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="sshd.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.95,
        rationale="Attempt to restart host sshd outside approved inventory.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_UNAUTHORIZED_TARGET in decision.rejection_codes


def test_policy_rejects_malformed_parameters_and_metacharacters() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident()

    # Case A: Shell metacharacters in target_unit
    bad_target_proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service; rm -rf /",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.95,
        rationale="Attempt command injection in unit name.",
    )
    decision_a = engine.evaluate(bad_target_proposal, incident)
    assert not decision_a.approved
    assert PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS in decision_a.rejection_codes

    # Case B: Extra undocumented fields in raw untrusted dict
    raw_bad_payload: dict[str, object] = {
        "action_id": "restart_service",
        "target_unit": "lab-api.service",
        "evidence_confidence": 0.9,
        "rationale": "Valid length rationale",
        "override_policy": True,
    }
    decision_b = engine.evaluate_raw(raw_bad_payload, incident)
    assert not decision_b.approved
    assert PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS in decision_b.rejection_codes


def test_policy_rejects_restart_when_upstream_dependency_unhealthy() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident(redis_healthy=False)
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.DEPENDENCY_FAILURE,
        evidence_confidence=0.90,
        rationale="Blindly restart lab-api even though upstream lab-redis is down.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_UPSTREAM_DEPENDENCY_UNHEALTHY in decision.rejection_codes


def test_policy_rejects_when_retry_budget_exhausted() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident(
        prior_recovery_attempts=2,
        action_history=("restart_service:lab-api.service",),
    )
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PERSISTENT_FAILURE,
        evidence_confidence=0.90,
        rationale="Try restarting again after retry cap reached.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_RETRY_LIMIT_EXHAUSTED in decision.rejection_codes


def test_policy_rejects_mutation_on_insufficient_evidence_confidence() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident()
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.UNKNOWN,
        evidence_confidence=0.40,
        rationale="Low-confidence guess to restart service.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_INSUFFICIENT_EVIDENCE in decision.rejection_codes


def test_selector_prefers_minimal_impact_reload_over_restart_and_abstains_when_blocked() -> None:
    cfg = _load_lab_config()
    engine = PolicyEngine(cfg)
    selector = MinimalImpactSelector(engine)

    # Active service with valid config: reload (Tier 1) must beat restart (Tier 2)
    active_incident = _make_incident(api_active="active", api_config_valid=True)
    restart_prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.95,
        rationale="Disruptive restart.",
    )
    reload_prop = ActionProposal(
        action_id=ActionId.RELOAD_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.85,
        rationale="Graceful reload in place.",
    )
    chosen, _ = selector.select([restart_prop, reload_prop], active_incident)
    assert chosen.action_id == ActionId.RELOAD_SERVICE.value

    # When config is invalid, both reload and restart are blocked -> selector abstains
    bad_cfg_incident = _make_incident(api_active="active", api_config_valid=False)
    chosen_abstain, _ = selector.select([restart_prop, reload_prop], bad_cfg_incident)
    assert chosen_abstain.action_id == ActionId.ABSTAIN_AND_ESCALATE.value
