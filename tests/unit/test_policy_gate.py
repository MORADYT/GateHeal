"""Unit, regression, and property-based tests for PolicyEngine and MinimalImpactSelector."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from gateheal.actions import DEFAULT_ACTION_CATALOGUE, ActionSpec
from gateheal.cli import main as cli_main
from gateheal.config import (
    ExecutionBudgets,
    GateHealConfig,
    InventoryConfig,
    PlatformSettings,
    ServiceInventoryItem,
    load_config,
)
from gateheal.controller import ExecutionController, OutcomeVerifier
from gateheal.diagnosis import DiagnosisEngine
from gateheal.models import (
    ActionId,
    ActionProposal,
    ExecutionResult,
    FaultClass,
    ImpactTier,
    IncidentRecord,
    PermissionTier,
    PolicyRejectionCode,
    ServiceEvidence,
    VerificationStatus,
)
from gateheal.policy import (
    MinimalImpactSelector,
    PolicyEngine,
    compute_effective_impact_and_blast_radius,
    compute_incident_state_hash,
    mint_approval_token,
)


def _load_lab_config() -> GateHealConfig:
    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_path)


def _make_incident(
    *,
    redis_healthy: bool = True,
    api_active: str = "failed",
    api_sub_state: str | None = None,
    api_probe_ok: bool = False,
    api_config_valid: bool | None = True,
    api_enter_age_sec: float | None = None,
    worker_healthy: bool = True,
    prior_recovery_attempts: int = 0,
    action_history: tuple[str, ...] = (),
    collected_at_utc: str = "2026-10-20T08:00:00Z",
    api_logs: tuple[str, ...] = (),
) -> IncidentRecord:
    resolved_sub = (
        api_sub_state
        if api_sub_state is not None
        else ("running" if api_active == "active" else "failed")
    )
    return IncidentRecord(
        incident_id="inc-001",
        target_unit="lab-api.service",
        collected_at_utc=collected_at_utc,
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
                sub_state=resolved_sub,
                result="exit-code" if api_active != "active" else "success",
                can_reload=True,
                health_probe_ok=api_probe_ok,
                config_valid=api_config_valid,
                active_enter_age_sec=api_enter_age_sec,
                sanitized_logs=api_logs,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="active" if worker_healthy else "failed",
                sub_state="running" if worker_healthy else "failed",
                health_probe_ok=worker_healthy,
            ),
        },
    )


def test_policy_rejects_unregistered_and_disabled_actions() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident()
    unreg_proposal = ActionProposal(
        action_id="execute_arbitrary_shell_command",
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Attempt to run an unregistered shell action.",
    )
    decision_unreg = engine.evaluate(unreg_proposal, incident)
    assert not decision_unreg.approved
    assert PolicyRejectionCode.ERR_UNREGISTERED_ACTION in decision_unreg.rejection_codes

    # Disabled action (restore_last_known_good_config) must emit ERR_ACTION_DISABLED
    bad_cfg_incident = _make_incident(
        api_active="active", api_probe_ok=True, api_config_valid=False
    )
    disabled_proposal = ActionProposal(
        action_id=ActionId.RESTORE_LAST_KNOWN_GOOD_CONFIG.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.INVALID_CONFIG,
        rationale="Attempt disabled config restore action.",
    )
    decision_dis = engine.evaluate(disabled_proposal, bad_cfg_incident)
    assert not decision_dis.approved
    assert PolicyRejectionCode.ERR_ACTION_DISABLED in decision_dis.rejection_codes


def test_policy_rejects_unauthorized_target() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident()
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="sshd.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Attempt to restart host sshd outside approved inventory.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_UNAUTHORIZED_TARGET in decision.rejection_codes


def test_policy_rejects_malformed_parameters_and_self_approval_fields() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident()

    bad_target_proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service; rm -rf /",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Attempt command injection in unit name.",
    )
    decision_a = engine.evaluate(bad_target_proposal, incident)
    assert not decision_a.approved
    assert PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS in decision_a.rejection_codes

    raw_self_approved: dict[str, object] = {
        "action_id": "restart_service",
        "target_unit": "lab-api.service",
        "rationale": "Attempt to self-approve action.",
        "human_approved": True,
    }
    decision_b = engine.evaluate_raw(raw_self_approved, incident)
    assert not decision_b.approved
    assert PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS in decision_b.rejection_codes

    raw_bad_fault_type: dict[str, object] = {
        "action_id": "restart_service",
        "target_unit": "lab-api.service",
        "inferred_fault": 12345,
        "rationale": "Invalid fault type.",
    }
    decision_c = engine.evaluate_raw(raw_bad_fault_type, incident)
    assert not decision_c.approved
    assert PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS in decision_c.rejection_codes


def test_policy_rejects_restart_when_upstream_dependency_unhealthy() -> None:
    engine = PolicyEngine(_load_lab_config())
    incident = _make_incident(redis_healthy=False)
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.DEPENDENCY_FAILURE,
        rationale="Blindly restart lab-api even though upstream lab-redis is down.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_UPSTREAM_DEPENDENCY_UNHEALTHY in decision.rejection_codes
    assert PolicyRejectionCode.ERR_INCOMPATIBLE_FAULT_ACTION in decision.rejection_codes


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
        rationale="Try restarting again after retry cap reached.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_RETRY_LIMIT_EXHAUSTED in decision.rejection_codes


def test_policy_uses_diagnosis_engine_confidence_and_ignores_spoofed_proposer_confidence() -> None:
    engine = PolicyEngine(_load_lab_config())
    ambiguous_incident = _make_incident(
        api_active="activating",
        api_sub_state="auto-restart",
        api_probe_ok=True,
    )
    spoofed_proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.99,
        rationale="Spoofed high confidence on ambiguous incident.",
    )
    decision = engine.evaluate(spoofed_proposal, ambiguous_incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_INSUFFICIENT_EVIDENCE in decision.rejection_codes
    assert PolicyRejectionCode.ERR_INCOMPATIBLE_FAULT_ACTION in decision.rejection_codes
    assert any("AUDIT_SIGNAL:" in note for note in decision.notes)


def test_policy_rejects_restart_of_healthy_service_wp1b_matrix() -> None:
    engine = PolicyEngine(_load_lab_config())
    healthy_incident = _make_incident(
        api_active="active",
        api_sub_state="running",
        api_probe_ok=True,
        api_config_valid=True,
    )
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Proposer claims crash on a healthy service.",
    )
    decision = engine.evaluate(proposal, healthy_incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_INCOMPATIBLE_FAULT_ACTION in decision.rejection_codes

    # Only NO_OP is approved on HEALTHY incident
    noop_prop = ActionProposal(
        action_id=ActionId.NO_OP.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.HEALTHY,
        rationale="Healthy service requires no operation.",
    )
    assert engine.evaluate(noop_prop, healthy_incident).approved


def test_selector_prefers_minimal_impact_and_ignores_spoofed_proposer_confidence() -> None:
    cfg = _load_lab_config()
    engine = PolicyEngine(cfg)
    selector = MinimalImpactSelector(engine)

    active_incident = _make_incident(api_active="active", api_config_valid=True)
    restart_prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.DEGRADED_RUNNING,
        evidence_confidence=1.0,
        rationale="Disruptive restart with spoofed 1.0 confidence.",
    )
    reload_prop = ActionProposal(
        action_id=ActionId.RELOAD_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.DEGRADED_RUNNING,
        evidence_confidence=0.01,
        rationale="Graceful reload in place with 0.01 proposer confidence.",
    )
    chosen, _ = selector.select([restart_prop, reload_prop], active_incident)
    assert chosen.action_id == ActionId.RELOAD_SERVICE.value

    inspect_api = ActionProposal(
        action_id=ActionId.INSPECT_SERVICE_STATUS.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.DEGRADED_RUNNING,
        evidence_confidence=0.01,
        rationale="Inspect lab-api.",
    )
    inspect_redis = ActionProposal(
        action_id=ActionId.INSPECT_SERVICE_STATUS.value,
        target_unit="lab-redis.service",
        inferred_fault=FaultClass.DEGRADED_RUNNING,
        evidence_confidence=0.99,
        rationale="Inspect lab-redis with spoofed confidence.",
    )
    chosen_a, _ = selector.select([inspect_redis, inspect_api], active_incident)
    chosen_b, _ = selector.select([inspect_api, inspect_redis], active_incident)
    assert chosen_a.target_unit == "lab-api.service"
    assert chosen_b.target_unit == "lab-api.service"

    bad_cfg_incident = _make_incident(api_active="active", api_config_valid=False)
    chosen_abstain, _ = selector.select([restart_prop, reload_prop], bad_cfg_incident)
    assert chosen_abstain.action_id == ActionId.ABSTAIN_AND_ESCALATE.value


def test_empty_catalogue_and_empty_permissions_fail_closed() -> None:
    cfg = _load_lab_config()
    incident = _make_incident()
    proposal = ActionProposal(
        action_id=ActionId.INSPECT_SERVICE_STATUS.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Read-only status check.",
    )

    empty_cat_engine = PolicyEngine(cfg, catalogue={})
    dec_cat = empty_cat_engine.evaluate(proposal, incident)
    assert not dec_cat.approved
    assert PolicyRejectionCode.ERR_UNREGISTERED_ACTION in dec_cat.rejection_codes

    empty_perm_engine = PolicyEngine(cfg, granted_permissions=frozenset())
    dec_perm = empty_perm_engine.evaluate(proposal, incident)
    assert not dec_perm.approved
    assert PolicyRejectionCode.ERR_INSUFFICIENT_PERMISSION in dec_perm.rejection_codes


def test_t11_default_action_catalogue_is_immutable() -> None:
    with pytest.raises(TypeError):
        DEFAULT_ACTION_CATALOGUE[ActionId.RESTART_SERVICE] = (  # type: ignore[index]
            DEFAULT_ACTION_CATALOGUE[ActionId.INSPECT_SERVICE_STATUS]
        )


def test_state_hash_ignores_logs_and_timestamps_and_tracks_dependents() -> None:
    cfg = _load_lab_config()
    inc_a = _make_incident(
        collected_at_utc="2026-10-20T08:00:00Z",
        api_logs=("line 1",),
    )
    inc_b = _make_incident(
        collected_at_utc="2026-10-20T09:30:00Z",
        api_logs=("completely different log line", "another line"),
    )
    assert compute_incident_state_hash(inc_a, cfg) == compute_incident_state_hash(
        inc_b, cfg
    )

    inc_changed = _make_incident(api_active="active", api_probe_ok=True)
    assert compute_incident_state_hash(inc_a, cfg) != compute_incident_state_hash(
        inc_changed, cfg
    )


def test_approval_token_verification_expiry_signature_key_len_and_consumption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = _load_lab_config()
    incident = _make_incident()
    fixed_now = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)

    with pytest.raises(ValueError, match="at least 32 bytes"):
        mint_approval_token(
            token_id="tok-short",
            incident=incident,
            config=cfg,
            action_id=ActionId.RESTART_SERVICE.value,
            target_unit="lab-api.service",
            expires_at_utc=(fixed_now + timedelta(minutes=5)).isoformat(),
            hmac_key=b"too-short-key",
        )

    secret_key = b"operator-test-hmac-secret-key-32b"
    monkeypatch.setenv("GATEHEAL_APPROVAL_HMAC_KEY", secret_key.decode("utf-8"))

    tier3_restart = ActionSpec(
        action_id=ActionId.RESTART_SERVICE,
        impact_tier=ImpactTier.SHARED_OR_CASCADE_RESTART,
        required_permission=PermissionTier.SERVICE_OPERATOR,
        requires_target_unit=True,
        requires_valid_config=True,
        requires_healthy_upstream=True,
        reversible=False,
        requires_human_approval=True,
        timeout_sec=10.0,
        max_retries_per_incident=1,
        description="Tier 3 shared restart requiring operator approval token.",
    )
    custom_cat = {
        **DEFAULT_ACTION_CATALOGUE,
        ActionId.RESTART_SERVICE: tier3_restart,
    }

    engine = PolicyEngine(
        cfg,
        catalogue=custom_cat,
        clock_utc=lambda: fixed_now,
    )
    controller = ExecutionController(
        cfg,
        policy_engine=engine,
        catalogue=engine.catalogue,
        consumed_tokens=engine.consumed_tokens_store,
        clock_utc=lambda: fixed_now,
    )

    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart requiring break-glass Tier 3 approval.",
    )

    dec_no_tok = engine.evaluate(proposal, incident)
    assert not dec_no_tok.approved
    assert PolicyRejectionCode.ERR_HUMAN_APPROVAL_REQUIRED in dec_no_tok.rejection_codes
    assert PolicyRejectionCode.ERR_IMPACT_TIER_EXCEEDED in dec_no_tok.rejection_codes

    expired_token = mint_approval_token(
        token_id="tok-expired",
        incident=incident,
        config=cfg,
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        expires_at_utc=(fixed_now - timedelta(seconds=1)).isoformat(),
        hmac_key=secret_key,
    )
    dec_exp = engine.evaluate(proposal, incident, approval_token=expired_token)
    assert not dec_exp.approved
    assert PolicyRejectionCode.ERR_INVALID_APPROVAL_TOKEN in dec_exp.rejection_codes
    assert any("expired" in n.lower() for n in dec_exp.notes)
    with pytest.raises(PermissionError):
        engine.mint_capability(proposal, incident, approval_token=expired_token)

    wrong_key_token = mint_approval_token(
        token_id="tok-badsig",
        incident=incident,
        config=cfg,
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        expires_at_utc=(fixed_now + timedelta(minutes=5)).isoformat(),
        hmac_key=b"wrong-operator-hmac-secret-key!!",
    )
    dec_sig = engine.evaluate(proposal, incident, approval_token=wrong_key_token)
    assert not dec_sig.approved
    assert PolicyRejectionCode.ERR_INVALID_APPROVAL_TOKEN in dec_sig.rejection_codes
    assert any("signature" in n.lower() for n in dec_sig.notes)
    with pytest.raises(PermissionError):
        engine.mint_capability(proposal, incident, approval_token=wrong_key_token)

    valid_token = mint_approval_token(
        token_id="tok-001",
        incident=incident,
        config=cfg,
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        expires_at_utc=(fixed_now + timedelta(minutes=5)).isoformat(),
        hmac_key=secret_key,
    )

    inspect_prop = ActionProposal(
        action_id=ActionId.INSPECT_SERVICE_STATUS.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Read-only status check does not need token.",
    )
    dec_insp = engine.evaluate(inspect_prop, incident, approval_token=wrong_key_token)
    assert dec_insp.approved
    insp_cap = engine.mint_capability(
        inspect_prop, incident, approval_token=valid_token
    )
    controller.execute(
        insp_cap, current_incident=incident, approval_token=valid_token
    )
    assert "tok-001" not in controller.consumed_tokens

    dec_eval_1 = engine.evaluate(proposal, incident, approval_token=valid_token)
    dec_eval_2 = engine.evaluate(proposal, incident, approval_token=valid_token)
    assert dec_eval_1.approved
    assert dec_eval_2.approved
    assert any("BREAK_GLASS_OVERRIDE:" in n for n in dec_eval_1.notes)
    assert "tok-001" not in controller.consumed_tokens

    cap = engine.mint_capability(
        proposal, incident, approval_token=valid_token
    )
    assert "tok-001" not in controller.consumed_tokens

    mutated_incident = _make_incident(api_active="active", api_probe_ok=True)
    with pytest.raises(PermissionError, match="state_hash mismatch"):
        controller.execute(
            cap, current_incident=mutated_incident, approval_token=valid_token
        )
    assert "tok-001" not in controller.consumed_tokens

    exec_res = controller.execute(
        cap, current_incident=incident, approval_token=valid_token
    )
    assert exec_res.exit_code == 0
    assert "tok-001" in controller.consumed_tokens

    dec_replay = engine.evaluate(proposal, incident, approval_token=valid_token)
    assert not dec_replay.approved
    assert PolicyRejectionCode.ERR_INVALID_APPROVAL_TOKEN in dec_replay.rejection_codes
    with pytest.raises(PermissionError, match="already been consumed"):
        controller.execute(
            cap, current_incident=incident, approval_token=valid_token
        )

def test_wp1b_degraded_running_grace_window_and_inactive_non_crash() -> None:
    cfg = _load_lab_config()
    diag_engine = DiagnosisEngine(cfg)

    # 1. Within startup grace window (2.0s < 5.0s) -> UNKNOWN (0.40), not DEGRADED_RUNNING
    grace_inc = _make_incident(
        api_active="active",
        api_sub_state="running",
        api_probe_ok=False,
        api_enter_age_sec=2.0,
    )
    assert diag_engine.diagnose(grace_inc).fault_class == FaultClass.UNKNOWN

    # 2. Past startup grace window (6.0s >= 5.0s) -> DEGRADED_RUNNING (0.90)
    degraded_inc = _make_incident(
        api_active="active",
        api_sub_state="running",
        api_probe_ok=False,
        api_enter_age_sec=6.0,
    )
    assert diag_engine.diagnose(degraded_inc).fault_class == FaultClass.DEGRADED_RUNNING

    # 3. Cleanly stopped unit (inactive, result="success") -> UNKNOWN, not PROCESS_CRASH
    clean_stop_inc = IncidentRecord(
        incident_id="inc-stop",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T08:00:00Z",
        services={
            **_make_incident().services,
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="inactive",
                sub_state="dead",
                result="success",
                health_probe_ok=False,
                config_valid=True,
            ),
        },
    )
    assert diag_engine.diagnose(clean_stop_inc).fault_class == FaultClass.UNKNOWN


def test_wp1b_blast_radius_table_and_inventory_dilution_invariance() -> None:
    cfg = _load_lab_config()
    engine = PolicyEngine(cfg)
    restart_spec = DEFAULT_ACTION_CATALOGUE[ActionId.RESTART_SERVICE]

    # S1: Crashed target (active_state="failed") -> B_dep = 0.0, Tier 2, approved
    s1_inc = _make_incident(api_active="failed", worker_healthy=True)
    s1_prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed lab-api.",
    )
    s1_imp = compute_effective_impact_and_blast_radius(
        s1_prop, s1_inc, cfg, restart_spec
    )
    assert s1_imp.blast_radius_weight == 0.0
    assert s1_imp.effective_tier == ImpactTier.TARGETED_RESTART
    assert engine.evaluate(s1_prop, s1_inc).approved

    # S5 / H2: Active target with healthy dependent -> B_dep = 1.0, Tier 3, requires token
    s5_inc = _make_incident(
        api_active="active", api_probe_ok=False, worker_healthy=True
    )
    s5_prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.DEGRADED_RUNNING,
        rationale="Restart active degraded lab-api.",
    )
    s5_imp = compute_effective_impact_and_blast_radius(
        s5_prop, s5_inc, cfg, restart_spec
    )
    assert s5_imp.blast_radius_weight == 1.0
    assert s5_imp.effective_tier == ImpactTier.SHARED_OR_CASCADE_RESTART
    s5_dec = engine.evaluate(s5_prop, s5_inc)
    assert not s5_dec.approved
    assert PolicyRejectionCode.ERR_BLAST_RADIUS_EXCEEDED in s5_dec.rejection_codes

    # H4: Adding 10 unrelated healthy services to the inventory never dilutes B_dep
    diluted_services = dict(cfg.inventory.services)
    diluted_incident_services = dict(s5_inc.services)
    for idx in range(1, 11):
        u_name = f"unrelated-{idx}.service"
        diluted_services[u_name] = ServiceInventoryItem(
            unit_name=u_name,
            config_check_mode="acknowledged_none",
            criticality_weight=10.0,
        )
        diluted_incident_services[u_name] = ServiceEvidence(
            unit_name=u_name,
            active_state="active",
            sub_state="running",
            health_probe_ok=True,
        )
    diluted_cfg = GateHealConfig(
        platform=PlatformSettings(
            controller_mode="deterministic",
            max_allowed_impact_tier=3,
            min_confidence_for_mutation=0.70,
            max_unapproved_blast_radius_weight=0.0,
        ),
        budgets=ExecutionBudgets(),
        inventory=InventoryConfig(services=diluted_services),
    )
    diluted_inc = IncidentRecord(
        incident_id="inc-diluted",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T08:00:00Z",
        services=diluted_incident_services,
    )
    diluted_engine = PolicyEngine(diluted_cfg)
    diluted_dec = diluted_engine.evaluate(s5_prop, diluted_inc)
    assert not diluted_dec.approved
    assert PolicyRejectionCode.ERR_BLAST_RADIUS_EXCEEDED in diluted_dec.rejection_codes
    assert PolicyRejectionCode.ERR_HUMAN_APPROVAL_REQUIRED in diluted_dec.rejection_codes


def test_wp1b_s2_fault_persists_service_up_outcome() -> None:
    cfg = _load_lab_config()
    verifier = OutcomeVerifier(cfg)
    s2_inc = _make_incident(
        api_active="active",
        api_sub_state="running",
        api_probe_ok=True,
        api_config_valid=False,
    )
    abstain_prop = ActionProposal(
        action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.INVALID_CONFIG,
        rationale="Abstain on broken config while service is running.",
    )
    exec_res = ExecutionResult(
        action_id=ActionId.ABSTAIN_AND_ESCALATE,
        target_unit="lab-api.service",
        argv=(),
        exit_code=0,
        duration_sec=0.0,
    )
    report = verifier.verify(abstain_prop, exec_res, s2_inc, pre_incident=s2_inc)
    assert report.status == VerificationStatus.FAULT_PERSISTS_SERVICE_UP
    assert report.target_healthy is True


@settings(max_examples=40, deadline=None)
@given(
    action_id=st.text(min_size=0, max_size=40),
    target_unit=st.one_of(st.none(), st.text(min_size=0, max_size=40)),
    confidence=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    rationale=st.text(min_size=3, max_size=80),
)
def test_property_policy_gate_never_approves_unregistered_or_unpermitted_actions(
    action_id: str,
    target_unit: str | None,
    confidence: float,
    rationale: str,
) -> None:
    cfg = _load_lab_config()
    incident = _make_incident()
    raw_payload: dict[str, object] = {
        "action_id": action_id,
        "target_unit": target_unit,
        "inferred_fault": "process_crash",
        "evidence_confidence": confidence,
        "rationale": rationale,
    }

    zero_perm_engine = PolicyEngine(cfg, granted_permissions=frozenset())
    zero_dec = zero_perm_engine.evaluate_raw(raw_payload, incident)
    assert not zero_dec.approved

    std_engine = PolicyEngine(cfg)
    std_dec = std_engine.evaluate_raw(raw_payload, incident)
    if std_dec.approved:
        assert action_id in {a.value for a in ActionId}
        if action_id not in (
            ActionId.ABSTAIN_AND_ESCALATE.value,
            ActionId.NO_OP.value,
        ):
            assert target_unit in cfg.inventory.services


def test_cli_recover_simulated_smoke_test(
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    rc = cli_main(
        [
            "recover",
            "--config",
            str(cfg_path),
            "--target",
            "lab-api.service",
            "--incident-id",
            "inc-cli-smoke-wp1",
            "--transport",
            "simulated",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["incident_id"] == "inc-cli-smoke-wp1"
    assert payload["selected_proposal"]["action_id"] == "restart_service"
    assert payload["verification_report"]["status"] == "recovered_clean"


def test_cli_recover_wires_shared_consumed_tokens_store_and_catalogue(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    captured_wiring: dict[str, object] = {}
    orig_policy_init = PolicyEngine.__init__
    orig_ctrl_init = ExecutionController.__init__

    def spy_policy_init(
        self: PolicyEngine, *args: object, **kwargs: object
    ) -> None:
        orig_policy_init(self, *args, **kwargs)  # type: ignore[arg-type]
        captured_wiring["policy_engine"] = self

    def spy_ctrl_init(
        self: ExecutionController, *args: object, **kwargs: object
    ) -> None:
        captured_wiring["ctrl_kwargs"] = dict(kwargs)
        orig_ctrl_init(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(PolicyEngine, "__init__", spy_policy_init)
    monkeypatch.setattr(ExecutionController, "__init__", spy_ctrl_init)

    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    rc = cli_main(
        [
            "recover",
            "--config",
            str(cfg_path),
            "--target",
            "lab-api.service",
            "--incident-id",
            "inc-cli-wiring-wp1",
        ]
    )
    _ = capsys.readouterr()
    assert rc == 0

    pe = captured_wiring["policy_engine"]
    assert isinstance(pe, PolicyEngine)
    ctrl_kwargs = captured_wiring["ctrl_kwargs"]
    assert isinstance(ctrl_kwargs, dict)
    assert ctrl_kwargs.get("consumed_tokens") is pe.consumed_tokens_store
    assert ctrl_kwargs.get("catalogue") == pe.catalogue
