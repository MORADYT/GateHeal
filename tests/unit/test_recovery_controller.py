"""Unit and regression tests for WP2 capability execution, orchestrator, state, and WAL audit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from gateheal.collector import IncidentCollector
from gateheal.config import GateHealConfig, load_config
from gateheal.controller import (
    AuditRecorder,
    EscalationSink,
    ExecutionController,
    OutcomeVerifier,
)
from gateheal.diagnosis import DiagnosisEngine
from gateheal.models import (
    ActionId,
    ActionProposal,
    AuditRecord,
    ExecutionResult,
    FaultClass,
    IncidentRecord,
    PolicyRejectionCode,
    ServiceEvidence,
    VerificationStatus,
)
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.policy import PolicyEngine
from gateheal.state import PersistentStateStore, UnitLockError


def _load_lab_cfg() -> GateHealConfig:
    cfg_p = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_p)


def _make_crashed_api_incident(
    incident_id: str = "inc-wp2-001",
    *,
    api_active: str = "failed",
    api_probe_ok: bool = False,
    last_mutation_age_sec: float | None = None,
    flap_count: int = 0,
) -> IncidentRecord:
    return IncidentRecord(
        incident_id=incident_id,
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:00Z",
        last_mutating_action_age_sec=last_mutation_age_sec,
        recent_mutations_in_flap_window=flap_count,
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
                active_state=api_active,
                sub_state="running" if api_active == "active" else "failed",
                result="success" if api_active == "active" else "signal",
                can_reload=True,
                health_probe_ok=api_probe_ok,
                config_valid=True,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
                config_valid=True,
            ),
        },
    )


def test_diagnosis_engine_classifies_faults() -> None:
    cfg = _load_lab_cfg()
    engine = DiagnosisEngine(cfg)

    incident = IncidentRecord(
        incident_id="inc-diag-1",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:00Z",
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=False,
                config_valid=False,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
        },
    )
    diag = engine.diagnose(incident)
    assert diag.fault_class == FaultClass.INVALID_CONFIG
    assert diag.confidence > 0.90


def test_exit_code_zero_does_not_imply_recovery_if_verifier_fails() -> None:
    cfg = _load_lab_cfg()
    verifier = OutcomeVerifier(cfg)

    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.95,
        rationale="Restart crashed API service.",
    )
    exec_result = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-api.service",
        argv=("systemctl", "restart", "lab-api.service"),
        exit_code=0,
        duration_sec=0.5,
    )
    post_incident = _make_crashed_api_incident("inc-ver-1")

    report = verifier.verify(proposal, exec_result, post_incident)
    assert report.status == VerificationStatus.NOT_RECOVERED
    assert not report.target_healthy


def test_wp2_capability_bound_execution_blocks_raw_forged_and_replayed_calls() -> None:
    cfg = _load_lab_cfg()
    policy = PolicyEngine(cfg)
    other_policy = PolicyEngine(cfg)
    controller = ExecutionController(cfg, policy_engine=policy)
    incident = _make_crashed_api_incident()

    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Authorized restart of crashed lab-api.",
    )

    with pytest.raises(PermissionError, match="AuthorizedActionCapability"):
        controller.execute(proposal, current_incident=incident)  # type: ignore[arg-type]

    foreign_cap = other_policy.mint_capability(proposal, incident)
    with pytest.raises(PermissionError, match="MAC verification failed"):
        controller.execute(foreign_cap, current_incident=incident)

    valid_cap = policy.mint_capability(proposal, incident)
    res = controller.execute(valid_cap, current_incident=incident)
    assert res.exit_code == 0
    with pytest.raises(PermissionError, match="already been consumed"):
        controller.execute(valid_cap, current_incident=incident)


def test_wp2_cooldown_flapping_and_unit_lock_enforcement(tmp_path: Path) -> None:
    cfg = _load_lab_cfg()
    policy = PolicyEngine(cfg)

    cooldown_inc = _make_crashed_api_incident(last_mutation_age_sec=5.0)
    restart_prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Attempt restart during cooldown window.",
    )
    dec_cd = policy.evaluate(restart_prop, cooldown_inc)
    assert not dec_cd.approved
    assert PolicyRejectionCode.ERR_COOLDOWN_ACTIVE in dec_cd.rejection_codes

    flap_inc = _make_crashed_api_incident(flap_count=3)
    dec_flap = policy.evaluate(restart_prop, flap_inc)
    assert not dec_flap.approved
    assert PolicyRejectionCode.ERR_FLAPPING_DETECTED in dec_flap.rejection_codes
    assert PolicyRejectionCode.ERR_INCOMPATIBLE_FAULT_ACTION in dec_flap.rejection_codes

    store = PersistentStateStore(tmp_path / "state.json")
    with store.lock_unit("lab-api.service"):
        with pytest.raises(UnitLockError, match="currently locked"):
            with store.lock_unit("lab-api.service"):
                pass


def test_wp2_orchestrator_wal_hash_chain_rotation_and_toctou_abort(
    tmp_path: Path,
) -> None:
    cfg = _load_lab_cfg()
    audit_path = tmp_path / "audit.jsonl"
    esc_path = tmp_path / "escalations.jsonl"
    state_path = tmp_path / "state.json"

    now_dt = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)
    mono_val = [100.0]

    def fake_mono() -> float:
        mono_val[0] += 0.25
        return mono_val[0]

    # Set max_bytes=3500 with backup_count=3 so all 4 records are preserved across rotation
    recorder = AuditRecorder(
        audit_path, max_bytes=3500, backup_count=3, clock_utc=lambda: now_dt
    )
    esc_sink = EscalationSink(esc_path)
    state_store = PersistentStateStore(state_path)
    collector = IncidentCollector(cfg)

    orchestrator = IncidentOrchestrator(
        cfg,
        collector=collector,
        audit_recorder=recorder,
        escalation_sink=esc_sink,
        state_store=state_store,
        clock_utc=lambda: now_dt,
        monotonic_clock=fake_mono,
    )

    # Case 1: TOCTOU state drift between selection and execution aborts mutation & escalates
    initial_crashed = _make_crashed_api_incident("inc-toctou-1")
    drifted_healthy = _make_crashed_api_incident(
        "inc-toctou-1", api_active="active", api_probe_ok=True
    )

    audit_toctou = orchestrator.handle_incident(
        incident_id="inc-toctou-1",
        target_unit="lab-api.service",
        evidence_supplier=lambda _id, _u, _d, _r, _h, _e: initial_crashed,
        recollect_supplier=lambda _id, _u, _d, _r, _h, _e: drifted_healthy,
        post_evidence_supplier=lambda _p, _ex, _pre, _e: drifted_healthy,
    )
    assert audit_toctou.abstained is True
    assert audit_toctou.escalated is True
    assert len(esc_sink.emitted_alerts) == 1
    assert esc_sink.alert_log_path.is_file()

    # Case 2: Normal recovery on a second incident writes intent + completed WAL records
    state_store.seed_unit_state("lab-api.service", incident_id="inc-clean-2")
    now_dt_2 = now_dt + timedelta(minutes=10)
    recovered_state = _make_crashed_api_incident(
        "inc-clean-2", api_active="active", api_probe_ok=True
    )
    crashed_state = _make_crashed_api_incident("inc-clean-2")

    orchestrator_2 = IncidentOrchestrator(
        cfg,
        collector=collector,
        audit_recorder=recorder,
        escalation_sink=esc_sink,
        state_store=state_store,
        clock_utc=lambda: now_dt_2,
        monotonic_clock=fake_mono,
    )
    audit_clean = orchestrator_2.handle_incident(
        incident_id="inc-clean-2",
        target_unit="lab-api.service",
        evidence_supplier=lambda _id, _u, _d, _r, _h, _e: crashed_state,
        recollect_supplier=lambda _id, _u, _d, _r, _h, _e: crashed_state,
        post_evidence_supplier=lambda _p, _ex, _pre, _e: recovered_state,
    )
    assert audit_clean.abstained is False
    assert (
        audit_clean.verification_report is not None
        and audit_clean.verification_report.status
        == VerificationStatus.RECOVERED_CLEAN
    )

    ordered_files = recorder.ordered_log_paths()
    assert len(ordered_files) >= 2
    lines: list[str] = []
    for fpath in ordered_files:
        lines.extend(
            ln
            for ln in fpath.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        )
    assert len(lines) == 4
    stages = [AuditRecord.model_validate_json(ln).audit_stage for ln in lines]
    assert stages == ["intent", "completed", "intent", "completed"]

    ok_chain, count_checked, msg = AuditRecorder.verify_chain(ordered_files)
    assert ok_chain is True
    assert count_checked == 4
    assert "verified" in msg.lower()

    # Tampering with any record breaks verify_chain()
    tampered_path = tmp_path / "tampered.jsonl"
    tampered_lines = list(lines)
    tampered_lines[1] = tampered_lines[1].replace(
        '"controller_mode":"deterministic"', '"controller_mode":"tampered"'
    )
    tampered_path.write_text("\n".join(tampered_lines) + "\n", encoding="utf-8")
    ok_tamp, _, tamp_msg = AuditRecorder.verify_chain(tampered_path)
    assert ok_tamp is False
    assert "mismatch" in tamp_msg.lower()
