"""WP2 and WP3 regression test suite (R1-R12 + WP3-fix invariants, zero xfail)."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from gateheal.actions import DEFAULT_ACTION_CATALOGUE
from gateheal.collector import IncidentCollector, redact_secrets_text
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
    PolicyDecision,
    PolicyRejectionCode,
    ServiceEvidence,
    VerificationStatus,
)
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.policy import PolicyEngine
from gateheal.state import PersistentStateStore, UnitLockError
from gateheal.transport import (
    EXPECTED_SENTINEL_TOKEN,
    HostSafetyViolationError,
    SSHLabTransport,
    TransportResult,
    run_isolated_process_group,
)


def _load_cfg() -> GateHealConfig:
    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_path)


def _make_incident(
    incident_id: str = "inc-reg-001",
    *,
    redis_active: str = "active",
    redis_probe: bool = True,
    api_active: str = "failed",
    api_probe: bool = False,
    api_cfg_valid: bool | None = True,
    worker_active: str = "active",
    worker_probe: bool = True,
    elapsed_sec: float = 0.0,
) -> IncidentRecord:
    return IncidentRecord(
        incident_id=incident_id,
        target_unit="lab-api.service",
        collected_at_utc="2026-10-22T12:00:00Z",
        elapsed_sec=elapsed_sec,
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state=redis_active,
                sub_state="running" if redis_active == "active" else "failed",
                result="success" if redis_active == "active" else "signal",
                health_probe_ok=redis_probe,
                config_valid=True,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state=api_active,
                sub_state="running" if api_active == "active" else "failed",
                result="success" if api_active == "active" else "signal",
                can_reload=True,
                health_probe_ok=api_probe,
                config_valid=api_cfg_valid,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state=worker_active,
                sub_state="running" if worker_active == "active" else "failed",
                result="success" if worker_active == "active" else "signal",
                health_probe_ok=worker_probe,
                config_valid=True,
            ),
        },
    )


def test_r1_verify_and_consume_capability_reruns_policy_evaluate_at_execution_time() -> None:
    """R1: Non-hashed incident fields (e.g. elapsed_sec exceeding budget) must block execution."""
    cfg = _load_cfg()
    policy = PolicyEngine(cfg)
    controller = ExecutionController(cfg, policy_engine=policy)

    inc_at_mint = _make_incident(elapsed_sec=1.0)
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed lab-api.",
    )
    cap = policy.mint_capability(proposal, inc_at_mint)

    # State hash is identical, but elapsed_sec now exceeds total_incident_timeout_sec (45s)
    inc_at_exec = _make_incident(elapsed_sec=44.5)
    with pytest.raises(PermissionError, match="ERR_TIME_BUDGET_EXCEEDED"):
        controller.execute(cap, current_incident=inc_at_exec)


def test_r2_capability_mac_enforces_expiry_timestamp() -> None:
    """R2: Expired AuthorizedActionCapability must be rejected at execution time."""
    cfg = _load_cfg()
    clock_now = [datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)]
    policy = PolicyEngine(cfg, clock_utc=lambda: clock_now[0], capability_ttl_sec=10.0)
    controller = ExecutionController(
        cfg, policy_engine=policy, clock_utc=lambda: clock_now[0]
    )

    inc = _make_incident()
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed lab-api.",
    )
    cap = policy.mint_capability(proposal, inc)

    # Advance controller clock past capability TTL (10s)
    clock_now[0] = clock_now[0] + timedelta(seconds=15)
    with pytest.raises(PermissionError, match="expired"):
        controller.execute(cap, current_incident=inc)


def test_r3_capability_mac_binds_proposal_and_decision_digest() -> None:
    """R3: Tampering with capability.proposal or capability.decision invalidates MAC."""
    cfg = _load_cfg()
    policy = PolicyEngine(cfg)
    controller = ExecutionController(cfg, policy_engine=policy)

    inc = _make_incident()
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Original rationale.",
    )
    cap = policy.mint_capability(proposal, inc)

    tampered_proposal = proposal.model_copy(
        update={"rationale": "Tampered rationale after minting."}
    )
    tampered_cap = cap.model_copy(update={"proposal": tampered_proposal})
    with pytest.raises(PermissionError, match="MAC verification failed"):
        controller.execute(tampered_cap, current_incident=inc)

    tampered_decision = PolicyDecision(
        approved=True,
        action_id=cap.action_id.value,
        target_unit=cap.target_unit,
        notes=("forged note",),
    )
    tampered_cap_2 = cap.model_copy(update={"decision": tampered_decision})
    with pytest.raises(PermissionError, match="MAC verification failed"):
        controller.execute(tampered_cap_2, current_incident=inc)


def test_r4_attempt_counters_and_action_history_are_keyed_by_incident_id(
    tmp_path: Path,
) -> None:
    """R4: A new incident_id after cooldown gets a fresh retry budget; cooldown/flap persist."""
    cfg = _load_cfg()
    store = PersistentStateStore(tmp_path / "state.json")
    t0 = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)

    # Exhaust recovery attempts on incident-A
    store.record_execution(
        incident_id="incident-A",
        unit_name="lab-api.service",
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        is_mutating=True,
        is_diagnostic=False,
        now_utc=t0,
        flap_window_sec=cfg.budgets.flap_window_sec,
        consumed_tokens=frozenset(),
    )

    state_a, _, _ = store.compute_unit_runtime_counters(
        "lab-api.service",
        now_utc=t0 + timedelta(seconds=60),
        flap_window_sec=cfg.budgets.flap_window_sec,
        incident_id="incident-A",
    )
    assert state_a.prior_recovery_attempts == 1
    assert state_a.action_history == ("restart_service:lab-api.service",)

    # A new incident-B after cooldown (60s > 30s) has 0 prior attempts for incident-B
    # while preserving the unit's flap count (1 mutation within 120s flap window).
    state_b, age_b, flap_b = store.compute_unit_runtime_counters(
        "lab-api.service",
        now_utc=t0 + timedelta(seconds=60),
        flap_window_sec=cfg.budgets.flap_window_sec,
        incident_id="incident-B",
    )
    assert state_b.prior_recovery_attempts == 0
    assert state_b.action_history == ()
    assert age_b == pytest.approx(60.0)
    assert flap_b == 1


def test_r5_orchestrator_escalates_on_not_recovered_uncertain_and_collateral(
    tmp_path: Path,
) -> None:
    """R5: EscalationAlert must be emitted when verification fails, times out, or has collateral."""
    cfg = _load_cfg()
    now_dt = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)
    esc_sink = EscalationSink(tmp_path / "escalations.jsonl")
    recorder = AuditRecorder(tmp_path / "audit.jsonl", clock_utc=lambda: now_dt)
    store = PersistentStateStore(tmp_path / "state.json")

    orchestrator = IncidentOrchestrator(
        cfg,
        collector=IncidentCollector(cfg),
        audit_recorder=recorder,
        escalation_sink=esc_sink,
        state_store=store,
        clock_utc=lambda: now_dt,
    )

    crashed = _make_incident("inc-r5-not-rec")
    # Post-state is still crashed -> VerificationStatus.NOT_RECOVERED
    audit_not_rec = orchestrator.handle_incident(
        incident_id="inc-r5-not-rec",
        target_unit="lab-api.service",
        evidence_supplier=lambda _id, _u, _d, _r, _h, _e: crashed,
        post_evidence_supplier=lambda _p, _ex, _pre, _e: crashed,
    )
    assert audit_not_rec.abstained is False
    assert (
        audit_not_rec.verification_report is not None
        and audit_not_rec.verification_report.status
        == VerificationStatus.NOT_RECOVERED
    )
    assert audit_not_rec.escalated is True
    assert len(esc_sink.emitted_alerts) == 1

    # Post-state has target up, but downstream worker crashed -> RECOVERED_WITH_COLLATERAL_FAILURE
    later_dt = now_dt + timedelta(minutes=5)
    orchestrator_collat = IncidentOrchestrator(
        cfg,
        collector=IncidentCollector(cfg),
        audit_recorder=recorder,
        escalation_sink=esc_sink,
        state_store=store,
        clock_utc=lambda: later_dt,
    )
    crashed_2 = _make_incident("inc-r5-collat")
    post_collat = _make_incident(
        "inc-r5-collat",
        api_active="active",
        api_probe=True,
        worker_active="failed",
        worker_probe=False,
    )
    audit_collat = orchestrator_collat.handle_incident(
        incident_id="inc-r5-collat",
        target_unit="lab-api.service",
        evidence_supplier=lambda _id, _u, _d, _r, _h, _e: crashed_2,
        post_evidence_supplier=lambda _p, _ex, _pre, _e: post_collat,
    )
    assert (
        audit_collat.verification_report is not None
        and audit_collat.verification_report.status
        == VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE
    )
    assert audit_collat.escalated is True
    assert len(esc_sink.emitted_alerts) == 2


def test_r6_dual_unit_locking_locks_mutated_upstream_unit(tmp_path: Path) -> None:
    """R6: Alerting lab-api mutating upstream lab-redis requires locking lab-redis."""
    cfg = _load_cfg()
    store = PersistentStateStore(tmp_path / "state.json")
    now_dt = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)

    orchestrator = IncidentOrchestrator(
        cfg,
        collector=IncidentCollector(cfg),
        audit_recorder=AuditRecorder(
            tmp_path / "audit.jsonl", clock_utc=lambda: now_dt
        ),
        escalation_sink=EscalationSink(tmp_path / "esc.jsonl"),
        state_store=store,
        clock_utc=lambda: now_dt,
    )
    s3_inc = _make_incident(
        "inc-r6-lock",
        redis_active="failed",
        redis_probe=False,
        api_active="active",
        api_probe=False,
    )

    # Holding lock on upstream lab-redis.service blocks handle_incident on lab-api.service
    with store.lock_unit("lab-redis.service"):
        with pytest.raises(UnitLockError, match="lab-redis.service"):
            orchestrator.handle_incident(
                incident_id="inc-r6-lock",
                target_unit="lab-api.service",
                evidence_supplier=lambda _id, _u, _d, _r, _h, _e: s3_inc,
                post_evidence_supplier=lambda _p, _ex, _pre, _e: s3_inc,
            )


def test_r7_state_persisted_before_subprocess_execution(tmp_path: Path) -> None:
    """R7: Attempt counter and consumed token must be flushed to state.json BEFORE transport.run."""
    cfg = _load_cfg()
    state_path = tmp_path / "state.json"
    store = PersistentStateStore(state_path)
    now_dt = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)
    observed_attempts_during_run: list[int] = []

    class _InspectingTransport:
        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            _ = (argv, timeout_sec)
            snap = store.load_snapshot()
            inc_state = snap.incidents.get("inc-r7-pre")
            if inc_state is not None:
                observed_attempts_during_run.append(
                    inc_state.prior_recovery_attempts
                )
            return TransportResult(exit_code=0, duration_sec=0.01)

    orchestrator = IncidentOrchestrator(
        cfg,
        transport=_InspectingTransport(),
        collector=IncidentCollector(cfg),
        audit_recorder=AuditRecorder(
            tmp_path / "audit.jsonl", clock_utc=lambda: now_dt
        ),
        escalation_sink=EscalationSink(tmp_path / "esc.jsonl"),
        state_store=store,
        clock_utc=lambda: now_dt,
    )
    crashed = _make_incident("inc-r7-pre")
    recovered = _make_incident("inc-r7-pre", api_active="active", api_probe=True)

    orchestrator.handle_incident(
        incident_id="inc-r7-pre",
        target_unit="lab-api.service",
        evidence_supplier=lambda _id, _u, _d, _r, _h, _e: crashed,
        post_evidence_supplier=lambda _p, _ex, _pre, _e: recovered,
    )
    assert observed_attempts_during_run == [1]


def test_r8_audit_rotation_eviction_preserves_anchor_and_verifies_chain(
    tmp_path: Path,
) -> None:
    """R8: Evicting the oldest rotated file writes .anchor so verify_chain(audit_path) succeeds."""
    cfg = _load_cfg()
    audit_path = tmp_path / "audit.jsonl"
    now_dt = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)
    # Very small max_bytes (600) and backup_count=1 forces multiple rotations and eviction
    recorder = AuditRecorder(
        audit_path, max_bytes=600, backup_count=1, clock_utc=lambda: now_dt
    )
    diag = DiagnosisEngine(cfg).diagnose(_make_incident())

    for idx in range(5):
        rec = AuditRecord(
            audit_stage="completed",
            incident_id=f"inc-rot-{idx}",
            recorded_at_utc=now_dt.isoformat(),
            controller_mode="deterministic",
            diagnosis=diag,
            evaluated_proposals=(),
            policy_decisions=(),
            abstained=True,
            escalated=True,
        )
        recorder.record(rec)

    assert audit_path.with_suffix(".anchor").is_file()
    ok, checked, msg = AuditRecorder.verify_chain(audit_path)
    assert ok is True, msg
    assert checked >= 2


def test_r9_verifier_does_not_flag_pre_existing_unhealthy_dependent_as_collateral() -> None:
    """R9: A dependent that was ALREADY unhealthy before execution is not collateral damage."""
    cfg = _load_cfg()
    verifier = OutcomeVerifier(cfg)

    # S3: lab-redis is failed, downstream lab-api is unhealthy BEFORE restarting lab-redis
    pre_s3 = _make_incident(
        "inc-r9",
        redis_active="failed",
        redis_probe=False,
        api_active="active",
        api_probe=False,
        worker_active="active",
        worker_probe=True,
    )
    # Suppose lab-redis recovers, and lab-api has not yet reconnected in the snapshot
    post_s3 = _make_incident(
        "inc-r9",
        redis_active="active",
        redis_probe=True,
        api_active="active",
        api_probe=False,
        worker_active="active",
        worker_probe=True,
    )
    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-redis.service",
        inferred_fault=FaultClass.DEPENDENCY_FAILURE,
        rationale="Restart failed lab-redis.",
    )
    exec_res = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-redis.service",
        argv=("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-redis.service"),
        exit_code=0,
        duration_sec=0.2,
    )
    report = verifier.verify(prop, exec_res, post_s3, pre_incident=pre_s3)
    assert "lab-api.service" not in report.collateral_failures
    assert report.status == VerificationStatus.RECOVERED_CLEAN


def test_r10_verifier_detects_transitive_2_hop_collateral_failure() -> None:
    """R10: Restarting lab-redis when 2-hop dependent lab-worker was healthy & then fails."""
    cfg = _load_cfg()
    verifier = OutcomeVerifier(cfg)

    pre_inc = _make_incident(
        "inc-r10",
        redis_active="failed",
        redis_probe=False,
        api_active="active",
        api_probe=False,
        worker_active="active",
        worker_probe=True,
    )
    post_inc = _make_incident(
        "inc-r10",
        redis_active="active",
        redis_probe=True,
        api_active="active",
        api_probe=True,
        worker_active="failed",
        worker_probe=False,
    )
    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-redis.service",
        inferred_fault=FaultClass.DEPENDENCY_FAILURE,
        rationale="Restart lab-redis.",
    )
    exec_res = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-redis.service",
        argv=("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-redis.service"),
        exit_code=0,
        duration_sec=0.2,
    )
    report = verifier.verify(prop, exec_res, post_inc, pre_incident=pre_inc)
    assert report.status == VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE
    assert report.collateral_failures == ("lab-worker.service",)


def test_r11_collector_redacts_multiline_pem_jwt_ghp_aws_secret_and_cookies() -> None:
    """R11: Multi-line PEM keys, JWTs, GitHub PATs, AWS secrets, and Cookies must be scrubbed."""
    cfg = _load_cfg()
    collector = IncidentCollector(cfg)

    jwt_sample = (
        "WARN: token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    multiline_logs = (
        "ERROR: TLS key dump: -----BEGIN RSA " + "PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEA7VJTUt9Us8cKjMzEfYyjiWA4R",
        "-----END RSA " + "PRIVATE KEY-----",
        jwt_sample,
        "WARN: github pat ghp_" + "1234567890abcdefghijklmnopqrstuvABCD",
        "ERROR: aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "INFO: private_key=super_secret_private_key_material_999",
        "WARN: Cookie: session_id=xyz987654321secret; theme=dark",
    )
    inc = collector.collect_simulated(
        incident_id="inc-r11",
        target_unit="lab-api.service",
        simulated_services={
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                health_probe_ok=False,
                config_valid=True,
                sanitized_logs=multiline_logs,
            )
        },
    )
    joined = "\n".join(inc.services["lab-api.service"].sanitized_logs)
    assert "MIIEpAIBAAKCAQEA7VJT" not in joined
    assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in joined
    assert ("ghp_" + "1234567890abcdefghijklmnopqrstuvABCD") not in joined
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in joined
    assert "super_secret_private_key_material_999" not in joined
    assert "xyz987654321secret" not in joined
    assert "[REDACTED_PEM_PRIVATE_KEY]" in joined
    assert "[REDACTED_JWT]" in joined
    assert "[REDACTED_GITHUB_TOKEN]" in joined
    assert "[REDACTED_COOKIE]" in joined
    redacted_gho = redact_secrets_text("gho_" + "1234567890abcdefghijklmnopqrstuvABCD")
    assert redacted_gho == "[REDACTED_GITHUB_TOKEN]"


def test_r12_hard_timeout_does_not_hang_when_grandchild_holds_pipe_in_new_session() -> None:
    """R12: If a timed-out process spawns a detached grandchild holding stdout open, run returns."""
    code = (
        "import os, subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
        "start_new_session=True); "
        "time.sleep(30)"
    )
    res = run_isolated_process_group(
        [sys.executable, "-c", code],
        timeout_sec=0.2,
        post_kill_communicate_timeout_sec=0.2,
    )
    assert res.timed_out is True
    assert res.exit_code == -999
    assert res.duration_sec < 2.5


def test_wp3_ssh_sentinel_verification_and_remote_timeout_handling() -> None:
    """WP3-fix: SSHLabTransport verifies remote sentinel and maps exit 124 to timed_out."""
    calls: list[tuple[str, ...]] = []

    def fake_runner(argv: Sequence[str], _timeout: float) -> TransportResult:
        cmd = tuple(argv)
        calls.append(cmd)
        if "cat /etc/gateheal-lab-sentinel" in cmd[-1]:
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=EXPECTED_SENTINEL_TOKEN + "\n",
            )
        return TransportResult(exit_code=124, duration_sec=5.0, stderr_excerpt="")

    ssh = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        use_remote_timeout=True,
        verify_remote_sentinel=True,
        runner=fake_runner,
    )
    res = ssh.run(["systemctl", "is-active", "lab-api.service"], timeout_sec=5.0)
    assert len(calls) == 2
    assert res.timed_out is True
    assert res.exit_code == -999

    # Bad sentinel blocks SSH execution
    bad_ssh = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        verify_remote_sentinel=True,
        runner=lambda _a, _t: TransportResult(
            exit_code=0, duration_sec=0.01, stdout_excerpt="WRONG_SENTINEL"
        ),
    )
    with pytest.raises(HostSafetyViolationError, match="sentinel verification"):
        bad_ssh.run(["systemctl", "is-active", "lab-api.service"], timeout_sec=5.0)


def test_wp3_h3_two_level_transitive_blast_radius_and_unhealthy_exclusion() -> None:
    """Kill mutation survivors on H3 two-level transitive BFS and unhealthy dependent exclusion."""
    cfg = _load_cfg()
    engine = PolicyEngine(cfg)

    # H3: Active degraded lab-redis -> healthy lab-api -> healthy lab-worker (B_dep = 2.0)
    h3_inc = IncidentRecord(
        incident_id="inc-h3",
        target_unit="lab-redis.service",
        collected_at_utc="2026-10-22T12:00:00Z",
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=False,
                config_valid=True,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
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
    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-redis.service",
        inferred_fault=FaultClass.DEGRADED_RUNNING,
        rationale="Restart degraded active redis.",
    )
    dec_h3 = engine.evaluate(prop, h3_inc)
    assert not dec_h3.approved
    assert PolicyRejectionCode.ERR_BLAST_RADIUS_EXCEEDED in dec_h3.rejection_codes
    assert any("2.00" in n for n in dec_h3.notes)

    # If direct dependent lab-api is UNHEALTHY, BFS stops at lab-api -> B_dep = 0.0 -> approved!
    unhealthy_dep_inc = h3_inc.model_copy(
        update={
            "services": {
                **h3_inc.services,
                "lab-api.service": ServiceEvidence(
                    unit_name="lab-api.service",
                    active_state="active",
                    sub_state="running",
                    health_probe_ok=False,
                    config_valid=True,
                ),
            }
        }
    )
    dec_unhealthy = engine.evaluate(prop, unhealthy_dep_inc)
    assert dec_unhealthy.approved


def test_wp3_collector_enforces_total_incident_time_budget() -> None:
    """WP3-fix #9: Collector stops running commands if incident time budget is exhausted."""
    cfg = _load_cfg()
    calls: list[tuple[str, ...]] = []

    class _CountingTransport:
        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            _ = timeout_sec
            calls.append(tuple(argv))
            return TransportResult(exit_code=0, duration_sec=0.01)

    collector = IncidentCollector(cfg)
    inc = collector.collect_from_transport(
        incident_id="inc-timeout-budget",
        target_unit="lab-api.service",
        transport=_CountingTransport(),
        elapsed_sec=cfg.budgets.total_incident_timeout_sec + 1.0,
    )
    assert calls == []
    assert inc.services["lab-api.service"].active_state == "unknown"


def test_wp3_sudo_argv_forbids_unprivileged_systemd_scope_wrapping() -> None:
    """WP3-fix #3: Mutating sudo -n commands are never wrapped in systemd-run --scope."""
    ssh = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        use_systemd_scope=True,
    )
    mut_argv = DEFAULT_ACTION_CATALOGUE[ActionId.RESTART_SERVICE].build_argv(
        "lab-api.service", None
    )
    ssh_cmd = ssh.build_ssh_argv(mut_argv)
    assert ssh_cmd[-1] == "sudo -n /usr/bin/systemctl restart lab-api.service"


def test_wp3_lab_s3_fault_injector_uses_sigkill_and_config_uses_module_validator() -> None:
    """WP3-fix #8 & #12: Verify phase1_lab.yaml config_check_argv and inject_fault.sh S3."""
    cfg = _load_cfg()
    api_argv = cfg.inventory.services["lab-api.service"].config_check_argv
    assert api_argv == (
        "/usr/bin/python3",
        "-m",
        "gateheal.lab_daemons",
        "--validate-config",
        "/etc/lab-api/config.yaml",
    )
    proc = subprocess.run(
        [sys.executable, *api_argv[1:]],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 65)

    inject_script = (
        Path(__file__).resolve().parents[2]
        / "lab"
        / "fault_injection"
        / "inject_fault.sh"
    ).read_text(encoding="utf-8")
    assert "systemctl kill -s SIGKILL lab-redis.service" in inject_script
