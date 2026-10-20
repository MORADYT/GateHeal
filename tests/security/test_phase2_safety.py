"""Phase 2 security, containment, and failure-handling tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from gateheal.collector import IncidentCollector
from gateheal.config import GateHealConfig, load_config
from gateheal.controller import ExecutionController, OutcomeVerifier
from gateheal.models import (
    ActionId,
    ActionProposal,
    FaultClass,
    IncidentRecord,
    PolicyRejectionCode,
    ServiceEvidence,
    VerificationStatus,
)
from gateheal.policy import MinimalImpactSelector, PolicyEngine
from gateheal.transport import (
    HostSafetyViolationError,
    LocalLabSubprocessTransport,
    SSHLabTransport,
    run_isolated_process_group,
)


def _load_lab_cfg() -> GateHealConfig:
    cfg_p = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_p)


def test_local_lab_transport_blocks_execution_on_omarchy_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GATEHEAL_INSIDE_LAB", raising=False)
    transport = LocalLabSubprocessTransport()
    with pytest.raises(HostSafetyViolationError):
        transport.run(["systemctl", "restart", "lab-api.service"], timeout_sec=2.0)


def test_ssh_transport_builds_isolated_batch_mode_argv() -> None:
    ssh = SSHLabTransport(host="127.0.0.1", port=2222, user="ubuntu")
    argv = ssh.build_ssh_argv(["systemctl", "restart", "lab-api.service"])
    assert argv[:4] == ("ssh", "-p", "2222", "-o")
    assert "BatchMode=yes" in argv
    assert argv[-2] == "ubuntu@127.0.0.1"
    assert argv[-1] == "systemctl restart lab-api.service"


def test_process_group_timeout_terminates_hung_subprocess() -> None:
    res = run_isolated_process_group(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_sec=0.2,
    )
    assert res.timed_out is True
    assert res.exit_code == -999
    assert "process group terminated" in res.stderr_excerpt


def test_collector_redacts_secrets_and_enforces_log_and_byte_limits() -> None:
    cfg = _load_lab_cfg()
    collector = IncidentCollector(cfg)

    noisy_logs = tuple(
        [
            "ERROR: upstream auth failed with api_key='AIzaSySecretKey1234567890'",
            "WARN: header Authorization: Bearer=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "INFO: db connect password=my_super_secret_password_123",
        ]
        + [f"log line {i}: " + ("X" * 400) for i in range(60)]
    )
    raw_services = {
        "lab-api.service": ServiceEvidence(
            unit_name="lab-api.service",
            active_state="failed",
            sub_state="failed",
            health_probe_ok=False,
            config_valid=True,
            sanitized_logs=noisy_logs,
        )
    }
    incident = collector.collect_simulated(
        incident_id="inc-sec-logs",
        target_unit="lab-api.service",
        simulated_services=raw_services,
    )
    saved_logs = incident.services["lab-api.service"].sanitized_logs

    assert len(saved_logs) <= cfg.budgets.max_log_lines
    joined = "\n".join(saved_logs)
    assert "AIzaSySecretKey1234567890" not in joined
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in joined
    assert "my_super_secret_password_123" not in joined
    assert "api_key='[REDACTED_SECRET]'" in joined
    assert "[TRUNCATED_MAX_BYTES_EXCEEDED]" in joined


def test_missing_config_evidence_blocks_mutating_actions() -> None:
    cfg = _load_lab_cfg()
    engine = PolicyEngine(cfg)

    incident = IncidentRecord(
        incident_id="inc-missing-ev",
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
                active_state="failed",
                sub_state="failed",
                health_probe_ok=False,
                config_valid=None,
            ),
        },
    )
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.90,
        rationale="Attempt restart without first validating config.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_PRECONDITION_FAILED in decision.rejection_codes


def test_verifier_detects_persistent_crash_recurrence_and_collateral_disruption() -> None:
    cfg = _load_lab_cfg()
    controller = ExecutionController(cfg)
    verifier = OutcomeVerifier(cfg)
    selector = MinimalImpactSelector(PolicyEngine(cfg))

    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.95,
        rationale="Restart crashed lab-api.service.",
    )
    exec_result = controller.execute(proposal)

    pre_incident = IncidentRecord(
        incident_id="inc-pre",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:00Z",
        prior_recovery_attempts=1,
        action_history=("restart_service:lab-api.service",),
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                n_restarts=1,
                health_probe_ok=False,
                config_valid=True,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
        },
    )

    # Case A: Service appears active briefly, but n_restarts incremented during soak
    post_recurrence = IncidentRecord(
        incident_id="inc-post-recur",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:05Z",
        services={
            **pre_incident.services,
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                n_restarts=2,
                health_probe_ok=True,
                config_valid=True,
            ),
        },
    )
    report_recur = verifier.verify(
        proposal, exec_result, post_recurrence, pre_incident=pre_incident
    )
    assert report_recur.status == VerificationStatus.NOT_RECOVERED

    # Next attempt on persistent failure must abstain, and verifier must report NOT_RECOVERED
    next_chosen, _ = selector.select([proposal], pre_incident)
    assert next_chosen.action_id == ActionId.ABSTAIN_AND_ESCALATE.value
    abstain_exec = controller.execute(next_chosen)
    abstain_report = verifier.verify(
        next_chosen, abstain_exec, pre_incident, pre_incident=pre_incident
    )
    assert abstain_report.status == VerificationStatus.NOT_RECOVERED
    assert not abstain_report.target_healthy

    # Case B: Target recovered cleanly, but downstream lab-worker.service failed
    post_collateral = IncidentRecord(
        incident_id="inc-post-collat",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:05Z",
        services={
            "lab-redis.service": pre_incident.services["lab-redis.service"],
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                n_restarts=1,
                health_probe_ok=True,
                config_valid=True,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="failed",
                sub_state="failed",
                health_probe_ok=False,
            ),
        },
    )
    report_collat = verifier.verify(
        proposal, exec_result, post_collateral, pre_incident=pre_incident
    )
    assert (
        report_collat.status
        == VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE
    )
    assert report_collat.collateral_failures == ("lab-worker.service",)
