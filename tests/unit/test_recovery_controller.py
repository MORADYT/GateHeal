"""Unit tests for the end-to-end recovery controller and verifier."""

from __future__ import annotations

from pathlib import Path

from gateheal.config import GateHealConfig, load_config
from gateheal.controller import OutcomeVerifier
from gateheal.diagnosis import DiagnosisEngine
from gateheal.models import (
    ActionId,
    ActionProposal,
    ExecutionResult,
    FaultClass,
    IncidentRecord,
    ServiceEvidence,
    VerificationStatus,
)


def _load_lab_cfg() -> GateHealConfig:
    cfg_p = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_p)


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
    post_incident = IncidentRecord(
        incident_id="inc-ver-1",
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
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
        },
    )

    report = verifier.verify(proposal, exec_result, post_incident)
    assert report.status == VerificationStatus.NOT_RECOVERED
    assert not report.target_healthy
