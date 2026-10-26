"""Phase 2 security regression and safety constraint test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from gateheal.config import GateHealConfig, load_config
from gateheal.models import (
    ActionId,
    ActionProposal,
    FaultClass,
    IncidentRecord,
    ServiceEvidence,
)
from gateheal.policy import PolicyEngine
from gateheal.transport import (
    EXPECTED_SENTINEL_TOKEN,
    HostSafetyViolationError,
    LocalLabSubprocessTransport,
    SSHLabTransport,
)


def _load_cfg() -> GateHealConfig:
    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_path)


def test_transport_rejects_non_loopback_hosts() -> None:
    """Verify SSHLabTransport strictly refuses non-loopback remote endpoints."""
    with pytest.raises(HostSafetyViolationError):
        SSHLabTransport(host="192.168.1.100", port=22, user="ubuntu")


def test_local_transport_rejects_host_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify LocalLabSubprocessTransport refuses execution on host workstation."""
    monkeypatch.delenv("GATEHEAL_INSIDE_LAB", raising=False)
    transport = LocalLabSubprocessTransport()
    with pytest.raises(HostSafetyViolationError):
        transport.run(("true",), timeout_sec=1.0)


def test_policy_engine_rejects_unregistered_actions() -> None:
    """Verify PolicyEngine rejects unregistered action IDs immediately."""
    cfg = _load_cfg()
    policy = PolicyEngine(cfg)
    incident = IncidentRecord(
        incident_id="inc-sec-01",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-23T12:00:00Z",
        services={
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                health_probe_ok=False,
                config_valid=True,
            )
        },
    )
    proposal = ActionProposal(
        action_id="malicious_unregistered_shell_exec",
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Attempting unapproved shell command execution.",
    )
    decision = policy.evaluate(proposal, incident)
    assert decision.approved is False
    assert "ERR_UNREGISTERED_ACTION" in [
        c.value for c in decision.rejection_codes
    ]
