"""WP4 unit and scripted fake-transport tests for multi-sample soak polling and oracle."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from pydantic import ValidationError

from gateheal.config import GateHealConfig, load_config
from gateheal.controller import OutcomeVerifier
from gateheal.models import (
    ActionId,
    ActionProposal,
    AuthorizedActionCapability,
    ExecutionResult,
    FaultClass,
    IncidentRecord,
    PolicyDecision,
    ServiceEvidence,
    VerificationStatus,
)
from gateheal.state import PersistentStateStore
from gateheal.transport import TransportResult, run_isolated_process_group


def _load_cfg() -> GateHealConfig:
    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_path)


def _make_pre_incident() -> IncidentRecord:
    return IncidentRecord(
        incident_id="inc-wp4-001",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-23T12:00:00Z",
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
                config_valid=True,
                invocation_id="inv-redis-1",
                exec_main_start_timestamp_usec=10_000_000,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                result="signal",
                n_restarts=0,
                can_reload=True,
                health_probe_ok=False,
                config_valid=True,
                invocation_id="inv-api-old",
                exec_main_start_timestamp_usec=20_000_000,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
                config_valid=True,
                invocation_id="inv-worker-1",
                exec_main_start_timestamp_usec=30_000_000,
            ),
        },
    )


class _ScriptedSoakTransport:
    """Scripted fake transport tracking soak sample index (1..N) across 5s soak."""

    def __init__(
        self,
        sample_behavior: Callable[[int, tuple[str, ...]], TransportResult],
    ) -> None:
        self._sample_behavior = sample_behavior
        self.sample_index = 0
        self.commands: list[tuple[str, ...]] = []

    def advance_sample(self) -> None:
        self.sample_index += 1

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        cmd = tuple(argv)
        self.commands.append(cmd)
        return self._sample_behavior(self.sample_index, cmd)


def _make_clock_and_sleep(
    transport: _ScriptedSoakTransport,
) -> tuple[Callable[[], float], Callable[[float], None], list[float]]:
    now_mono = [100.0]
    slept: list[float] = []

    def fake_mono() -> float:
        return now_mono[0]

    def fake_sleep(sec: float) -> None:
        now_mono[0] += sec
        slept.append(sec)
        transport.advance_sample()

    return fake_mono, fake_sleep, slept


def test_pre_wp4_capability_requires_explicit_expires_at_and_seed_requires_incident_id(
    tmp_path: Path,
) -> None:
    """Pre-WP4 #3: expires_at_utc has no 2099 default; seed_unit_state requires incident_id."""
    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed service.",
    )
    dec = PolicyDecision(
        approved=True,
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
    )

    with pytest.raises(ValidationError):
        AuthorizedActionCapability.model_validate(
            {
                "capability_id": "cap-no-expiry",
                "incident_id": "inc-1",
                "action_id": ActionId.RESTART_SERVICE,
                "target_unit": "lab-api.service",
                "proposal": prop,
                "decision": dec,
                "state_hash": "a" * 64,
                "issued_at_utc": "2026-10-23T12:00:00Z",
                "mac_signature": "b" * 64,
            }
        )

    store = PersistentStateStore(tmp_path / "state.json")
    with pytest.raises(TypeError):
        store.seed_unit_state("lab-api.service")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="non-empty incident_id"):
        store.seed_unit_state("lab-api.service", incident_id="   ")


def test_wp4_1_clean_recovery_across_5_soak_samples() -> None:
    """T_WP4_1: All 5 soak samples healthy -> RECOVERED_CLEAN with measured unavailability."""
    cfg = _load_cfg()
    pre_inc = _make_pre_incident()

    def clean_behavior(_sample_idx: int, cmd: tuple[str, ...]) -> TransportResult:
        if cmd[:2] == ("systemctl", "show"):
            unit = cmd[2]
            inv = "inv-api-new" if unit == "lab-api.service" else f"inv-{unit}"
            start_us = 50_000_000 if unit == "lab-api.service" else 10_000_000
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=(
                    "ActiveState=active\nSubState=running\nResult=success\n"
                    f"NRestarts=0\nCanReload=yes\nInvocationID={inv}\n"
                    f"ExecMainStartTimestampMonotonic={start_us}\n"
                ),
            )
        return TransportResult(exit_code=0, duration_sec=0.01, stdout_excerpt="ok")

    transport = _ScriptedSoakTransport(clean_behavior)
    mono_fn, sleep_fn, slept = _make_clock_and_sleep(transport)
    verifier = OutcomeVerifier(cfg, monotonic_clock=mono_fn, sleep_fn=sleep_fn)

    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed lab-api.",
    )
    exec_res = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-api.service",
        argv=("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-api.service"),
        exit_code=0,
        duration_sec=0.2,
    )

    report, _ = verifier.verify_with_transport(prop, exec_res, pre_inc, transport)
    assert report.status == VerificationStatus.RECOVERED_CLEAN
    assert report.target_healthy is True
    assert report.samples_collected == 5
    assert slept == [1.0, 1.0, 1.0, 1.0, 1.0]
    assert report.first_healthy_at_sec == pytest.approx(1.0)
    assert report.first_failed_at_sec is None
    assert report.measured_unavailability_sec == pytest.approx(1.0)
    assert report.collateral_failures == ()


def test_wp4_2_recovery_then_crash_at_t_2s_with_nrestarts_zero() -> None:
    """T_WP4_2: Healthy at t=1s, crashes at t=2s (Restart=no, NRestarts=0) -> NOT_RECOVERED."""
    cfg = _load_cfg()
    pre_inc = _make_pre_incident()

    def crash_at_2s(sample_idx: int, cmd: tuple[str, ...]) -> TransportResult:
        if cmd[:2] == ("systemctl", "show"):
            unit = cmd[2]
            if unit == "lab-api.service" and sample_idx >= 2:
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=failed\nSubState=failed\nResult=signal\n"
                        "NRestarts=0\nCanReload=yes\nInvocationID=inv-api-new\n"
                        "ExecMainStartTimestampMonotonic=50000000\n"
                    ),
                )
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=(
                    "ActiveState=active\nSubState=running\nResult=success\n"
                    "NRestarts=0\nCanReload=yes\nInvocationID=inv-api-new\n"
                    "ExecMainStartTimestampMonotonic=50000000\n"
                ),
            )
        if cmd[0] == "curl" and sample_idx >= 2:
            return TransportResult(exit_code=22, duration_sec=0.01)
        return TransportResult(exit_code=0, duration_sec=0.01)

    transport = _ScriptedSoakTransport(crash_at_2s)
    mono_fn, sleep_fn, _ = _make_clock_and_sleep(transport)
    verifier = OutcomeVerifier(cfg, monotonic_clock=mono_fn, sleep_fn=sleep_fn)

    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed lab-api.",
    )
    exec_res = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-api.service",
        argv=("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-api.service"),
        exit_code=0,
        duration_sec=0.2,
    )

    report, _ = verifier.verify_with_transport(prop, exec_res, pre_inc, transport)
    assert report.status == VerificationStatus.NOT_RECOVERED
    assert report.target_healthy is False
    assert report.first_healthy_at_sec == pytest.approx(1.0)
    assert report.first_failed_at_sec == pytest.approx(2.0)
    assert report.measured_unavailability_sec == pytest.approx(5.0)


def test_wp4_3_flapping_health_and_mid_soak_invocation_id_or_timestamp_change() -> None:
    """T_WP4_3: active->failed->active or mid-soak InvocationID change -> NOT_RECOVERED."""
    cfg = _load_cfg()
    pre_inc = _make_pre_incident()

    def flap_and_respawn(sample_idx: int, cmd: tuple[str, ...]) -> TransportResult:
        if cmd[:2] == ("systemctl", "show"):
            unit = cmd[2]
            if unit == "lab-api.service":
                if sample_idx == 1:
                    return TransportResult(
                        exit_code=0,
                        duration_sec=0.01,
                        stdout_excerpt=(
                            "ActiveState=active\nSubState=running\nResult=success\n"
                            "NRestarts=0\nCanReload=yes\nInvocationID=inv-run-1\n"
                            "ExecMainStartTimestampMonotonic=50000000\n"
                        ),
                    )
                if sample_idx == 2:
                    return TransportResult(
                        exit_code=0,
                        duration_sec=0.01,
                        stdout_excerpt=(
                            "ActiveState=failed\nSubState=failed\nResult=signal\n"
                            "NRestarts=0\nCanReload=yes\nInvocationID=inv-run-1\n"
                            "ExecMainStartTimestampMonotonic=50000000\n"
                        ),
                    )
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=active\nSubState=running\nResult=success\n"
                        "NRestarts=0\nCanReload=yes\nInvocationID=inv-run-2\n"
                        "ExecMainStartTimestampMonotonic=53000000\n"
                    ),
                )
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=(
                    "ActiveState=active\nSubState=running\nResult=success\n"
                    "NRestarts=0\nCanReload=no\nInvocationID=inv-other\n"
                    "ExecMainStartTimestampMonotonic=10000000\n"
                ),
            )
        if cmd[0] == "curl" and sample_idx == 2:
            return TransportResult(exit_code=22, duration_sec=0.01)
        return TransportResult(exit_code=0, duration_sec=0.01)

    transport = _ScriptedSoakTransport(flap_and_respawn)
    mono_fn, sleep_fn, _ = _make_clock_and_sleep(transport)
    verifier = OutcomeVerifier(cfg, monotonic_clock=mono_fn, sleep_fn=sleep_fn)

    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed lab-api.",
    )
    exec_res = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-api.service",
        argv=("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-api.service"),
        exit_code=0,
        duration_sec=0.2,
    )

    report, _ = verifier.verify_with_transport(prop, exec_res, pre_inc, transport)
    assert report.status == VerificationStatus.NOT_RECOVERED
    assert report.target_healthy is False
    assert report.first_healthy_at_sec == pytest.approx(1.0)
    assert report.first_failed_at_sec == pytest.approx(2.0)


def test_wp4_4_probe_timeout_mid_soak_returns_outcome_uncertain() -> None:
    """T_WP4_4: Probe timing out at sample 3 (t=3s) -> OUTCOME_UNCERTAIN."""
    cfg = _load_cfg()
    pre_inc = _make_pre_incident()

    def timeout_at_sample_3(sample_idx: int, cmd: tuple[str, ...]) -> TransportResult:
        if cmd[0] == "curl" and sample_idx == 3:
            return TransportResult(
                exit_code=-999,
                timed_out=True,
                duration_sec=2.0,
                stderr_excerpt="curl timed out",
            )
        if cmd[:2] == ("systemctl", "show"):
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=(
                    "ActiveState=active\nSubState=running\nResult=success\n"
                    "NRestarts=0\nCanReload=yes\nInvocationID=inv-api-1\n"
                    "ExecMainStartTimestampMonotonic=50000000\n"
                ),
            )
        return TransportResult(exit_code=0, duration_sec=0.01)

    transport = _ScriptedSoakTransport(timeout_at_sample_3)
    mono_fn, sleep_fn, _ = _make_clock_and_sleep(transport)
    verifier = OutcomeVerifier(cfg, monotonic_clock=mono_fn, sleep_fn=sleep_fn)

    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed lab-api.",
    )
    exec_res = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-api.service",
        argv=("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-api.service"),
        exit_code=0,
        duration_sec=0.2,
    )

    report, _ = verifier.verify_with_transport(prop, exec_res, pre_inc, transport)
    assert report.status == VerificationStatus.OUTCOME_UNCERTAIN
    assert report.target_healthy is False
    assert report.samples_collected == 2
    assert "sample 3" in report.details.lower()


def test_wp4_5_dependent_failing_late_at_t_4s_reports_collateral_failure() -> None:
    """T_WP4_5: Target stays up, but lab-worker fails at sample 4 (t=4s) -> collateral failure."""
    cfg = _load_cfg()
    pre_inc = _make_pre_incident()

    def worker_fails_at_4s(sample_idx: int, cmd: tuple[str, ...]) -> TransportResult:
        if cmd[:2] == ("systemctl", "show"):
            unit = cmd[2]
            if unit == "lab-worker.service" and sample_idx >= 4:
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=failed\nSubState=failed\nResult=exit-code\n"
                        "NRestarts=0\nCanReload=no\nInvocationID=inv-worker-1\n"
                        "ExecMainStartTimestampMonotonic=30000000\n"
                    ),
                )
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=(
                    "ActiveState=active\nSubState=running\nResult=success\n"
                    "NRestarts=0\nCanReload=yes\nInvocationID=inv-ok\n"
                    "ExecMainStartTimestampMonotonic=50000000\n"
                ),
            )
        if "--check-tcp" in cmd and "8081" in cmd and sample_idx >= 4:
            return TransportResult(exit_code=1, duration_sec=0.01)
        return TransportResult(exit_code=0, duration_sec=0.01)

    transport = _ScriptedSoakTransport(worker_fails_at_4s)
    mono_fn, sleep_fn, _ = _make_clock_and_sleep(transport)
    verifier = OutcomeVerifier(cfg, monotonic_clock=mono_fn, sleep_fn=sleep_fn)

    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed lab-api.",
    )
    exec_res = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-api.service",
        argv=("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-api.service"),
        exit_code=0,
        duration_sec=0.2,
    )

    report, _ = verifier.verify_with_transport(prop, exec_res, pre_inc, transport)
    assert report.status == VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE
    assert report.target_healthy is True
    assert report.collateral_failures == ("lab-worker.service",)
    assert report.samples_collected == 5


def test_wp4_6_hung_action_command_marks_outcome_uncertain_with_zero_samples() -> None:
    """T_WP4_6: Hung action command killed by timeout -> OUTCOME_UNCERTAIN, 0 soak samples."""
    cfg = _load_cfg()
    pre_inc = _make_pre_incident()

    hung_transport_res = run_isolated_process_group(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_sec=0.15,
    )
    assert hung_transport_res.timed_out is True

    exec_res = ExecutionResult(
        action_id=ActionId.RESTART_SERVICE,
        target_unit="lab-api.service",
        argv=("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-api.service"),
        exit_code=hung_transport_res.exit_code,
        timed_out=hung_transport_res.timed_out,
        duration_sec=hung_transport_res.duration_sec,
        stderr_excerpt=hung_transport_res.stderr_excerpt,
    )
    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart hung service.",
    )

    transport = _ScriptedSoakTransport(
        lambda _i, _c: TransportResult(exit_code=0, duration_sec=0.01)
    )
    verifier = OutcomeVerifier(cfg)
    report, _ = verifier.verify_with_transport(prop, exec_res, pre_inc, transport)
    assert report.status == VerificationStatus.OUTCOME_UNCERTAIN
    assert report.target_healthy is False
    assert report.soak_duration_sec == 0.0
    assert report.samples_collected == 0
    assert transport.commands == []
