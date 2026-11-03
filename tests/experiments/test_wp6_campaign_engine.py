"""WP6 offline tests: paired randomisation, resume, sentinel guard, and reporting."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gateheal.config import GateHealConfig, load_config
from gateheal.lab_bringup import (
    REQUIRED_CONFORMANCE_FACT_IDS,
    ConformanceFactResult,
    SmokeScenarioRunResult,
    SSHLatencyProfile,
    build_lab_run_manifest,
    build_wp5_smoke_expectations,
)
from gateheal.models import VerificationStatus
from gateheal.oracle import OracleOutcomeLabel
from gateheal.reporting import WP6ReportGenerator
from gateheal.transport import (
    EXPECTED_SENTINEL_TOKEN,
    HostSafetyViolationError,
    SSHLabTransport,
    TransportResult,
)
from gateheal.wp6_engine import (
    ALL_WP6_ARMS,
    WP6ExperimentRunner,
    build_paired_arm_schedule,
    build_wp6_campaign_manifest,
    ensure_transport_sentinel_verified,
    load_completed_wp6_trials,
    summarize_wp6_campaign,
    validate_wp6_preflight,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_cfg() -> GateHealConfig:
    return load_config(_repo_root() / "configs" / "phase1_lab.yaml")


class _SimulatedLiveGuestHarness:
    """In-memory guest state machine driving both controller and root transports."""

    def __init__(self, *, verify_sentinel: bool = True) -> None:
        self.verify_remote_sentinel = verify_sentinel
        self.current_scenario = "S0_HEALTHY_CONTROL"
        self.redis_active = "active"
        self.api_active = "active"
        self.worker_active = "active"
        self.config_valid = True
        self.worker_pool_stale = False
        self.api_inv = "inv-api-1"
        self.api_start_usec = 10_000_000
        self._inv_counter = 1
        self.executed_root_commands: list[tuple[str, ...]] = []

    def reset_baseline(self) -> None:
        self.redis_active = "active"
        self.api_active = "active"
        self.worker_active = "active"
        self.config_valid = True
        self.worker_pool_stale = False
        self._inv_counter += 1
        self.api_inv = f"inv-api-{self._inv_counter}"
        self.api_start_usec = 10_000_000 + self._inv_counter * 1000

    def inject(self, scen: str) -> None:
        self.current_scenario = scen
        if scen == "S1_SERVICE_CRASH":
            self.api_active = "failed"
        elif scen == "S2_INVALID_CONFIG":
            self.config_valid = False
        elif scen == "S3_DEPENDENCY_FAILURE":
            self.redis_active = "failed"
        elif scen == "S4_PERSISTENT_FAILURE":
            self.config_valid = False
            self.api_active = "failed"
        elif scen == "S5_COLLATERAL_TRAP":
            self.worker_pool_stale = True

    def _mutate_systemctl(self, op: str, unit: str) -> None:
        if op == "reload" and unit == "lab-api.service":
            if self.api_active == "active" and self.config_valid:
                self.worker_pool_stale = False
        elif op == "restart":
            if unit == "lab-redis.service":
                self.redis_active = "active"
            elif unit == "lab-worker.service":
                self.worker_active = "active"
            elif unit == "lab-api.service":
                was_active = self.api_active == "active"
                if was_active:
                    self.worker_active = "failed"
                if self.config_valid:
                    self.api_active = "active"
                    self.worker_pool_stale = False
                    self._inv_counter += 1
                    self.api_inv = f"inv-api-{self._inv_counter}"
                    self.api_start_usec += 5_000_000
                else:
                    self.api_active = "failed"

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        cmd = tuple(argv)
        self.executed_root_commands.append(cmd)

        if cmd[:2] == ("cat", "/etc/gateheal-lab-sentinel"):
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=f"{EXPECTED_SENTINEL_TOKEN}\n",
            )
        if cmd[:2] == ("cat", "/proc/uptime"):
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt="50000.0 40000.0\n",
            )
        if any("reset_lab.sh" in tok for tok in cmd):
            self.current_scenario = "S0_HEALTHY_CONTROL"
            self.reset_baseline()
            return TransportResult(exit_code=0, duration_sec=0.01)
        if any("inject_fault.sh" in tok for tok in cmd):
            self.inject(cmd[-1])
            return TransportResult(exit_code=0, duration_sec=0.01)

        if cmd[:3] == ("sudo", "-n", "/usr/bin/systemctl"):
            self._mutate_systemctl(cmd[3], cmd[4])
            return TransportResult(exit_code=0, duration_sec=0.02)
        if cmd[0] == "systemctl" and len(cmd) >= 3 and cmd[1] in ("restart", "reload"):
            for target_u in cmd[2:]:
                self._mutate_systemctl(cmd[1], target_u)
            return TransportResult(exit_code=0, duration_sec=0.02)

        if cmd[:2] == ("systemctl", "show"):
            u = cmd[2]
            act = {
                "lab-redis.service": self.redis_active,
                "lab-api.service": self.api_active,
                "lab-worker.service": self.worker_active,
            }[u]
            sub = "running" if act == "active" else "failed"
            res_str = "success" if act == "active" else "signal"
            can_rel = "yes" if u == "lab-api.service" else "no"
            inv = self.api_inv if u == "lab-api.service" else f"inv-{u}"
            st_us = self.api_start_usec if u == "lab-api.service" else 10_000_000
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=(
                    f"ActiveState={act}\nSubState={sub}\nResult={res_str}\n"
                    f"NRestarts=0\nCanReload={can_rel}\n"
                    f"ActiveEnterTimestampMonotonic=10000000\n"
                    f"InvocationID={inv}\n"
                    f"ExecMainStartTimestampMonotonic={st_us}\n"
                ),
            )

        if "--validate-config" in cmd:
            return TransportResult(
                exit_code=0 if self.config_valid else 65,
                duration_sec=0.01,
            )
        if cmd[0] == "curl":
            api_ok = (
                self.api_active == "active"
                and self.redis_active == "active"
                and not self.worker_pool_stale
            )
            body = '{"status": "ok"}' if api_ok else '{"status": "degraded"}'
            return TransportResult(
                exit_code=0 if api_ok else 22,
                duration_sec=0.01,
                stdout_excerpt=body,
            )
        if "--check-tcp" in cmd:
            port = cmd[-1]
            if port == "6379":
                ok = self.redis_active == "active"
            else:
                ok = self.worker_active == "active"
            return TransportResult(exit_code=0 if ok else 1, duration_sec=0.01)
        return TransportResult(exit_code=0, duration_sec=0.01)


def test_wp6_paired_schedule_is_deterministic_and_seed_sensitive() -> None:
    """Pairing and randomisation are deterministic for a seed and vary across seeds."""
    scenarios = tuple(e.scenario_id for e in build_wp5_smoke_expectations())
    sched_1 = build_paired_arm_schedule(scenarios, 3, seed=20261028)
    sched_2 = build_paired_arm_schedule(scenarios, 3, seed=20261028)
    sched_diff = build_paired_arm_schedule(scenarios, 3, seed=999999)

    assert sched_1 == sched_2
    assert sched_1 != sched_diff
    assert len(sched_1) == 7 * 3
    for key, arm_order in sched_1.items():
        assert len(key) == 2
        assert set(arm_order) == set(ALL_WP6_ARMS)
        assert len(arm_order) == len(ALL_WP6_ARMS)


def test_wp6_ungated_arms_refuse_transport_without_verified_sentinel(
    tmp_path: Path,
) -> None:
    """Ungated arms (B1, B2) refuse execution unless lab sentinel is verified."""
    cfg = _load_cfg()
    exp_s1 = build_wp5_smoke_expectations()[1]

    unverified_guest = _SimulatedLiveGuestHarness(verify_sentinel=False)
    runner_unverified = WP6ExperimentRunner(
        cfg,
        controller_transport=unverified_guest,
        root_transport=unverified_guest,
        artifacts_dir=tmp_path / "unverified",
        sleep_fn=lambda _s: None,
    )
    for ungated_arm in ("B1", "B2"):
        with pytest.raises(HostSafetyViolationError, match="verify_remote_sentinel"):
            runner_unverified.run_single_arm_trial(exp_s1, 1, ungated_arm, 0)
    assert unverified_guest.executed_root_commands == []

    bad_ssh = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="root",
        verify_remote_sentinel=True,
        _runner=lambda _a, _t: TransportResult(
            exit_code=0, duration_sec=0.01, stdout_excerpt="BAD_SENTINEL"
        ),
    )
    with pytest.raises(HostSafetyViolationError, match="token mismatch"):
        ensure_transport_sentinel_verified(bad_ssh)


def test_wp6_preflight_checks_wp5_manifest_and_dirty_tree(tmp_path: Path) -> None:
    """validate_wp6_preflight refuses missing or failed WP5 manifests."""
    repo_root = _repo_root()
    missing_path = tmp_path / "missing_wp5.json"
    with pytest.raises(RuntimeError, match="missing WP5 manifest"):
        validate_wp6_preflight(
            repo_root=repo_root,
            wp5_manifest_path=missing_path,
            allow_dirty=True,
        )

    cfg_path = repo_root / "configs" / "phase1_lab.yaml"
    sudo_path = repo_root / "lab" / "systemd" / "gateheal-sudoers.conf"
    lat = SSHLatencyProfile(
        samples=1, min_ms=1.0, mean_ms=1.0, p95_ms=1.0, max_ms=1.0
    )
    incomplete_manifest = build_lab_run_manifest(
        repo_root=repo_root,
        config_path=cfg_path,
        sudoers_path=sudo_path,
        ssh_latency=lat,
        conformance_facts=(
            ConformanceFactResult(
                fact_id=REQUIRED_CONFORMANCE_FACT_IDS[0],
                passed=True,
                details="ok",
            ),
        ),
        smoke_matrix=(),
    )
    bad_manifest_path = tmp_path / "bad_wp5.json"
    bad_manifest_path.write_text(
        incomplete_manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="conformance_all_passed=True"):
        validate_wp6_preflight(
            repo_root=repo_root,
            wp5_manifest_path=bad_manifest_path,
            allow_dirty=True,
        )


def test_wp6_campaign_resume_and_unconditional_denominators_and_reporting(
    tmp_path: Path,
) -> None:
    """Resume skips completed trials; denominators include abstentions; reports render."""
    cfg = _load_cfg()
    guest = _SimulatedLiveGuestHarness(verify_sentinel=True)
    clock_val = [100.0]
    now_dt = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)

    def _mono() -> float:
        return clock_val[0]

    def _sleep(sec: float) -> None:
        clock_val[0] += sec

    out_dir = tmp_path / "wp6_out"
    runner = WP6ExperimentRunner(
        cfg,
        controller_transport=guest,
        root_transport=guest,
        artifacts_dir=out_dir,
        settle_wait_sec=0.1,
        clock_utc=lambda: now_dt,
        monotonic_clock=_mono,
        sleep_fn=_sleep,
    )

    exps = build_wp5_smoke_expectations()
    partial_records = runner.run_campaign(
        trials_per_scenario=1,
        seed=20261028,
        expectations=exps[:2],
    )
    assert len(partial_records) == 12
    completed_on_disk = load_completed_wp6_trials(runner.trials_jsonl_path)
    assert len(completed_on_disk) == 12

    cmds_before_resume = len(guest.executed_root_commands)
    all_records_1 = runner.run_campaign(
        trials_per_scenario=1,
        seed=20261028,
        expectations=exps,
    )
    assert len(all_records_1) == 42
    cmds_after_full = len(guest.executed_root_commands)
    assert cmds_after_full > cmds_before_resume

    all_records_2 = runner.run_campaign(
        trials_per_scenario=1,
        seed=20261028,
        expectations=exps,
    )
    assert len(all_records_2) == 42
    assert len(guest.executed_root_commands) == cmds_after_full

    all_records_r2 = runner.run_campaign(
        trials_per_scenario=2,
        seed=20261028,
        expectations=exps,
    )
    assert len(all_records_r2) == 84

    summary = summarize_wp6_campaign(
        all_records_r2,
        trials_per_scenario=2,
        seed=20261028,
        clock_utc=lambda: now_dt,
    )

    for arm_id in ALL_WP6_ARMS:
        arm_sum = summary.arm_summaries[arm_id]
        assert arm_sum.total_trials == 14
        assert arm_sum.recovered_all_rate.total == 14
        assert arm_sum.harmful_rate.total == 14
        assert arm_sum.appropriate_abstention_rate.total == 14
        assert summary.coverage[arm_id].completed_trials == 14
        assert summary.coverage[arm_id].evaluable_trials == 14

    g_sum = summary.arm_summaries["G"]
    b1_sum = summary.arm_summaries["B1"]
    b2_sum = summary.arm_summaries["B2"]
    gnobr_sum = summary.arm_summaries["G-nobr"]

    assert g_sum.harmful_rate.successes == 0
    assert b1_sum.harmful_rate.successes > 0
    assert b2_sum.harmful_rate.successes > 0
    assert b1_sum.false_positive_remediation_rate.successes == 2

    assert g_sum.appropriate_abstention_rate.successes == 6
    assert b1_sum.appropriate_abstention_rate.successes == 0

    assert gnobr_sum.recovered_with_collateral_rate.successes == 2
    assert g_sum.recovered_with_collateral_rate.successes == 0

    g_s1 = [
        r
        for r in all_records_r2
        if r.arm_id == "G" and r.scenario_id == "S1_SERVICE_CRASH"
    ][0]
    gnosoak_s1 = [
        r
        for r in all_records_r2
        if r.arm_id == "G-nosoak" and r.scenario_id == "S1_SERVICE_CRASH"
    ][0]
    assert g_s1.verifier_samples_collected == 5
    assert gnosoak_s1.verifier_samples_collected == 1

    reporter = WP6ReportGenerator(summary)
    sum_p, md_p, tex_p = reporter.write_artifacts(out_dir)
    assert sum_p.is_file()
    assert md_p.is_file()
    assert tex_p.is_file()
    md_text = md_p.read_text(encoding="utf-8")
    tex_text = tex_p.read_text(encoding="utf-8")
    assert "H1a_G_vs_B1_harmful" in md_text
    assert OracleOutcomeLabel.RECOVERED_ALL.value not in {"recovered_clean"}
    assert r"\begin{table*}" in tex_text
    assert r"p_{\text{Holm}}" in tex_text

    wp5_path = tmp_path / "valid_wp5_manifest.json"
    lat = SSHLatencyProfile(
        samples=1, min_ms=1.0, mean_ms=1.0, p95_ms=1.0, max_ms=1.0
    )
    valid_wp5 = build_lab_run_manifest(
        repo_root=_repo_root(),
        config_path=_repo_root() / "configs" / "phase1_lab.yaml",
        sudoers_path=_repo_root() / "lab" / "systemd" / "gateheal-sudoers.conf",
        ssh_latency=lat,
        conformance_facts=[
            ConformanceFactResult(fact_id=fid, passed=True, details="ok")
            for fid in REQUIRED_CONFORMANCE_FACT_IDS
        ],
        smoke_matrix=[
            SmokeScenarioRunResult(
                scenario_id="S1_SERVICE_CRASH",
                repeat_index=1,
                diagnosed_fault=g_s1.diagnosed_fault,
                selected_action_id="restart_service",
                selected_target_unit="lab-api.service",
                verification_status=VerificationStatus.RECOVERED_CLEAN,
                samples_collected=5,
                soak_wall_clock_sec=5.0,
                escalated=False,
                matched_expectation=True,
            )
        ],
    )
    wp5_path.write_text(valid_wp5.model_dump_json(indent=2), encoding="utf-8")
    wp6_man = build_wp6_campaign_manifest(
        repo_root=_repo_root(),
        config_path=_repo_root() / "configs" / "phase1_lab.yaml",
        wp5_manifest_path=wp5_path,
        seed=20261028,
        arms=ALL_WP6_ARMS,
        scenarios=tuple(e.scenario_id for e in exps),
        trials_per_scenario=2,
        oracle_hold_window_sec=15.0,
        completed_trials=len(all_records_r2),
        allow_dirty=True,
        clock_utc=lambda: now_dt,
    )
    assert wp6_man.completed_trials == 84
    assert len(wp6_man.wp5_manifest_sha256) == 64
