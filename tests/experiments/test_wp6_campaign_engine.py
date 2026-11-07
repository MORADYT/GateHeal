"""WP6 offline tests: engine semantics, pre-registered statistics wiring and the report.

The fake guest is driven in oracle inline mode (`oracle_background=False`): the oracle samples
on the fake clock, so these tests are deterministic. The background monitor is covered by the
oracle tests; live runs use it.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gateheal.config import GateHealConfig, load_config
from gateheal.lab_bringup import (
    REQUIRED_CONFORMANCE_FACT_IDS,
    ConformanceFactResult,
    SmokeMatrixExpectation,
    SmokeScenarioRunResult,
    SSHLatencyProfile,
    build_lab_run_manifest,
    build_wp5_smoke_expectations,
)
from gateheal.models import VerificationStatus
from gateheal.oracle import OracleOutcomeLabel
from gateheal.reporting import WP6ReportGenerator, render_markdown_table
from gateheal.transport import (
    EXPECTED_SENTINEL_TOKEN,
    HostSafetyViolationError,
    SSHLabTransport,
    TransportResult,
)
from gateheal.wp6_engine import (
    ALL_WP6_ARMS,
    GATEHEAL_ARMS,
    GATEHEAL_ONLY_SCENARIOS,
    H2_NON_INFERIORITY_MARGIN,
    NON_EVALUABLE_KEY,
    S5B_SCENARIO,
    WP6ExperimentRunner,
    WP6TrialRecord,
    append_wp6_trial_record,
    arms_for_scenario,
    build_paired_arm_schedule,
    build_wp6_campaign_manifest,
    count_planned_trials,
    ensure_transport_sentinel_verified,
    load_completed_wp6_trials,
    summarize_wp6_campaign,
    validate_wp6_preflight,
)

NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)


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



class _ObservationFaultingRoot:
    """Root-transport facade that can fail the oracle's /healthz probe (exit 255)."""

    def __init__(self, guest: _SimulatedLiveGuestHarness) -> None:
        self._guest = guest
        self.verify_remote_sentinel = guest.verify_remote_sentinel
        self.fail_oracle_probes = 0
        self.oracle_probe_failures_injected = 0

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        cmd = tuple(argv)
        if cmd[0] == "curl" and "--max-time" in cmd and self.fail_oracle_probes != 0:
            if self.fail_oracle_probes > 0:
                self.fail_oracle_probes -= 1
            self.oracle_probe_failures_injected += 1
            return TransportResult(exit_code=255, duration_sec=0.01)
        return self._guest.run(cmd, timeout_sec)


class _Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def mono(self) -> float:
        return self.value

    def sleep(self, sec: float) -> None:
        self.value += sec


def _make_runner(
    tmp_path: Path,
    *,
    guest: _SimulatedLiveGuestHarness | None = None,
    root: object | None = None,
    max_trial_attempts: int = 3,
    name: str = "out",
) -> tuple[WP6ExperimentRunner, _SimulatedLiveGuestHarness]:
    guest = guest if guest is not None else _SimulatedLiveGuestHarness()
    clock = _Clock()
    runner = WP6ExperimentRunner(
        _load_cfg(),
        controller_transport=guest,
        root_transport=root if root is not None else guest,  # type: ignore[arg-type]
        artifacts_dir=tmp_path / name,
        oracle_background=False,
        settle_wait_sec=0.1,
        max_trial_attempts=max_trial_attempts,
        clock_utc=lambda: NOW,
        monotonic_clock=clock.mono,
        sleep_fn=clock.sleep,
    )
    return runner, guest


def _exp(scenario_id: str) -> SmokeMatrixExpectation:
    return next(e for e in build_wp5_smoke_expectations() if e.scenario_id == scenario_id)


def _by(records: Sequence[WP6TrialRecord]) -> dict[tuple[str, str], WP6TrialRecord]:
    return {(r.scenario_id, r.arm_id): r for r in records if r.repeat_index == 1}


@pytest.fixture(scope="module")
def full_campaign(tmp_path_factory: pytest.TempPathFactory) -> tuple[WP6TrialRecord, ...]:
    """One offline repeat of every scenario for every eligible arm (shared by several tests)."""
    runner, _ = _make_runner(tmp_path_factory.mktemp("wp6_full"))
    return runner.run_campaign(trials_per_scenario=2, seed=20261028)


def test_wp6_paired_schedule_is_deterministic_and_seed_sensitive() -> None:
    """Pairing and randomisation are deterministic for a seed and vary across seeds."""
    scenarios = tuple(e.scenario_id for e in build_wp5_smoke_expectations())
    sched_1 = build_paired_arm_schedule(scenarios, 3, seed=20261028)
    sched_2 = build_paired_arm_schedule(scenarios, 3, seed=20261028)
    sched_diff = build_paired_arm_schedule(scenarios, 3, seed=999999)

    assert sched_1 == sched_2
    assert sched_1 != sched_diff
    assert len(sched_1) == 7 * 3
    for arm_order in sched_1.values():
        assert set(arm_order) == set(ALL_WP6_ARMS)
        assert len(arm_order) == len(ALL_WP6_ARMS)


def test_wp6_s5b_is_gateheal_family_only() -> None:
    """S5B differs from S5 only in controller state, so baselines never run it."""
    assert GATEHEAL_ONLY_SCENARIOS == {S5B_SCENARIO}
    assert arms_for_scenario(S5B_SCENARIO, ALL_WP6_ARMS) == tuple(
        a for a in ALL_WP6_ARMS if a in GATEHEAL_ARMS
    )
    assert arms_for_scenario("S1_SERVICE_CRASH", ALL_WP6_ARMS) == ALL_WP6_ARMS
    scenarios = tuple(e.scenario_id for e in build_wp5_smoke_expectations())
    assert count_planned_trials(scenarios, ALL_WP6_ARMS, 20) == (6 * 6 + 3) * 20


def test_wp6_ungated_arms_refuse_transport_without_verified_sentinel(tmp_path: Path) -> None:
    """Ungated arms (B1, B2) refuse execution unless lab sentinel is verified."""
    unverified = _SimulatedLiveGuestHarness(verify_sentinel=False)
    runner, _ = _make_runner(tmp_path, guest=unverified)
    for ungated_arm in ("B1", "B2"):
        with pytest.raises(HostSafetyViolationError, match="verify_remote_sentinel"):
            runner.run_single_arm_trial(_exp("S1_SERVICE_CRASH"), 1, ungated_arm, 0)
    assert unverified.executed_root_commands == []

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


def test_wp6_baselines_cannot_run_s5b(tmp_path: Path) -> None:
    runner, _ = _make_runner(tmp_path)
    with pytest.raises(ValueError, match="GateHeal-family"):
        runner.run_single_arm_trial(_exp(S5B_SCENARIO), 1, "B1", 0)


def test_wp6_preflight_checks_wp5_manifest_and_dirty_tree(tmp_path: Path) -> None:
    """validate_wp6_preflight refuses missing or failed WP5 manifests."""
    repo_root = _repo_root()
    with pytest.raises(RuntimeError, match="missing WP5 manifest"):
        validate_wp6_preflight(
            repo_root=repo_root, wp5_manifest_path=tmp_path / "missing.json", allow_dirty=True
        )
    lat = SSHLatencyProfile(samples=1, min_ms=1.0, mean_ms=1.0, p95_ms=1.0, max_ms=1.0)
    incomplete = build_lab_run_manifest(
        repo_root=repo_root,
        config_path=repo_root / "configs" / "phase1_lab.yaml",
        sudoers_path=repo_root / "lab" / "systemd" / "gateheal-sudoers.conf",
        ssh_latency=lat,
        conformance_facts=(
            ConformanceFactResult(
                fact_id=REQUIRED_CONFORMANCE_FACT_IDS[0], passed=True, details="ok"
            ),
        ),
        smoke_matrix=(),
    )
    bad = tmp_path / "bad_wp5.json"
    bad.write_text(incomplete.model_dump_json(indent=2), encoding="utf-8")
    with pytest.raises(RuntimeError, match="conformance_all_passed=True"):
        validate_wp6_preflight(repo_root=repo_root, wp5_manifest_path=bad, allow_dirty=True)


def test_wp6_engine_never_uses_the_removed_oracle_shortcut() -> None:
    """The engine must score trials from the oracle's measured timeline only."""
    src = (_repo_root() / "src" / "gateheal" / "wp6_engine.py").read_text(encoding="utf-8")
    oracle_src = (_repo_root() / "src" / "gateheal" / "oracle.py").read_text(encoding="utf-8")
    assert "evaluate_after_action" not in src
    assert "evaluate_after_action" not in oracle_src


def test_wp6_trial_counts_and_pairing(full_campaign: tuple[WP6TrialRecord, ...]) -> None:
    """39 trials per repeat (6 scenarios x 6 arms + S5B x 3 G arms), all evaluable."""
    assert len(full_campaign) == 2 * 39
    assert all(r.evaluable and r.oracle_evaluation is not None for r in full_campaign)
    s5b_arms = {r.arm_id for r in full_campaign if r.scenario_id == S5B_SCENARIO}
    assert s5b_arms == GATEHEAL_ARMS
    for rep in (1, 2):
        for scen in {r.scenario_id for r in full_campaign if r.scenario_id != S5B_SCENARIO}:
            arms = {
                r.arm_id
                for r in full_campaign
                if r.scenario_id == scen and r.repeat_index == rep
            }
            assert arms == set(ALL_WP6_ARMS)


def test_wp6_oracle_semantics_in_campaign(full_campaign: tuple[WP6TrialRecord, ...]) -> None:
    """Spot-check the oracle-derived endpoints the hypotheses depend on."""
    t = _by(full_campaign)

    def ev(scen: str, arm: str):  # type: ignore[no-untyped-def]
        e = t[(scen, arm)].oracle_evaluation
        assert e is not None
        return e

    # S1: a restart recovers; B0 never acts, so it never recovers and is censored.
    assert ev("S1_SERVICE_CRASH", "G").outcome == OracleOutcomeLabel.RECOVERED_ALL
    assert ev("S1_SERVICE_CRASH", "B1").outcome == OracleOutcomeLabel.RECOVERED_ALL
    assert ev("S1_SERVICE_CRASH", "B0").outcome == OracleOutcomeLabel.NOT_RECOVERED
    assert ev("S1_SERVICE_CRASH", "B0").censored
    # Unavailability comes from the measured timeline, not the controller's own duration.
    assert ev("S1_SERVICE_CRASH", "B0").unavailability_sec == pytest.approx(60.0)
    # S5: blunt restart kills the worker (a harm event); GateHeal reloads instead.
    assert ev("S5_COLLATERAL_TRAP", "B1").harm_event
    assert not ev("S5_COLLATERAL_TRAP", "G").harm_event
    assert ev("S5_COLLATERAL_TRAP", "G").outcome == OracleOutcomeLabel.RECOVERED_ALL
    # S0: a needless restart is a false positive; GateHeal does nothing.
    assert ev("S0_HEALTHY_CONTROL", "B1").outcome == OracleOutcomeLabel.FALSE_POSITIVE_REMEDIATION
    assert not t[("S0_HEALTHY_CONTROL", "G")].mutating_action_taken
    # Appropriate abstention requires an explicit abstain on an unrecoverable scenario.
    assert ev("S2_INVALID_CONFIG", "G").appropriate_abstention
    assert not ev("S2_INVALID_CONFIG", "B0").appropriate_abstention
    assert not ev("S2_INVALID_CONFIG", "B1").appropriate_abstention


def test_wp6_s5b_uses_an_approval_token_and_restarts(
    full_campaign: tuple[WP6TrialRecord, ...],
) -> None:
    """S5B seeds history and mints an approval token; G is then allowed the forced restart."""
    rec = _by(full_campaign)[(S5B_SCENARIO, "G")]
    assert rec.mutating_action_taken
    assert rec.selected_action_id == "restart_service"
    assert any("restart" in argv for argv in rec.executed_argvs)


def test_wp6_observation_failure_is_retried_then_valid(tmp_path: Path) -> None:
    """A failed oracle observation invalidates the attempt; it is retried, not scored."""
    guest = _SimulatedLiveGuestHarness()
    root = _ObservationFaultingRoot(guest)
    root.fail_oracle_probes = 1
    runner, _ = _make_runner(tmp_path, guest=guest, root=root)
    rec = runner.run_single_arm_trial(_exp("S1_SERVICE_CRASH"), 1, "G", 0)
    assert root.oracle_probe_failures_injected == 1
    assert rec.evaluable
    assert rec.attempts == 2
    assert rec.oracle_evaluation is not None
    assert rec.oracle_evaluation.outcome == OracleOutcomeLabel.RECOVERED_ALL


def test_wp6_persistent_observation_failure_is_non_evaluable_and_rerun_on_resume(
    tmp_path: Path,
) -> None:
    """After max attempts the trial is stored as non-evaluable and retried on the next run."""
    guest = _SimulatedLiveGuestHarness()
    root = _ObservationFaultingRoot(guest)
    root.fail_oracle_probes = -1  # fail forever
    runner, _ = _make_runner(tmp_path, guest=guest, root=root, max_trial_attempts=2)
    exps = (_exp("S1_SERVICE_CRASH"),)
    first = runner.run_campaign(trials_per_scenario=1, arms=("G",), expectations=exps)
    assert len(first) == 1
    assert not first[0].evaluable
    assert first[0].oracle_evaluation is None
    assert first[0].attempts == 2
    assert first[0].invalid_reason and "OracleObservationError" in first[0].invalid_reason

    summary = summarize_wp6_campaign(
        first, trials_per_scenario=1, arms=("G",), scenarios=("S1_SERVICE_CRASH",)
    )
    assert summary.coverage["G"].non_evaluable_trials == 1
    assert summary.coverage["G"].evaluable_trials == 0
    assert summary.arm_summaries["G"].recovery_rate.total == 0
    assert summary.scenario_arm_outcomes["S1_SERVICE_CRASH"]["G"][NON_EVALUABLE_KEY] == 1

    root.fail_oracle_probes = 0
    second = runner.run_campaign(trials_per_scenario=1, arms=("G",), expectations=exps)
    assert second[0].evaluable
    # The later record wins on reload.
    loaded = load_completed_wp6_trials(runner.trials_jsonl_path)
    assert len(loaded) == 1
    assert next(iter(loaded.values())).evaluable


def test_wp6_setup_failure_is_retried_and_reported(tmp_path: Path) -> None:
    """A reset or injection that exits non-zero is a lab setup failure, never an outcome."""
    guest = _SimulatedLiveGuestHarness()
    original = guest.run

    def failing_reset(argv: Sequence[str], timeout_sec: float) -> TransportResult:
        if any("reset_lab.sh" in tok for tok in argv):
            return TransportResult(exit_code=1, duration_sec=0.01)
        return original(argv, timeout_sec)

    guest.run = failing_reset  # type: ignore[method-assign]
    runner, _ = _make_runner(tmp_path, guest=guest, max_trial_attempts=2)
    rec = runner.run_single_arm_trial(_exp("S1_SERVICE_CRASH"), 1, "B0", 0)
    assert not rec.evaluable
    assert rec.invalid_reason and "LabSetupError" in rec.invalid_reason


def test_wp6_s5_precondition_requires_degraded_healthz(tmp_path: Path) -> None:
    """If the S5 fault did not take, the trial is invalid instead of a fake recovery."""
    guest = _SimulatedLiveGuestHarness()
    original_inject = guest.inject

    def no_inject(scen: str) -> None:
        if scen != "S5_COLLATERAL_TRAP":
            original_inject(scen)

    guest.inject = no_inject  # type: ignore[method-assign]
    runner, _ = _make_runner(tmp_path, guest=guest, max_trial_attempts=1)
    rec = runner.run_single_arm_trial(_exp("S5_COLLATERAL_TRAP"), 1, "B1", 0)
    assert not rec.evaluable
    assert rec.invalid_reason and "not degraded" in rec.invalid_reason


def test_wp6_resume_repairs_torn_last_line(tmp_path: Path) -> None:
    """A half-written last line is dropped and repaired; other corruption still raises."""
    runner, _ = _make_runner(tmp_path)
    exps = (_exp("S1_SERVICE_CRASH"),)
    recs = runner.run_campaign(trials_per_scenario=1, arms=("B0", "G"), expectations=exps)
    assert len(recs) == 2
    path = runner.trials_jsonl_path
    good = path.read_text(encoding="utf-8")
    path.write_text(good + '{"schema_version": "2.0", "trial_id": "wp6-tor', encoding="utf-8")
    loaded = load_completed_wp6_trials(path)
    assert len(loaded) == 2
    assert path.read_text(encoding="utf-8") == good  # repaired in place
    # New appends after repair stay valid.
    again = runner.run_campaign(trials_per_scenario=1, arms=("B0", "G"), expectations=exps)
    assert len(again) == 2

    lines = good.splitlines()
    path.write_text("not json\n" + "\n".join(lines[1:]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Corrupt trial record at line 1"):
        load_completed_wp6_trials(path)


def test_wp6_resume_skips_evaluable_trials(tmp_path: Path) -> None:
    runner, guest = _make_runner(tmp_path)
    exps = (_exp("S1_SERVICE_CRASH"),)
    runner.run_campaign(trials_per_scenario=1, arms=("B0", "G"), expectations=exps)
    n = len(guest.executed_root_commands)
    runner.run_campaign(trials_per_scenario=1, arms=("B0", "G"), expectations=exps)
    assert len(guest.executed_root_commands) == n


def test_wp6_record_rejects_inconsistent_evaluability() -> None:
    with pytest.raises(ValueError, match="evaluable"):
        WP6TrialRecord(
            trial_id="t",
            scenario_id="S1_SERVICE_CRASH",
            repeat_index=1,
            arm_id="G",
            arm_order_in_block=0,
            ungated_arm=False,
            started_at_utc="x",
            finished_at_utc="y",
            evaluable=True,
        )
    with pytest.raises(ValueError, match="invalid_reason"):
        WP6TrialRecord(
            trial_id="t",
            scenario_id="S1_SERVICE_CRASH",
            repeat_index=1,
            arm_id="G",
            arm_order_in_block=0,
            ungated_arm=False,
            started_at_utc="x",
            finished_at_utc="y",
            evaluable=False,
        )


def test_wp6_summary_uses_preregistered_families_and_holm_of_four(
    full_campaign: tuple[WP6TrialRecord, ...],
) -> None:
    """Primary tests are wired to the families fixed in docs/experiment-design.md."""
    summary = summarize_wp6_campaign(full_campaign, trials_per_scenario=2, clock_utc=lambda: NOW)
    comps = {c.comparison_id: c for c in summary.primary_comparisons}
    assert set(comps) == {
        "H1a_G_vs_B1_harm_event",
        "H1b_G_vs_B2_harm_event",
        "H2_G_vs_B1_clean_recovery_noninferiority",
        "H3a_G_vs_B1_appropriate_abstention",
        "H3b_G_vs_B2_appropriate_abstention",
    }
    harm_fam = {
        "S1_SERVICE_CRASH",
        "S2_INVALID_CONFIG",
        "S3_DEPENDENCY_FAILURE",
        "S4_PERSISTENT_FAILURE",
        "S5_COLLATERAL_TRAP",
    }
    assert set(comps["H1a_G_vs_B1_harm_event"].scenarios) == harm_fam
    assert set(comps["H1b_G_vs_B2_harm_event"].scenarios) == harm_fam
    assert comps["H1a_G_vs_B1_harm_event"].n_pairs == 5 * 2
    assert set(comps["H2_G_vs_B1_clean_recovery_noninferiority"].scenarios) == {
        "S1_SERVICE_CRASH",
        "S3_DEPENDENCY_FAILURE",
        "S5_COLLATERAL_TRAP",
    }
    assert comps["H2_G_vs_B1_clean_recovery_noninferiority"].n_pairs == 3 * 2
    assert set(comps["H3a_G_vs_B1_appropriate_abstention"].scenarios) == {
        "S2_INVALID_CONFIG",
        "S4_PERSISTENT_FAILURE",
    }
    assert S5B_SCENARIO not in {s for c in comps.values() for s in c.scenarios}
    assert "S0_HEALTHY_CONTROL" not in {s for c in comps.values() for s in c.scenarios}

    ni = comps["H2_G_vs_B1_clean_recovery_noninferiority"].noninferiority
    assert ni is not None
    assert ni.margin == pytest.approx(0.10) == H2_NON_INFERIORITY_MARGIN
    assert [h.hypothesis_id for h in summary.holm_bonferroni_family] == ["H1a", "H1b", "H2", "H3"]
    holm = {h.hypothesis_id: h for h in summary.holm_bonferroni_family}
    assert holm["H3"].raw_p_value == pytest.approx(
        max(
            comps["H3a_G_vs_B1_appropriate_abstention"].p_value,
            comps["H3b_G_vs_B2_appropriate_abstention"].p_value,
        )
    )
    assert holm["H2"].raw_p_value == pytest.approx(
        comps["H2_G_vs_B1_clean_recovery_noninferiority"].p_value
    )
    assert {c.comparison_id for c in summary.secondary_comparisons} == {
        "G_vs_B1",
        "G_vs_B2",
        "G_vs_G-nobr",
        "G_vs_G-nosoak",
    }


def test_wp6_summary_denominators_and_coverage(full_campaign: tuple[WP6TrialRecord, ...]) -> None:
    summary = summarize_wp6_campaign(full_campaign, trials_per_scenario=2, clock_utc=lambda: NOW)
    for arm in ALL_WP6_ARMS:
        a = summary.arm_summaries[arm]
        assert a.recovery_rate.total == 3 * 2
        assert a.harm_event_rate.total == 5 * 2
        assert a.false_positive_rate.total == 1 * 2
        assert a.appropriate_abstention_rate.total == 2 * 2
        cov = summary.coverage[arm]
        assert cov.non_evaluable_trials == 0 and cov.not_run_trials == 0
        assert cov.evaluable_trials == cov.planned_trials
    assert summary.coverage["B1"].planned_trials == 6 * 2
    assert summary.coverage["G"].planned_trials == 7 * 2
    assert set(summary.scenario_arm_outcomes[S5B_SCENARIO]) == GATEHEAL_ARMS

    g, b1, b2 = (summary.arm_summaries[x] for x in ("G", "B1", "B2"))
    assert g.harm_event_rate.successes == 0
    assert b1.harm_event_rate.successes > 0
    assert b2.harm_event_rate.successes > 0
    assert g.appropriate_abstention_rate.successes == 4
    assert b1.appropriate_abstention_rate.successes == 0
    assert b1.false_positive_rate.successes == 2
    # S5B's approved forced restart does harm the worker, but it is outside the H1 family.
    s5b = summary.scenario_arm_outcomes[S5B_SCENARIO]["G"]
    assert s5b[OracleOutcomeLabel.RECOVERED_WITH_COLLATERAL.value] == 2
    assert g.harm_event_rate.successes == 0


def test_wp6_unevaluable_pairs_are_dropped_and_counted(
    full_campaign: tuple[WP6TrialRecord, ...],
) -> None:
    """A non-evaluable B1 trial removes its pair from the tests and is counted as dropped."""
    victim = next(
        r for r in full_campaign if r.arm_id == "B1" and r.scenario_id == "S1_SERVICE_CRASH"
    )
    broken = WP6TrialRecord(
        trial_id=victim.trial_id,
        scenario_id=victim.scenario_id,
        repeat_index=victim.repeat_index,
        arm_id="B1",
        arm_order_in_block=victim.arm_order_in_block,
        ungated_arm=True,
        started_at_utc="x",
        finished_at_utc="y",
        attempts=3,
        evaluable=False,
        invalid_reason="attempt 3: OracleObservationError: x",
    )
    records = [broken if r is victim else r for r in full_campaign]
    summary = summarize_wp6_campaign(records, trials_per_scenario=2, clock_utc=lambda: NOW)
    comp = next(c for c in summary.primary_comparisons if c.comparison_id.startswith("H1a"))
    assert comp.n_pairs == 10 - 1
    assert comp.n_dropped_pairs == 1
    assert summary.coverage["B1"].non_evaluable_trials == 1
    assert summary.coverage["B1"].retried_trials == 1


def _check_markdown_tables(text: str) -> int:
    """Every table block must have identical cell counts on all of its rows."""
    tables = 0
    block: list[str] = []
    for line in [*text.splitlines(), ""]:
        if line.startswith("|"):
            block.append(line)
            continue
        if block:
            counts = {len(re.findall(r"(?<!\\)\|", ln)) for ln in block}
            assert len(counts) == 1, f"inconsistent cell counts in table: {block[0]}"
            assert re.fullmatch(r"\|( :?---:? \|)+", block[1]), f"bad separator: {block[1]}"
            tables += 1
            block = []
    return tables


def test_wp6_markdown_report_is_well_formed(
    full_campaign: tuple[WP6TrialRecord, ...], tmp_path: Path
) -> None:
    summary = summarize_wp6_campaign(full_campaign, trials_per_scenario=2, clock_utc=lambda: NOW)
    reporter = WP6ReportGenerator(summary)
    summary_path, md_path, tex_path = reporter.write_artifacts(tmp_path / "report")
    md = md_path.read_text(encoding="utf-8")
    tex = tex_path.read_text(encoding="utf-8")
    assert _check_markdown_tables(md) == 6
    assert "H1a_G_vs_B1_harm_event" in md
    assert "Non-evaluable" in md
    assert summary_path.is_file()
    assert r"\begin{table*}" in tex and r"\end{table*}" in tex
    assert "H2_G_vs_B1" in tex.replace("\\_", "_")
    assert tex.count(r"\begin{tabular}") == tex.count(r"\end{tabular}") == 1
    # Row-level arithmetic: scenario table has exactly one row per (scenario, eligible arm).
    rows = re.findall(r"^\| `S\w+` \| `[\w-]+` \|", md, flags=re.MULTILINE)
    assert len(rows) == 6 * 6 + 3


def test_wp6_render_markdown_table_rejects_bad_rows() -> None:
    assert render_markdown_table(["a", "b"], [["1", "2"]]) == [
        "| a | b |",
        "| :--- | :---: |",
        "| 1 | 2 |",
    ]
    with pytest.raises(ValueError, match="expected 2"):
        render_markdown_table(["a", "b"], [["1"]])
    with pytest.raises(ValueError, match="newline"):
        render_markdown_table(["a"], [["x|y"]])


def test_wp6_manifest_and_provenance(
    full_campaign: tuple[WP6TrialRecord, ...], tmp_path: Path
) -> None:
    lat = SSHLatencyProfile(samples=1, min_ms=1.0, mean_ms=1.0, p95_ms=1.0, max_ms=1.0)
    g_s1 = next(r for r in full_campaign if r.arm_id == "G" and r.scenario_id == "S1_SERVICE_CRASH")
    assert g_s1.diagnosed_fault is not None
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
    wp5_path = tmp_path / "wp5.json"
    wp5_path.write_text(valid_wp5.model_dump_json(indent=2), encoding="utf-8")
    scen = tuple(e.scenario_id for e in build_wp5_smoke_expectations())
    man = build_wp6_campaign_manifest(
        repo_root=_repo_root(),
        config_path=_repo_root() / "configs" / "phase1_lab.yaml",
        wp5_manifest_path=wp5_path,
        seed=20261028,
        arms=ALL_WP6_ARMS,
        scenarios=scen,
        trials_per_scenario=2,
        oracle_hold_window_sec=15.0,
        completed_trials=len(full_campaign),
        allow_dirty=True,
        clock_utc=lambda: NOW,
    )
    assert man.completed_trials == 78
    assert man.total_planned_trials == 78
    assert man.gateheal_only_scenarios == (S5B_SCENARIO,)
    assert man.h2_non_inferiority_margin == pytest.approx(0.10)
    assert len(man.wp5_manifest_sha256) == 64


def test_wp6_append_roundtrip(full_campaign: tuple[WP6TrialRecord, ...], tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    for rec in full_campaign[:3]:
        append_wp6_trial_record(path, rec)
    loaded = load_completed_wp6_trials(path)
    assert len(loaded) == 3
    assert all(v.oracle_evaluation is not None for v in loaded.values())


def test_wp6_h1_and_h3_directions_and_h3_uses_the_larger_p(
    full_campaign: tuple[WP6TrialRecord, ...],
) -> None:
    """One-sided directions are right, and H3 enters Holm with the larger of its two p-values."""
    base = summarize_wp6_campaign(full_campaign, trials_per_scenario=2, clock_utc=lambda: NOW)
    comps = {c.comparison_id: c for c in base.primary_comparisons}
    # G has no harm events, B1 has some: "G fewer" must be significant-direction, not p = 1.
    assert comps["H1a_G_vs_B1_harm_event"].p_value <= 0.25
    assert comps["H1b_G_vs_B2_harm_event"].p_value <= 0.25
    assert comps["H3a_G_vs_B1_appropriate_abstention"].p_value == pytest.approx(0.0625)

    # Give B2 appropriate abstention in 3 of the 4 H3 trials: G vs B2 now has one discordant pair.
    changed: list[WP6TrialRecord] = []
    given = 0
    for rec in full_campaign:
        if (
            rec.arm_id == "B2"
            and rec.scenario_id in ("S2_INVALID_CONFIG", "S4_PERSISTENT_FAILURE")
            and given < 3
            and rec.oracle_evaluation is not None
        ):
            given += 1
            ev = rec.oracle_evaluation.model_copy(update={"appropriate_abstention": True})
            rec = rec.model_copy(update={"oracle_evaluation": ev})
        changed.append(rec)
    summary = summarize_wp6_campaign(changed, trials_per_scenario=2, clock_utc=lambda: NOW)
    c2 = {c.comparison_id: c for c in summary.primary_comparisons}
    assert c2["H3a_G_vs_B1_appropriate_abstention"].p_value == pytest.approx(0.0625)
    assert c2["H3b_G_vs_B2_appropriate_abstention"].p_value == pytest.approx(0.5)
    holm = {h.hypothesis_id: h for h in summary.holm_bonferroni_family}
    assert holm["H3"].raw_p_value == pytest.approx(0.5)


def test_wp6_coverage_reports_not_run_trials(full_campaign: tuple[WP6TrialRecord, ...]) -> None:
    """Trials planned but not yet run are visible in coverage, not silently missing."""
    partial = [r for r in full_campaign if r.repeat_index == 1]
    summary = summarize_wp6_campaign(partial, trials_per_scenario=2, clock_utc=lambda: NOW)
    for arm in ALL_WP6_ARMS:
        cov = summary.coverage[arm]
        assert cov.not_run_trials == cov.planned_trials // 2 > 0


def test_wp6_report_shows_holm_adjusted_p_not_raw(
    full_campaign: tuple[WP6TrialRecord, ...], tmp_path: Path
) -> None:
    summary = summarize_wp6_campaign(full_campaign, trials_per_scenario=2, clock_utc=lambda: NOW)
    md = WP6ReportGenerator(summary).render_markdown_report()
    holm = {h.hypothesis_id: h for h in summary.holm_bonferroni_family}
    differs = 0
    for comp in summary.primary_comparisons:
        row = next(ln for ln in md.splitlines() if ln.startswith(f"| `{comp.comparison_id}`"))
        cells = [c.strip() for c in row.strip("|").split("|")]
        item = holm[comp.hypothesis_id]
        assert cells[8] == f"{comp.p_value:.4g}"
        assert cells[9] == f"{item.adjusted_p_value:.4g}"
        assert cells[10] == str(item.rejected).lower()
        differs += int(cells[8] != cells[9])
    assert differs >= 1
