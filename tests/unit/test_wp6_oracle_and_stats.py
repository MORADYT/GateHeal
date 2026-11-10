"""WP6 Batch 1 tests: independent oracle (timeline-based) and pure statistics.

All oracle tests are offline and deterministic: a fake clock and a time-driven fake transport
script the lab state, so the expected timeline, labels and unavailability are exact. Statistics
tests use fixed reference values (computed once with scipy/statsmodels, or from the Newcombe
1998 paper) and an in-test brute-force enumeration; scipy is NOT imported here.
"""

from __future__ import annotations

import ast
import itertools
import json
import os
import random
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import gateheal.oracle as oracle_module
from gateheal import stats
from gateheal.oracle import (
    H3_UNRECOVERABLE_SCENARIOS,
    LAB_UNITS,
    SCENARIO_RECOVERABLE,
    IndependentLabOracle,
    OracleEvaluation,
    OracleObservationError,
    OracleOutcomeLabel,
    OracleStateSnapshot,
    OracleUnitObservation,
    classify_oracle_outcome,
    evaluate_timeline,
    scenario_is_recoverable,
)
from gateheal.transport import TransportResult

REDIS = "lab-redis.service"
API = "lab-api.service"
WORKER = "lab-worker.service"


# --------------------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------------------
class FakeEnv:
    """Deterministic clock: sleeping advances time; nothing else does."""

    def __init__(self, start: float = 1000.0) -> None:
        self.start = start
        self.now = start

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


@dataclass(frozen=True)
class LabState:
    failing: frozenset[str] = frozenset()
    invocation: Mapping[str, str] = field(default_factory=dict)
    restarts: Mapping[str, int] = field(default_factory=dict)


def lab(*failing: str, invocation: Mapping[str, str] | None = None) -> LabState:
    return LabState(frozenset(failing), invocation or {})


def script(*segments: tuple[float, LabState]) -> Callable[[float], LabState]:
    """State as a function of seconds since trial start: last segment with t_from <= t."""
    ordered = sorted(segments, key=lambda seg: seg[0])

    def state_at(t_rel: float) -> LabState:
        current = ordered[0][1]
        for t_from, state in ordered:
            if t_from <= t_rel + 1e-9:
                current = state
        return current

    return state_at


def result(
    stdout: str = "", exit_code: int = 0, *, timed_out: bool = False
) -> TransportResult:
    return TransportResult(
        exit_code=exit_code, timed_out=timed_out, duration_sec=0.0, stdout_excerpt=stdout
    )


class TimedTransport:
    """Fake root transport whose answers are a pure function of the fake clock."""

    def __init__(
        self,
        env: FakeEnv,
        state_at: Callable[[float], LabState],
        override: Callable[[tuple[str, ...]], TransportResult | None] | None = None,
    ) -> None:
        self.env = env
        self.state_at = state_at
        self.override = override

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        cmd = tuple(argv)
        if self.override is not None:
            forced = self.override(cmd)
            if forced is not None:
                return forced
        state = self.state_at(self.env.now - self.env.start)
        if cmd[0] == "systemctl":
            unit = cmd[2]
            bad = unit in state.failing
            return result(
                f"ActiveState={'failed' if bad else 'active'}\n"
                f"SubState={'failed' if bad else 'running'}\n"
                "Result=success\n"
                f"NRestarts={state.restarts.get(unit, 0)}\n"
                f"InvocationID={state.invocation.get(unit, 'inv-' + unit)}\n"
                "ExecMainStartTimestampMonotonic=123\n"
            )
        if cmd[0] == "curl":
            if API in state.failing:
                return result("", 22)
            return result('{"status": "ok", "reload_count": 0}')
        if cmd[0] == "/usr/bin/python3":
            unit = {"8081": WORKER, "6379": REDIS}[cmd[-1]]
            return result("", 1 if unit in state.failing else 0)
        raise AssertionError(f"unexpected command {cmd}")


def run_trial(
    scenario_id: str,
    state_at: Callable[[float], LabState],
    *,
    action_sec: float = 2.0,
    mutating: bool = True,
    abstained: bool = False,
    interval: float = 1.0,
) -> OracleEvaluation:
    env = FakeEnv()
    transport = TimedTransport(env, state_at)
    oracle = IndependentLabOracle(
        transport,
        sample_interval_sec=interval,
        monotonic_clock=env.clock,
        sleep_fn=env.sleep,
    )
    session = oracle.begin_trial(scenario_id, background=False)
    session.start()
    session.mark_action_started()
    elapsed = 0.0
    while elapsed + interval <= action_sec + 1e-9:
        env.sleep(interval)
        session.sample()
        elapsed += interval
    env.sleep(max(0.0, action_sec - elapsed))
    session.mark_action_finished()
    return session.finish(mutating_action_taken=mutating, abstained=abstained)


def make_snapshot(
    t: float,
    failing: Sequence[str] = (),
    *,
    stage: str = "sample",
    invocation: Mapping[str, str] | None = None,
) -> OracleStateSnapshot:
    units = {
        unit: OracleUnitObservation(
            unit_name=unit,
            active_state="failed" if unit in failing else "active",
            sub_state="failed" if unit in failing else "running",
            result="success",
            n_restarts=0,
            invocation_id=(invocation or {}).get(unit, f"inv-{unit}"),
            exec_main_start_usec=1,
            endpoint_ok=unit not in failing,
            unit_healthy=unit not in failing,
        )
        for unit in LAB_UNITS
    }
    return OracleStateSnapshot(
        stage=stage,
        captured_at_mono=t,
        units=units,
        api_http_ok=API not in failing,
        worker_tcp_ok=WORKER not in failing,
        redis_tcp_ok=REDIS not in failing,
        failing_units=tuple(u for u in LAB_UNITS if u in failing),
    )


# --------------------------------------------------------------------------------------
# Oracle: independence
# --------------------------------------------------------------------------------------
def test_oracle_import_closure_is_only_transport() -> None:
    """Fresh interpreter: importing the oracle must load no GateHeal decision module."""
    src_dir = Path(oracle_module.__file__).resolve().parents[1]
    code = (
        "import json, sys; import gateheal.oracle; "
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('gateheal'))))"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src_dir) + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True
    )
    loaded = set(json.loads(out.stdout))
    assert loaded <= {"gateheal", "gateheal.oracle", "gateheal.transport"}, loaded


def test_oracle_source_imports_only_allowed_modules() -> None:
    tree = ast.parse(Path(oracle_module.__file__).read_text(encoding="utf-8"))
    gateheal_imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("gateheal"):
            gateheal_imports.add(node.module)
        if isinstance(node, ast.Import):
            gateheal_imports |= {a.name for a in node.names if a.name.startswith("gateheal")}
    assert gateheal_imports == {"gateheal.transport"}


# --------------------------------------------------------------------------------------
# Oracle: scenario table and constructor validation
# --------------------------------------------------------------------------------------
def test_scenario_recoverability_table() -> None:
    assert scenario_is_recoverable("S5B_COLLATERAL_FORCED_RESTART") is True
    assert scenario_is_recoverable("S5_COLLATERAL_TRAP") is True
    assert scenario_is_recoverable("S2_INVALID_CONFIG") is False
    assert scenario_is_recoverable("S4_PERSISTENT_FAILURE") is False
    assert H3_UNRECOVERABLE_SCENARIOS == {"S2_INVALID_CONFIG", "S4_PERSISTENT_FAILURE"}
    assert {k for k, v in SCENARIO_RECOVERABLE.items() if not v} == H3_UNRECOVERABLE_SCENARIOS


def test_unknown_scenario_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        scenario_is_recoverable("S9_TYPO")
    env = FakeEnv()
    oracle = IndependentLabOracle(TimedTransport(env, script((0, lab()))))
    with pytest.raises(KeyError):
        oracle.begin_trial("S9_TYPO", background=False)
    with pytest.raises(KeyError):
        evaluate_timeline(
            scenario_id="S9_TYPO",
            mutating_action_taken=False,
            abstained=False,
            pre_snapshot=make_snapshot(0.0),
            immediate_post_snapshot=make_snapshot(1.0),
            hold_post_snapshot=make_snapshot(16.0),
            samples=[make_snapshot(0.0)],
            action_started_mono=0.0,
            action_finished_mono=1.0,
            hold_window_sec=15.0,
            sample_interval_sec=1.0,
        )


def test_constructor_validation() -> None:
    env = FakeEnv()
    transport = TimedTransport(env, script((0, lab())))
    with pytest.raises(ValueError, match="hold_window_sec"):
        IndependentLabOracle(transport, hold_window_sec=14.9)
    with pytest.raises(ValueError, match="sample_interval_sec"):
        IndependentLabOracle(transport, sample_interval_sec=0.0)
    with pytest.raises(ValueError, match="sample_interval_sec"):
        IndependentLabOracle(transport, sample_interval_sec=2.5)
    with pytest.raises(ValueError, match="horizon_sec"):
        IndependentLabOracle(transport, hold_window_sec=20.0, horizon_sec=19.0)
    oracle = IndependentLabOracle(transport)
    with pytest.raises(ValueError, match="monitor_transport"):
        oracle.begin_trial("S1_SERVICE_CRASH", background=True)
    with pytest.raises(ValueError, match="monitor_transport"):
        oracle.begin_trial("S1_SERVICE_CRASH", monitor_transport=transport, background=True)


# --------------------------------------------------------------------------------------
# Oracle: observation errors are never scored as outcomes
# --------------------------------------------------------------------------------------
def _oracle_with_override(
    override: Callable[[tuple[str, ...]], TransportResult | None],
) -> IndependentLabOracle:
    env = FakeEnv()
    return IndependentLabOracle(
        TimedTransport(env, script((0, lab())), override),
        monotonic_clock=env.clock,
        sleep_fn=env.sleep,
    )


@pytest.mark.parametrize(
    "forced",
    [
        result("", 0, timed_out=True),
        result("", 255),
        result("", 124),
        result("", 127),
    ],
)
def test_systemctl_channel_failure_raises(forced: TransportResult) -> None:
    oracle = _oracle_with_override(
        lambda cmd: forced if cmd[0] == "systemctl" and cmd[2] == WORKER else None
    )
    with pytest.raises(OracleObservationError):
        oracle.capture_snapshot("x")


def test_systemctl_nonzero_or_empty_output_raises() -> None:
    with pytest.raises(OracleObservationError):
        _oracle_with_override(
            lambda cmd: result("", 1) if cmd[0] == "systemctl" and cmd[2] == API else None
        ).capture_snapshot("x")
    with pytest.raises(OracleObservationError, match="ActiveState"):
        _oracle_with_override(
            lambda cmd: result("Result=success\n") if cmd[0] == "systemctl" else None
        ).capture_snapshot("x")


def test_probe_channel_failures_raise_but_service_failures_do_not() -> None:
    with pytest.raises(OracleObservationError):
        _oracle_with_override(
            lambda cmd: result("", 0, timed_out=True) if cmd[0] == "curl" else None
        ).capture_snapshot("x")
    with pytest.raises(OracleObservationError, match="unexpected exit code"):
        _oracle_with_override(
            lambda cmd: result("", 7) if cmd[0] == "/usr/bin/python3" else None
        ).capture_snapshot("x")
    # curl exit 7 (connection refused) is a legitimate "service not answering" observation.
    snap = _oracle_with_override(
        lambda cmd: result("", 7) if cmd[0] == "curl" else None
    ).capture_snapshot("x")
    assert snap.failing_units == (API,)
    # healthz that answers 200 but is not status ok is unhealthy too.
    snap = _oracle_with_override(
        lambda cmd: result('{"status": "degraded"}') if cmd[0] == "curl" else None
    ).capture_snapshot("x")
    assert API in snap.failing_units


def test_transport_timeout_mid_trial_invalidates_instead_of_scoring_harm() -> None:
    env = FakeEnv()
    state: dict[str, bool] = {"flaky": False}

    def override(cmd: tuple[str, ...]) -> TransportResult | None:
        if state["flaky"] and cmd[0] == "systemctl" and cmd[2] == WORKER:
            return result("", 255, timed_out=True)
        return None

    oracle = IndependentLabOracle(
        TimedTransport(env, script((0, lab())), override),
        monotonic_clock=env.clock,
        sleep_fn=env.sleep,
    )
    session = oracle.begin_trial("S1_SERVICE_CRASH", background=False)
    session.start()
    session.mark_action_started()
    session.mark_action_finished()
    state["flaky"] = True
    with pytest.raises(OracleObservationError):
        session.finish(mutating_action_taken=True, abstained=False)


def test_s0_not_healthy_before_trial_raises() -> None:
    env = FakeEnv()
    oracle = IndependentLabOracle(
        TimedTransport(env, script((0, lab(API)))),
        monotonic_clock=env.clock,
        sleep_fn=env.sleep,
    )
    session = oracle.begin_trial("S0_HEALTHY_CONTROL", background=False)
    with pytest.raises(OracleObservationError, match="S0"):
        session.start()


# --------------------------------------------------------------------------------------
# Oracle: labels, harm_event, abstention
# --------------------------------------------------------------------------------------
def test_clean_recovery_is_recovered_all_without_harm() -> None:
    ev = run_trial("S1_SERVICE_CRASH", script((0, lab(API)), (1.0, lab())))
    assert ev.outcome is OracleOutcomeLabel.RECOVERED_ALL
    assert ev.harm_event is False
    assert ev.collateral_units == ()
    assert ev.censored is False


def test_s5_blunt_restart_is_recovered_with_collateral_and_counts_as_harm() -> None:
    """B1 restart on S5: api fixed, worker lost. Same count of failing units, still harm."""
    ev = run_trial(
        "S5_COLLATERAL_TRAP",
        script((0, lab(API)), (1.0, lab()), (2.0, lab(WORKER))),
    )
    assert ev.outcome is OracleOutcomeLabel.RECOVERED_WITH_COLLATERAL
    assert ev.collateral_units == (WORKER,)
    assert ev.harm_event is True


def test_s5_reload_is_clean() -> None:
    ev = run_trial("S5_COLLATERAL_TRAP", script((0, lab(API)), (1.0, lab())))
    assert ev.outcome is OracleOutcomeLabel.RECOVERED_ALL
    assert ev.harm_event is False


def test_s2_blind_restart_is_harmful() -> None:
    ev = run_trial("S2_INVALID_CONFIG", script((0, lab()), (1.0, lab(API))))
    assert ev.outcome is OracleOutcomeLabel.HARMFUL
    assert ev.harm_event is True
    assert ev.collateral_units == (API,)


def test_abstention_flag_uses_abstained_and_physical_recoverability() -> None:
    down = script((0, lab(API)))
    ev = run_trial("S4_PERSISTENT_FAILURE", down, mutating=False, abstained=True)
    assert ev.outcome is OracleOutcomeLabel.NO_CHANGE_CORRECT
    assert ev.appropriate_abstention is True
    assert ev.harm_event is False
    # Observe-only arm (never abstained): same label, but NOT counted as appropriate abstention.
    ev = run_trial("S4_PERSISTENT_FAILURE", down, mutating=False, abstained=False)
    assert ev.outcome is OracleOutcomeLabel.NO_CHANGE_CORRECT
    assert ev.appropriate_abstention is False
    # S5B is physically recoverable: abstaining there is NOT appropriate and is not recovery.
    ev = run_trial("S5B_COLLATERAL_FORCED_RESTART", down, mutating=False, abstained=True)
    assert ev.outcome is OracleOutcomeLabel.NOT_RECOVERED
    assert ev.appropriate_abstention is False


def test_mutating_action_on_unrecoverable_fault_that_persists() -> None:
    ev = run_trial("S4_PERSISTENT_FAILURE", script((0, lab(API))), mutating=True)
    assert ev.outcome is OracleOutcomeLabel.NOT_RECOVERED
    assert ev.harm_event is False


def test_s0_labels_and_harm_event() -> None:
    healthy = script((0, lab()))
    ev = run_trial("S0_HEALTHY_CONTROL", healthy, mutating=False)
    assert ev.outcome is OracleOutcomeLabel.NO_CHANGE_CORRECT
    assert ev.unavailability_sec == 0.0
    ev = run_trial("S0_HEALTHY_CONTROL", healthy, mutating=True)
    assert ev.outcome is OracleOutcomeLabel.FALSE_POSITIVE_REMEDIATION
    assert ev.harm_event is False
    # A needless action that also broke something is a false positive AND a harm event.
    ev = run_trial("S0_HEALTHY_CONTROL", script((0, lab()), (1.0, lab(API))), mutating=True)
    assert ev.outcome is OracleOutcomeLabel.FALSE_POSITIVE_REMEDIATION
    assert ev.harm_event is True


def test_no_mutation_means_no_attributable_harm() -> None:
    ev = run_trial(
        "S1_SERVICE_CRASH", script((0, lab(API)), (1.0, lab(API, WORKER))), mutating=False
    )
    assert ev.outcome is OracleOutcomeLabel.HARMFUL
    assert ev.harm_event is False


def test_flapping_unit_in_sustain_window_is_not_recovered() -> None:
    """Healthy at every sample but restarted inside the sustained window: not stable."""
    ev = run_trial(
        "S1_SERVICE_CRASH",
        script((0, lab(API)), (1.0, lab()), (10.0, lab(invocation={API: "inv-new"}))),
    )
    assert ev.restart_during_hold_units == (API,)
    assert ev.outcome is OracleOutcomeLabel.NOT_RECOVERED


def test_restart_counter_increase_in_sustain_window_is_flapping() -> None:
    pre = make_snapshot(0.0, (API,), stage="pre")
    samples = [pre, make_snapshot(1.0, (API,), stage="immediate_post")]
    for t in range(2, 18):
        snap = make_snapshot(float(t))
        if t >= 12:
            units = dict(snap.units)
            units[API] = units[API].model_copy(update={"n_restarts": 3})
            snap = snap.model_copy(update={"units": units})
        samples.append(snap)
    ev = evaluate_timeline(
        scenario_id="S1_SERVICE_CRASH",
        mutating_action_taken=True,
        abstained=False,
        pre_snapshot=pre,
        immediate_post_snapshot=samples[1],
        hold_post_snapshot=samples[-1],
        samples=samples,
        action_started_mono=0.0,
        action_finished_mono=1.0,
        hold_window_sec=15.0,
        sample_interval_sec=1.0,
    )
    assert ev.restart_during_hold_units == (API,)
    assert ev.outcome is OracleOutcomeLabel.NOT_RECOVERED


def test_transient_blip_is_reported_but_does_not_change_the_label() -> None:
    ev = run_trial(
        "S1_SERVICE_CRASH",
        script((0, lab(API)), (1.0, lab(API, WORKER)), (2.5, lab())),
        action_sec=3.0,
    )
    assert ev.outcome is OracleOutcomeLabel.RECOVERED_ALL
    assert ev.transient_collateral_units == (WORKER,)
    assert ev.collateral_units == ()
    assert ev.harm_event is False


def test_classification_is_pure_function_of_sustained_state() -> None:
    cls = classify_oracle_outcome(
        scenario_id="S5_COLLATERAL_TRAP",
        recoverable=True,
        mutating_action_taken=True,
        abstained=False,
        pre_failing=frozenset({API}),
        sustained_failing=frozenset({WORKER, REDIS}),
    )
    assert cls.label is OracleOutcomeLabel.HARMFUL
    assert cls.harm_event is True
    assert cls.collateral_units == (REDIS, WORKER)


# --------------------------------------------------------------------------------------
# Oracle: measured unavailability
# --------------------------------------------------------------------------------------
def test_unavailability_is_integrated_from_the_timeline_not_the_controller_clock() -> None:
    api_down_until_2s = script((0, lab(API)), (2.0, lab()))
    short = run_trial("S1_SERVICE_CRASH", api_down_until_2s, action_sec=3.0)
    long = run_trial("S1_SERVICE_CRASH", api_down_until_2s, action_sec=14.0)
    # samples at t=0 and t=1 are down, t=2 is up -> midpoint rule: down over [0, 1.5].
    assert short.unavailability_sec == pytest.approx(1.5)
    assert long.unavailability_sec == pytest.approx(1.5)
    assert short.unit_down_sec[API] == pytest.approx(1.5)
    assert short.unit_down_sec[REDIS] == 0.0
    assert short.sample_count < long.sample_count


def test_unrecovered_trial_is_censored_at_the_horizon() -> None:
    ev = run_trial("S1_SERVICE_CRASH", script((0, lab(API))), action_sec=2.0)
    assert ev.censored is True
    assert ev.horizon_sec == 60.0
    assert ev.unavailability_sec == pytest.approx(60.0)


def test_recovery_after_a_long_outage_is_longer_than_a_short_one() -> None:
    quick = run_trial("S1_SERVICE_CRASH", script((0, lab(API)), (3.0, lab())), action_sec=4.0)
    slow = run_trial("S1_SERVICE_CRASH", script((0, lab(API)), (9.0, lab())), action_sec=10.0)
    assert slow.unavailability_sec > quick.unavailability_sec
    assert slow.unavailability_sec == pytest.approx(8.5)
    assert quick.unavailability_sec == pytest.approx(2.5)


def test_evaluation_json_round_trip() -> None:
    ev = run_trial("S5_COLLATERAL_TRAP", script((0, lab(API)), (1.0, lab()), (2.0, lab(WORKER))))
    restored = OracleEvaluation.model_validate_json(ev.model_dump_json())
    assert restored == ev


# --------------------------------------------------------------------------------------
# Oracle: sampling completeness and the background monitor
# --------------------------------------------------------------------------------------
def _eval_samples(samples: list[OracleStateSnapshot]) -> OracleEvaluation:
    return evaluate_timeline(
        scenario_id="S1_SERVICE_CRASH",
        mutating_action_taken=True,
        abstained=False,
        pre_snapshot=samples[0],
        immediate_post_snapshot=samples[1],
        hold_post_snapshot=samples[-1],
        samples=samples,
        action_started_mono=0.0,
        action_finished_mono=1.0,
        hold_window_sec=15.0,
        sample_interval_sec=1.0,
    )


def test_under_sampled_hold_window_is_rejected() -> None:
    dense = [make_snapshot(float(t)) for t in range(0, 17)]
    assert _eval_samples(dense).outcome is OracleOutcomeLabel.RECOVERED_ALL
    sparse = [make_snapshot(0.0), make_snapshot(1.0), make_snapshot(16.0)]
    with pytest.raises(OracleObservationError, match="under-sampled"):
        _eval_samples(sparse)
    gap = [make_snapshot(float(t)) for t in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16)]
    with pytest.raises(OracleObservationError, match="under-sampled"):
        _eval_samples(gap)
    short = [make_snapshot(float(t)) for t in range(0, 10)]
    with pytest.raises(OracleObservationError, match="not fully observed"):
        _eval_samples(short)


def test_session_state_machine_rejects_misuse() -> None:
    env = FakeEnv()
    oracle = IndependentLabOracle(
        TimedTransport(env, script((0, lab()))), monotonic_clock=env.clock, sleep_fn=env.sleep
    )
    session = oracle.begin_trial("S1_SERVICE_CRASH", background=False)
    with pytest.raises(RuntimeError):
        session.mark_action_started()
    session.start()
    with pytest.raises(RuntimeError):
        session.start()
    with pytest.raises(RuntimeError):
        session.mark_action_finished()
    with pytest.raises(RuntimeError):
        session.finish(mutating_action_taken=False, abstained=False)


def test_background_monitor_samples_and_stops() -> None:
    env = FakeEnv()
    state_at = script((0, lab()))
    oracle = IndependentLabOracle(
        TimedTransport(env, state_at),
        sample_interval_sec=0.005,
        monotonic_clock=time.monotonic,
        sleep_fn=time.sleep,
    )
    with oracle.begin_trial(
        "S1_SERVICE_CRASH", monitor_transport=TimedTransport(env, state_at), background=True
    ) as session:
        session.start()
        deadline = time.monotonic() + 10.0
        while session.sample_count < 4 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert session.sample_count >= 4
        assert session.monitor_running
    assert not session.monitor_running


def test_background_monitor_failure_invalidates_the_trial() -> None:
    env = FakeEnv()
    state_at = script((0, lab()))

    class BrokenMonitor:
        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            raise RuntimeError("ssh control socket lost")

    oracle = IndependentLabOracle(
        TimedTransport(env, state_at),
        sample_interval_sec=0.005,
        monotonic_clock=env.clock,
        sleep_fn=env.sleep,
    )
    session = oracle.begin_trial(
        "S1_SERVICE_CRASH", monitor_transport=BrokenMonitor(), background=True
    )
    session.start()
    deadline = time.monotonic() + 10.0
    while session.monitor_running and time.monotonic() < deadline:
        time.sleep(0.01)
    session.mark_action_started()
    session.mark_action_finished()
    with pytest.raises(OracleObservationError, match="Background monitor failed"):
        session.finish(mutating_action_taken=True, abstained=False)


@pytest.mark.parametrize("exit_code", [124, 127, 255])
def test_curl_channel_failure_raises_instead_of_reporting_api_down(exit_code: int) -> None:
    oracle = _oracle_with_override(
        lambda cmd: result("", exit_code) if cmd[0] == "curl" else None
    )
    with pytest.raises(OracleObservationError, match="transport"):
        oracle.capture_snapshot("x")


def test_min_sustain_samples_is_enforced_independently_of_the_gap_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oracle_module, "MAX_SUSTAIN_SAMPLE_GAP_SEC", 1e9)
    sparse = [make_snapshot(0.0), make_snapshot(1.0), make_snapshot(16.0)]
    with pytest.raises(OracleObservationError, match="samples"):
        _eval_samples(sparse)


def test_unavailability_is_truncated_at_the_horizon() -> None:
    ev = run_trial("S1_SERVICE_CRASH", script((0, lab(API))), action_sec=50.0)
    assert ev.observed_sec == pytest.approx(65.0)
    assert ev.horizon_sec == 60.0
    assert ev.unavailability_sec == pytest.approx(60.0)
    assert ev.unit_down_sec[API] == pytest.approx(60.0)


# --------------------------------------------------------------------------------------
# Statistics: McNemar
# --------------------------------------------------------------------------------------
def test_mcnemar_exact_values() -> None:
    first = [True] * 7 + [False]
    second = [False] * 7 + [True]
    r = stats.exact_mcnemar_test(first, second)
    assert (r.b_only_first_true, r.c_only_second_true, r.discordant_total) == (7, 1, 8)
    assert r.p_value == pytest.approx(0.0703125)
    assert stats.exact_mcnemar_test(first, second, alternative="greater").p_value == pytest.approx(
        9 / 256
    )
    assert stats.exact_mcnemar_test(first, second, alternative="less").p_value == pytest.approx(
        255 / 256
    )
    assert stats.exact_mcnemar_test([True, False], [True, False]).p_value == 1.0
    with pytest.raises(ValueError):
        stats.exact_mcnemar_test([True], [])


def test_mcnemar_large_discordant_counts_do_not_overflow() -> None:
    assert stats.exact_mcnemar_test([True] * 1500, [False] * 1500).p_value == 0.0
    mid = stats.exact_mcnemar_test([True] * 800 + [False] * 700, [False] * 800 + [True] * 700)
    assert mid.p_value == pytest.approx(0.010559255467, abs=1e-11)  # scipy.stats.binomtest


# --------------------------------------------------------------------------------------
# Statistics: Wilcoxon
# --------------------------------------------------------------------------------------
def _brute_force_two_sided_p(diffs: Sequence[float]) -> float:
    nonzero = [d for d in diffs if d != 0]
    n = len(nonzero)
    absolute = sorted(abs(d) for d in nonzero)
    midrank: dict[float, float] = {}
    i = 0
    while i < n:
        j = i
        while j < n and absolute[j] == absolute[i]:
            j += 1
        midrank[absolute[i]] = (i + 1 + j) / 2
        i = j
    ranks = [midrank[abs(d)] for d in nonzero]
    w_plus = sum(r for d, r in zip(nonzero, ranks, strict=True) if d > 0)
    w_minus = sum(r for d, r in zip(nonzero, ranks, strict=True) if d < 0)
    observed = min(w_plus, w_minus)
    total = sum(ranks)
    hits = 0
    for signs in itertools.product((0, 1), repeat=n):
        plus = sum(r for s, r in zip(signs, ranks, strict=True) if s)
        if min(plus, total - plus) <= observed + 1e-9:
            hits += 1
    return hits / (1 << n)


def test_wilcoxon_exact_matches_scipy_reference_on_tie_free_data() -> None:
    diffs = [1, -2, 3, 4, -5, 6, 7, 8, 9, -10, 12, -11, 0]
    r = stats.wilcoxon_signed_rank_test(diffs, [0] * len(diffs))
    assert r.method == "exact"
    assert (r.n_pairs, r.n_nonzero) == (13, 12)
    assert (r.w_plus, r.w_minus, r.statistic) == (50.0, 28.0, 28.0)
    assert r.p_value == pytest.approx(0.423828125)  # scipy.stats.wilcoxon(method="exact")
    small = stats.wilcoxon_signed_rank_test([1, -2, 3, 4, -5, 6], [0] * 6)
    assert small.p_value == pytest.approx(0.5625)
    assert stats.wilcoxon_signed_rank_test(list(range(1, 26)), [0] * 25).p_value == pytest.approx(
        5.9605e-08, abs=1e-11
    )


def test_wilcoxon_exact_handles_ties_like_brute_force_enumeration() -> None:
    tied = [1, 1, 2, 2, 2, -3, -1, 4, 0, 5, -2, 3]
    r = stats.wilcoxon_signed_rank_test(tied, [0] * len(tied))
    assert r.method == "exact"
    assert r.p_value == pytest.approx(_brute_force_two_sided_p(tied))
    assert r.p_value == pytest.approx(0.1455078125)
    rng = random.Random(2026)
    for _ in range(25):
        diffs = [rng.choice([-3, -2, -1, 0, 1, 1, 2, 3, 4]) for _ in range(rng.randint(3, 11))]
        got = stats.wilcoxon_signed_rank_test(diffs, [0] * len(diffs))
        assert got.p_value == pytest.approx(_brute_force_two_sided_p(diffs), abs=1e-11)


def test_wilcoxon_all_zero_and_validation() -> None:
    r = stats.wilcoxon_signed_rank_test([1.0, 2.0], [1.0, 2.0])
    assert (r.n_nonzero, r.p_value, r.method) == (0, 1.0, "exact")
    with pytest.raises(ValueError):
        stats.wilcoxon_signed_rank_test([1.0], [])


def test_wilcoxon_switches_to_normal_approximation_above_the_exact_limit() -> None:
    assert stats.EXACT_WILCOXON_MAX_NONZERO == 25
    at_limit = stats.wilcoxon_signed_rank_test(list(range(1, 26)), [0] * 25)
    above = stats.wilcoxon_signed_rank_test(list(range(1, 27)), [0] * 26)
    assert at_limit.method == "exact"
    assert above.method == "normal"
    assert above.p_value == pytest.approx(8.298099e-06, abs=1e-11)


def test_wilcoxon_normal_matches_scipy_reference() -> None:
    xb = [28, 35, 29, 28, 32, 37, 12, 11, 32, 30, 40, 39, 11, 6, 28, 19, 9, 5, 34, 40]
    xb += [2, 38, 25, 28, 39, 10, 39, 0, 33, 4, 3, 2, 12, 15, 38, 1, 29, 20, 28, 37]
    xb += [12, 33, 14, 40, 18, 31, 0, 5, 29, 17, 26, 35, 5, 16, 20, 14, 32, 18, 1, 4]
    yb = [6, 25, 6, 18, 24, 4, 1, 0, 13, 13, 3, 30, 24, 25, 26, 4, 12, 17, 21, 5]
    yb += [19, 21, 0, 26, 7, 8, 15, 6, 0, 3, 29, 31, 11, 35, 12, 28, 32, 12, 8, 26]
    yb += [24, 7, 25, 26, 13, 0, 17, 19, 1, 13, 11, 25, 6, 2, 9, 13, 28, 16, 0, 21]
    r = stats.wilcoxon_signed_rank_test(xb, yb)
    assert (r.method, r.n_nonzero) == ("normal", 60)
    assert r.p_value == pytest.approx(0.005079416222, abs=1e-11)  # scipy method="approx"


# --------------------------------------------------------------------------------------
# Statistics: Wilson, Newcombe paired interval, non-inferiority
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("k", "n", "conf", "lower", "upper"),
    [
        (7, 20, 0.95, 0.181192, 0.567146),
        (0, 20, 0.95, 0.0, 0.161125),
        (20, 20, 0.95, 0.838875, 1.0),
        (140, 700, 0.90, 0.176308, 0.226002),
        (3, 10, 0.99, 0.079566, 0.679975),
    ],
)
def test_wilson_matches_statsmodels_reference(
    k: int, n: int, conf: float, lower: float, upper: float
) -> None:
    w = stats.wilson_score_interval(k, n, confidence=conf)
    assert w.lower == pytest.approx(lower, abs=2e-6)
    assert w.upper == pytest.approx(upper, abs=2e-6)


def test_wilson_validation_and_empty() -> None:
    assert stats.wilson_score_interval(0, 0).upper == 0.0
    with pytest.raises(ValueError):
        stats.wilson_score_interval(5, 3)
    with pytest.raises(ValueError):
        stats.wilson_score_interval(1, 3, confidence=1.0)


def _paired(a: int, b: int, c: int, d: int) -> tuple[list[bool], list[bool]]:
    return [True] * (a + b) + [False] * (c + d), [True] * a + [False] * b + [True] * c + [False] * d


@pytest.mark.parametrize(
    ("cells", "lower", "upper"),
    [  # Newcombe (1998), Statistics in Medicine 17:2635, Table III, method 10, 95%
        ((36, 12, 2, 0), 0.0569, 0.3404),
        ((20, 12, 2, 16), 0.0562, 0.3292),
        ((2, 97, 1, 0), 0.8721, 0.9854),
        ((0, 29, 1, 0), 0.6666, 0.9882),
        ((2, 98, 0, 0), 0.9178, 0.9945),
        ((54, 0, 0, 0), -0.0664, 0.0664),
    ],
)
def test_newcombe_paired_interval_matches_published_examples(
    cells: tuple[int, int, int, int], lower: float, upper: float
) -> None:
    first, second = _paired(*cells)
    r = stats.newcombe_paired_difference_interval(first, second)
    assert r.lower == pytest.approx(lower, abs=6e-5)
    assert r.upper == pytest.approx(upper, abs=6e-5)
    assert (r.both_true, r.first_only, r.second_only, r.both_false) == cells


def test_noninferiority_decision_and_p_value() -> None:
    first, second = _paired(20, 12, 2, 16)  # difference +0.2, 95% lower limit 0.0562
    ok = stats.paired_noninferiority_test(first, second, margin=0.05)
    assert ok.non_inferior is True
    assert ok.lower_bound == pytest.approx(0.0562, abs=1e-3) or ok.lower_bound > -0.05
    assert ok.p_value < ok.alpha
    # Reversed roles: first is clearly worse than second, so non-inferiority must fail.
    bad = stats.paired_noninferiority_test(second, first, margin=0.10)
    assert bad.non_inferior is False
    assert bad.p_value == 1.0
    # A larger margin can only make the p-value smaller.
    tight = stats.paired_noninferiority_test(first, second, margin=0.02).p_value
    loose = stats.paired_noninferiority_test(first, second, margin=0.20).p_value
    assert loose <= tight


def test_noninferiority_p_value_is_consistent_with_the_decision() -> None:
    rng = random.Random(7)
    checked = 0
    for _ in range(300):
        n = rng.randint(10, 60)
        first = [rng.random() < 0.8 for _ in range(n)]
        second = [rng.random() < 0.8 for _ in range(n)]
        margin = rng.choice([0.05, 0.1, 0.15, 0.2])
        r = stats.paired_noninferiority_test(first, second, margin=margin, alpha=0.025)
        if abs(r.p_value - 0.025) < 1e-6:
            continue
        assert r.non_inferior == (r.p_value < 0.025)
        checked += 1
    assert checked > 200


def test_noninferiority_validation_and_empty() -> None:
    with pytest.raises(ValueError):
        stats.paired_noninferiority_test([True], [True], margin=0.0)
    with pytest.raises(ValueError):
        stats.paired_noninferiority_test([True], [True], margin=0.1, alpha=0.6)
    with pytest.raises(ValueError):
        stats.paired_noninferiority_test([True], [], margin=0.1)
    empty = stats.paired_noninferiority_test([], [], margin=0.1)
    assert empty.non_inferior is False
    assert empty.p_value == 1.0


# --------------------------------------------------------------------------------------
# Statistics: Holm and bootstrap
# --------------------------------------------------------------------------------------
def test_holm_textbook_example_mapping_and_sequence() -> None:
    raw = {"h1": 0.01, "h2": 0.04, "h3": 0.03, "h4": 0.005}
    for family in (raw, list(raw.items())):
        items = {i.hypothesis_id: i for i in stats.holm_bonferroni_correction(family, alpha=0.05)}
        assert items["h4"].adjusted_p_value == pytest.approx(0.02)
        assert items["h1"].adjusted_p_value == pytest.approx(0.03)
        assert items["h3"].adjusted_p_value == pytest.approx(0.06)
        assert items["h2"].adjusted_p_value == pytest.approx(0.06)
        assert [items[k].rejected for k in ("h4", "h1", "h3", "h2")] == [True, True, False, False]
    assert stats.holm_bonferroni_correction({}) == ()
    with pytest.raises(ValueError):
        stats.holm_bonferroni_correction({"x": 1.5})


def test_holm_stops_at_first_non_rejection_and_enforces_monotone_adjusted_p() -> None:
    items = stats.holm_bonferroni_correction({"a": 0.03, "b": 0.04, "c": 0.0001}, alpha=0.05)
    by_id = {i.hypothesis_id: i for i in items}
    assert by_id["c"].adjusted_p_value == pytest.approx(0.0003)
    assert by_id["c"].rejected is True
    assert by_id["a"].adjusted_p_value == pytest.approx(0.06)
    assert by_id["a"].rejected is False
    # b's own Holm product is 0.04, but adjusted p-values are non-decreasing, so it is 0.06.
    assert by_id["b"].adjusted_p_value == pytest.approx(0.06)
    assert by_id["b"].rejected is False


def test_bootstrap_is_deterministic_and_matches_regression_values() -> None:
    x = [3.0, 5.0, 4.0, 6.0, 2.0, 7.0, 5.0, 4.0]
    y = [2.0, 5.0, 3.0, 4.0, 2.0, 5.0, 4.0, 4.0]
    a = stats.paired_bootstrap_mean_diff(x, y, seed=7)
    b = stats.paired_bootstrap_mean_diff(x, y, seed=7)
    c = stats.paired_bootstrap_mean_diff(x, y, seed=8)
    assert a == b
    assert a != c
    assert a.mean_diff == pytest.approx(0.875)
    assert a.ci_lower == pytest.approx(0.375)
    assert a.ci_upper == pytest.approx(1.378125)
    assert a.ci_lower <= a.mean_diff <= a.ci_upper
    assert stats.paired_bootstrap_mean_diff([], []).n_pairs == 0
    with pytest.raises(ValueError):
        stats.paired_bootstrap_mean_diff([1.0], [])
    with pytest.raises(ValueError):
        stats.paired_bootstrap_mean_diff([1.0], [1.0], n_resamples=0)


def test_tiny_p_values_are_not_rounded_to_a_floor() -> None:
    """With 40 discordant pairs p = 2**-40; neither it nor the Holm values may collapse to 1e-12."""
    mc = stats.exact_mcnemar_test([False] * 40, [True] * 40, alternative="less")
    assert mc.p_value == pytest.approx(2.0**-40, rel=1e-9)
    assert mc.p_value < 1e-12

    first = [True] * 60
    second = [True] * 20 + [False] * 40
    ni = stats.paired_noninferiority_test(first, second, margin=0.10)
    assert ni.non_inferior
    assert 0.0 < ni.p_value < 1e-15  # far below the old 1e-12 floor

    holm = stats.holm_bonferroni_correction(
        [("a", 2.0**-40), ("b", 2.0**-40), ("c", ni.p_value), ("d", 2.0**-40)]
    )
    by_id = {h.hypothesis_id: h for h in holm}
    assert by_id["c"].raw_p_value == pytest.approx(ni.p_value, rel=1e-9)
    assert by_id["c"].adjusted_p_value == pytest.approx(4 * ni.p_value, rel=1e-9)
    # c is the smallest, so the others are multiplied by 3 (not 4) and kept monotone.
    for key in ("a", "b", "d"):
        assert by_id[key].raw_p_value == pytest.approx(2.0**-40, rel=1e-9)
        assert by_id[key].adjusted_p_value == pytest.approx(3 * 2.0**-40, rel=1e-9)
        assert by_id[key].rejected


def test_noninferiority_p_is_still_one_when_the_estimate_is_inside_the_margin() -> None:
    first = [True] * 5 + [False] * 15
    second = [True] * 15 + [False] * 5
    ni = stats.paired_noninferiority_test(first, second, margin=0.10)
    assert ni.p_value == 1.0
    assert not ni.non_inferior
