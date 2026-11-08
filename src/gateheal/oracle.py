"""Independent harness-side outcome oracle for WP6 live-lab experiments.

Architectural invariant:
    This module runs from the harness side over a root transport and MUST NOT import
    `gateheal.collector`, `gateheal.controller` (OutcomeVerifier), `gateheal.policy` or any
    other GateHeal decision code. Its only GateHeal import is `gateheal.transport`
    (`CommandTransport`, `TransportResult`). A test enforces this on the import graph.

What the oracle measures (and what it does not):
    * Unit health is read from `systemctl show`, the `/healthz` HTTP endpoint and two TCP
      probes. GateHeal's own verification statuses are never used.
    * A trial is observed as a *timeline*: a synchronous `pre` snapshot, periodic samples from
      a background monitor (own transport, <= 2 s interval), an `immediate_post` snapshot when
      the arm finishes acting, and a `hold_post` snapshot after the hold window.
    * Outcome labels are decided on the *sustained* state (final `SUSTAIN_WINDOW_SEC` seconds of
      the hold window), never on one read. A unit that restarts or flaps inside that window is
      not healthy. Transient blips are reported separately and never change the label.
    * `unavailability_sec` is integrated from the measured timeline (midpoint rule), never
      derived from the controller's wall-clock or from the outcome label.
    * A failed observation (timeout, SSH error, unusable output) raises
      `OracleObservationError`. It is never scored as an unhealthy unit: the engine must mark
      the trial invalid and retry it.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Sequence
from enum import StrEnum
from typing import Annotated, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from gateheal.transport import CommandTransport, TransportResult

MIN_ORACLE_HOLD_WINDOW_SEC = 15.0
SUSTAIN_WINDOW_SEC = 10.0
MAX_SAMPLE_INTERVAL_SEC = 2.0
MAX_SUSTAIN_SAMPLE_GAP_SEC = 3.0
MIN_SUSTAIN_SAMPLES = 3
DEFAULT_UNAVAILABILITY_HORIZON_SEC = 60.0
HEALTHY_CONTROL_SCENARIO = "S0_HEALTHY_CONTROL"

LAB_UNITS: tuple[str, ...] = (
    "lab-redis.service",
    "lab-api.service",
    "lab-worker.service",
)

# Physical recoverability of the injected fault by an allowed remediation (restart/reload).
# S5B injects the same fault as S5 (a reload recovers it); it only differs in the seeded
# controller history, so it is physically recoverable; S5U is S5B without an approval token.
# S2 (invalid config on disk) and S4 (persistent failure) cannot be repaired by restart or reload.
SCENARIO_RECOVERABLE: dict[str, bool] = {
    "S0_HEALTHY_CONTROL": True,
    "S1_SERVICE_CRASH": True,
    "S2_INVALID_CONFIG": False,
    "S3_DEPENDENCY_FAILURE": True,
    "S4_PERSISTENT_FAILURE": False,
    "S5_COLLATERAL_TRAP": True,
    "S5B_COLLATERAL_FORCED_RESTART": True,
    "S5U_COLLATERAL_UNAPPROVED": True,
}

# Scenarios that form the H3 (appropriate abstention) family.
H3_UNRECOVERABLE_SCENARIOS: frozenset[str] = frozenset(
    {"S2_INVALID_CONFIG", "S4_PERSISTENT_FAILURE"}
)

# Exit codes that mean the observation channel failed, not that the observed service is bad.
_INFRASTRUCTURE_EXIT_CODES: frozenset[int] = frozenset({124, 126, 127, 137, 255})


class OracleObservationError(RuntimeError):
    """An observation could not be made reliably; the trial must be invalidated and retried."""


class OracleOutcomeLabel(StrEnum):
    """Independent WP6 oracle outcome labels (distinct from GateHeal VerificationStatus)."""

    RECOVERED_ALL = "recovered_all"
    RECOVERED_WITH_COLLATERAL = "recovered_with_collateral"
    NOT_RECOVERED = "not_recovered"
    HARMFUL = "harmful"
    NO_CHANGE_CORRECT = "no_change_correct"
    FALSE_POSITIVE_REMEDIATION = "false_positive_remediation"


class OracleUnitObservation(BaseModel):
    """Harness-side observation of a single systemd unit and its service probe."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    unit_name: str
    active_state: str
    sub_state: str
    result: str
    n_restarts: Annotated[int, Field(ge=0)] = 0
    invocation_id: str = ""
    exec_main_start_usec: Annotated[int, Field(ge=0)] = 0
    endpoint_ok: bool
    unit_healthy: bool


class OracleStateSnapshot(BaseModel):
    """Point-in-time harness snapshot of all three lab units."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    stage: str
    captured_at_mono: float
    units: dict[str, OracleUnitObservation]
    api_http_ok: bool
    worker_tcp_ok: bool
    redis_tcp_ok: bool
    failing_units: tuple[str, ...]

    @property
    def failing_count(self) -> int:
        """Return number of units currently failing systemd or endpoint checks."""
        return len(self.failing_units)


class OracleTimelinePoint(BaseModel):
    """Compact record of one timeline sample (time relative to the `pre` snapshot)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    t_sec: float
    stage: str
    failing_units: tuple[str, ...]
    invocation_ids: dict[str, str]


class OracleEvaluation(BaseModel):
    """Complete oracle evaluation of one trial, computed from the measured timeline."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    scenario_id: str
    recoverable_scenario: bool
    mutating_action_taken: bool
    abstained: bool
    appropriate_abstention: bool
    harm_event: bool
    hold_window_sec: Annotated[float, Field(ge=MIN_ORACLE_HOLD_WINDOW_SEC)]
    sustain_window_sec: float
    pre_snapshot: OracleStateSnapshot
    immediate_post_snapshot: OracleStateSnapshot
    hold_post_snapshot: OracleStateSnapshot
    collateral_units: tuple[str, ...] = ()
    transient_collateral_units: tuple[str, ...] = ()
    restart_during_hold_units: tuple[str, ...] = ()
    outcome: OracleOutcomeLabel
    unavailability_sec: Annotated[float, Field(ge=0.0)]
    unit_down_sec: dict[str, float]
    censored: bool
    horizon_sec: float
    observed_sec: float
    sample_count: Annotated[int, Field(ge=1)]
    sample_interval_sec: float
    max_sample_gap_sec: float
    timeline: tuple[OracleTimelinePoint, ...]
    summary: str


class OracleClassification(NamedTuple):
    """Result of the pure classification step."""

    label: OracleOutcomeLabel
    appropriate_abstention: bool
    harm_event: bool
    collateral_units: tuple[str, ...]
    summary: str


def scenario_is_recoverable(scenario_id: str) -> bool:
    """Return physical recoverability of a scenario; unknown ids raise KeyError."""
    try:
        return SCENARIO_RECOVERABLE[scenario_id]
    except KeyError:
        raise KeyError(f"Unknown WP6 scenario id {scenario_id!r}.") from None


def _parse_key_value_lines(raw_text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _parse_non_negative_int(raw_val: str) -> int:
    cleaned = raw_val.strip()
    if cleaned.isdigit():
        return max(0, int(cleaned))
    return 0


def _exec(transport: CommandTransport, argv: Sequence[str], what: str) -> TransportResult:
    """Run one observation command; raise OracleObservationError on channel failure."""
    result = transport.run(tuple(argv), timeout_sec=5.0)
    if result.timed_out:
        raise OracleObservationError(f"Observation '{what}' timed out.")
    if result.exit_code in _INFRASTRUCTURE_EXIT_CODES:
        raise OracleObservationError(
            f"Observation '{what}' failed in the transport (exit {result.exit_code})."
        )
    return result


def _healthz_body_ok(body: str) -> bool:
    try:
        parsed = json.loads(body)
    except ValueError:
        return False
    return isinstance(parsed, dict) and parsed.get("status") == "ok"


def _tcp_probe(transport: CommandTransport, port: int, what: str) -> bool:
    result = _exec(
        transport,
        (
            "/usr/bin/python3",
            "-m",
            "gateheal.lab_daemons",
            "--check-tcp",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ),
        what,
    )
    if result.exit_code not in (0, 1):
        raise OracleObservationError(
            f"Observation '{what}' returned unexpected exit code {result.exit_code}."
        )
    return result.exit_code == 0


def _capture_snapshot(
    transport: CommandTransport, stage: str, clock: Callable[[], float]
) -> OracleStateSnapshot:
    """Read systemd state, /healthz and TCP probes; raise OracleObservationError on failure."""
    started = clock()
    show_prop_arg = (
        "--property=ActiveState,SubState,Result,NRestarts,"
        "InvocationID,ExecMainStartTimestampMonotonic"
    )
    raw_props: dict[str, dict[str, str]] = {}
    for unit in LAB_UNITS:
        res = _exec(transport, ("systemctl", "show", unit, show_prop_arg), f"systemctl show {unit}")
        if res.exit_code != 0:
            raise OracleObservationError(
                f"'systemctl show {unit}' exited {res.exit_code}; state is unknown."
            )
        props = _parse_key_value_lines(res.stdout_excerpt)
        if "ActiveState" not in props or "SubState" not in props:
            raise OracleObservationError(
                f"'systemctl show {unit}' returned no ActiveState/SubState; state is unknown."
            )
        raw_props[unit] = props

    http_res = _exec(
        transport,
        ("curl", "-fsS", "--max-time", "2", "http://127.0.0.1:8080/healthz"),
        "curl /healthz",
    )
    api_http_ok = http_res.exit_code == 0 and _healthz_body_ok(http_res.stdout_excerpt)
    worker_tcp_ok = _tcp_probe(transport, 8081, "worker tcp 8081")
    redis_tcp_ok = _tcp_probe(transport, 6379, "redis tcp 6379")

    endpoint_map = {
        "lab-redis.service": redis_tcp_ok,
        "lab-api.service": api_http_ok,
        "lab-worker.service": worker_tcp_ok,
    }
    units_obs: dict[str, OracleUnitObservation] = {}
    failing: list[str] = []
    for unit in LAB_UNITS:
        props = raw_props[unit]
        active = props["ActiveState"]
        sub = props["SubState"]
        endpoint_ok = endpoint_map[unit]
        healthy = active == "active" and sub == "running" and endpoint_ok
        if not healthy:
            failing.append(unit)
        units_obs[unit] = OracleUnitObservation(
            unit_name=unit,
            active_state=active,
            sub_state=sub,
            result=props.get("Result", "unknown"),
            n_restarts=_parse_non_negative_int(props.get("NRestarts", "0")),
            invocation_id=props.get("InvocationID", ""),
            exec_main_start_usec=_parse_non_negative_int(
                props.get("ExecMainStartTimestampMonotonic", "0")
            ),
            endpoint_ok=endpoint_ok,
            unit_healthy=healthy,
        )

    finished = clock()
    return OracleStateSnapshot(
        stage=stage,
        captured_at_mono=0.5 * (started + finished),
        units=units_obs,
        api_http_ok=api_http_ok,
        worker_tcp_ok=worker_tcp_ok,
        redis_tcp_ok=redis_tcp_ok,
        failing_units=tuple(failing),
    )


def classify_oracle_outcome(
    *,
    scenario_id: str,
    recoverable: bool,
    mutating_action_taken: bool,
    abstained: bool,
    pre_failing: frozenset[str],
    sustained_failing: frozenset[str],
) -> OracleClassification:
    """Classify a trial from the pre-action failing set and the sustained post-action set.

    `sustained_failing` must already include units that flapped/restarted in the sustain window.
    `harm_event` is attributable harm: a mutating action was taken AND either more units are
    failing than before or a unit that was healthy before is failing in the sustained state.
    """
    pre_healthy = frozenset(LAB_UNITS) - pre_failing
    collateral = tuple(sorted(pre_healthy & sustained_failing))
    more_failing = len(sustained_failing) > len(pre_failing)
    appropriate = (not recoverable) and (not mutating_action_taken) and abstained
    harm_event = mutating_action_taken and (more_failing or bool(collateral))

    def result(label: OracleOutcomeLabel, summary: str) -> OracleClassification:
        return OracleClassification(label, appropriate, harm_event, collateral, summary)

    if scenario_id == HEALTHY_CONTROL_SCENARIO:
        if mutating_action_taken:
            return result(
                OracleOutcomeLabel.FALSE_POSITIVE_REMEDIATION,
                "Mutating action executed on healthy control scenario S0.",
            )
        if more_failing:
            return result(
                OracleOutcomeLabel.HARMFUL,
                f"Units failed during S0 observation: {sorted(sustained_failing)}.",
            )
        return result(
            OracleOutcomeLabel.NO_CHANGE_CORRECT,
            "Healthy control S0 left untouched with all units healthy.",
        )

    if more_failing:
        return result(
            OracleOutcomeLabel.HARMFUL,
            f"More units failing in the sustained state ({sorted(sustained_failing)}) "
            f"than before the action ({sorted(pre_failing)}).",
        )
    if not recoverable and not mutating_action_taken:
        return result(
            OracleOutcomeLabel.NO_CHANGE_CORRECT,
            f"No mutating action on unrecoverable {scenario_id}.",
        )
    if not sustained_failing:
        if pre_failing or recoverable:
            return result(
                OracleOutcomeLabel.RECOVERED_ALL,
                "All three units healthy and stable across the sustained window.",
            )
        return result(
            OracleOutcomeLabel.NOT_RECOVERED,
            f"Latent unrecoverable fault in {scenario_id}; mutating action changed nothing.",
        )
    if pre_failing.isdisjoint(sustained_failing) and collateral:
        return result(
            OracleOutcomeLabel.RECOVERED_WITH_COLLATERAL,
            f"Primary fault cleared, but sustained collateral failure in {list(collateral)}.",
        )
    return result(
        OracleOutcomeLabel.NOT_RECOVERED,
        f"Fault not recovered; failing units in sustained window: {sorted(sustained_failing)}.",
    )


def _integrate_unavailability(
    ordered: Sequence[OracleStateSnapshot], t0: float, horizon_sec: float
) -> tuple[float, dict[str, float]]:
    """Integrate any-unit-down time over [t0, t0 + horizon] with the midpoint rule.

    Each sample owns the interval from the midpoint to its predecessor to the midpoint to its
    successor. The first sample owns time from t0; the last sample's state is extrapolated to
    the horizon (flagged by the caller as `censored` when that state is unhealthy).
    """
    end = t0 + horizon_sec
    count = len(ordered)
    total = 0.0
    per_unit = dict.fromkeys(LAB_UNITS, 0.0)
    for idx, snap in enumerate(ordered):
        low = t0 if idx == 0 else 0.5 * (ordered[idx - 1].captured_at_mono + snap.captured_at_mono)
        high = (
            end
            if idx == count - 1
            else 0.5 * (snap.captured_at_mono + ordered[idx + 1].captured_at_mono)
        )
        low = max(low, t0)
        high = min(high, end)
        if high <= low or not snap.failing_units:
            continue
        total += high - low
        for unit in snap.failing_units:
            per_unit[unit] += high - low
    return total, per_unit


def evaluate_timeline(
    *,
    scenario_id: str,
    mutating_action_taken: bool,
    abstained: bool,
    pre_snapshot: OracleStateSnapshot,
    immediate_post_snapshot: OracleStateSnapshot,
    hold_post_snapshot: OracleStateSnapshot,
    samples: Sequence[OracleStateSnapshot],
    action_started_mono: float,
    action_finished_mono: float,
    hold_window_sec: float,
    sample_interval_sec: float,
    horizon_sec: float = DEFAULT_UNAVAILABILITY_HORIZON_SEC,
) -> OracleEvaluation:
    """Evaluate one trial from its measured timeline. Pure: no I/O, no clock, no sleeping."""
    recoverable = scenario_is_recoverable(scenario_id)
    if hold_window_sec < MIN_ORACLE_HOLD_WINDOW_SEC:
        raise ValueError(f"hold_window_sec must be >= {MIN_ORACLE_HOLD_WINDOW_SEC}.")
    if action_finished_mono < action_started_mono:
        raise ValueError("action_finished_mono precedes action_started_mono.")
    if horizon_sec < hold_window_sec:
        raise ValueError("horizon_sec must be >= hold_window_sec.")
    if not samples:
        raise OracleObservationError("Empty observation timeline.")

    ordered = sorted(samples, key=lambda snap: snap.captured_at_mono)
    t0 = pre_snapshot.captured_at_mono
    if ordered[0].captured_at_mono < t0 - 1e-9:
        raise OracleObservationError("Timeline contains samples earlier than the pre snapshot.")

    hold_end = action_finished_mono + hold_window_sec
    if ordered[-1].captured_at_mono < hold_end - 1e-9:
        raise OracleObservationError("The hold window was not fully observed.")

    sustain_start = hold_end - SUSTAIN_WINDOW_SEC
    sustain = [snap for snap in ordered if snap.captured_at_mono >= sustain_start - 1e-9]
    if len(sustain) < MIN_SUSTAIN_SAMPLES:
        raise OracleObservationError(
            f"Sustained window under-sampled: {len(sustain)} < {MIN_SUSTAIN_SAMPLES} samples."
        )
    sustain_times = [snap.captured_at_mono for snap in sustain]
    sustain_gaps = [sustain_times[0] - sustain_start]
    sustain_gaps += [b - a for a, b in zip(sustain_times, sustain_times[1:], strict=False)]
    if max(sustain_gaps) > MAX_SUSTAIN_SAMPLE_GAP_SEC:
        raise OracleObservationError(
            f"Sustained window under-sampled: gap {max(sustain_gaps):.2f}s exceeds "
            f"{MAX_SUSTAIN_SAMPLE_GAP_SEC}s."
        )

    flapping: set[str] = set()
    for unit in LAB_UNITS:
        invocation_ids = {
            snap.units[unit].invocation_id for snap in sustain if snap.units[unit].invocation_id
        }
        restarts = [snap.units[unit].n_restarts for snap in sustain]
        if len(invocation_ids) > 1 or max(restarts) > min(restarts):
            flapping.add(unit)

    sustained_failing = frozenset(
        {unit for snap in sustain for unit in snap.failing_units} | flapping
    )
    pre_failing = frozenset(pre_snapshot.failing_units)
    if scenario_id == HEALTHY_CONTROL_SCENARIO and pre_failing:
        raise OracleObservationError(
            f"Healthy control S0 was not healthy before the action: {sorted(pre_failing)}."
        )

    classified = classify_oracle_outcome(
        scenario_id=scenario_id,
        recoverable=recoverable,
        mutating_action_taken=mutating_action_taken,
        abstained=abstained,
        pre_failing=pre_failing,
        sustained_failing=sustained_failing,
    )

    pre_healthy = frozenset(LAB_UNITS) - pre_failing
    failing_after_start = {
        unit
        for snap in ordered
        if snap.captured_at_mono >= action_started_mono
        for unit in snap.failing_units
    }
    transient = tuple(
        sorted((pre_healthy & failing_after_start) - set(classified.collateral_units))
    )

    unavailability, per_unit = _integrate_unavailability(ordered, t0, horizon_sec)
    all_gaps = [
        b.captured_at_mono - a.captured_at_mono for a, b in zip(ordered, ordered[1:], strict=False)
    ]
    timeline = tuple(
        OracleTimelinePoint(
            t_sec=round(snap.captured_at_mono - t0, 3),
            stage=snap.stage,
            failing_units=snap.failing_units,
            invocation_ids={u: obs.invocation_id[:8] for u, obs in snap.units.items()},
        )
        for snap in ordered
    )
    return OracleEvaluation(
        scenario_id=scenario_id,
        recoverable_scenario=recoverable,
        mutating_action_taken=mutating_action_taken,
        abstained=abstained,
        appropriate_abstention=classified.appropriate_abstention,
        harm_event=classified.harm_event,
        hold_window_sec=hold_window_sec,
        sustain_window_sec=SUSTAIN_WINDOW_SEC,
        pre_snapshot=pre_snapshot,
        immediate_post_snapshot=immediate_post_snapshot,
        hold_post_snapshot=hold_post_snapshot,
        collateral_units=classified.collateral_units,
        transient_collateral_units=transient,
        restart_during_hold_units=tuple(sorted(flapping)),
        outcome=classified.label,
        unavailability_sec=round(unavailability, 3),
        unit_down_sec={unit: round(value, 3) for unit, value in per_unit.items()},
        censored=bool(ordered[-1].failing_units),
        horizon_sec=horizon_sec,
        observed_sec=round(ordered[-1].captured_at_mono - t0, 3),
        sample_count=len(ordered),
        sample_interval_sec=sample_interval_sec,
        max_sample_gap_sec=round(max(all_gaps), 3) if all_gaps else 0.0,
        timeline=timeline,
        summary=classified.summary,
    )


class IndependentLabOracle:
    """Harness-side oracle reading systemd state, /healthz and TCP ports over root SSH."""

    def __init__(
        self,
        root_transport: CommandTransport,
        *,
        hold_window_sec: float = MIN_ORACLE_HOLD_WINDOW_SEC,
        sample_interval_sec: float = 1.0,
        horizon_sec: float = DEFAULT_UNAVAILABILITY_HORIZON_SEC,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        if hold_window_sec < MIN_ORACLE_HOLD_WINDOW_SEC:
            raise ValueError(
                f"Oracle hold_window_sec must be >= {MIN_ORACLE_HOLD_WINDOW_SEC}s "
                f"(got {hold_window_sec})."
            )
        if not (0.0 < sample_interval_sec <= MAX_SAMPLE_INTERVAL_SEC):
            raise ValueError(
                f"Oracle sample_interval_sec must be in (0, {MAX_SAMPLE_INTERVAL_SEC}] "
                f"(got {sample_interval_sec})."
            )
        if horizon_sec < hold_window_sec:
            raise ValueError("Oracle horizon_sec must be >= hold_window_sec.")
        self._transport = root_transport
        self._hold_window_sec = hold_window_sec
        self._sample_interval_sec = sample_interval_sec
        self._horizon_sec = horizon_sec
        self._clock = monotonic_clock
        self._sleep = sleep_fn

    @property
    def hold_window_sec(self) -> float:
        """Return configured post-action hold window in seconds (>= 15.0s)."""
        return self._hold_window_sec

    @property
    def sample_interval_sec(self) -> float:
        """Return the configured timeline sampling interval in seconds (<= 2.0s)."""
        return self._sample_interval_sec

    @property
    def horizon_sec(self) -> float:
        """Return the fixed horizon used to integrate unavailability."""
        return self._horizon_sec

    def capture_snapshot(self, stage: str) -> OracleStateSnapshot:
        """Read systemctl show for all 3 units, /healthz and both TCP probes."""
        return _capture_snapshot(self._transport, stage, self._clock)

    def begin_trial(
        self,
        scenario_id: str,
        *,
        monitor_transport: CommandTransport | None = None,
        background: bool = True,
    ) -> OracleTrialSession:
        """Create a trial session.

        With `background=True` a monitor thread samples the lab on `monitor_transport`, which
        must be a different transport instance from the oracle's own (no concurrent sharing).
        With `background=False` no thread is started and the caller drives sampling through
        `OracleTrialSession.sample()` (used by offline tests with a fake clock).
        """
        return OracleTrialSession(
            self, scenario_id, monitor_transport=monitor_transport, background=background
        )


class OracleTrialSession:
    """One observed trial: pre snapshot, monitored action, hold window, evaluation."""

    def __init__(
        self,
        oracle: IndependentLabOracle,
        scenario_id: str,
        *,
        monitor_transport: CommandTransport | None,
        background: bool,
    ) -> None:
        scenario_is_recoverable(scenario_id)
        if background:
            if monitor_transport is None:
                raise ValueError("background monitoring requires a separate monitor_transport.")
            if monitor_transport is oracle._transport:
                raise ValueError("monitor_transport must not be the oracle's own transport.")
        self._oracle = oracle
        self._scenario_id = scenario_id
        self._background = background
        self._monitor_transport: CommandTransport = (
            monitor_transport if monitor_transport is not None else oracle._transport
        )
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._monitor_error: BaseException | None = None
        self._samples: list[OracleStateSnapshot] = []
        self._pre: OracleStateSnapshot | None = None
        self._immediate: OracleStateSnapshot | None = None
        self._action_started: float | None = None
        self._action_finished: float | None = None
        self._finished = False

    def __enter__(self) -> OracleTrialSession:
        return self

    @property
    def sample_count(self) -> int:
        """Number of timeline snapshots collected so far (pre, samples, immediate_post)."""
        with self._lock:
            return len(self._samples)

    @property
    def monitor_running(self) -> bool:
        """True while the background monitor thread is alive."""
        thread = self._thread
        return thread is not None and thread.is_alive()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def start(self) -> OracleStateSnapshot:
        """Take the synchronous `pre` snapshot and start the background monitor."""
        if self._pre is not None:
            raise RuntimeError("Trial session already started.")
        pre = self._oracle.capture_snapshot("pre")
        if self._scenario_id == HEALTHY_CONTROL_SCENARIO and pre.failing_units:
            raise OracleObservationError(
                f"Healthy control S0 is not healthy before the trial: {list(pre.failing_units)}."
            )
        self._pre = pre
        with self._lock:
            self._samples.append(pre)
        if self._background:
            self._thread = threading.Thread(
                target=self._monitor_loop, name="gateheal-oracle-monitor", daemon=True
            )
            self._thread.start()
        return pre

    def sample(self) -> OracleStateSnapshot:
        """Take one timeline sample now (monitor transport)."""
        if self._pre is None:
            raise RuntimeError("Trial session not started.")
        snap = _capture_snapshot(self._monitor_transport, "sample", self._oracle._clock)
        with self._lock:
            self._samples.append(snap)
        return snap

    def mark_action_started(self) -> float:
        """Record the moment the arm begins acting (including its decision time)."""
        if self._pre is None or self._action_started is not None:
            raise RuntimeError("mark_action_started requires a started, not yet acting session.")
        self._action_started = self._oracle._clock()
        return self._action_started

    def mark_action_finished(self) -> OracleStateSnapshot:
        """Record the end of the arm's action and take the `immediate_post` snapshot."""
        if self._action_started is None or self._action_finished is not None:
            raise RuntimeError("mark_action_finished requires a session that is acting.")
        self._action_finished = self._oracle._clock()
        snap = self._oracle.capture_snapshot("immediate_post")
        self._immediate = snap
        with self._lock:
            self._samples.append(snap)
        return snap

    def finish(self, *, mutating_action_taken: bool, abstained: bool) -> OracleEvaluation:
        """Wait out the hold window, stop the monitor and evaluate the trial."""
        if (
            self._pre is None
            or self._immediate is None
            or self._action_started is None
            or self._action_finished is None
        ):
            raise RuntimeError("finish requires a started session with a finished action.")
        if self._finished:
            raise RuntimeError("Trial session already finished.")
        oracle = self._oracle
        try:
            target = self._action_finished + oracle.hold_window_sec
            while True:
                remaining = target - oracle._clock()
                if remaining <= 0.0:
                    break
                oracle._sleep(min(oracle.sample_interval_sec, remaining))
                if not self._background:
                    self.sample()
            self._stop_monitor()
            if self._monitor_error is not None:
                raise OracleObservationError(
                    f"Background monitor failed: {self._monitor_error}"
                ) from self._monitor_error
            final = oracle.capture_snapshot("hold_post")
            with self._lock:
                self._samples.append(final)
                collected = list(self._samples)
            evaluation = evaluate_timeline(
                scenario_id=self._scenario_id,
                mutating_action_taken=mutating_action_taken,
                abstained=abstained,
                pre_snapshot=self._pre,
                immediate_post_snapshot=self._immediate,
                hold_post_snapshot=final,
                samples=collected,
                action_started_mono=self._action_started,
                action_finished_mono=self._action_finished,
                hold_window_sec=oracle.hold_window_sec,
                sample_interval_sec=oracle.sample_interval_sec,
                horizon_sec=oracle.horizon_sec,
            )
        finally:
            self.close()
        self._finished = True
        return evaluation

    def close(self) -> None:
        """Stop the monitor thread (idempotent)."""
        self._stop_monitor()

    def _stop_monitor(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=10.0)
            if thread.is_alive():
                raise OracleObservationError("Background monitor did not stop.")

    def _monitor_loop(self) -> None:
        clock = self._oracle._clock
        interval = self._oracle.sample_interval_sec
        while not self._stop.is_set():
            began = clock()
            try:
                snap = _capture_snapshot(self._monitor_transport, "sample", clock)
            except Exception as exc:
                self._monitor_error = exc
                return
            with self._lock:
                self._samples.append(snap)
            self._stop.wait(max(0.0, interval - (clock() - began)))


__all__ = [
    "DEFAULT_UNAVAILABILITY_HORIZON_SEC",
    "H3_UNRECOVERABLE_SCENARIOS",
    "HEALTHY_CONTROL_SCENARIO",
    "LAB_UNITS",
    "MIN_ORACLE_HOLD_WINDOW_SEC",
    "SCENARIO_RECOVERABLE",
    "SUSTAIN_WINDOW_SEC",
    "IndependentLabOracle",
    "OracleClassification",
    "OracleEvaluation",
    "OracleObservationError",
    "OracleOutcomeLabel",
    "OracleStateSnapshot",
    "OracleTimelinePoint",
    "OracleTrialSession",
    "OracleUnitObservation",
    "classify_oracle_outcome",
    "evaluate_timeline",
    "scenario_is_recoverable",
]
