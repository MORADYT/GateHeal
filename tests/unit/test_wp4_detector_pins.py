# ruff: noqa: E501
"""Auditor-supplied WP4 pins: every soak detector must be killable in isolation.

Each scenario changes exactly ONE signal so that removing the matching detector in
`OutcomeVerifier` flips the verdict. Plus three orchestrator end-to-end runs that go
through the real `verify_with_transport` path (no `post_evidence_supplier`).
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from gateheal.config import GateHealConfig, load_config
from gateheal.controller import AuditRecorder, EscalationSink, OutcomeVerifier
from gateheal.models import (
    ActionId,
    ActionProposal,
    ExecutionResult,
    FaultClass,
    IncidentRecord,
    ServiceEvidence,
    VerificationStatus,
)
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.state import PersistentStateStore
from gateheal.transport import TransportResult

API, REDIS, WORKER = "lab-api.service", "lab-redis.service", "lab-worker.service"
State = Callable[[float, str], dict[str, Any]]


def _cfg() -> GateHealConfig:
    return load_config(Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml")


def _ev(u: str, act: str = "active", ok: bool = True, inv: str = "i", st: int = 1) -> ServiceEvidence:
    return ServiceEvidence(
        unit_name=u,
        active_state=act,
        sub_state="running" if act == "active" else act,
        health_probe_ok=ok,
        config_valid=True,
        n_restarts=0,
        invocation_id=inv,
        exec_main_start_timestamp_usec=st,
    )


def _pre(api_active: bool = False, api_inv: str = "old", api_st: int = 5) -> IncidentRecord:
    api = _ev(API, "active", False, api_inv, api_st) if api_active else _ev(API, "failed", False, api_inv, api_st)
    return IncidentRecord(
        incident_id="pin-1",
        target_unit=API,
        collected_at_utc="2026-10-23T12:00:00Z",
        services={REDIS: _ev(REDIS, inv=REDIS + "1"), API: api, WORKER: _ev(WORKER, inv=WORKER + "1")},
    )


class _Scripted:
    def __init__(self, f: State) -> None:
        self.f, self.t = f, 0.0

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        a = tuple(argv)
        if a[0] == "systemctl":
            s = self.f(self.t, a[2])
            props = {
                "ActiveState": s["a"],
                "SubState": "running" if s["a"] == "active" else s["a"],
                "Result": "success",
                "NRestarts": s.get("nr", 0),
                "CanReload": "yes",
                "InvocationID": s.get("inv", "x"),
                "ExecMainStartTimestampMonotonic": s.get("st", 100),
            }
            out = "\n".join(f"{k}={v}" for k, v in props.items()) + "\n"
            return TransportResult(exit_code=0, stdout_excerpt=out, duration_sec=0.01)
        port_unit = {"8080": API, "6379": REDIS, "8081": WORKER}
        key = [k for k in port_unit if k in " ".join(a)]
        if a[0] == "curl" or "--check-tcp" in a:
            ok = self.f(self.t, port_unit[key[0]] if key else API).get("ok", True)
            return TransportResult(exit_code=0 if ok else 1, duration_sec=0.01)
        return TransportResult(exit_code=0, duration_sec=0.01)


def _verify(
    f: State, action: ActionId = ActionId.RESTART_SERVICE, pre: IncidentRecord | None = None
) -> Any:
    cfg = _cfg()
    clk = [0.0]
    tr = _Scripted(f)

    def sleep(s: float) -> None:
        clk[0] += s
        tr.t = clk[0]

    v = OutcomeVerifier(
        cfg,
        monotonic_clock=lambda: clk[0],
        sleep_fn=sleep,
        default_poll_interval_sec=cfg.budgets.verification_poll_interval_sec,
    )
    p = ActionProposal(action_id=action.value, target_unit=API, inferred_fault=FaultClass.PROCESS_CRASH, rationale="pin")
    er = ExecutionResult(action_id=action, target_unit=API, argv=("x",), exit_code=0, duration_sec=0.1)
    rep, _ = v.verify_with_transport(p, er, pre or _pre(), tr)
    return rep


def _api_changes(**chg: Any) -> State:
    def f(t: float, u: str) -> dict[str, Any]:
        d: dict[str, Any] = {"a": "active", "inv": u + "1", "st": 10}
        if u == API and t >= 3:
            d.update(chg)
        return d

    return f


def test_clean_recovery_takes_five_samples() -> None:
    rep = _verify(lambda t, u: {"a": "active", "inv": u + "1", "st": 10})
    assert rep.status == VerificationStatus.RECOVERED_CLEAN
    assert rep.samples_collected == 5


@pytest.mark.parametrize(
    "chg",
    [{"nr": 1}, {"inv": "api-new"}, {"st": 999}],
    ids=["nrestarts_only", "invocation_only", "start_ts_only"],
)
def test_each_recurrence_signal_alone_is_not_recovered(chg: dict[str, Any]) -> None:
    rep = _verify(_api_changes(**chg))
    assert rep.status == VerificationStatus.NOT_RECOVERED


def test_reload_must_not_change_invocation_id() -> None:
    pre = _pre(api_active=True, api_inv=API + "1", api_st=5)
    rep = _verify(
        lambda t, u: {"a": "active", "inv": "CHANGED" if u == API else u + "1", "st": 5},
        ActionId.RELOAD_SERVICE,
        pre,
    )
    assert rep.status == VerificationStatus.NOT_RECOVERED


def test_reload_must_not_change_exec_main_start_timestamp() -> None:
    pre = _pre(api_active=True, api_inv=API + "1", api_st=5)
    rep = _verify(
        lambda t, u: {"a": "active", "inv": u + "1", "st": 777 if u == API else 10},
        ActionId.RELOAD_SERVICE,
        pre,
    )
    assert rep.status == VerificationStatus.NOT_RECOVERED


def test_unhealthy_only_in_one_middle_sample_is_not_clean() -> None:
    rep = _verify(lambda t, u: {"a": "active", "ok": not (u == API and 2.5 < t < 3.5), "inv": u + "1"})
    assert rep.status == VerificationStatus.NOT_RECOVERED


def test_unhealthy_only_in_first_sample_is_not_clean() -> None:
    rep = _verify(lambda t, u: {"a": "active", "ok": not (u == API and t < 1.5), "inv": u + "1"})
    assert rep.status == VerificationStatus.NOT_RECOVERED


def test_dependent_failing_in_a_middle_sample_only_is_collateral() -> None:
    rep = _verify(lambda t, u: {"a": "active", "ok": not (u == WORKER and 1.5 < t < 2.5), "inv": u + "1"})
    assert rep.status == VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE
    assert rep.collateral_failures == (WORKER,)


def test_dependent_already_dead_before_is_not_collateral() -> None:
    pre = _pre()
    pre = pre.model_copy(update={"services": {**pre.services, WORKER: _ev(WORKER, "failed", False)}})
    rep = _verify(
        lambda t, u: {"a": "failed" if u == WORKER else "active", "ok": u != WORKER, "inv": u + "1"},
        pre=pre,
    )
    assert rep.status == VerificationStatus.RECOVERED_CLEAN
    assert rep.collateral_failures == ()


def test_oracle_tcp_probe_is_authoritative_over_systemd_state() -> None:
    # systemd says active/running, but the dependent's TCP probe fails -> must be seen
    rep = _verify(lambda t, u: {"a": "active", "ok": u != WORKER, "inv": u + "1"})
    assert rep.collateral_failures == (WORKER,)


def test_oracle_http_probe_is_authoritative_over_systemd_state() -> None:
    rep = _verify(lambda t, u: {"a": "active", "ok": u != API, "inv": u + "1"})
    assert rep.status == VerificationStatus.NOT_RECOVERED


def test_oracle_probe_timeout_mid_soak_is_uncertain_with_partial_samples() -> None:
    cfg = _cfg()
    clk = [0.0]

    class Hang(_Scripted):
        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            if self.t >= 3 and tuple(argv)[0] == "systemctl":
                return TransportResult(exit_code=-1, timed_out=True, duration_sec=5.0)
            return super().run(argv, timeout_sec)

    tr = Hang(lambda t, u: {"a": "active", "inv": u + "1"})

    def sleep(s: float) -> None:
        clk[0] += s
        tr.t = clk[0]

    v = OutcomeVerifier(cfg, monotonic_clock=lambda: clk[0], sleep_fn=sleep, default_poll_interval_sec=1.0)
    p = ActionProposal(action_id=ActionId.RESTART_SERVICE.value, target_unit=API, inferred_fault=FaultClass.PROCESS_CRASH, rationale="pin")
    er = ExecutionResult(action_id=ActionId.RESTART_SERVICE, target_unit=API, argv=("x",), exit_code=0, duration_sec=0.1)
    rep, _ = v.verify_with_transport(p, er, _pre(), tr)
    assert rep.status == VerificationStatus.OUTCOME_UNCERTAIN
    assert rep.samples_collected == 2


def test_abstain_and_noop_do_not_soak() -> None:
    for act in (ActionId.ABSTAIN_AND_ESCALATE, ActionId.NO_OP):
        rep = _verify(lambda t, u: {"a": "active", "inv": u + "1"}, act)
        assert rep.samples_collected == 1
        assert rep.soak_duration_sec == 0.0


def test_read_only_diagnostic_does_not_pay_the_full_soak() -> None:
    """WP4 regression: pre-WP4 only mutating actions soaked; diagnostics must stay cheap."""
    rep = _verify(lambda t, u: {"a": "active", "inv": u + "1"}, ActionId.INSPECT_SERVICE_STATUS)
    assert rep.samples_collected == 1


# ---------------- orchestrator end-to-end through the REAL oracle path ----------------
class _Guest:
    def __init__(self, clk: list[float], crash_after: float | None = None, kill_worker: bool = False) -> None:
        self.clk, self.crash_after, self.kill_worker = clk, crash_after, kill_worker
        self.u: dict[str, dict[str, Any]] = {
            API: {"a": "failed", "inv": "api0", "st": 1, "since": 0.0},
            REDIS: {"a": "active", "inv": "r0", "st": 1, "since": 0.0},
            WORKER: {"a": "active", "inv": "w0", "st": 1, "since": 0.0},
        }
        self.restart_at: float | None = None
        self.n = 0

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        a = tuple(argv)
        if self.restart_at is not None and self.crash_after is not None and self.clk[0] >= self.restart_at + self.crash_after:
            self.u[API]["a"] = "failed"

        def ok(out: str = "", code: int = 0) -> TransportResult:
            return TransportResult(exit_code=code, stdout_excerpt=out, duration_sec=0.01)

        if a[:2] == ("cat", "/proc/uptime"):
            return ok("1000.0 900.0\n")
        if a[0] == "systemctl" and a[1] == "show":
            s = self.u[a[2]]
            sub = "running" if s["a"] == "active" else s["a"]
            return ok(
                f"ActiveState={s['a']}\nSubState={sub}\nResult={'success' if s['a'] == 'active' else 'signal'}\n"
                f"NRestarts=0\nCanReload=yes\nInvocationID={s['inv']}\nExecMainStartTimestampMonotonic={s['st']}\n"
                f"ActiveEnterTimestampMonotonic={int(s['since'] * 1e6) + 1}\nNowMonotonic={int((self.clk[0] + 1000) * 1e6)}\n"
            )
        if a[0] == "sudo" and "restart" in a:
            unit = a[-1]
            self.n += 1
            self.u[unit].update(a="active", inv=f"{unit}-{self.n}", st=int(self.clk[0] * 1e6) + 2, since=self.clk[0] + 1000)
            if unit == API:
                self.restart_at = self.clk[0]
                if self.kill_worker:
                    self.u[WORKER]["a"] = "failed"
            return ok()
        if a[0] == "curl":
            return ok(code=0 if self.u[API]["a"] == "active" else 22)
        if "--check-tcp" in a:
            unit = {"6379": REDIS, "8081": WORKER}[a[-1]]
            return ok(code=0 if self.u[unit]["a"] == "active" else 1)
        return ok()


def _e2e(**kw: Any) -> tuple[Any, EscalationSink, float]:
    clk = [100.0]
    tmp = Path(tempfile.mkdtemp())
    esc = EscalationSink(tmp / "esc.jsonl")
    now = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)

    def sleep(s: float) -> None:
        clk[0] += s

    o = IncidentOrchestrator(
        _cfg(),
        transport=_Guest(clk, **kw),
        audit_recorder=AuditRecorder(tmp / "audit.jsonl", clock_utc=lambda: now),
        escalation_sink=esc,
        state_store=PersistentStateStore(tmp / "st.json"),
        clock_utc=lambda: now,
        monotonic_clock=lambda: clk[0],
        sleep_fn=sleep,
    )
    audit = o.handle_incident(incident_id="inc-e2e", target_unit=API)
    return audit, esc, clk[0] - 100.0


def test_e2e_real_oracle_clean_recovery_after_sigkill_fault() -> None:
    audit, esc, elapsed = _e2e()
    assert audit.verification_report is not None
    assert audit.verification_report.status == VerificationStatus.RECOVERED_CLEAN
    assert audit.verification_report.samples_collected == 5
    assert elapsed >= 5.0
    assert not audit.escalated and not esc.emitted_alerts


def test_e2e_real_oracle_crash_two_seconds_after_restart_escalates() -> None:
    audit, esc, _ = _e2e(crash_after=2.0)
    assert audit.verification_report is not None
    assert audit.verification_report.status == VerificationStatus.NOT_RECOVERED
    assert audit.escalated and len(esc.emitted_alerts) == 1


def test_e2e_real_oracle_reports_collateral_and_escalates() -> None:
    audit, esc, _ = _e2e(kill_worker=True)
    assert audit.verification_report is not None
    assert audit.verification_report.status == VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE
    assert audit.verification_report.collateral_failures == (WORKER,)
    assert audit.escalated and len(esc.emitted_alerts) == 1
