"""Regression tests for findings from the first full live WP5 capture (2026-10-26)."""

from __future__ import annotations

import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path

import pytest

from gateheal import transport as transport_mod
from gateheal.lab_bringup import (
    REQUIRED_CONFORMANCE_FACT_IDS,
    ConformanceFactResult,
    LabRunManifest,
    SmokeScenarioRunResult,
    SSHLatencyProfile,
    build_lab_run_manifest,
    conformance_is_complete_and_passed,
    missing_conformance_fact_ids,
)
from gateheal.lab_daemons import LabApiRuntimeState
from gateheal.models import FaultClass, VerificationStatus
from gateheal.transport import SSHLabTransport, TransportResult

_REPO = Path(__file__).resolve().parents[2]


def _facts(ids: Sequence[str], passed: bool = True) -> list[ConformanceFactResult]:
    return [ConformanceFactResult(fact_id=i, passed=passed, details="") for i in ids]


def _write_cfg(
    path: Path, *, stale: bool, port: int = 8080, redis_port: int = 6379
) -> None:
    path.write_text(
        "listen_host: '127.0.0.1'\n"
        f"listen_port: {port}\n"
        "redis_host: '127.0.0.1'\n"
        f"redis_port: {redis_port}\n"
        f"worker_pool_stale: {'true' if stale else 'false'}\n",
        encoding="utf-8",
    )


# ---- Finding 1: S5 stale-pool fault must be runtime-only (a restart must clear it) --------


def test_runtime_stale_flag_is_cleared_by_restart_and_sighup(tmp_path: Path) -> None:
    cfg = tmp_path / "api.yaml"
    _write_cfg(cfg, stale=False)
    state = LabApiRuntimeState(cfg)
    assert state.load_or_reload(is_sighup=False)
    state.mark_worker_pool_stale()
    assert state.worker_pool_stale is True
    # SIGHUP clears it
    assert state.load_or_reload(is_sighup=True)
    assert state.worker_pool_stale is False
    # a fresh process (restart) never inherits it, because the config file says false
    state.mark_worker_pool_stale()
    restarted = LabApiRuntimeState(cfg)
    assert restarted.load_or_reload(is_sighup=False)
    assert restarted.worker_pool_stale is False
    assert "worker_pool_stale: false" in cfg.read_text(encoding="utf-8")


def test_inject_s5_does_not_persist_fault_in_config_file() -> None:
    script = (_REPO / "lab" / "fault_injection" / "inject_fault.sh").read_text(
        encoding="utf-8"
    )
    s5 = script.split("S5_COLLATERAL_TRAP)", 1)[1].split(";;", 1)[0]
    assert "SIGUSR1" in s5
    assert "sed -i" not in s5
    code_lines = [ln for ln in s5.splitlines() if not ln.strip().startswith("#")]
    assert not any("config.yaml" in ln for ln in code_lines)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _get_health(port: int) -> tuple[int, dict[str, object]]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        return resp.status, json.loads(resp.read().decode("utf-8"))
    finally:
        conn.close()


def _wait_http(port: int) -> None:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            _get_health(port)
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("lab-api daemon did not start listening")


@pytest.mark.skipif(not hasattr(signal, "SIGUSR1"), reason="POSIX only")
def test_real_api_daemon_sigusr1_degrades_then_restart_and_sighup_recover(
    tmp_path: Path,
) -> None:
    redis_port, api_port = _free_port(), _free_port()
    redis_srv = socket.socket()
    redis_srv.bind(("127.0.0.1", redis_port))
    redis_srv.listen(8)
    stop = threading.Event()

    def _accept() -> None:
        redis_srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = redis_srv.accept()
                conn.settimeout(0.5)
                try:
                    _ = conn.recv(64)
                except OSError:
                    pass
                conn.sendall(b"+OK\r\n")
                conn.close()
            except OSError:
                continue

    t = threading.Thread(target=_accept, daemon=True)
    t.start()
    cfg = tmp_path / "api.yaml"
    _write_cfg(cfg, stale=False, port=api_port, redis_port=redis_port)
    env = {**os.environ, "PYTHONPATH": str(_REPO / "src")}
    cmd = [
        sys.executable,
        "-m",
        "gateheal.lab_daemons",
        "--role",
        "api",
        "--config",
        str(cfg),
    ]
    procs: list[subprocess.Popen[bytes]] = []
    try:
        p1 = subprocess.Popen(cmd, env=env)
        procs.append(p1)
        _wait_http(api_port)
        assert _get_health(api_port)[0] == 200
        p1.send_signal(signal.SIGUSR1)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and _get_health(api_port)[0] != 503:
            time.sleep(0.05)
        code, body = _get_health(api_port)
        assert (code, body["status"]) == (503, "degraded")
        assert p1.poll() is None  # SIGUSR1 must not kill the daemon
        p1.send_signal(signal.SIGHUP)  # reload clears it
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and _get_health(api_port)[0] != 200:
            time.sleep(0.05)
        assert _get_health(api_port)[0] == 200
        p1.send_signal(signal.SIGUSR1)
        time.sleep(0.3)
        assert _get_health(api_port)[0] == 503
        p1.kill()
        p1.wait(timeout=5)
        p2 = subprocess.Popen(cmd, env=env)  # restart: fresh process
        procs.append(p2)
        _wait_http(api_port)
        assert _get_health(api_port)[0] == 200
    finally:
        stop.set()
        for p in procs:
            if p.poll() is None:
                p.kill()
                p.wait(timeout=5)
        redis_srv.close()


# ---- Finding 2: truncated conformance output must never count as "all passed" -------------


def test_conformance_missing_facts_are_not_all_passed() -> None:
    full = _facts(REQUIRED_CONFORMANCE_FACT_IDS)
    assert conformance_is_complete_and_passed(full) is True
    # the live capture lost the oldest 4 facts to tail truncation
    truncated = full[4:]
    assert missing_conformance_fact_ids(truncated) == tuple(
        REQUIRED_CONFORMANCE_FACT_IDS[:4]
    )
    assert conformance_is_complete_and_passed(truncated) is False
    assert conformance_is_complete_and_passed([]) is False
    failing = [
        *full[:-1],
        ConformanceFactResult(fact_id="SUDO_NEG_DENIED", passed=False, details=""),
    ]
    assert conformance_is_complete_and_passed(failing) is False


def test_ssh_transport_passes_output_budget_to_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, int] = {}

    def _fake(
        argv: Sequence[str], timeout_sec: float, max_output_chars: int = 2048
    ) -> TransportResult:
        _ = (argv, timeout_sec)
        seen["max"] = max_output_chars
        return TransportResult(exit_code=0, duration_sec=0.0, stdout_excerpt="ok")

    monkeypatch.setattr(transport_mod, "run_isolated_process_group", _fake)
    t = SSHLabTransport(verify_remote_sentinel=False, max_output_chars=262144)
    t.run(("true",), timeout_sec=1.0)
    assert seen["max"] == 262144
    seen.clear()
    SSHLabTransport(verify_remote_sentinel=False).run(("true",), timeout_sec=1.0)
    assert seen["max"] == 2048


# ---- Finding 3: a consistently wrong scenario is a mismatch, not a flake ------------------


def _run(rep: int, status: VerificationStatus, matched: bool) -> SmokeScenarioRunResult:
    return SmokeScenarioRunResult(
        scenario_id="S5B_COLLATERAL_FORCED_RESTART",
        repeat_index=rep,
        diagnosed_fault=FaultClass.DEGRADED_RUNNING,
        selected_action_id="restart_service",
        selected_target_unit="lab-api.service",
        verification_status=status,
        samples_collected=5,
        soak_wall_clock_sec=1.0,
        escalated=True,
        matched_expectation=matched,
    )


def _manifest(runs: list[SmokeScenarioRunResult], tmp_path: Path) -> LabRunManifest:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("x: 1\n", encoding="utf-8")
    sud = tmp_path / "s.conf"
    sud.write_text("y\n", encoding="utf-8")
    lat = SSHLatencyProfile(samples=1, min_ms=1.0, mean_ms=1.0, p95_ms=1.0, max_ms=1.0)
    return build_lab_run_manifest(
        repo_root=tmp_path,
        config_path=cfg,
        sudoers_path=sud,
        ssh_latency=lat,
        conformance_facts=_facts(REQUIRED_CONFORMANCE_FACT_IDS),
        smoke_matrix=runs,
        repeats=len(runs),
    )


def test_manifest_counts_mismatches_and_flakes_separately(tmp_path: Path) -> None:
    bad = [_run(i, VerificationStatus.NOT_RECOVERED, False) for i in (1, 2, 3)]
    m = _manifest(bad, tmp_path)
    assert (m.mismatch_count, m.flake_count, m.smoke_all_passed) == (3, 0, False)
    mixed = [
        _run(1, VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE, True),
        _run(2, VerificationStatus.NOT_RECOVERED, True),
    ]
    m2 = _manifest(mixed, tmp_path)
    assert (m2.mismatch_count, m2.flake_count, m2.smoke_all_passed) == (0, 1, False)
    ok = [
        _run(i, VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE, True)
        for i in (1, 2)
    ]
    m3 = _manifest(ok, tmp_path)
    assert (m3.mismatch_count, m3.flake_count, m3.smoke_all_passed) == (0, 0, True)
    assert m3.conformance_all_passed is True


def test_manifest_conformance_not_all_passed_when_facts_truncated(tmp_path: Path) -> None:
    ok = [_run(1, VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE, True)]
    cfg = tmp_path / "c.yaml"
    cfg.write_text("x: 1\n", encoding="utf-8")
    sud = tmp_path / "s.conf"
    sud.write_text("y\n", encoding="utf-8")
    lat = SSHLatencyProfile(samples=1, min_ms=1.0, mean_ms=1.0, p95_ms=1.0, max_ms=1.0)
    m = build_lab_run_manifest(
        repo_root=tmp_path,
        config_path=cfg,
        sudoers_path=sud,
        ssh_latency=lat,
        conformance_facts=_facts(REQUIRED_CONFORMANCE_FACT_IDS[4:]),
        smoke_matrix=ok,
    )
    assert m.conformance_all_passed is False
