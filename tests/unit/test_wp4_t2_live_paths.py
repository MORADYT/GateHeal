"""WP4 T2 live-path tests: orchestrator oracle path, TCP probe negatives, SIGTERM, and st=0."""

from __future__ import annotations

import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gateheal.collector import parse_invocation_and_start_usec
from gateheal.config import GateHealConfig, load_config
from gateheal.controller import AuditRecorder, EscalationSink
from gateheal.lab_daemons import check_tcp_port
from gateheal.models import VerificationStatus
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.state import PersistentStateStore
from gateheal.transport import TransportResult


def _load_cfg() -> GateHealConfig:
    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_path)


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


def test_t2_orchestrator_handle_incident_without_post_evidence_supplier(
    tmp_path: Path,
) -> None:
    """T2.1: Orchestrator run with post_evidence_supplier=None uses verify_with_transport."""
    cfg = _load_cfg()
    now_dt = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    restarted = [False]

    def live_guest(_sample_idx: int, cmd: tuple[str, ...]) -> TransportResult:
        if cmd[:2] == ("cat", "/proc/uptime"):
            return TransportResult(
                exit_code=0, duration_sec=0.01, stdout_excerpt="500.0 400.0\n"
            )
        if cmd[:4] == ("sudo", "-n", "/usr/bin/systemctl", "restart"):
            restarted[0] = True
            return TransportResult(exit_code=0, duration_sec=0.05)
        if cmd[:2] == ("systemctl", "show"):
            unit = cmd[2]
            if unit == "lab-api.service" and not restarted[0]:
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=failed\nSubState=failed\nResult=signal\n"
                        "NRestarts=0\nCanReload=yes\nInvocationID=inv-dead\n"
                        "ExecMainStartTimestampMonotonic=0\n"
                    ),
                )
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=(
                    "ActiveState=active\nSubState=running\nResult=success\n"
                    "NRestarts=0\nCanReload=yes\nInvocationID=inv-live\n"
                    "ExecMainStartTimestampMonotonic=55000000\n"
                ),
            )
        if cmd[0] == "curl":
            return TransportResult(
                exit_code=0 if restarted[0] else 22, duration_sec=0.01
            )
        return TransportResult(exit_code=0, duration_sec=0.01, stdout_excerpt="ok")

    transport = _ScriptedSoakTransport(live_guest)
    mono_fn, sleep_fn, slept = _make_clock_and_sleep(transport)
    store = PersistentStateStore(tmp_path / "t2_state.json")
    recorder = AuditRecorder(
        tmp_path / "t2_audit.jsonl", clock_utc=lambda: now_dt
    )
    esc = EscalationSink(tmp_path / "t2_esc.jsonl")

    orch = IncidentOrchestrator(
        cfg,
        transport=transport,
        audit_recorder=recorder,
        escalation_sink=esc,
        state_store=store,
        clock_utc=lambda: now_dt,
        monotonic_clock=mono_fn,
        sleep_fn=sleep_fn,
    )
    audit = orch.handle_incident(
        incident_id="inc-t2-live-oracle",
        target_unit="lab-api.service",
    )
    assert audit.verification_report is not None
    assert audit.verification_report.status == VerificationStatus.RECOVERED_CLEAN
    assert audit.verification_report.samples_collected == 5
    assert audit.verification_report.in_window_unavailability_sec == pytest.approx(
        1.0
    )
    assert len(slept) == 5


def test_t2_check_tcp_port_returns_false_on_err_reply_or_silent_peer() -> None:
    """T2.2: check_tcp_port returns False when peer replies -ERR or stays silent."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_err:
        srv_err.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_err.bind(("127.0.0.1", 0))
        srv_err.listen(4)
        port_err = int(srv_err.getsockname()[1])

        def _reply_err() -> None:
            conn, _ = srv_err.accept()
            with conn:
                _ = conn.recv(64)
                conn.sendall(b"-ERR_DISRUPTED\r\n")

        t_err = threading.Thread(target=_reply_err, daemon=True)
        t_err.start()
        assert check_tcp_port("127.0.0.1", port_err, timeout_sec=0.2) is False
        t_err.join(timeout=1.0)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_sil:
        srv_sil.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sil.bind(("127.0.0.1", 0))
        srv_sil.listen(4)
        port_sil = int(srv_sil.getsockname()[1])

        def _stay_silent() -> None:
            conn, _ = srv_sil.accept()
            with conn:
                _ = conn.recv(64)

        t_sil = threading.Thread(target=_stay_silent, daemon=True)
        t_sil.start()
        assert check_tcp_port("127.0.0.1", port_sil, timeout_sec=0.2) is False
        t_sil.join(timeout=1.0)


def test_t2_real_api_subprocess_sigterm_handler_notifies_and_stops_worker_subprocess(
    tmp_path: Path,
) -> None:
    """T2.3: Spawn real lab_daemons API & worker subprocesses; SIGTERM on API kills worker."""

    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])

    redis_port = _free_port()
    worker_port = _free_port()
    api_port = _free_port()

    cfg_file = tmp_path / "api_subproc.yaml"
    cfg_file.write_text(
        f"listen_host: '127.0.0.1'\n"
        f"listen_port: {api_port}\n"
        f"redis_host: '127.0.0.1'\n"
        f"redis_port: {redis_port}\n"
        f"worker_host: '127.0.0.1'\n"
        f"worker_port: {worker_port}\n"
        f"worker_pool_stale: false\n",
        encoding="utf-8",
    )

    redis_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "gateheal.lab_daemons",
            "--role",
            "redis",
            "--host",
            "127.0.0.1",
            "--port",
            str(redis_port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    worker_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "gateheal.lab_daemons",
            "--role",
            "worker",
            "--host",
            "127.0.0.1",
            "--port",
            str(worker_port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    api_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "gateheal.lab_daemons",
            "--role",
            "api",
            "--config",
            str(cfg_file),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        deadline = time.monotonic() + 5.0
        worker_ready = False
        api_ready = False
        while time.monotonic() < deadline:
            if not worker_ready:
                worker_ready = check_tcp_port(
                    "127.0.0.1", worker_port, timeout_sec=0.1
                )
            if not api_ready:
                try:
                    with socket.create_connection(
                        ("127.0.0.1", api_port), timeout=0.1
                    ):
                        api_ready = True
                except OSError:
                    pass
            if worker_ready and api_ready:
                break
            time.sleep(0.05)

        assert worker_ready is True
        assert api_ready is True
        assert worker_proc.poll() is None

        api_proc.send_signal(signal.SIGTERM)
        api_rc = api_proc.wait(timeout=3.0)
        assert api_rc == 0

        worker_rc = worker_proc.wait(timeout=3.0)
        assert worker_rc != 0
    finally:
        for p in (api_proc, worker_proc, redis_proc):
            if p.poll() is None:
                p.kill()
            if p.stdout is not None:
                p.stdout.close()
            if p.stderr is not None:
                p.stderr.close()


def test_t2_exec_main_start_timestamp_monotonic_zero_gives_none() -> None:
    """T2.4: ExecMainStartTimestampMonotonic=0 must parse as None, not 0."""
    inv, start_usec = parse_invocation_and_start_usec(
        {
            "InvocationID": "deadbeef1234",
            "ExecMainStartTimestampMonotonic": "0",
        }
    )
    assert inv == "deadbeef1234"
    assert start_usec is None
