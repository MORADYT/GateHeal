"""Integration tests for lab daemons, config validation, reload, coupling, and collector."""

from __future__ import annotations

import socket
import subprocess
import threading
from collections.abc import Sequence
from pathlib import Path

from gateheal.collector import IncidentCollector, parse_systemctl_show
from gateheal.config import GateHealConfig, load_config
from gateheal.lab_daemons import (
    CONFIG_INVALID_EXIT_CODE,
    LabApiRuntimeState,
    LabWorkerRuntimeState,
    check_tcp_port,
    main as daemon_main,
    validate_api_config_file,
)
from gateheal.transport import TransportResult


def _load_lab_cfg() -> GateHealConfig:
    cfg_p = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_p)


def test_lab_guard_script_refuses_to_run_on_omarchy_host() -> None:
    guard_script = (
        Path(__file__).resolve().parents[2]
        / "lab"
        / "scripts"
        / "lab_guard.sh"
    )
    proc = subprocess.run(
        ["bash", str(guard_script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "FATAL" in proc.stderr


def test_api_config_validator_accepts_valid_and_rejects_corrupted_yaml(
    tmp_path: Path,
) -> None:
    valid_cfg = tmp_path / "valid_config.yaml"
    valid_cfg.write_text(
        "listen_host: '127.0.0.1'\n"
        "listen_port: 8080\n"
        "redis_host: '127.0.0.1'\n"
        "redis_port: 6379\n"
        "worker_pool_stale: false\n",
        encoding="utf-8",
    )
    ok, msg = validate_api_config_file(valid_cfg)
    assert ok is True
    assert msg == "Configuration valid."
    assert daemon_main(["--validate-config", str(valid_cfg)]) == 0

    bad_cfg = tmp_path / "bad_config.yaml"
    bad_cfg.write_text("listen_port: 'invalid_int'\n", encoding="utf-8")
    ok_bad, _ = validate_api_config_file(bad_cfg)
    assert ok_bad is False
    assert (
        daemon_main(["--validate-config", str(bad_cfg)])
        == CONFIG_INVALID_EXIT_CODE
    )


def test_lab_api_sighup_reload_vs_hard_restart_worker_coupling(
    tmp_path: Path,
) -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fake_redis,
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as worker_srv,
    ):
        fake_redis.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        fake_redis.bind(("127.0.0.1", 0))
        fake_redis.listen(8)
        redis_port = int(fake_redis.getsockname()[1])

        worker_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        worker_srv.bind(("127.0.0.1", 0))
        worker_srv.listen(8)
        worker_port = int(worker_srv.getsockname()[1])

        worker_state = LabWorkerRuntimeState()
        stop_threads = threading.Event()

        def _serve_redis() -> None:
            while not stop_threads.is_set():
                try:
                    fake_redis.settimeout(0.05)
                    conn, _ = fake_redis.accept()
                except OSError:
                    continue
                with conn:
                    try:
                        _ = conn.recv(64)
                    except OSError:
                        pass
                    conn.sendall(b"+OK\r\n")

        def _serve_worker() -> None:
            while not stop_threads.is_set():
                try:
                    worker_srv.settimeout(0.05)
                    conn, _ = worker_srv.accept()
                except OSError:
                    continue
                with conn:
                    try:
                        frame = conn.recv(64)
                    except OSError:
                        frame = b""
                    reply, should_exit = worker_state.handle_frame(frame)
                    conn.sendall(reply)
                    if should_exit:
                        break

        redis_thread = threading.Thread(target=_serve_redis, daemon=True)
        worker_thread = threading.Thread(target=_serve_worker, daemon=True)
        redis_thread.start()
        worker_thread.start()

        try:
            cfg_file = tmp_path / "api.yaml"
            cfg_file.write_text(
                "listen_host: '127.0.0.1'\n"
                "listen_port: 18080\n"
                "redis_host: '127.0.0.1'\n"
                f"redis_port: {redis_port}\n"
                "worker_pool_stale: true\n",
                encoding="utf-8",
            )
            state = LabApiRuntimeState(
                cfg_file, worker_host="127.0.0.1", worker_port=worker_port
            )
            assert state.load_or_reload(is_sighup=False) is True

            # 1. Before reload: API is degraded (503), worker is healthy (+OK)
            code_before, body_before = state.evaluate_health()
            assert code_before == 503
            assert body_before["status"] == "degraded"
            assert check_tcp_port("127.0.0.1", worker_port) is True

            # 2. SIGHUP reload: API becomes healthy (200), boot_id preserved, worker stays healthy!
            boot_id_before = state.boot_id
            assert state.load_or_reload(is_sighup=True) is True
            code_after, body_after = state.evaluate_health()
            assert code_after == 200
            assert body_after["status"] == "ok"
            assert body_after["reload_count"] == 1
            assert state.boot_id == boot_id_before
            assert check_tcp_port("127.0.0.1", worker_port) is True

            # 3. Hard restart (SIGTERM on active API): notifies worker -> worker fails!
            assert state.on_sigterm_hard_restart() is True
            worker_thread.join(timeout=1.0)
            assert worker_state.disrupted_by_api_restart is True
            assert check_tcp_port("127.0.0.1", worker_port) is False
        finally:
            stop_threads.set()


class _FakeSystemdTransport:
    """Mock transport returning realistic `systemctl show` and `journalctl` outputs."""

    def __init__(self, config_exit_code: int = 0, config_timed_out: bool = False) -> None:
        self._config_exit_code = config_exit_code
        self._config_timed_out = config_timed_out

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        cmd = tuple(argv)
        if cmd[:2] == ("systemctl", "show"):
            unit = cmd[2]
            if unit == "lab-api.service":
                out = (
                    "ActiveState=failed\n"
                    "SubState=failed\n"
                    "Result=exit-code\n"
                    "NRestarts=1\n"
                    "CanReload=yes\n"
                    "InvocationID=99aa88bb77cc66dd\n"
                    "ExecMainStartTimestampMonotonic=123456789\n"
                )
            else:
                out = (
                    "ActiveState=active\n"
                    "SubState=running\n"
                    "Result=success\n"
                    "NRestarts=0\n"
                    "CanReload=no\n"
                    "InvocationID=1122334455667788\n"
                    "ExecMainStartTimestampMonotonic=98765432\n"
                )
            return TransportResult(exit_code=0, duration_sec=0.01, stdout_excerpt=out)

        if cmd[0] == "curl":
            return TransportResult(
                exit_code=22,
                duration_sec=0.01,
                stderr_excerpt="curl: (22) The requested URL returned error: 503",
            )

        if cmd[0] == "journalctl":
            fake_secret = "SecretToken" + "Value987654"
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=f"ERROR: auth failed with api_key={fake_secret}\n",
            )

        return TransportResult(
            exit_code=self._config_exit_code,
            timed_out=self._config_timed_out,
            duration_sec=0.01,
            stdout_excerpt="config validator output",
        )


def test_live_collector_parses_systemctl_invocation_id_and_three_valued_config_check() -> None:
    props = parse_systemctl_show("ActiveState=active\nSubState=running\nNRestarts=2\n")
    assert props["ActiveState"] == "active"
    assert props["NRestarts"] == "2"

    cfg = _load_lab_cfg()
    collector = IncidentCollector(cfg)

    incident_ok = collector.collect_from_transport(
        incident_id="inc-live-001",
        target_unit="lab-api.service",
        transport=_FakeSystemdTransport(config_exit_code=0),
    )
    api_ev = incident_ok.services["lab-api.service"]
    assert api_ev.active_state == "failed"
    assert api_ev.n_restarts == 1
    assert api_ev.can_reload is True
    assert api_ev.config_valid is True
    assert api_ev.health_probe_ok is False
    assert api_ev.invocation_id == "99aa88bb77cc66dd"
    assert api_ev.exec_main_start_timestamp_usec == 123456789
    fake_secret = "SecretToken" + "Value987654"
    assert fake_secret not in "\n".join(api_ev.sanitized_logs)
    assert "[REDACTED_SECRET]" in "\n".join(api_ev.sanitized_logs)

    incident_bad_cfg = collector.collect_from_transport(
        incident_id="inc-live-002",
        target_unit="lab-api.service",
        transport=_FakeSystemdTransport(config_exit_code=CONFIG_INVALID_EXIT_CODE),
    )
    assert incident_bad_cfg.services["lab-api.service"].config_valid is False

    incident_crash = collector.collect_from_transport(
        incident_id="inc-live-003",
        target_unit="lab-api.service",
        transport=_FakeSystemdTransport(config_exit_code=1),
    )
    assert incident_crash.services["lab-api.service"].config_valid is None

    incident_timeout = collector.collect_from_transport(
        incident_id="inc-live-004",
        target_unit="lab-api.service",
        transport=_FakeSystemdTransport(config_exit_code=0, config_timed_out=True),
    )
    assert incident_timeout.services["lab-api.service"].config_valid is None
