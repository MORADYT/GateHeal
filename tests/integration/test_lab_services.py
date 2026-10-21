"""Integration tests for lab daemons, config validation, SIGHUP reload, and live collector."""

from __future__ import annotations

import socket
import subprocess
from collections.abc import Sequence
from pathlib import Path

from gateheal.collector import IncidentCollector, parse_systemctl_show
from gateheal.config import GateHealConfig, load_config
from gateheal.lab_daemons import (
    LabApiRuntimeState,
    check_tcp_port,
    validate_api_config_file,
)
from gateheal.lab_daemons import (
    main as daemon_main,
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
    assert daemon_main(["--validate-config", str(bad_cfg)]) == 1


def test_lab_api_runtime_health_and_sighup_reload_semantics(
    tmp_path: Path,
) -> None:
    # Bind an ephemeral local TCP socket to act as a live lab-redis server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fake_redis:
        fake_redis.bind(("127.0.0.1", 0))
        fake_redis.listen(4)
        redis_port = int(fake_redis.getsockname()[1])

        cfg_file = tmp_path / "api.yaml"
        cfg_file.write_text(
            "listen_host: '127.0.0.1'\n"
            "listen_port: 18080\n"
            "redis_host: '127.0.0.1'\n"
            f"redis_port: {redis_port}\n"
            "worker_pool_stale: true\n",
            encoding="utf-8",
        )
        state = LabApiRuntimeState(cfg_file)
        assert state.load_or_reload(is_sighup=False) is True

        # Initial state has worker_pool_stale=True -> HTTP 503
        code_before, body_before = state.evaluate_health()
        assert code_before == 503
        assert body_before["status"] == "degraded"

        # Simulate SIGHUP reload -> clears stale flag in place and returns HTTP 200
        assert state.load_or_reload(is_sighup=True) is True
        code_after, body_after = state.evaluate_health()
        assert code_after == 200
        assert body_after["status"] == "ok"
        assert body_after["reload_count"] == 1
        assert check_tcp_port("127.0.0.1", redis_port) is True


class _FakeSystemdTransport:
    """Mock transport returning realistic `systemctl show` and `journalctl` outputs."""

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
                )
            else:
                out = (
                    "ActiveState=active\n"
                    "SubState=running\n"
                    "Result=success\n"
                    "NRestarts=0\n"
                    "CanReload=no\n"
                )
            return TransportResult(exit_code=0, duration_sec=0.01, stdout_excerpt=out)

        if cmd[0] == "curl":
            return TransportResult(
                exit_code=22,
                duration_sec=0.01,
                stderr_excerpt="curl: (22) The requested URL returned error: 503",
            )

        if cmd[0] == "journalctl":
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt="ERROR: auth failed with api_key=SecretTokenValue987654\n",
            )

        # Config validation command succeeds
        return TransportResult(exit_code=0, duration_sec=0.01, stdout_excerpt="ok")


def test_live_collector_parses_systemctl_and_redacts_journal_secrets() -> None:
    props = parse_systemctl_show("ActiveState=active\nSubState=running\nNRestarts=2\n")
    assert props["ActiveState"] == "active"
    assert props["NRestarts"] == "2"

    cfg = _load_lab_cfg()
    collector = IncidentCollector(cfg)
    incident = collector.collect_from_transport(
        incident_id="inc-live-001",
        target_unit="lab-api.service",
        transport=_FakeSystemdTransport(),
    )

    api_ev = incident.services["lab-api.service"]
    assert api_ev.active_state == "failed"
    assert api_ev.n_restarts == 1
    assert api_ev.can_reload is True
    assert api_ev.config_valid is True
    assert api_ev.health_probe_ok is False
    assert "SecretTokenValue987654" not in "\n".join(api_ev.sanitized_logs)
    assert "[REDACTED_SECRET]" in "\n".join(api_ev.sanitized_logs)
