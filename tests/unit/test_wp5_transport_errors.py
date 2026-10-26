"""WP5 A1-A3 unit tests: sentinel error classification, known_hosts, and multiplexing."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from gateheal.transport import (
    EXPECTED_SENTINEL_TOKEN,
    HostSafetyViolationError,
    SSHLabTransport,
    TransportResult,
    TransportUnavailableError,
)


def test_a1_exit_255_permission_denied_raises_transport_unavailable_error() -> None:
    """A1: exit 255 with 'Permission denied (publickey)' gives TransportUnavailableError."""

    def fake_runner(_argv: Sequence[str], _timeout: float) -> TransportResult:
        return TransportResult(
            exit_code=255,
            duration_sec=0.04,
            stdout_excerpt="",
            stderr_excerpt="ubuntu@127.0.0.1: Permission denied (publickey).",
        )

    transport = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        verify_remote_sentinel=True,
        _runner=fake_runner,
    )
    with pytest.raises(TransportUnavailableError) as exc_info:
        transport.run(("true",), timeout_sec=3.0)

    msg = str(exc_info.value)
    assert "SSH to ubuntu@127.0.0.1:2222 failed (exit=255):" in msg
    assert "Permission denied (publickey)" in msg


def test_a1_exit_1_no_such_file_raises_host_safety_violation_error() -> None:
    """A1: exit 1 with 'No such file' gives HostSafetyViolationError."""

    def fake_runner(_argv: Sequence[str], _timeout: float) -> TransportResult:
        return TransportResult(
            exit_code=1,
            duration_sec=0.02,
            stdout_excerpt="",
            stderr_excerpt="cat: /etc/gateheal-lab-sentinel: No such file or directory",
        )

    transport = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        verify_remote_sentinel=True,
        _runner=fake_runner,
    )
    with pytest.raises(HostSafetyViolationError, match="sentinel verification"):
        transport.run(("true",), timeout_sec=3.0)


def test_a1_exit_0_wrong_token_raises_host_safety_violation_error() -> None:
    """A1: exit 0 with a wrong token gives HostSafetyViolationError."""

    def fake_runner(_argv: Sequence[str], _timeout: float) -> TransportResult:
        return TransportResult(
            exit_code=0,
            duration_sec=0.02,
            stdout_excerpt="WRONG_TOKEN_VALUE\n",
            stderr_excerpt="",
        )

    transport = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        verify_remote_sentinel=True,
        _runner=fake_runner,
    )
    with pytest.raises(HostSafetyViolationError, match="token mismatch"):
        transport.run(("true",), timeout_sec=3.0)


def test_a1_exit_0_right_token_passes_and_sentinel_cached_across_two_runs() -> None:
    """A1: exit 0 with right token passes, and sentinel check runs once across two run() calls."""
    sentinel_calls: list[tuple[str, ...]] = []
    all_calls: list[tuple[str, ...]] = []

    def fake_runner(argv: Sequence[str], _timeout: float) -> TransportResult:
        cmd = tuple(argv)
        all_calls.append(cmd)
        if "cat /etc/gateheal-lab-sentinel" in cmd[-1]:
            sentinel_calls.append(cmd)
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=f"{EXPECTED_SENTINEL_TOKEN}\n",
            )
        return TransportResult(
            exit_code=0,
            duration_sec=0.01,
            stdout_excerpt="ok\n",
        )

    transport = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        verify_remote_sentinel=True,
        _runner=fake_runner,
    )
    # Two _ensure_remote_sentinel() calls invoke the runner only once
    transport._ensure_remote_sentinel()
    transport._ensure_remote_sentinel()
    assert len(all_calls) == 1
    assert len(sentinel_calls) == 1

    # Fresh transport: across two run() calls, sentinel runner check happens once
    sentinel_calls.clear()
    all_calls.clear()
    transport2 = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        verify_remote_sentinel=True,
        _runner=fake_runner,
    )
    r1 = transport2.run(("true",), timeout_sec=2.0)
    r2 = transport2.run(("true",), timeout_sec=2.0)
    assert r1.exit_code == 0
    assert r2.exit_code == 0
    assert len(sentinel_calls) == 1
    assert len(all_calls) == 3


def test_a2_build_ssh_argv_known_hosts_and_identities_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A2: build_ssh_argv emits UserKnownHostsFile, accept-new, LogLevel=ERROR, IdentitiesOnly."""
    kh_file = str(tmp_path / "custom_known_hosts")
    t_no_id = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        identity_file=None,
        known_hosts_file=kh_file,
    )
    argv_no_id = t_no_id.build_ssh_argv(("uname", "-r"))
    sep_idx = argv_no_id.index("--")
    pre_sep = argv_no_id[:sep_idx]

    assert f"UserKnownHostsFile={kh_file}" in pre_sep
    assert "StrictHostKeyChecking=accept-new" in pre_sep
    assert "LogLevel=ERROR" in pre_sep
    assert "IdentitiesOnly=yes" not in pre_sep

    t_with_id = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        identity_file="/tmp/id_ed25519",
        known_hosts_file=kh_file,
        ssh_multiplex=True,
    )
    argv_with_id = t_with_id.build_ssh_argv(("uname", "-r"))
    sep_idx_2 = argv_with_id.index("--")
    pre_sep_2 = argv_with_id[:sep_idx_2]

    assert "IdentitiesOnly=yes" in pre_sep_2
    assert "ControlMaster=auto" in pre_sep_2
    assert f"ControlPath={tmp_path}/cm-%C" in pre_sep_2
    assert "ControlPersist=60s" in pre_sep_2

    env_kh = str(tmp_path / "env_known_hosts")
    monkeypatch.setenv("GATEHEAL_LAB_KNOWN_HOSTS", env_kh)
    t_env = SSHLabTransport(host="127.0.0.1", port=2222, user="ubuntu")
    assert t_env.known_hosts_file == env_kh
