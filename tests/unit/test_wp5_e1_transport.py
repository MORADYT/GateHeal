"""WP5 E1 unit tests: SSHLabTransport TransportUnavailableError vs HostSafetyViolationError."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from gateheal.transport import (
    HostSafetyViolationError,
    SSHLabTransport,
    TransportResult,
    TransportUnavailableError,
)


def test_e1_ssh_sentinel_exit_255_raises_transport_unavailable_with_exit_and_stderr() -> None:
    """E1: Non-zero SSH exit (e.g. 255) raises TransportUnavailableError with code and stderr."""

    def runner_exit_255(_argv: Sequence[str], _timeout: float) -> TransportResult:
        return TransportResult(
            exit_code=255,
            duration_sec=0.05,
            stdout_excerpt="",
            stderr_excerpt="ssh: connect to host 127.0.0.1 port 2222: Connection refused\n",
        )

    transport = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        verify_remote_sentinel=True,
        runner=runner_exit_255,
    )
    with pytest.raises(TransportUnavailableError) as exc_info:
        transport.run(("systemctl", "--version"), timeout_sec=3.0)

    err = exc_info.value
    assert err.exit_code == 255
    assert "Connection refused" in err.stderr_excerpt
    assert "255" in str(err)


def test_e1_ssh_sentinel_wrong_token_with_exit_0_raises_host_safety_violation() -> None:
    """E1: Exit 0 with wrong sentinel token raises HostSafetyViolationError."""

    def runner_wrong_token(_argv: Sequence[str], _timeout: float) -> TransportResult:
        return TransportResult(
            exit_code=0,
            duration_sec=0.02,
            stdout_excerpt="UNTRUSTED_HOST_SYSTEM_V0\n",
            stderr_excerpt="",
        )

    transport = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        verify_remote_sentinel=True,
        runner=runner_wrong_token,
    )
    with pytest.raises(HostSafetyViolationError, match="sentinel verification"):
        transport.run(("systemctl", "--version"), timeout_sec=3.0)
