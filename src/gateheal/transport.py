"""Isolated command transport layer preventing accidental host execution."""

from __future__ import annotations

import os
import platform
import shlex
import signal
import subprocess
import time
from collections.abc import Sequence
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class HostSafetyViolationError(RuntimeError):
    """Raised when local lab execution is attempted on the host workstation."""


class TransportResult(BaseModel):
    """Bounded result returned by a CommandTransport implementation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    exit_code: int
    timed_out: bool = False
    duration_sec: float = Field(ge=0.0)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""


class CommandTransport(Protocol):
    """Protocol for executing approved argv arrays in an isolated target."""

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        """Execute argv with a hard timeout and return a bounded result."""


def run_isolated_process_group(
    argv: Sequence[str],
    timeout_sec: float,
    max_output_chars: int = 2048,
) -> TransportResult:
    """Run argv with shell=False in a new POSIX session and killpg on timeout."""
    start_time = time.monotonic()
    proc = subprocess.Popen(
        list(argv),
        shell=False,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
        duration = time.monotonic() - start_time
        return TransportResult(
            exit_code=proc.returncode,
            timed_out=False,
            duration_sec=duration,
            stdout_excerpt=stdout[:max_output_chars],
            stderr_excerpt=stderr[:max_output_chars],
        )
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - start_time
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            time.sleep(0.2)
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = proc.communicate()
        timeout_note = "\n[Command timed out; process group terminated]"
        return TransportResult(
            exit_code=-999,
            timed_out=True,
            duration_sec=duration,
            stdout_excerpt=stdout[:max_output_chars],
            stderr_excerpt=(stderr[:max_output_chars] + timeout_note),
        )


class LocalLabSubprocessTransport:
    """Executes commands locally ONLY when running inside an isolated lab guest."""

    def __init__(self, *, allow_host_override: bool = False) -> None:
        self._allow_host_override = allow_host_override

    def _verify_inside_lab(self) -> None:
        if self._allow_host_override:
            return
        kernel_rel = platform.release().lower()
        inside_env = os.environ.get("GATEHEAL_INSIDE_LAB") == "1"
        if "omarchy" in kernel_rel or not inside_env:
            raise HostSafetyViolationError(
                "Refusing to run local subprocess transport on host workstation "
                f"(kernel={kernel_rel!r}, GATEHEAL_INSIDE_LAB={inside_env}). "
                "Use SimulatedLabTransport or SSHLabTransport."
            )

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        """Verify lab sentinel before executing argv in an isolated process group."""
        self._verify_inside_lab()
        return run_isolated_process_group(argv, timeout_sec)


class SSHLabTransport:
    """Executes approved argv inside the disposable QEMU/KVM guest via SSH."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2222,
        user: str = "ubuntu",
        identity_file: str | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._user = user
        self._identity_file = identity_file

    def build_ssh_argv(self, remote_argv: Sequence[str]) -> tuple[str, ...]:
        """Construct a non-interactive SSH command vector targeting the lab VM."""
        cmd: list[str] = [
            "ssh",
            "-p",
            str(self._port),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=5",
        ]
        if self._identity_file:
            cmd.extend(["-i", self._identity_file])
        remote_command_str = shlex.join(remote_argv)
        cmd.append(f"{self._user}@{self._host}")
        cmd.append(remote_command_str)
        return tuple(cmd)

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        """Execute argv over SSH inside the isolated lab VM."""
        ssh_argv = self.build_ssh_argv(argv)
        return run_isolated_process_group(ssh_argv, timeout_sec)


class SimulatedLabTransport:
    """Deterministic in-memory transport for safe host CLI runs and unit tests."""

    def __init__(self, simulated_exit_code: int = 0) -> None:
        self._exit_code = simulated_exit_code
        self.executed_commands: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        """Record argv and return a deterministic simulated result."""
        _ = timeout_sec
        cmd_tuple = tuple(argv)
        self.executed_commands.append(cmd_tuple)
        return TransportResult(
            exit_code=self._exit_code,
            timed_out=False,
            duration_sec=0.05,
            stdout_excerpt=f"[simulated] executed: {' '.join(cmd_tuple)}",
            stderr_excerpt="",
        )
