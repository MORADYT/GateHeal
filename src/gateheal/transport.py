"""Isolated command transport layer preventing accidental host execution.

Guest Privilege Requirement:
Inside the isolated QEMU/KVM or systemd-nspawn guest, the unprivileged `ubuntu`
account requires the exact allowlisted sudoers rules in `lab/systemd/gateheal-sudoers.conf`
to execute mutating `sudo -n /usr/bin/systemctl reload|restart <unit>` actions.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import shlex
import signal
import subprocess
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_LAB_SENTINEL_PATH = Path("/etc/gateheal-lab-sentinel")
EXPECTED_SENTINEL_TOKEN = "GATEHEAL_ISOLATED_LAB_GUEST_V1"
DEFAULT_KNOWN_HOSTS_PATH = Path.home() / ".cache" / "gateheal-vm" / "known_hosts"
ALLOWED_VIRT_TYPES: frozenset[str] = frozenset(
    {"kvm", "qemu", "systemd-nspawn", "lxc", "lxc-libvirt", "oracle", "vmware"}
)
SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class HostSafetyViolationError(RuntimeError):
    """Raised when local lab execution or non-lab SSH is attempted on the host."""


class TransportUnavailableError(RuntimeError):
    """Raised when SSH transport fails to connect or times out during sentinel check."""

    def __init__(
        self,
        message: str,
        *,
        exit_code: int = -1,
        stderr_excerpt: str = "",
    ) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr_excerpt = stderr_excerpt


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


class RecordingTransport:
    """Transport wrapper recording total and mutating command executions."""

    def __init__(self, inner: CommandTransport) -> None:
        self._inner = inner
        self.commands: list[tuple[str, ...]] = []
        self.mutating_commands: list[tuple[str, ...]] = []

    @property
    def ssh_command_count(self) -> int:
        """Return total number of commands executed through this wrapper."""
        return len(self.commands)

    @property
    def mutating_commands_executed(self) -> int:
        """Return count of mutating commands executed through this wrapper."""
        return len(self.mutating_commands)

    def reset_counts(self) -> None:
        """Clear recorded command lists."""
        self.commands.clear()
        self.mutating_commands.clear()

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        """Forward argv to inner transport and record command counts."""
        cmd = tuple(argv)
        self.commands.append(cmd)
        if self._is_mutating(cmd):
            self.mutating_commands.append(cmd)
        return self._inner.run(cmd, timeout_sec)

    @staticmethod
    def _is_mutating(cmd: tuple[str, ...]) -> bool:
        if not cmd:
            return False
        if cmd[0] == "sudo":
            return True
        return cmd[0] == "systemctl" and len(cmd) >= 2 and cmd[1] in {
            "restart",
            "reload",
            "stop",
            "start",
            "kill",
            "reset-failed",
            "daemon-reload",
        }


def truncate_output_tail(text: str, max_chars: int = 2048) -> str:
    """Keep the newest tail of command output when output exceeds max_chars."""
    if len(text) <= max_chars:
        return text
    marker = "[TRUNCATED_OLDEST_OUTPUT]\n"
    if max_chars <= len(marker):
        return text[-max_chars:]
    kept_len = max_chars - len(marker)
    return marker + text[-kept_len:]


def build_systemd_scope_argv(
    argv: Sequence[str],
    *,
    memory_max: str = "256M",
    cpu_quota: str = "50%",
) -> tuple[str, ...]:
    """Wrap a command vector in a transient cgroup v2 systemd-run scope (T10)."""
    if argv and argv[0] == "sudo":
        raise ValueError(
            "Cannot wrap a `sudo -n` command inside an unprivileged `systemd-run --scope` "
            "because sudoers requires `/usr/bin/systemctl` as the direct sudo target."
        )
    return (
        "/usr/bin/systemd-run",
        "--scope",
        "--collect",
        "-p",
        f"MemoryMax={memory_max}",
        "-p",
        f"CPUQuota={cpu_quota}",
        "--",
        *argv,
    )


def build_remote_timeout_argv(
    argv: Sequence[str],
    timeout_sec: float,
    kill_after_sec: float = 2.0,
) -> tuple[str, ...]:
    """Wrap remote command in POSIX timeout so guest OS kills hung remote children."""
    return (
        "timeout",
        "--foreground",
        "--signal=TERM",
        f"--kill-after={kill_after_sec:.1f}s",
        f"{timeout_sec:.1f}s",
        *argv,
    )


def _default_detect_virt() -> str:
    """Query `systemd-detect-virt` and return the virtualization identifier."""
    try:
        proc = subprocess.run(
            ["systemd-detect-virt"],
            shell=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=2.0,
            check=False,
        )
        return proc.stdout.strip().lower() or "none"
    except OSError:
        return "none"


def run_isolated_process_group(
    argv: Sequence[str],
    timeout_sec: float,
    max_output_chars: int = 2048,
    post_kill_communicate_timeout_sec: float = 1.0,
) -> TransportResult:
    """Run argv with shell=False in a new POSIX session and killpg on timeout (R12)."""
    start_time = time.monotonic()
    proc = subprocess.Popen(
        list(argv),
        shell=False,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_sec)
        duration = time.monotonic() - start_time
        return TransportResult(
            exit_code=proc.returncode,
            timed_out=False,
            duration_sec=duration,
            stdout_excerpt=truncate_output_tail(stdout, max_output_chars),
            stderr_excerpt=truncate_output_tail(stderr, max_output_chars),
        )
    except subprocess.TimeoutExpired:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            time.sleep(0.1)
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.kill()
        except OSError:
            pass

        stdout = ""
        stderr = ""
        try:
            stdout, stderr = proc.communicate(
                timeout=post_kill_communicate_timeout_sec
            )
        except (subprocess.TimeoutExpired, OSError):
            stdout = ""
            stderr = ""
        finally:
            if proc.stdout is not None:
                try:
                    proc.stdout.close()
                except OSError:
                    pass
            if proc.stderr is not None:
                try:
                    proc.stderr.close()
                except OSError:
                    pass
            try:
                proc.wait(timeout=0.2)
            except (subprocess.TimeoutExpired, OSError):
                pass

        duration = time.monotonic() - start_time
        timeout_note = "\n[Command timed out; process group terminated]"
        return TransportResult(
            exit_code=-999,
            timed_out=True,
            duration_sec=duration,
            stdout_excerpt=truncate_output_tail(stdout, max_output_chars),
            stderr_excerpt=(
                truncate_output_tail(stderr, max_output_chars) + timeout_note
            ),
        )
    finally:
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass
        if proc.stderr is not None:
            try:
                proc.stderr.close()
            except OSError:
                pass


class LocalLabSubprocessTransport:
    """Executes commands locally ONLY inside an isolated VM/container with sentinel."""

    def __init__(
        self,
        *,
        allow_host_override: bool = False,
        sentinel_path: Path = DEFAULT_LAB_SENTINEL_PATH,
        virt_detector: Callable[[], str] | None = None,
        use_systemd_scope: bool = False,
    ) -> None:
        self._allow_host_override = allow_host_override
        self._sentinel_path = sentinel_path
        self._virt_detector = virt_detector or _default_detect_virt
        self._use_systemd_scope = use_systemd_scope

    def _verify_inside_lab(self) -> None:
        if self._allow_host_override:
            return

        kernel_rel = platform.release().lower()
        inside_env = os.environ.get("GATEHEAL_INSIDE_LAB") == "1"

        sentinel_ok = False
        if self._sentinel_path.is_file():
            try:
                content = self._sentinel_path.read_text(
                    encoding="utf-8", errors="replace"
                ).strip()
                sentinel_ok = content == EXPECTED_SENTINEL_TOKEN
            except OSError:
                sentinel_ok = False

        virt_type = self._virt_detector()
        virt_ok = virt_type in ALLOWED_VIRT_TYPES

        if (
            "omarchy" in kernel_rel
            or not inside_env
            or not sentinel_ok
            or not virt_ok
        ):
            raise HostSafetyViolationError(
                "Refusing to run local subprocess transport outside verified lab guest "
                f"(kernel={kernel_rel!r}, GATEHEAL_INSIDE_LAB={inside_env}, "
                f"sentinel_ok={sentinel_ok}, virt={virt_type!r}). "
                "Use SimulatedLabTransport or SSHLabTransport."
            )

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        """Verify lab sentinel and virtualization before executing argv."""
        self._verify_inside_lab()
        effective_argv = (
            build_systemd_scope_argv(argv)
            if (self._use_systemd_scope and (not argv or argv[0] != "sudo"))
            else tuple(argv)
        )
        return run_isolated_process_group(effective_argv, timeout_sec)


def _validate_ssh_lab_host(host: str) -> None:
    """Ensure SSH transport targets only loopback or explicit local lab addresses."""
    cleaned = host.strip().lower()
    if cleaned == "localhost":
        return
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise HostSafetyViolationError(
            f"SSHLabTransport host {host!r} must be a loopback IP or 'localhost'."
        ) from exc
    if not ip_obj.is_loopback:
        raise HostSafetyViolationError(
            f"SSHLabTransport refuses non-loopback target host {host!r}."
        )


def _validate_ssh_user(user: str) -> None:
    """Validate SSH username to prevent option injection (e.g. -oProxyCommand=...)."""
    if not SSH_USER_RE.fullmatch(user):
        raise ValueError(
            f"Invalid SSH username {user!r}; must match {SSH_USER_RE.pattern}."
        )


def _resolve_known_hosts_file(known_hosts_file: str | None) -> str:
    """Resolve the dedicated lab known_hosts file path."""
    if known_hosts_file is not None and known_hosts_file.strip():
        return str(Path(known_hosts_file).expanduser())
    env_override = os.environ.get("GATEHEAL_LAB_KNOWN_HOSTS", "").strip()
    if env_override:
        return str(Path(env_override).expanduser())
    return str(DEFAULT_KNOWN_HOSTS_PATH)


class SSHLabTransport:
    """Executes approved argv inside the disposable QEMU/KVM guest via SSH."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2222,
        user: str = "ubuntu",
        identity_file: str | None = None,
        *,
        known_hosts_file: str | None = None,
        ssh_multiplex: bool = False,
        use_systemd_scope: bool = False,
        use_remote_timeout: bool = False,
        verify_remote_sentinel: bool = True,
        runner: Callable[[Sequence[str], float], TransportResult] | None = None,
        _runner: Callable[[Sequence[str], float], TransportResult] | None = None,
    ) -> None:
        _validate_ssh_lab_host(host)
        _validate_ssh_user(user)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid SSH port: {port}")
        self._host = host
        self._port = port
        self._user = user
        self._identity_file = identity_file
        self._known_hosts_file = _resolve_known_hosts_file(known_hosts_file)
        self._ssh_multiplex = ssh_multiplex
        self._use_systemd_scope = use_systemd_scope
        self._use_remote_timeout = use_remote_timeout
        self._verify_remote_sentinel = verify_remote_sentinel
        self._sentinel_verified = False
        chosen_runner = _runner if _runner is not None else runner
        self._runner: Callable[[Sequence[str], float], TransportResult] = (
            run_isolated_process_group if chosen_runner is None else chosen_runner
        )

    @property
    def host(self) -> str:
        """Return target SSH host."""
        return self._host

    @property
    def port(self) -> int:
        """Return target SSH port."""
        return self._port

    @property
    def user(self) -> str:
        """Return target SSH user."""
        return self._user

    @property
    def identity_file(self) -> str | None:
        """Return optional SSH identity file path."""
        return self._identity_file

    @property
    def known_hosts_file(self) -> str:
        """Return dedicated SSH known_hosts file path."""
        return self._known_hosts_file

    @property
    def ssh_multiplex(self) -> bool:
        """Return True if SSH ControlMaster multiplexing is enabled."""
        return self._ssh_multiplex

    @property
    def verify_remote_sentinel(self) -> bool:
        """Return True if remote guest sentinel verification is enabled."""
        return self._verify_remote_sentinel

    def build_ssh_argv(
        self,
        remote_argv: Sequence[str],
        *,
        remote_timeout_sec: float | None = None,
        wrap_systemd_scope: bool | None = None,
    ) -> tuple[str, ...]:
        """Construct a non-interactive SSH command vector targeting the lab VM."""
        cmd: list[str] = [
            "ssh",
            "-p",
            str(self._port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"UserKnownHostsFile={self._known_hosts_file}",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=5",
        ]
        if self._identity_file:
            cmd.extend(["-o", "IdentitiesOnly=yes", "-i", self._identity_file])

        if self._ssh_multiplex:
            control_dir = str(Path(self._known_hosts_file).parent)
            cmd.extend(
                [
                    "-o",
                    "ControlMaster=auto",
                    "-o",
                    f"ControlPath={control_dir}/cm-%C",
                    "-o",
                    "ControlPersist=60s",
                ]
            )

        inner_argv: tuple[str, ...] = tuple(remote_argv)
        should_scope = (
            self._use_systemd_scope
            if wrap_systemd_scope is None
            else wrap_systemd_scope
        )
        if should_scope and (not inner_argv or inner_argv[0] != "sudo"):
            inner_argv = build_systemd_scope_argv(inner_argv)

        if remote_timeout_sec is not None:
            inner_argv = build_remote_timeout_argv(inner_argv, remote_timeout_sec)

        remote_command_str = shlex.join(inner_argv)
        cmd.append("--")
        cmd.append(f"{self._user}@{self._host}")
        cmd.append(remote_command_str)
        return tuple(cmd)

    def _ensure_remote_sentinel(self) -> None:
        if not self._verify_remote_sentinel or self._sentinel_verified:
            return
        try:
            Path(self._known_hosts_file).parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        check_argv = self.build_ssh_argv(
            ("cat", str(DEFAULT_LAB_SENTINEL_PATH)),
            remote_timeout_sec=3.0,
            wrap_systemd_scope=False,
        )
        res = self._runner(check_argv, 5.0)
        if res.timed_out or res.exit_code in (255, 124, 137):
            stderr_slice = res.stderr_excerpt[:200]
            raise TransportUnavailableError(
                f"SSH to {self._user}@{self._host}:{self._port} failed "
                f"(exit={res.exit_code}): {stderr_slice}",
                exit_code=res.exit_code,
                stderr_excerpt=res.stderr_excerpt,
            )
        if res.exit_code != 0:
            raise HostSafetyViolationError(
                "Remote SSH target failed lab sentinel verification "
                f"({DEFAULT_LAB_SENTINEL_PATH} missing or read failed: "
                f"exit={res.exit_code}, stderr={res.stderr_excerpt.strip()[:200]})."
            )
        if res.stdout_excerpt.strip() != EXPECTED_SENTINEL_TOKEN:
            raise HostSafetyViolationError(
                "Remote SSH target failed lab sentinel verification "
                f"({DEFAULT_LAB_SENTINEL_PATH}: token mismatch)."
            )
        self._sentinel_verified = True

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        """Execute argv over SSH inside the isolated lab VM."""
        self._ensure_remote_sentinel()
        remote_to = timeout_sec if self._use_remote_timeout else None
        ssh_argv = self.build_ssh_argv(argv, remote_timeout_sec=remote_to)
        res = self._runner(ssh_argv, timeout_sec + 2.0)
        if self._use_remote_timeout and res.exit_code in (124, 137):
            return TransportResult(
                exit_code=-999,
                timed_out=True,
                duration_sec=res.duration_sec,
                stdout_excerpt=res.stdout_excerpt,
                stderr_excerpt=(
                    res.stderr_excerpt
                    + "\n[Remote command timed out; terminated by guest timeout]"
                ),
            )
        return res


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
