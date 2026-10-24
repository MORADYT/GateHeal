"""Self-contained Linux lab service daemons and config validator for GateHeal."""

from __future__ import annotations

import argparse
import json
import signal
import socket
import sys
import time
import uuid
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import FrameType

import yaml

CONFIG_INVALID_EXIT_CODE = 65
WORKER_ABORT_FRAME = b"API_HARD_RESTART\n"


def validate_api_config_file(path: Path) -> tuple[bool, str]:
    """Validate `/etc/lab-api/config.yaml` schema and value types."""
    if not path.is_file():
        return False, f"Configuration file {path} does not exist."
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return False, f"YAML syntax error: {exc}"

    if not isinstance(loaded, dict):
        return False, "Configuration root must be a YAML mapping."

    required_types: dict[str, type[object]] = {
        "listen_host": str,
        "listen_port": int,
        "redis_host": str,
        "redis_port": int,
        "worker_pool_stale": bool,
    }
    for key, expected_type in required_types.items():
        if key not in loaded:
            return False, f"Missing required configuration key: {key!r}"
        val = loaded[key]
        if isinstance(val, bool) and expected_type is int:
            return False, f"Key {key!r} must be an integer, got boolean."
        if not isinstance(val, expected_type):
            return False, f"Key {key!r} must be of type {expected_type.__name__}."

    port = int(loaded["listen_port"])
    redis_port = int(loaded["redis_port"])
    if not (1 <= port <= 65535) or not (1 <= redis_port <= 65535):
        return False, "Port numbers must be between 1 and 65535."

    return True, "Configuration valid."


def check_tcp_port(host: str, port: int, timeout_sec: float = 0.5) -> bool:
    """Return True if a TCP connection to (host, port) succeeds and returns +OK."""
    try:
        with socket.create_connection((host, port), timeout=timeout_sec) as sock:
            sock.settimeout(timeout_sec)
            sock.sendall(b"PING\n")
            data = sock.recv(64)
            return data.startswith(b"+OK")
    except OSError:
        return False


def notify_worker_of_api_hard_restart(
    worker_host: str = "127.0.0.1",
    worker_port: int = 8081,
    timeout_sec: float = 0.5,
) -> bool:
    """Send hard-restart termination frame to coupled lab-worker when active API stops."""
    try:
        with socket.create_connection(
            (worker_host, worker_port), timeout=timeout_sec
        ) as sock:
            sock.sendall(WORKER_ABORT_FRAME)
            return True
    except OSError:
        return False


class LabWorkerRuntimeState:
    """Runtime state for lab-worker coupled to active lab-api lifecycle."""

    def __init__(
        self,
        *,
        api_host: str = "127.0.0.1",
        api_port: int = 8080,
    ) -> None:
        self.api_host = api_host
        self.api_port = api_port
        self.disrupted_by_api_restart = False

    def handle_frame(self, raw_frame: bytes) -> tuple[bytes, bool]:
        """Process incoming TCP frame; return (response_bytes, should_exit_failure)."""
        if raw_frame.startswith(WORKER_ABORT_FRAME.strip()):
            self.disrupted_by_api_restart = True
            return b"-ERR_API_RESTART_COLLATERAL\r\n", True
        if self.disrupted_by_api_restart:
            return b"-ERR_DISRUPTED\r\n", True
        return b"+OK\r\n", False


class LabApiRuntimeState:
    """Mutable runtime state for the lab-api daemon supporting SIGHUP reload."""

    def __init__(
        self,
        config_path: Path,
        *,
        worker_host: str = "127.0.0.1",
        worker_port: int = 8081,
    ) -> None:
        self.config_path = config_path
        self.listen_host = "127.0.0.1"
        self.listen_port = 8080
        self.redis_host = "127.0.0.1"
        self.redis_port = 6379
        self.worker_host = worker_host
        self.worker_port = worker_port
        self.worker_pool_stale = False
        self.reload_count = 0
        self.boot_id = uuid.uuid4().hex

    def load_or_reload(self, *, is_sighup: bool = False) -> bool:
        """Validate and apply configuration from disk; clear stale pool on SIGHUP."""
        ok, _ = validate_api_config_file(self.config_path)
        if not ok:
            return False
        raw = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        self.listen_host = str(raw["listen_host"])
        self.listen_port = int(raw["listen_port"])
        self.redis_host = str(raw["redis_host"])
        self.redis_port = int(raw["redis_port"])
        if "worker_host" in raw:
            self.worker_host = str(raw["worker_host"])
        if "worker_port" in raw:
            self.worker_port = int(raw["worker_port"])
        if is_sighup:
            self.worker_pool_stale = False
            self.reload_count += 1
        else:
            self.worker_pool_stale = bool(raw["worker_pool_stale"])
        return True

    def on_sigterm_hard_restart(self) -> bool:
        """Notify coupled lab-worker when active lab-api receives SIGTERM (hard restart)."""
        return notify_worker_of_api_hard_restart(
            self.worker_host, self.worker_port
        )

    def evaluate_health(self) -> tuple[int, dict[str, object]]:
        """Evaluate `/healthz` HTTP status code and JSON body."""
        if self.worker_pool_stale:
            return 503, {
                "status": "degraded",
                "reason": "WARN: worker pool stale; send SIGHUP to reload",
                "reload_count": self.reload_count,
                "boot_id": self.boot_id,
            }
        if not check_tcp_port(self.redis_host, self.redis_port):
            return 503, {
                "status": "unhealthy",
                "reason": (
                    f"ERROR: Redis connection refused on "
                    f"{self.redis_host}:{self.redis_port}"
                ),
                "reload_count": self.reload_count,
                "boot_id": self.boot_id,
            }
        return 200, {
            "status": "ok",
            "reload_count": self.reload_count,
            "boot_id": self.boot_id,
        }


def run_tcp_listener_forever(host: str, port: int) -> int:
    """Run a lightweight TCP listener for lab-redis."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(16)
        while True:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(0.5)
                try:
                    _ = conn.recv(64)
                except OSError:
                    pass
                conn.sendall(b"+OK\r\n")


def run_worker_daemon(host: str, port: int) -> int:
    """Run lab-worker TCP daemon coupled to active lab-api hard restarts."""
    worker_state = LabWorkerRuntimeState()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(16)
        while True:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(0.5)
                try:
                    frame = conn.recv(64)
                except OSError:
                    frame = b""
                reply, should_exit = worker_state.handle_frame(frame)
                conn.sendall(reply)
                if should_exit:
                    print(
                        "FATAL: Upstream lab-api hard-restarted while active; "
                        "coupled worker session broken.",
                        file=sys.stderr,
                    )
                    return 1


def run_api_daemon(config_path: Path) -> int:
    """Run the lab-api HTTP daemon with SIGHUP reload and SIGTERM worker coupling."""
    state = LabApiRuntimeState(config_path)
    if not state.load_or_reload(is_sighup=False):
        print("FATAL: Invalid configuration on startup.", file=sys.stderr)
        return CONFIG_INVALID_EXIT_CODE

    def _handle_sighup(signum: int, frame: FrameType | None) -> None:
        _ = (signum, frame)
        state.load_or_reload(is_sighup=True)

    def _handle_sigterm(signum: int, frame: FrameType | None) -> None:
        _ = (signum, frame)
        state.on_sigterm_hard_restart()
        sys.exit(0)

    signal.signal(signal.SIGHUP, _handle_sighup)
    signal.signal(signal.SIGTERM, _handle_sigterm)

    class HealthHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            code, payload = state.evaluate_health()
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            _ = (fmt, args)

    server = HTTPServer((state.listen_host, state.listen_port), HealthHandler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


def build_daemon_parser() -> argparse.ArgumentParser:
    """Construct CLI parser for lab service roles and config validation."""
    parser = argparse.ArgumentParser(prog="gateheal-lab-daemon")
    parser.add_argument(
        "--validate-config",
        type=Path,
        default=None,
        help="Validate the specified lab-api YAML configuration file and exit.",
    )
    parser.add_argument(
        "--check-tcp",
        action="store_true",
        help="Probe a local TCP port inside the guest and exit 0 if reachable.",
    )
    parser.add_argument(
        "--role",
        choices=["redis", "api", "worker"],
        default=None,
        help="Daemon role to run inside the isolated lab.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/lab-api/config.yaml"),
        help="Path to lab-api config file.",
    )
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6379)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for lab daemons and configuration validator."""
    parser = build_daemon_parser()
    args = parser.parse_args(argv)

    if args.validate_config is not None:
        ok, msg = validate_api_config_file(args.validate_config)
        if ok:
            print(msg)
            return 0
        print(msg, file=sys.stderr)
        return CONFIG_INVALID_EXIT_CODE

    if args.check_tcp:
        return 0 if check_tcp_port(args.host, args.port) else 1

    if args.role == "redis":
        return run_tcp_listener_forever(args.host, args.port)
    if args.role == "worker":
        return run_worker_daemon(args.host, args.port)
    if args.role == "api":
        return run_api_daemon(args.config)

    time.sleep(0.01)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
