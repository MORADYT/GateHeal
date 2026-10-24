"""Bounded incident evidence collector with secret redaction and untrusted framing.

Note: Regular-expression secret redaction is a best-effort defense-in-depth layer
at the Zone 2 boundary; novel or custom unformatted secrets may not match fixed patterns.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime

from gateheal.config import GateHealConfig
from gateheal.models import IncidentRecord, ServiceEvidence
from gateheal.transport import CommandTransport

UNTRUSTED_LOG_PREFIX = "[UNTRUSTED_LOG] "

PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)
PEM_UNTERMINATED_BEGIN_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*",
    re.DOTALL | re.IGNORECASE,
)
PEM_ORPHAN_END_RE = re.compile(
    r"^.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)

AWS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
GITHUB_PAT_RE = re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,})\b")
STRIPE_KEY_RE = re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,})\b")
SLACK_TOKEN_RE = re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")
JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(['\"]?aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]?)([A-Za-z0-9/+=]{16,})(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"(['\"]?private[_-]?key['\"]?\s*[:=]\s*['\"]?)([^\s,;'\"]{8,})(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"(['\"]?(?:set-cookie|cookie)['\"]?\s*:\s*)([^\r\n]+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_COOKIE]",
    ),
    (
        re.compile(
            r"(['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"]?)([A-Za-z0-9_\-\.]{8,})(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"(['\"]?(?:[a-z0-9_]+_)?token['\"]?\s*[:=]\s*['\"]?)([^\s,;'\"]{8,})(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"(['\"]?(?:[a-z0-9_]+_)?secret['\"]?\s*[:=]\s*['\"]?)([^\s,;'\"]{6,})(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"(['\"]?(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?)([^\s,;'\"]{6,})(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"(['\"]?bearer['\"]?\s*[:=\s]\s*['\"]?)([A-Za-z0-9_\-\.=+/]{8,})(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"(['\"]?authorization['\"]?\s*:\s*['\"]?basic\s+|['\"]?basic['\"]?\s*[:=]\s*['\"]?)([A-Za-z0-9+/=]{8,})(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
    (
        re.compile(
            r"([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
)


def redact_secrets_text(text: str) -> str:
    """Scrub credentials, PEM blocks, JWTs, PATs, Stripe/Slack/AWS keys, and cookies."""
    sanitized = PEM_BLOCK_RE.sub("[REDACTED_PEM_PRIVATE_KEY]", text)
    sanitized = PEM_UNTERMINATED_BEGIN_RE.sub(
        "[REDACTED_PEM_PRIVATE_KEY]", sanitized
    )
    sanitized = PEM_ORPHAN_END_RE.sub("[REDACTED_PEM_PRIVATE_KEY]", sanitized)
    sanitized = AWS_KEY_RE.sub("[REDACTED_AWS_KEY]", sanitized)
    sanitized = GITHUB_PAT_RE.sub("[REDACTED_GITHUB_TOKEN]", sanitized)
    sanitized = STRIPE_KEY_RE.sub("[REDACTED_STRIPE_KEY]", sanitized)
    sanitized = SLACK_TOKEN_RE.sub("[REDACTED_SLACK_TOKEN]", sanitized)
    sanitized = JWT_RE.sub("[REDACTED_JWT]", sanitized)
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def cap_line_bytes(line: str, max_line_bytes: int) -> str:
    """Cap a single log line to max_line_bytes UTF-8 bytes without splitting codepoints."""
    encoded = line.encode("utf-8")
    if len(encoded) <= max_line_bytes:
        return line
    suffix = "...[LINE_TRUNCATED]"
    suffix_bytes = len(suffix.encode("utf-8"))
    if max_line_bytes <= suffix_bytes:
        return encoded[:max_line_bytes].decode("utf-8", errors="ignore")
    prefix = encoded[: max_line_bytes - suffix_bytes].decode(
        "utf-8", errors="ignore"
    )
    return prefix + suffix


def frame_untrusted_log_line(line: str) -> str:
    """Wrap a log line in an explicit untrusted-data tag (Zone 2 boundary)."""
    if line.startswith(UNTRUSTED_LOG_PREFIX):
        return line
    return f"{UNTRUSTED_LOG_PREFIX}{line}"


def parse_systemctl_show(raw_output: str) -> dict[str, str]:
    """Parse Key=Value lines emitted by `systemctl show`."""
    parsed: dict[str, str] = {}
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _parse_guest_uptime_sec(raw_uptime: str) -> float | None:
    """Parse the first float token from guest `/proc/uptime` output."""
    tokens = raw_uptime.strip().split()
    if not tokens:
        return None
    try:
        val = float(tokens[0])
        return val if val >= 0.0 else None
    except ValueError:
        return None


def parse_invocation_and_start_usec(
    props: dict[str, str],
) -> tuple[str | None, int | None]:
    """Extract InvocationID and ExecMainStartTimestampMonotonic from systemctl show props."""
    raw_inv = props.get("InvocationID", "").strip()
    invocation_id = raw_inv if raw_inv else None

    raw_start = (
        props.get("ExecMainStartTimestampMonotonic", "").strip()
        or props.get("ExecMainStartTimestamp", "").strip()
    )
    exec_start_usec: int | None = None
    if raw_start.isdigit():
        val = int(raw_start)
        if val > 0:
            exec_start_usec = val
    return invocation_id, exec_start_usec


class IncidentCollector:
    """Collects and sanitizes bounded diagnostic evidence from the lab."""

    def __init__(
        self,
        config: GateHealConfig,
        *,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._monotonic_clock = (
            time.monotonic if monotonic_clock is None else monotonic_clock
        )

    def redact_secrets(self, text: str) -> str:
        """Scrub sensitive credential patterns while preserving key labels."""
        return redact_secrets_text(text)

    def collect_simulated(
        self,
        incident_id: str,
        target_unit: str,
        simulated_services: dict[str, ServiceEvidence],
        prior_diagnostic_attempts: int = 0,
        prior_recovery_attempts: int = 0,
        action_history: tuple[str, ...] = (),
        elapsed_sec: float = 0.0,
        last_mutating_action_age_sec: float | None = None,
        recent_mutations_in_flap_window: int = 0,
    ) -> IncidentRecord:
        """Create a sanitized incident record with per-service fair byte budgets."""
        sanitized_services: dict[str, ServiceEvidence] = {}
        max_lines = self._config.budgets.max_log_lines
        max_bytes = self._config.budgets.max_evidence_bytes
        max_line_bytes = self._config.budgets.max_log_line_bytes

        num_services = max(1, len(simulated_services))
        per_service_budget = max(512, max_bytes // num_services)

        for unit, ev in simulated_services.items():
            joined_raw = "\n".join(ev.sanitized_logs)
            redacted_full = self.redact_secrets(joined_raw)
            all_redacted_lines = (
                [ln for ln in redacted_full.splitlines() if ln.strip()]
                if joined_raw
                else []
            )

            tail_logs = all_redacted_lines[-max_lines:]
            kept_reversed: list[str] = []
            service_bytes = 0
            truncated_by_bytes = False

            for redacted_line in reversed(tail_logs):
                capped = cap_line_bytes(redacted_line, max_line_bytes)
                framed = frame_untrusted_log_line(capped)
                encoded_len = len(framed.encode("utf-8"))
                if service_bytes + encoded_len > per_service_budget:
                    truncated_by_bytes = True
                    break
                kept_reversed.append(framed)
                service_bytes += encoded_len

            clean_logs = list(reversed(kept_reversed))
            if truncated_by_bytes or len(all_redacted_lines) > max_lines:
                clean_logs.append("[TRUNCATED_MAX_BYTES_EXCEEDED]")

            sanitized_services[unit] = ServiceEvidence(
                unit_name=ev.unit_name,
                active_state=ev.active_state,
                sub_state=ev.sub_state,
                result=ev.result,
                n_restarts=ev.n_restarts,
                can_reload=ev.can_reload,
                health_probe_ok=ev.health_probe_ok,
                config_valid=ev.config_valid,
                active_enter_age_sec=ev.active_enter_age_sec,
                invocation_id=ev.invocation_id,
                exec_main_start_timestamp_usec=ev.exec_main_start_timestamp_usec,
                sanitized_logs=tuple(clean_logs),
            )

        now_utc = datetime.now(UTC).isoformat()
        return IncidentRecord(
            incident_id=incident_id,
            target_unit=target_unit,
            collected_at_utc=now_utc,
            services=sanitized_services,
            prior_diagnostic_attempts=prior_diagnostic_attempts,
            prior_recovery_attempts=prior_recovery_attempts,
            action_history=action_history,
            elapsed_sec=elapsed_sec,
            last_mutating_action_age_sec=last_mutating_action_age_sec,
            recent_mutations_in_flap_window=recent_mutations_in_flap_window,
        )

    def collect_from_transport(
        self,
        incident_id: str,
        target_unit: str,
        transport: CommandTransport,
        prior_diagnostic_attempts: int = 0,
        prior_recovery_attempts: int = 0,
        action_history: tuple[str, ...] = (),
        elapsed_sec: float = 0.0,
        last_mutating_action_age_sec: float | None = None,
        recent_mutations_in_flap_window: int = 0,
    ) -> IncidentRecord:
        """Collect live systemd state, guest uptime, config checks, probes, and logs."""
        raw_services: dict[str, ServiceEvidence] = {}
        max_lines = self._config.budgets.max_log_lines
        total_budget = self._config.budgets.total_incident_timeout_sec
        base_cmd_timeout = min(5.0, self._config.budgets.per_action_timeout_sec)
        start_mono = self._monotonic_clock()

        def _remaining_timeout() -> float:
            spent = max(0.0, self._monotonic_clock() - start_mono)
            rem = total_budget - (elapsed_sec + spent)
            return min(base_cmd_timeout, rem)

        guest_uptime_sec: float | None = None
        uptime_to = _remaining_timeout()
        if uptime_to > 0.0:
            up_res = transport.run(("cat", "/proc/uptime"), timeout_sec=uptime_to)
            if not up_res.timed_out and up_res.exit_code == 0:
                guest_uptime_sec = _parse_guest_uptime_sec(up_res.stdout_excerpt)

        show_props_arg = (
            "--property=ActiveState,SubState,Result,NRestarts,CanReload,"
            "ActiveEnterTimestampMonotonic,InvocationID,ExecMainStartTimestampMonotonic"
        )

        for unit, item in self._config.inventory.services.items():
            cmd_to = _remaining_timeout()
            if cmd_to <= 0.0:
                raw_services[unit] = ServiceEvidence(
                    unit_name=unit,
                    active_state="unknown",
                    sub_state="unknown",
                    result="timeout",
                    health_probe_ok=False,
                    config_valid=None,
                    sanitized_logs=("[COLLECTION_TIME_BUDGET_EXCEEDED]",),
                )
                continue

            show_res = transport.run(
                ("systemctl", "show", unit, show_props_arg),
                timeout_sec=cmd_to,
            )
            props = parse_systemctl_show(show_res.stdout_excerpt)
            active_state = props.get("ActiveState", "unknown")
            sub_state = props.get("SubState", "unknown")
            result_prop = props.get("Result", "unknown")
            try:
                n_restarts = max(0, int(props.get("NRestarts", "0")))
            except ValueError:
                n_restarts = 0
            can_reload = props.get("CanReload", "no").lower() == "yes"
            invocation_id, exec_start_usec = parse_invocation_and_start_usec(
                props
            )

            active_enter_age_sec: float | None = None
            raw_enter_us = props.get("ActiveEnterTimestampMonotonic", "")
            raw_now_us = props.get("NowMonotonic", "")
            if raw_enter_us.isdigit() and int(raw_enter_us) > 0:
                enter_sec = int(raw_enter_us) / 1_000_000.0
                now_guest_sec: float | None = None
                if raw_now_us.isdigit() and int(raw_now_us) >= int(raw_enter_us):
                    now_guest_sec = int(raw_now_us) / 1_000_000.0
                elif guest_uptime_sec is not None:
                    now_guest_sec = guest_uptime_sec
                if now_guest_sec is not None and now_guest_sec >= enter_sec:
                    active_enter_age_sec = max(0.0, now_guest_sec - enter_sec)

            config_valid: bool | None = None
            if item.config_check_mode == "argv" and item.config_check_argv:
                cfg_to = _remaining_timeout()
                if cfg_to > 0.0:
                    cfg_res = transport.run(item.config_check_argv, timeout_sec=cfg_to)
                    if not cfg_res.timed_out and cfg_res.exit_code == 0:
                        config_valid = True
                    elif (
                        not cfg_res.timed_out
                        and cfg_res.exit_code == item.config_invalid_exit_code
                    ):
                        config_valid = False
                    else:
                        config_valid = None

            probe_ok = active_state == "active" and sub_state == "running"
            if probe_ok and item.health_check_http_url:
                http_to = _remaining_timeout()
                if http_to > 0.0:
                    http_res = transport.run(
                        ("curl", "-fsS", "--max-time", "2", item.health_check_http_url),
                        timeout_sec=http_to,
                    )
                    probe_ok = http_res.exit_code == 0 and not http_res.timed_out
                else:
                    probe_ok = False
            elif probe_ok and item.health_check_tcp_port is not None:
                tcp_to = _remaining_timeout()
                if tcp_to > 0.0:
                    tcp_res = transport.run(
                        (
                            "/usr/bin/python3",
                            "-m",
                            "gateheal.lab_daemons",
                            "--check-tcp",
                            "--host",
                            "127.0.0.1",
                            "--port",
                            str(item.health_check_tcp_port),
                        ),
                        timeout_sec=tcp_to,
                    )
                    probe_ok = tcp_res.exit_code == 0 and not tcp_res.timed_out
                else:
                    probe_ok = False

            log_to = _remaining_timeout()
            if log_to > 0.0:
                log_res = transport.run(
                    (
                        "journalctl",
                        "-u",
                        unit,
                        "-n",
                        str(max_lines),
                        "--no-pager",
                        "-o",
                        "cat",
                    ),
                    timeout_sec=log_to,
                )
                redacted_journal = self.redact_secrets(log_res.stdout_excerpt)
                log_lines = tuple(
                    line
                    for line in redacted_journal.splitlines()
                    if line.strip()
                )
            else:
                log_lines = ()

            raw_services[unit] = ServiceEvidence(
                unit_name=unit,
                active_state=active_state,
                sub_state=sub_state,
                result=result_prop,
                n_restarts=n_restarts,
                can_reload=can_reload,
                health_probe_ok=probe_ok,
                config_valid=config_valid,
                active_enter_age_sec=active_enter_age_sec,
                invocation_id=invocation_id,
                exec_main_start_timestamp_usec=exec_start_usec,
                sanitized_logs=log_lines,
            )

        total_elapsed = elapsed_sec + max(0.0, self._monotonic_clock() - start_mono)
        return self.collect_simulated(
            incident_id=incident_id,
            target_unit=target_unit,
            simulated_services=raw_services,
            prior_diagnostic_attempts=prior_diagnostic_attempts,
            prior_recovery_attempts=prior_recovery_attempts,
            action_history=action_history,
            elapsed_sec=total_elapsed,
            last_mutating_action_age_sec=last_mutating_action_age_sec,
            recent_mutations_in_flap_window=recent_mutations_in_flap_window,
        )
