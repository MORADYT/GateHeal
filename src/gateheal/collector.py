"""Bounded incident evidence collector with secret redaction and sanitization."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from gateheal.config import GateHealConfig
from gateheal.models import IncidentRecord, ServiceEvidence
from gateheal.transport import CommandTransport

SECRET_PATTERNS = (
    re.compile(
        r"(api[_-]?key\s*[:=]\s*['\"]?)([A-Za-z0-9_\-\.]{10,})(['\"]?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(bearer\s*[:=\s]\s*['\"]?)([A-Za-z0-9_\-\.]{10,})(['\"]?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(password\s*[:=]\s*['\"]?)([^\s,;'\"]{6,})(['\"]?)",
        re.IGNORECASE,
    ),
)


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


class IncidentCollector:
    """Collects and sanitizes bounded diagnostic evidence from the lab."""

    def __init__(self, config: GateHealConfig) -> None:
        self._config = config

    def redact_secrets(self, text: str) -> str:
        """Scrub sensitive credential patterns while preserving key labels."""
        sanitized = text
        for pattern in SECRET_PATTERNS:
            sanitized = pattern.sub(r"\1[REDACTED_SECRET]\3", sanitized)
        return sanitized

    def collect_simulated(
        self,
        incident_id: str,
        target_unit: str,
        simulated_services: dict[str, ServiceEvidence],
        prior_diagnostic_attempts: int = 0,
        prior_recovery_attempts: int = 0,
        action_history: tuple[str, ...] = (),
        elapsed_sec: float = 0.0,
    ) -> IncidentRecord:
        """Create an incident record from simulated telemetry."""
        sanitized_services: dict[str, ServiceEvidence] = {}
        max_lines = self._config.budgets.max_log_lines
        max_bytes = self._config.budgets.max_evidence_bytes

        total_bytes = 0
        for unit, ev in simulated_services.items():
            raw_logs = list(ev.sanitized_logs[:max_lines])
            clean_logs: list[str] = []
            for line in raw_logs:
                redacted = self.redact_secrets(line)
                encoded_len = len(redacted.encode("utf-8"))
                if total_bytes + encoded_len > max_bytes:
                    clean_logs.append("[TRUNCATED_MAX_BYTES_EXCEEDED]")
                    break
                clean_logs.append(redacted)
                total_bytes += encoded_len

            sanitized_services[unit] = ServiceEvidence(
                unit_name=ev.unit_name,
                active_state=ev.active_state,
                sub_state=ev.sub_state,
                result=ev.result,
                n_restarts=ev.n_restarts,
                can_reload=ev.can_reload,
                health_probe_ok=ev.health_probe_ok,
                config_valid=ev.config_valid,
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
    ) -> IncidentRecord:
        """Collect live systemd unit state, config checks, and logs via transport."""
        raw_services: dict[str, ServiceEvidence] = {}
        timeout = min(5.0, self._config.budgets.per_action_timeout_sec)
        max_lines = self._config.budgets.max_log_lines

        for unit, item in self._config.inventory.services.items():
            show_res = transport.run(
                (
                    "systemctl",
                    "show",
                    unit,
                    "--property=ActiveState,SubState,Result,NRestarts,CanReload",
                ),
                timeout_sec=timeout,
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

            config_valid: bool | None = None
            if item.config_check_argv:
                cfg_res = transport.run(item.config_check_argv, timeout_sec=timeout)
                config_valid = cfg_res.exit_code == 0 and not cfg_res.timed_out

            probe_ok = active_state == "active" and sub_state == "running"
            if item.health_check_http_url:
                http_res = transport.run(
                    ("curl", "-fsS", "--max-time", "2", item.health_check_http_url),
                    timeout_sec=timeout,
                )
                probe_ok = http_res.exit_code == 0 and not http_res.timed_out

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
                timeout_sec=timeout,
            )
            log_lines = tuple(
                line
                for line in log_res.stdout_excerpt.splitlines()
                if line.strip()
            )

            raw_services[unit] = ServiceEvidence(
                unit_name=unit,
                active_state=active_state,
                sub_state=sub_state,
                result=result_prop,
                n_restarts=n_restarts,
                can_reload=can_reload,
                health_probe_ok=probe_ok,
                config_valid=config_valid,
                sanitized_logs=log_lines,
            )

        return self.collect_simulated(
            incident_id=incident_id,
            target_unit=target_unit,
            simulated_services=raw_services,
            prior_diagnostic_attempts=prior_diagnostic_attempts,
            prior_recovery_attempts=prior_recovery_attempts,
            action_history=action_history,
            elapsed_sec=elapsed_sec,
        )
