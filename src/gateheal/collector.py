"""Bounded incident evidence collector with secret redaction and sanitization."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from gateheal.config import GateHealConfig
from gateheal.models import IncidentRecord, ServiceEvidence

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
