"""Deterministic rule-based diagnosis engine."""

from __future__ import annotations

from gateheal.config import GateHealConfig
from gateheal.models import DiagnosisResult, FaultClass, IncidentRecord


class DiagnosisEngine:
    """Rule-based engine classifying faults from incident evidence."""

    def __init__(self, config: GateHealConfig) -> None:
        self._config = config

    def diagnose(self, incident: IncidentRecord) -> DiagnosisResult:
        """Evaluate deterministic fault classification rules."""
        target = incident.target_unit
        target_ev = incident.services.get(target)

        if target_ev is None:
            return DiagnosisResult(
                fault_class=FaultClass.UNKNOWN,
                primary_suspect_unit=target,
                confidence=0.1,
                evidence_refs=(),
                summary=f"Target unit {target} not found in evidence.",
            )

        if target_ev.config_valid is False:
            return DiagnosisResult(
                fault_class=FaultClass.INVALID_CONFIG,
                primary_suspect_unit=target,
                confidence=0.95,
                evidence_refs=(f"services.{target}.config_valid",),
                summary=f"Configuration validation failed for {target}.",
            )

        service_cfg = self._config.inventory.services.get(target)
        if service_cfg is not None:
            for upstream in service_cfg.upstream_dependencies:
                up_ev = incident.services.get(upstream)
                if (
                    up_ev is None
                    or up_ev.active_state != "active"
                    or not up_ev.health_probe_ok
                ):
                    return DiagnosisResult(
                        fault_class=FaultClass.DEPENDENCY_FAILURE,
                        primary_suspect_unit=upstream,
                        confidence=0.90,
                        evidence_refs=(
                            f"services.{upstream}.active_state",
                            f"services.{upstream}.health_probe_ok",
                        ),
                        summary=f"Upstream dependency {upstream} unhealthy.",
                    )

        if (
            target_ev.active_state == "failed"
            or target_ev.sub_state == "failed"
            or not target_ev.health_probe_ok
        ):
            if target_ev.n_restarts > 1:
                summary_msg = (
                    f"Service {target} failing repeatedly "
                    f"(n_restarts={target_ev.n_restarts})."
                )
                return DiagnosisResult(
                    fault_class=FaultClass.PERSISTENT_FAILURE,
                    primary_suspect_unit=target,
                    confidence=0.85,
                    evidence_refs=(
                        f"services.{target}.active_state",
                        f"services.{target}.n_restarts",
                    ),
                    summary=summary_msg,
                )
            return DiagnosisResult(
                fault_class=FaultClass.PROCESS_CRASH,
                primary_suspect_unit=target,
                confidence=0.90,
                evidence_refs=(
                    f"services.{target}.active_state",
                    f"services.{target}.health_probe_ok",
                ),
                summary=f"Service {target} crashed or failed probe.",
            )

        if (
            target_ev.active_state == "active"
            and target_ev.health_probe_ok
        ):
            return DiagnosisResult(
                fault_class=FaultClass.HEALTHY,
                primary_suspect_unit=target,
                confidence=1.0,
                evidence_refs=(f"services.{target}.active_state",),
                summary=f"Service {target} is active and healthy.",
            )

        return DiagnosisResult(
            fault_class=FaultClass.UNKNOWN,
            primary_suspect_unit=target,
            confidence=0.4,
            evidence_refs=(),
            summary=f"Ambiguous state for unit {target}.",
        )
