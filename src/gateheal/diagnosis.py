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

        # Rule 0: Persistent Flapping across recent runs
        flap_count = incident.recent_mutations_in_flap_window
        if (
            flap_count >= self._config.budgets.flap_max_restarts
            and (target_ev.active_state != "active" or not target_ev.health_probe_ok)
        ):
            return DiagnosisResult(
                fault_class=FaultClass.PERSISTENT_FAILURE,
                primary_suspect_unit=target,
                confidence=0.90,
                evidence_refs=(
                    f"services.{target}.active_state",
                    "recent_mutations_in_flap_window",
                ),
                summary=(
                    f"Service {target} is flapping "
                    f"(recent_mutations_in_flap_window={flap_count})."
                ),
            )

        # Rule 1: Explicit Invalid Configuration (config_valid is strictly False)
        if target_ev.config_valid is False:
            return DiagnosisResult(
                fault_class=FaultClass.INVALID_CONFIG,
                primary_suspect_unit=target,
                confidence=0.95,
                evidence_refs=(f"services.{target}.config_valid",),
                summary=f"Configuration validation failed for {target}.",
            )

        # Rule 2: Upstream Dependency Failure
        service_cfg = self._config.inventory.services.get(target)
        if service_cfg is not None:
            for upstream in service_cfg.upstream_dependencies:
                up_ev = incident.services.get(upstream)
                if (
                    up_ev is None
                    or up_ev.active_state != "active"
                    or up_ev.sub_state != "running"
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

        # Rule 3: Active Unit States (Healthy, Transitional, Grace Window, or Degraded Running)
        if target_ev.active_state == "active":
            if target_ev.sub_state != "running":
                return DiagnosisResult(
                    fault_class=FaultClass.UNKNOWN,
                    primary_suspect_unit=target,
                    confidence=0.40,
                    evidence_refs=(
                        f"services.{target}.active_state",
                        f"services.{target}.sub_state",
                    ),
                    summary=(
                        f"Service {target} is active but in transitional "
                        f"sub_state={target_ev.sub_state!r}."
                    ),
                )

            if target_ev.health_probe_ok:
                return DiagnosisResult(
                    fault_class=FaultClass.HEALTHY,
                    primary_suspect_unit=target,
                    confidence=1.0,
                    evidence_refs=(
                        f"services.{target}.active_state",
                        f"services.{target}.health_probe_ok",
                    ),
                    summary=f"Service {target} is active and healthy.",
                )

            grace_sec = self._config.budgets.startup_grace_sec
            if (
                target_ev.active_enter_age_sec is not None
                and target_ev.active_enter_age_sec < grace_sec
            ):
                return DiagnosisResult(
                    fault_class=FaultClass.UNKNOWN,
                    primary_suspect_unit=target,
                    confidence=0.40,
                    evidence_refs=(
                        f"services.{target}.active_enter_age_sec",
                        f"services.{target}.health_probe_ok",
                    ),
                    summary=(
                        f"Service {target} is within startup grace window "
                        f"({target_ev.active_enter_age_sec:.1f}s < {grace_sec:.1f}s)."
                    ),
                )

            return DiagnosisResult(
                fault_class=FaultClass.DEGRADED_RUNNING,
                primary_suspect_unit=target,
                confidence=0.90,
                evidence_refs=(
                    f"services.{target}.active_state",
                    f"services.{target}.sub_state",
                    f"services.{target}.health_probe_ok",
                ),
                summary=f"Service {target} is running but failing health probe.",
            )

        # Rule 4: Process Crash / Persistent Failure
        has_failure_result = target_ev.result not in ("success", "unknown", "")
        is_crashed = target_ev.active_state == "failed" or (
            target_ev.active_state == "inactive" and has_failure_result
        )
        if is_crashed:
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
                    f"services.{target}.result",
                ),
                summary=f"Service {target} crashed (state={target_ev.active_state!r}).",
            )

        return DiagnosisResult(
            fault_class=FaultClass.UNKNOWN,
            primary_suspect_unit=target,
            confidence=0.40,
            evidence_refs=(
                f"services.{target}.active_state",
                f"services.{target}.result",
            ),
            summary=f"Ambiguous or operator-stopped state for unit {target}.",
        )
