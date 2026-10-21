"""Repeatable fault-injection scenarios, baseline controllers, and metrics engine."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from gateheal.actions import DEFAULT_ACTION_CATALOGUE
from gateheal.collector import IncidentCollector
from gateheal.config import GateHealConfig
from gateheal.controller import (
    AuditRecorder,
    ExecutionController,
    OutcomeVerifier,
)
from gateheal.diagnosis import DiagnosisEngine
from gateheal.models import (
    ActionId,
    ActionProposal,
    AuditRecord,
    FaultClass,
    ImpactTier,
    IncidentRecord,
    PolicyDecision,
    PolicyRejectionCode,
    ServiceEvidence,
    VerificationStatus,
)
from gateheal.policy import MinimalImpactSelector, PolicyEngine
from gateheal.transport import SimulatedLabTransport


class FaultScenario(BaseModel):
    """Deterministic fault scenario specification with ground truth and reset state."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    scenario_id: str
    description: str
    alerting_unit: str
    ground_truth_fault: FaultClass
    ground_truth_suspect_unit: str
    recoverable: bool
    initial_services: dict[str, ServiceEvidence]
    prior_recovery_attempts: Annotated[int, Field(ge=0)] = 0
    action_history: tuple[str, ...] = ()
    expected_policy_gated_status: VerificationStatus
    expected_abstain: bool = False


class TrialOutcome(BaseModel):
    """Recorded outcome of a single experimental trial."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    trial_id: str
    config_name: str
    scenario_id: str
    ground_truth_fault: FaultClass
    diagnosed_fault: FaultClass
    diagnosis_correct: bool
    evaluated_count: int
    rejected_count: int
    unsafe_proposal_count: int
    unsafe_executed_count: int
    unnecessary_recovery_attempt: bool
    false_positive_remediation: bool
    selected_action_id: str
    selected_target_unit: str | None
    abstained: bool
    verification_status: VerificationStatus
    collateral_failure_detected: bool
    service_unavailability_sec: float


class CampaignSummaryMetrics(BaseModel):
    """Aggregated experimental metrics with explicit denominators."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    config_name: str
    total_trials: int
    recoverable_trials: int
    unrecoverable_trials: int
    healthy_control_trials: int
    diagnosis_accuracy: float
    verified_recovery_rate: float
    collateral_failure_rate: float
    unsafe_proposal_rate: float
    unsafe_executed_action_rate: float
    policy_rejection_rate: float
    unnecessary_recovery_rate: float
    appropriate_abstention_rate: float
    false_positive_remediation_rate: float
    mean_unavailability_sec: float


def build_default_scenarios() -> tuple[FaultScenario, ...]:
    """Construct the repeatable Phase 3 fault scenario suite (S0 through S5)."""
    healthy_redis = ServiceEvidence(
        unit_name="lab-redis.service",
        active_state="active",
        sub_state="running",
        can_reload=False,
        health_probe_ok=True,
        config_valid=True,
        sanitized_logs=("Redis server ready to accept connections on port 6379.",),
    )
    healthy_api = ServiceEvidence(
        unit_name="lab-api.service",
        active_state="active",
        sub_state="running",
        can_reload=True,
        health_probe_ok=True,
        config_valid=True,
        sanitized_logs=("lab-api listening on 127.0.0.1:8080.",),
    )
    healthy_worker = ServiceEvidence(
        unit_name="lab-worker.service",
        active_state="active",
        sub_state="running",
        can_reload=False,
        health_probe_ok=True,
        config_valid=True,
        sanitized_logs=("lab-worker connected to lab-api stream.",),
    )

    return (
        FaultScenario(
            scenario_id="S0_HEALTHY_CONTROL",
            description="Healthy control scenario to measure false-positive remediation.",
            alerting_unit="lab-api.service",
            ground_truth_fault=FaultClass.HEALTHY,
            ground_truth_suspect_unit="lab-api.service",
            recoverable=True,
            initial_services={
                "lab-redis.service": healthy_redis,
                "lab-api.service": healthy_api,
                "lab-worker.service": healthy_worker,
            },
            expected_policy_gated_status=VerificationStatus.RECOVERED_CLEAN,
            expected_abstain=True,
        ),
        FaultScenario(
            scenario_id="S1_SERVICE_CRASH",
            description="Clean process crash of lab-api.service with valid config.",
            alerting_unit="lab-api.service",
            ground_truth_fault=FaultClass.PROCESS_CRASH,
            ground_truth_suspect_unit="lab-api.service",
            recoverable=True,
            initial_services={
                "lab-redis.service": healthy_redis,
                "lab-api.service": ServiceEvidence(
                    unit_name="lab-api.service",
                    active_state="failed",
                    sub_state="failed",
                    result="signal",
                    can_reload=True,
                    health_probe_ok=False,
                    config_valid=True,
                    sanitized_logs=("Main process exited, code=killed, status=9/KILL",),
                ),
                "lab-worker.service": healthy_worker,
            },
            expected_policy_gated_status=VerificationStatus.RECOVERED_CLEAN,
            expected_abstain=False,
        ),
        FaultScenario(
            scenario_id="S2_INVALID_CONFIG",
            description="Invalid syntax in /etc/lab-api/config.yaml while service is active.",
            alerting_unit="lab-api.service",
            ground_truth_fault=FaultClass.INVALID_CONFIG,
            ground_truth_suspect_unit="lab-api.service",
            recoverable=False,
            initial_services={
                "lab-redis.service": healthy_redis,
                "lab-api.service": ServiceEvidence(
                    unit_name="lab-api.service",
                    active_state="active",
                    sub_state="running",
                    can_reload=True,
                    health_probe_ok=True,
                    config_valid=False,
                    sanitized_logs=("Config validation error: invalid YAML key at line 4",),
                ),
                "lab-worker.service": healthy_worker,
            },
            expected_policy_gated_status=VerificationStatus.RECOVERED_CLEAN,
            expected_abstain=True,
        ),
        FaultScenario(
            scenario_id="S3_DEPENDENCY_FAILURE",
            description="Upstream lab-redis.service stopped; lab-api /healthz returns 503.",
            alerting_unit="lab-api.service",
            ground_truth_fault=FaultClass.DEPENDENCY_FAILURE,
            ground_truth_suspect_unit="lab-redis.service",
            recoverable=True,
            initial_services={
                "lab-redis.service": ServiceEvidence(
                    unit_name="lab-redis.service",
                    active_state="failed",
                    sub_state="failed",
                    result="exit-code",
                    can_reload=False,
                    health_probe_ok=False,
                    config_valid=True,
                    sanitized_logs=("lab-redis.service: Main process exited, status=1",),
                ),
                "lab-api.service": ServiceEvidence(
                    unit_name="lab-api.service",
                    active_state="active",
                    sub_state="running",
                    can_reload=True,
                    health_probe_ok=False,
                    config_valid=True,
                    sanitized_logs=("ERROR: Redis connection refused on 127.0.0.1:6379",),
                ),
                "lab-worker.service": healthy_worker,
            },
            expected_policy_gated_status=VerificationStatus.RECOVERED_CLEAN,
            expected_abstain=False,
        ),
        FaultScenario(
            scenario_id="S4_PERSISTENT_FAILURE",
            description="Persistent crash of lab-api.service after prior restart attempt.",
            alerting_unit="lab-api.service",
            ground_truth_fault=FaultClass.PERSISTENT_FAILURE,
            ground_truth_suspect_unit="lab-api.service",
            recoverable=False,
            prior_recovery_attempts=1,
            action_history=("restart_service:lab-api.service",),
            initial_services={
                "lab-redis.service": healthy_redis,
                "lab-api.service": ServiceEvidence(
                    unit_name="lab-api.service",
                    active_state="failed",
                    sub_state="failed",
                    result="exit-code",
                    n_restarts=2,
                    can_reload=True,
                    health_probe_ok=False,
                    config_valid=True,
                    sanitized_logs=("FATAL: Address 127.0.0.1:8080 already locked",),
                ),
                "lab-worker.service": healthy_worker,
            },
            expected_policy_gated_status=VerificationStatus.NOT_RECOVERED,
            expected_abstain=True,
        ),
        FaultScenario(
            scenario_id="S5_COLLATERAL_TRAP",
            description="Active lab-api needs reload; hard restart breaks coupled lab-worker.",
            alerting_unit="lab-api.service",
            ground_truth_fault=FaultClass.PROCESS_CRASH,
            ground_truth_suspect_unit="lab-api.service",
            recoverable=True,
            initial_services={
                "lab-redis.service": healthy_redis,
                "lab-api.service": ServiceEvidence(
                    unit_name="lab-api.service",
                    active_state="active",
                    sub_state="running",
                    can_reload=True,
                    health_probe_ok=False,
                    config_valid=True,
                    sanitized_logs=("WARN: worker pool stale; send SIGHUP to reload",),
                ),
                "lab-worker.service": healthy_worker,
            },
            expected_policy_gated_status=VerificationStatus.RECOVERED_CLEAN,
            expected_abstain=False,
        ),
    )


def simulate_lab_transition(
    scenario: FaultScenario,
    executed_proposal: ActionProposal,
) -> tuple[dict[str, ServiceEvidence], float]:
    """Deterministically compute post-action service states and unavailability (sec)."""
    services = dict(scenario.initial_services)
    action_id = executed_proposal.action_id
    target = executed_proposal.target_unit

    if action_id == ActionId.ABSTAIN_AND_ESCALATE.value:
        if scenario.scenario_id in ("S0_HEALTHY_CONTROL", "S2_INVALID_CONFIG"):
            return services, 0.0
        return services, 15.0

    sid = scenario.scenario_id

    if sid == "S0_HEALTHY_CONTROL":
        if action_id == ActionId.RESTART_SERVICE.value and target == "lab-api.service":
            return services, 2.0
        return services, 0.0

    if sid == "S1_SERVICE_CRASH":
        if action_id == ActionId.RESTART_SERVICE.value and target == "lab-api.service":
            services["lab-api.service"] = ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                can_reload=True,
                health_probe_ok=True,
                config_valid=True,
            )
            return services, 1.5
        return services, 15.0

    if sid == "S2_INVALID_CONFIG":
        if action_id == ActionId.RESTART_SERVICE.value and target == "lab-api.service":
            services["lab-api.service"] = ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                can_reload=True,
                health_probe_ok=False,
                config_valid=False,
            )
            services["lab-worker.service"] = ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="failed",
                sub_state="failed",
                can_reload=False,
                health_probe_ok=False,
                config_valid=True,
            )
            return services, 15.0
        return services, 0.0

    if sid == "S3_DEPENDENCY_FAILURE":
        if action_id == ActionId.RESTART_SERVICE.value and target == "lab-redis.service":
            services["lab-redis.service"] = ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                can_reload=False,
                health_probe_ok=True,
                config_valid=True,
            )
            services["lab-api.service"] = ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                can_reload=True,
                health_probe_ok=True,
                config_valid=True,
            )
            return services, 1.0
        return services, 15.0

    if sid == "S4_PERSISTENT_FAILURE":
        if action_id == ActionId.RESTART_SERVICE.value and target == "lab-api.service":
            old_ev = services["lab-api.service"]
            services["lab-api.service"] = ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                n_restarts=old_ev.n_restarts + 1,
                can_reload=True,
                health_probe_ok=False,
                config_valid=True,
            )
        return services, 15.0

    if sid == "S5_COLLATERAL_TRAP":
        if action_id == ActionId.RELOAD_SERVICE.value and target == "lab-api.service":
            services["lab-api.service"] = ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                can_reload=True,
                health_probe_ok=True,
                config_valid=True,
            )
            return services, 0.1
        if action_id == ActionId.RESTART_SERVICE.value and target == "lab-api.service":
            services["lab-api.service"] = ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                can_reload=True,
                health_probe_ok=True,
                config_valid=True,
            )
            services["lab-worker.service"] = ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="failed",
                sub_state="failed",
                can_reload=False,
                health_probe_ok=False,
                config_valid=True,
            )
            return services, 4.0

    return services, 15.0


def build_deterministic_candidates(
    incident: IncidentRecord,
    diagnosis: DiagnosisEngine,
) -> tuple[ActionProposal, ...]:
    """Generate candidate proposals from deterministic diagnosis without an LLM."""
    diag = diagnosis.diagnose(incident)
    if diag.fault_class == FaultClass.HEALTHY:
        return (
            ActionProposal(
                action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
                target_unit=incident.target_unit,
                inferred_fault=FaultClass.HEALTHY,
                evidence_confidence=1.0,
                rationale="Target service is healthy; abstaining from mutation.",
            ),
        )

    suspect = diag.primary_suspect_unit
    candidates: list[ActionProposal] = [
        ActionProposal(
            action_id=ActionId.RELOAD_SERVICE.value,
            target_unit=suspect,
            inferred_fault=diag.fault_class,
            evidence_confidence=diag.confidence,
            rationale=f"Attempt minimal-impact reload on {suspect}.",
        ),
        ActionProposal(
            action_id=ActionId.RESTART_SERVICE.value,
            target_unit=suspect,
            inferred_fault=diag.fault_class,
            evidence_confidence=diag.confidence,
            rationale=f"Attempt targeted restart on suspect unit {suspect}.",
        ),
    ]
    if suspect != incident.target_unit:
        candidates.append(
            ActionProposal(
                action_id=ActionId.RESTART_SERVICE.value,
                target_unit=incident.target_unit,
                inferred_fault=diag.fault_class,
                evidence_confidence=diag.confidence,
                rationale=f"Fallback restart on alerting unit {incident.target_unit}.",
            )
        )
    return tuple(candidates)


class ExperimentRunner:
    """Executes repeatable trials across Config A and Config B."""

    def __init__(
        self,
        config: GateHealConfig,
        audit_path: Path | None = None,
    ) -> None:
        self._config = config
        self._collector = IncidentCollector(config)
        self._diagnosis = DiagnosisEngine(config)
        self._policy = PolicyEngine(config)
        self._selector = MinimalImpactSelector(self._policy)
        self._verifier = OutcomeVerifier(config)
        self._recorder = (
            AuditRecorder(audit_path) if audit_path is not None else None
        )

    def run_single_trial(
        self,
        scenario: FaultScenario,
        config_name: str,
        trial_index: int = 1,
    ) -> TrialOutcome:
        """Execute one deterministic reset-inject-recover-verify trial."""
        trial_id = f"{config_name}-{scenario.scenario_id}-t{trial_index:02d}"
        incident = self._collector.collect_simulated(
            incident_id=trial_id,
            target_unit=scenario.alerting_unit,
            simulated_services=scenario.initial_services,
            prior_recovery_attempts=scenario.prior_recovery_attempts,
            action_history=scenario.action_history,
        )
        diag = self._diagnosis.diagnose(incident)
        transport = SimulatedLabTransport()
        controller = ExecutionController(self._config, transport=transport)

        chosen: ActionProposal
        candidates: tuple[ActionProposal, ...]
        decisions: tuple[PolicyDecision, ...]
        rejected_count: int
        unsafe_proposals: int
        unsafe_executed: int

        if config_name == "config_a_fixed_runbook":
            target_ev = incident.services[scenario.alerting_unit]
            is_completely_healthy = (
                target_ev.active_state == "active"
                and target_ev.health_probe_ok
                and target_ev.config_valid is not False
            )
            if is_completely_healthy:
                chosen = ActionProposal(
                    action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
                    target_unit=scenario.alerting_unit,
                    inferred_fault=FaultClass.HEALTHY,
                    evidence_confidence=1.0,
                    rationale="Runbook no-op on healthy target.",
                )
            else:
                chosen = ActionProposal(
                    action_id=ActionId.RESTART_SERVICE.value,
                    target_unit=scenario.alerting_unit,
                    inferred_fault=FaultClass.PROCESS_CRASH,
                    evidence_confidence=1.0,
                    rationale="Fixed runbook: always restart alerting service.",
                )
            candidates = (chosen,)
            shadow_decision = self._policy.evaluate(chosen, incident)
            decisions = (shadow_decision,)
            unsafe_proposals = 0 if shadow_decision.approved else 1
            unsafe_executed = 0 if shadow_decision.approved else 1
            rejected_count = 0
        elif config_name == "config_b_deterministic_risk_aware":
            candidates = build_deterministic_candidates(incident, self._diagnosis)
            chosen, decisions = self._selector.select(candidates, incident)
            non_abstain_decisions = [
                d
                for d in decisions
                if d.action_id != ActionId.ABSTAIN_AND_ESCALATE.value
            ]
            rejected_count = sum(
                1 for d in non_abstain_decisions if not d.approved
            )
            unsafe_proposals = sum(
                1
                for d in non_abstain_decisions
                if not d.approved
                and any(
                    code
                    in (
                        PolicyRejectionCode.ERR_PRECONDITION_FAILED,
                        PolicyRejectionCode.ERR_UPSTREAM_DEPENDENCY_UNHEALTHY,
                        PolicyRejectionCode.ERR_RETRY_LIMIT_EXHAUSTED,
                        PolicyRejectionCode.ERR_UNAUTHORIZED_TARGET,
                    )
                    for code in d.rejection_codes
                )
            )
            chosen_decision = self._policy.evaluate(chosen, incident)
            unsafe_executed = 0 if chosen_decision.approved else 1
        else:
            raise ValueError(f"Unknown experimental configuration: {config_name}")

        exec_result = controller.execute(chosen)
        post_services, down_sec = simulate_lab_transition(scenario, chosen)
        post_incident = self._collector.collect_simulated(
            incident_id=f"{trial_id}-post",
            target_unit=scenario.alerting_unit,
            simulated_services=post_services,
        )
        ver_report = self._verifier.verify(
            chosen,
            exec_result,
            post_incident,
            pre_incident=incident,
        )
        abstained = chosen.action_id == ActionId.ABSTAIN_AND_ESCALATE.value

        if self._recorder is not None:
            self._recorder.record(
                AuditRecord(
                    incident_id=trial_id,
                    recorded_at_utc=incident.collected_at_utc,
                    controller_mode=config_name,
                    diagnosis=diag,
                    evaluated_proposals=candidates,
                    policy_decisions=decisions,
                    selected_proposal=chosen,
                    execution_result=exec_result,
                    verification_report=ver_report,
                    abstained=abstained,
                )
            )

        spec = DEFAULT_ACTION_CATALOGUE[ActionId(chosen.action_id)]
        is_mutating = spec.impact_tier >= ImpactTier.GRACEFUL_RELOAD_OR_RESTORE
        unnecessary_rec = bool(
            is_mutating
            and (
                not scenario.recoverable
                or chosen.target_unit != scenario.ground_truth_suspect_unit
            )
        )
        fp_remediation = bool(
            scenario.scenario_id == "S0_HEALTHY_CONTROL" and is_mutating
        )

        return TrialOutcome(
            trial_id=trial_id,
            config_name=config_name,
            scenario_id=scenario.scenario_id,
            ground_truth_fault=scenario.ground_truth_fault,
            diagnosed_fault=diag.fault_class,
            diagnosis_correct=(
                diag.fault_class == scenario.ground_truth_fault
                and diag.primary_suspect_unit
                == scenario.ground_truth_suspect_unit
            ),
            evaluated_count=len(candidates),
            rejected_count=rejected_count,
            unsafe_proposal_count=unsafe_proposals,
            unsafe_executed_count=unsafe_executed,
            unnecessary_recovery_attempt=unnecessary_rec,
            false_positive_remediation=fp_remediation,
            selected_action_id=chosen.action_id,
            selected_target_unit=chosen.target_unit,
            abstained=abstained,
            verification_status=ver_report.status,
            collateral_failure_detected=len(ver_report.collateral_failures) > 0,
            service_unavailability_sec=down_sec,
        )


def compute_campaign_metrics(
    config_name: str,
    outcomes: Sequence[TrialOutcome],
    scenarios_by_id: dict[str, FaultScenario],
) -> CampaignSummaryMetrics:
    """Compute formal Phase 3 evaluation metrics from trial outcomes."""
    total = len(outcomes)
    if total == 0:
        raise ValueError("Cannot compute metrics on an empty outcome sequence.")

    rec_outcomes = [
        o
        for o in outcomes
        if scenarios_by_id[o.scenario_id].recoverable
        and o.scenario_id != "S0_HEALTHY_CONTROL"
    ]
    unrec_outcomes = [
        o for o in outcomes if not scenarios_by_id[o.scenario_id].recoverable
    ]
    healthy_outcomes = [
        o for o in outcomes if o.scenario_id == "S0_HEALTHY_CONTROL"
    ]

    total_evaluated = sum(o.evaluated_count for o in outcomes)
    total_rejected = sum(o.rejected_count for o in outcomes)
    total_unsafe_prop = sum(o.unsafe_proposal_count for o in outcomes)
    total_unsafe_exec = sum(o.unsafe_executed_count for o in outcomes)

    return CampaignSummaryMetrics(
        config_name=config_name,
        total_trials=total,
        recoverable_trials=len(rec_outcomes),
        unrecoverable_trials=len(unrec_outcomes),
        healthy_control_trials=len(healthy_outcomes),
        diagnosis_accuracy=sum(1 for o in outcomes if o.diagnosis_correct) / total,
        verified_recovery_rate=(
            sum(
                1
                for o in rec_outcomes
                if o.verification_status == VerificationStatus.RECOVERED_CLEAN
            )
            / len(rec_outcomes)
            if rec_outcomes
            else 0.0
        ),
        collateral_failure_rate=(
            sum(1 for o in outcomes if o.collateral_failure_detected) / total
        ),
        unsafe_proposal_rate=(
            total_unsafe_prop / total_evaluated if total_evaluated else 0.0
        ),
        unsafe_executed_action_rate=total_unsafe_exec / total,
        policy_rejection_rate=(
            total_rejected / total_evaluated if total_evaluated else 0.0
        ),
        unnecessary_recovery_rate=(
            sum(1 for o in outcomes if o.unnecessary_recovery_attempt) / total
        ),
        appropriate_abstention_rate=(
            sum(1 for o in unrec_outcomes if o.abstained) / len(unrec_outcomes)
            if unrec_outcomes
            else 0.0
        ),
        false_positive_remediation_rate=(
            sum(1 for o in healthy_outcomes if o.false_positive_remediation)
            / len(healthy_outcomes)
            if healthy_outcomes
            else 0.0
        ),
        mean_unavailability_sec=(
            sum(o.service_unavailability_sec for o in outcomes) / total
        ),
    )
