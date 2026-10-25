"""Unified incident orchestrator loop with TOCTOU recheck, WAL audit, and locking."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from gateheal.actions import DEFAULT_ACTION_CATALOGUE
from gateheal.collector import IncidentCollector
from gateheal.config import GateHealConfig
from gateheal.controller import (
    AuditRecorder,
    EscalationSink,
    ExecutionController,
    OutcomeVerifier,
    default_artifacts_dir,
)
from gateheal.diagnosis import DiagnosisEngine
from gateheal.models import (
    ActionId,
    ActionProposal,
    ApprovalToken,
    AuditRecord,
    AuthorizedActionCapability,
    DiagnosisResult,
    EscalationAlert,
    ExecutionResult,
    FaultClass,
    ImpactTier,
    IncidentRecord,
    PolicyRejectionCode,
    VerificationStatus,
    validated_incident_update,
)
from gateheal.policy import (
    READ_ONLY_DIAGNOSTIC_ACTIONS,
    MinimalImpactSelector,
    PolicyEngine,
)
from gateheal.state import PersistentStateStore
from gateheal.transport import CommandTransport, SimulatedLabTransport

EvidenceSupplier = Callable[
    [str, str, int, int, tuple[str, ...], float], IncidentRecord
]
PostEvidenceSupplier = Callable[
    [ActionProposal, ExecutionResult, IncidentRecord, float], IncidentRecord
]
CandidateSupplier = Callable[
    [IncidentRecord, DiagnosisResult], Sequence[ActionProposal]
]


def build_default_deterministic_candidates(
    incident: IncidentRecord,
    diagnosis: DiagnosisResult,
) -> tuple[ActionProposal, ...]:
    """Generate deterministic candidate proposals from authoritative diagnosis."""
    if diagnosis.fault_class == FaultClass.HEALTHY:
        return (
            ActionProposal(
                action_id=ActionId.NO_OP.value,
                target_unit=incident.target_unit,
                inferred_fault=FaultClass.HEALTHY,
                rationale="Target service is healthy; no operation required.",
            ),
        )

    suspect = diagnosis.primary_suspect_unit
    candidates: list[ActionProposal] = [
        ActionProposal(
            action_id=ActionId.RELOAD_SERVICE.value,
            target_unit=suspect,
            inferred_fault=diagnosis.fault_class,
            rationale=f"Attempt minimal-impact reload on {suspect}.",
        ),
        ActionProposal(
            action_id=ActionId.RESTART_SERVICE.value,
            target_unit=suspect,
            inferred_fault=diagnosis.fault_class,
            rationale=f"Attempt targeted restart on suspect unit {suspect}.",
        ),
    ]
    if suspect != incident.target_unit:
        candidates.append(
            ActionProposal(
                action_id=ActionId.RESTART_SERVICE.value,
                target_unit=incident.target_unit,
                inferred_fault=diagnosis.fault_class,
                rationale=(
                    f"Fallback restart on alerting unit {incident.target_unit}."
                ),
            )
        )
    return tuple(candidates)


class IncidentOrchestrator:
    """Single authoritative incident handling pipeline for CLI and experiments."""

    def __init__(
        self,
        config: GateHealConfig,
        *,
        transport: CommandTransport | None = None,
        collector: IncidentCollector | None = None,
        diagnosis_engine: DiagnosisEngine | None = None,
        policy_engine: PolicyEngine | None = None,
        selector: MinimalImpactSelector | None = None,
        controller: ExecutionController | None = None,
        verifier: OutcomeVerifier | None = None,
        audit_recorder: AuditRecorder | None = None,
        escalation_sink: EscalationSink | None = None,
        state_store: PersistentStateStore | None = None,
        clock_utc: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ) -> None:
        self._config = config
        self._clock_utc: Callable[[], datetime] = (
            (lambda: datetime.now(UTC)) if clock_utc is None else clock_utc
        )
        self._monotonic_clock: Callable[[], float] = (
            time.monotonic if monotonic_clock is None else monotonic_clock
        )
        self._sleep_fn: Callable[[float], None] = (
            time.sleep if sleep_fn is None else sleep_fn
        )
        self._transport: CommandTransport = (
            SimulatedLabTransport() if transport is None else transport
        )
        self._collector: IncidentCollector = (
            IncidentCollector(config) if collector is None else collector
        )
        self._diagnosis_engine: DiagnosisEngine = (
            DiagnosisEngine(config)
            if diagnosis_engine is None
            else diagnosis_engine
        )
        self._state_store: PersistentStateStore = (
            PersistentStateStore(default_artifacts_dir() / "incident_state.json")
            if state_store is None
            else state_store
        )
        persisted_snap = self._state_store.load_snapshot()
        initial_tokens = set(persisted_snap.consumed_approval_tokens)

        self._policy_engine: PolicyEngine = (
            PolicyEngine(
                config,
                diagnosis_engine=self._diagnosis_engine,
                consumed_tokens=initial_tokens,
                clock_utc=self._clock_utc,
            )
            if policy_engine is None
            else policy_engine
        )
        self._policy_engine.consumed_tokens_store.update(initial_tokens)
        self._selector: MinimalImpactSelector = (
            MinimalImpactSelector(
                self._policy_engine, catalogue=self._policy_engine.catalogue
            )
            if selector is None
            else selector
        )
        self._controller: ExecutionController = (
            ExecutionController(
                config,
                transport=self._transport,
                policy_engine=self._policy_engine,
                catalogue=self._policy_engine.catalogue,
                consumed_tokens=self._policy_engine.consumed_tokens_store,
                clock_utc=self._clock_utc,
            )
            if controller is None
            else controller
        )
        self._verifier: OutcomeVerifier = (
            OutcomeVerifier(
                config,
                monotonic_clock=self._monotonic_clock,
                sleep_fn=self._sleep_fn,
                default_poll_interval_sec=config.budgets.verification_poll_interval_sec,
            )
            if verifier is None
            else verifier
        )
        self._audit_recorder: AuditRecorder = (
            AuditRecorder(clock_utc=self._clock_utc)
            if audit_recorder is None
            else audit_recorder
        )
        self._escalation_sink: EscalationSink = (
            EscalationSink() if escalation_sink is None else escalation_sink
        )

    @property
    def policy_engine(self) -> PolicyEngine:
        """Return the PolicyEngine bound to this orchestrator."""
        return self._policy_engine

    @property
    def controller(self) -> ExecutionController:
        """Return the ExecutionController bound to this orchestrator."""
        return self._controller

    @property
    def audit_recorder(self) -> AuditRecorder:
        """Return the AuditRecorder bound to this orchestrator."""
        return self._audit_recorder

    @property
    def escalation_sink(self) -> EscalationSink:
        """Return the EscalationSink bound to this orchestrator."""
        return self._escalation_sink

    @property
    def state_store(self) -> PersistentStateStore:
        """Return the PersistentStateStore bound to this orchestrator."""
        return self._state_store

    def _enrich_incident_from_store(
        self,
        raw_incident: IncidentRecord,
        *,
        incident_id: str,
        target_unit: str,
        elapsed_sec: float,
        now_utc: datetime,
    ) -> IncidentRecord:
        """Populate per-incident counters (R4) and per-unit cooldown/flap counters (R6)."""
        flap_win = self._config.budgets.flap_window_sec
        inc_state, last_age_sec, flap_count = (
            self._state_store.compute_unit_runtime_counters(
                target_unit,
                now_utc=now_utc,
                flap_window_sec=flap_win,
                incident_id=incident_id,
            )
        )
        unit_cooldowns: dict[str, float] = {}
        unit_flaps: dict[str, int] = {}
        for u_name in self._config.inventory.services:
            _, u_age, u_flap = self._state_store.compute_unit_runtime_counters(
                u_name,
                now_utc=now_utc,
                flap_window_sec=flap_win,
                incident_id=incident_id,
            )
            if u_age is not None:
                unit_cooldowns[u_name] = u_age
            if u_flap > 0:
                unit_flaps[u_name] = u_flap

        return validated_incident_update(
            raw_incident,
            elapsed_sec=elapsed_sec,
            prior_diagnostic_attempts=inc_state.prior_diagnostic_attempts,
            prior_recovery_attempts=inc_state.prior_recovery_attempts,
            action_history=inc_state.action_history,
            last_mutating_action_age_sec=last_age_sec,
            recent_mutations_in_flap_window=flap_count,
            unit_cooldown_age_sec=unit_cooldowns,
            unit_flap_counts=unit_flaps,
        )

    def handle_incident(
        self,
        *,
        incident_id: str,
        target_unit: str,
        evidence_supplier: EvidenceSupplier | None = None,
        recollect_supplier: EvidenceSupplier | None = None,
        post_evidence_supplier: PostEvidenceSupplier | None = None,
        candidate_supplier: CandidateSupplier | None = None,
        approval_token: ApprovalToken | None = None,
        controller_mode_override: str | None = None,
    ) -> AuditRecord:
        """Execute the bounded Runtime Assurance loop with per-unit locking and WAL."""
        mode_label = controller_mode_override or self._config.platform.controller_mode
        supply_ev: EvidenceSupplier = (
            (
                lambda inc_id, unit, d_att, r_att, hist, elap: (
                    self._collector.collect_from_transport(
                        incident_id=inc_id,
                        target_unit=unit,
                        transport=self._transport,
                        prior_diagnostic_attempts=d_att,
                        prior_recovery_attempts=r_att,
                        action_history=hist,
                        elapsed_sec=elap,
                    )
                )
            )
            if evidence_supplier is None
            else evidence_supplier
        )
        supply_recollect: EvidenceSupplier = (
            supply_ev if recollect_supplier is None else recollect_supplier
        )
        supply_candidates: CandidateSupplier = (
            build_default_deterministic_candidates
            if candidate_supplier is None
            else candidate_supplier
        )

        max_steps = (
            self._config.budgets.max_diagnostic_attempts
            + self._config.budgets.max_recovery_attempts
        )
        start_mono = self._monotonic_clock()
        last_completed_audit: AuditRecord | None = None

        with self._state_store.lock_unit(target_unit):
            for _step in range(max_steps):
                elapsed_sec = max(0.0, self._monotonic_clock() - start_mono)
                now_utc = self._clock_utc()
                inc_state, _, _ = (
                    self._state_store.compute_unit_runtime_counters(
                        target_unit,
                        now_utc=now_utc,
                        flap_window_sec=self._config.budgets.flap_window_sec,
                        incident_id=incident_id,
                    )
                )

                raw_incident = supply_ev(
                    incident_id,
                    target_unit,
                    inc_state.prior_diagnostic_attempts,
                    inc_state.prior_recovery_attempts,
                    inc_state.action_history,
                    elapsed_sec,
                )
                incident = self._enrich_incident_from_store(
                    raw_incident,
                    incident_id=incident_id,
                    target_unit=target_unit,
                    elapsed_sec=elapsed_sec,
                    now_utc=now_utc,
                )

                diagnosis = self._diagnosis_engine.diagnose(incident)
                candidates = tuple(supply_candidates(incident, diagnosis))
                chosen, decisions = self._selector.select(
                    candidates, incident, approval_token=approval_token
                )

                mutated_unit = chosen.target_unit or target_unit
                extra_units = (
                    (mutated_unit,) if mutated_unit != target_unit else ()
                )

                with self._state_store.lock_units(extra_units):
                    elapsed_pre_exec = max(
                        0.0, self._monotonic_clock() - start_mono
                    )
                    recollected_raw = supply_recollect(
                        incident_id,
                        target_unit,
                        inc_state.prior_diagnostic_attempts,
                        inc_state.prior_recovery_attempts,
                        inc_state.action_history,
                        elapsed_pre_exec,
                    )
                    recollected_incident = self._enrich_incident_from_store(
                        recollected_raw,
                        incident_id=incident_id,
                        target_unit=target_unit,
                        elapsed_sec=elapsed_pre_exec,
                        now_utc=self._clock_utc(),
                    )

                    capability = self._policy_engine.mint_capability(
                        chosen, incident, approval_token=approval_token
                    )

                    abstained = (
                        chosen.action_id == ActionId.ABSTAIN_AND_ESCALATE.value
                    )
                    intent_record = AuditRecord(
                        audit_stage="intent",
                        incident_id=incident.incident_id,
                        recorded_at_utc=self._clock_utc().isoformat(),
                        controller_mode=mode_label,
                        diagnosis=diagnosis,
                        evaluated_proposals=candidates,
                        policy_decisions=decisions,
                        selected_proposal=chosen,
                        capability_id=capability.capability_id,
                        abstained=abstained,
                        escalated=abstained,
                    )
                    self._audit_recorder.record(intent_record)

                    persisted_before_exec = [False]

                    def _persist_pre_exec(
                        cap: AuthorizedActionCapability,
                        _flag: list[bool] = persisted_before_exec,
                        _inc_id: str = incident_id,
                        _unit: str = target_unit,
                    ) -> None:
                        act_enum = cap.action_id
                        act_spec = DEFAULT_ACTION_CATALOGUE[act_enum]
                        is_mut = (
                            act_spec.impact_tier
                            >= ImpactTier.GRACEFUL_RELOAD_OR_RESTORE
                        )
                        is_diag = act_enum in READ_ONLY_DIAGNOSTIC_ACTIONS
                        self._state_store.record_execution(
                            incident_id=_inc_id,
                            unit_name=_unit,
                            action_id=cap.action_id.value,
                            target_unit=cap.target_unit,
                            is_mutating=is_mut,
                            is_diagnostic=is_diag,
                            now_utc=self._clock_utc(),
                            flap_window_sec=self._config.budgets.flap_window_sec,
                            consumed_tokens=self._policy_engine.consumed_tokens_store,
                        )
                        _flag[0] = True

                    prev_hook = self._controller._pre_execute_hook
                    self._controller._pre_execute_hook = _persist_pre_exec
                    try:
                        try:
                            exec_result = self._controller.execute(
                                capability,
                                current_incident=recollected_incident,
                                approval_token=approval_token,
                            )
                        except PermissionError as exc:
                            chosen = ActionProposal(
                                action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
                                target_unit=target_unit,
                                inferred_fault=diagnosis.fault_class,
                                rationale=(
                                    "Aborted execution on TOCTOU/capability "
                                    f"check: {exc}"
                                ),
                            )
                            abstained = True
                            recollected_diag = self._diagnosis_engine.diagnose(
                                recollected_incident
                            )
                            abstain_inc = (
                                incident
                                if recollected_diag.fault_class
                                == FaultClass.HEALTHY
                                else recollected_incident
                            )
                            abstain_cap = self._policy_engine.mint_capability(
                                chosen, abstain_inc
                            )
                            exec_result = self._controller.execute(
                                abstain_cap,
                                current_incident=abstain_inc,
                            )
                            capability = abstain_cap
                    finally:
                        self._controller._pre_execute_hook = prev_hook

                    action_enum = ActionId(chosen.action_id)
                    spec = DEFAULT_ACTION_CATALOGUE[action_enum]
                    is_mutating = (
                        spec.impact_tier
                        >= ImpactTier.GRACEFUL_RELOAD_OR_RESTORE
                    )
                    is_diagnostic = action_enum in READ_ONLY_DIAGNOSTIC_ACTIONS

                    if not persisted_before_exec[0]:
                        self._state_store.record_execution(
                            incident_id=incident_id,
                            unit_name=target_unit,
                            action_id=chosen.action_id,
                            target_unit=chosen.target_unit,
                            is_mutating=is_mutating,
                            is_diagnostic=is_diagnostic,
                            now_utc=self._clock_utc(),
                            flap_window_sec=self._config.budgets.flap_window_sec,
                            consumed_tokens=self._policy_engine.consumed_tokens_store,
                        )

                    updated_inc_state, _, _ = (
                        self._state_store.compute_unit_runtime_counters(
                            target_unit,
                            now_utc=self._clock_utc(),
                            flap_window_sec=self._config.budgets.flap_window_sec,
                            incident_id=incident_id,
                        )
                    )

                    if post_evidence_supplier is not None:
                        elapsed_post = max(
                            0.0, self._monotonic_clock() - start_mono
                        )
                        post_incident = post_evidence_supplier(
                            chosen,
                            exec_result,
                            recollected_incident,
                            elapsed_post,
                        )
                        ver_report = self._verifier.verify(
                            chosen,
                            exec_result,
                            post_incident,
                            pre_incident=incident,
                        )
                    else:
                        ver_report, _ = self._verifier.verify_with_transport(
                            chosen,
                            exec_result,
                            incident,
                            self._transport,
                        )
                        elapsed_post = max(
                            0.0, self._monotonic_clock() - start_mono
                        )

                    needs_escalation = abstained or (
                        ver_report.status
                        in (
                            VerificationStatus.NOT_RECOVERED,
                            VerificationStatus.OUTCOME_UNCERTAIN,
                            VerificationStatus.VERIFICATION_FAILED,
                            VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE,
                            VerificationStatus.FAULT_PERSISTS_SERVICE_UP,
                        )
                    )

                    if needs_escalation:
                        all_rej: list[PolicyRejectionCode] = []
                        all_notes: list[str] = []
                        for dec in decisions:
                            if not dec.approved:
                                all_rej.extend(dec.rejection_codes)
                                all_notes.extend(dec.notes)
                        if not abstained:
                            all_notes.append(
                                f"POST_EXECUTION_ESCALATION: status={ver_report.status.value} "
                                f"({ver_report.details})"
                            )
                        self._escalation_sink.emit(
                            EscalationAlert(
                                alert_id=f"alert-{uuid.uuid4().hex[:12]}",
                                incident_id=incident.incident_id,
                                target_unit=target_unit,
                                emitted_at_utc=self._clock_utc().isoformat(),
                                diagnosed_fault=diagnosis.fault_class,
                                rationale=chosen.rationale,
                                rejection_codes=tuple(dict.fromkeys(all_rej)),
                                notes=tuple(all_notes),
                            )
                        )

                    completed_record = AuditRecord(
                        audit_stage="completed",
                        incident_id=incident.incident_id,
                        recorded_at_utc=self._clock_utc().isoformat(),
                        controller_mode=mode_label,
                        diagnosis=diagnosis,
                        evaluated_proposals=candidates,
                        policy_decisions=decisions,
                        selected_proposal=chosen,
                        capability_id=capability.capability_id,
                        execution_result=exec_result,
                        verification_report=ver_report,
                        abstained=abstained,
                        escalated=needs_escalation,
                    )
                    last_completed_audit = self._audit_recorder.record(
                        completed_record
                    )

                    if (
                        is_diagnostic
                        and updated_inc_state.prior_diagnostic_attempts
                        < self._config.budgets.max_diagnostic_attempts
                        and elapsed_post
                        < self._config.budgets.total_incident_timeout_sec
                    ):
                        continue
                    return last_completed_audit

        assert last_completed_audit is not None
        return last_completed_audit
