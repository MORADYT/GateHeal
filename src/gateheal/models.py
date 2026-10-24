"""Immutable domain schemas for GateHeal."""

from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

SCHEMA_VERSION = "1.0"
GENESIS_RECORD_HASH = "0" * 64


def _coerce_list_to_tuple(value: object) -> object:
    """Convert JSON/YAML lists to tuples while preserving strict element checks."""
    if isinstance(value, list):
        return tuple(value)
    return value


StrictStrTuple = Annotated[tuple[str, ...], BeforeValidator(_coerce_list_to_tuple)]


class ImpactTier(IntEnum):
    """Discrete service disruption tiers ordered from least to most disruptive."""

    READ_ONLY_DIAGNOSTIC = 0
    GRACEFUL_RELOAD_OR_RESTORE = 1
    TARGETED_RESTART = 2
    SHARED_OR_CASCADE_RESTART = 3


class ActionId(StrEnum):
    """Registered recovery and diagnostic action identifiers."""

    NO_OP = "no_op"
    INSPECT_SERVICE_STATUS = "inspect_service_status"
    VALIDATE_SERVICE_CONFIG = "validate_service_config"
    CHECK_DEPENDENCY_HEALTH = "check_dependency_health"
    RESTORE_LAST_KNOWN_GOOD_CONFIG = "restore_last_known_good_config"
    RELOAD_SERVICE = "reload_service"
    RESTART_SERVICE = "restart_service"
    ABSTAIN_AND_ESCALATE = "abstain_and_escalate"


class PermissionTier(StrEnum):
    """Privilege scope required by an action."""

    READ_ONLY = "read_only"
    SERVICE_OPERATOR = "service_operator"
    HUMAN_ESCALATION = "human_escalation"


class FaultClass(StrEnum):
    """Structured fault classifications produced by the DiagnosisEngine."""

    HEALTHY = "healthy"
    PROCESS_CRASH = "process_crash"
    DEGRADED_RUNNING = "degraded_running"
    INVALID_CONFIG = "invalid_config"
    DEPENDENCY_FAILURE = "dependency_failure"
    PERSISTENT_FAILURE = "persistent_failure"
    UNKNOWN = "unknown"


class PolicyRejectionCode(StrEnum):
    """Deterministic rejection codes emitted by the independent PolicyEngine."""

    ERR_UNREGISTERED_ACTION = "ERR_UNREGISTERED_ACTION"
    ERR_ACTION_DISABLED = "ERR_ACTION_DISABLED"
    ERR_UNAUTHORIZED_TARGET = "ERR_UNAUTHORIZED_TARGET"
    ERR_MALFORMED_ARGUMENTS = "ERR_MALFORMED_ARGUMENTS"
    ERR_INCOMPATIBLE_FAULT_ACTION = "ERR_INCOMPATIBLE_FAULT_ACTION"
    ERR_PRECONDITION_FAILED = "ERR_PRECONDITION_FAILED"
    ERR_INSUFFICIENT_PERMISSION = "ERR_INSUFFICIENT_PERMISSION"
    ERR_UPSTREAM_DEPENDENCY_UNHEALTHY = "ERR_UPSTREAM_DEPENDENCY_UNHEALTHY"
    ERR_TIME_BUDGET_EXCEEDED = "ERR_TIME_BUDGET_EXCEEDED"
    ERR_RETRY_LIMIT_EXHAUSTED = "ERR_RETRY_LIMIT_EXHAUSTED"
    ERR_COOLDOWN_ACTIVE = "ERR_COOLDOWN_ACTIVE"
    ERR_FLAPPING_DETECTED = "ERR_FLAPPING_DETECTED"
    ERR_IMPACT_TIER_EXCEEDED = "ERR_IMPACT_TIER_EXCEEDED"
    ERR_BLAST_RADIUS_EXCEEDED = "ERR_BLAST_RADIUS_EXCEEDED"
    ERR_HUMAN_APPROVAL_REQUIRED = "ERR_HUMAN_APPROVAL_REQUIRED"
    ERR_INVALID_APPROVAL_TOKEN = "ERR_INVALID_APPROVAL_TOKEN"
    ERR_INSUFFICIENT_EVIDENCE = "ERR_INSUFFICIENT_EVIDENCE"


class VerificationStatus(StrEnum):
    """Independent post-action recovery verification outcomes."""

    RECOVERED_CLEAN = "recovered_clean"
    RECOVERED_WITH_COLLATERAL_FAILURE = "recovered_with_collateral_failure"
    FAULT_PERSISTS_SERVICE_UP = "fault_persists_service_up"
    NOT_RECOVERED = "not_recovered"
    OUTCOME_UNCERTAIN = "outcome_uncertain"
    VERIFICATION_FAILED = "verification_failed"


class ServiceEvidence(BaseModel):
    """Sanitized, bounded diagnostic snapshot for a single Linux systemd unit."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    unit_name: str
    active_state: str
    sub_state: str
    result: str = "success"
    n_restarts: Annotated[int, Field(ge=0)] = 0
    can_reload: bool = False
    health_probe_ok: bool
    config_valid: bool | None = None
    active_enter_age_sec: Annotated[float, Field(ge=0.0)] | None = None
    invocation_id: str | None = None
    exec_main_start_timestamp_usec: Annotated[int, Field(ge=0)] | None = None
    sanitized_logs: StrictStrTuple = ()


class IncidentRecord(BaseModel):
    """Structured incident context collected from the isolated lab environment."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    incident_id: str
    target_unit: str
    collected_at_utc: str
    services: dict[str, ServiceEvidence]
    prior_diagnostic_attempts: Annotated[int, Field(ge=0)] = 0
    prior_recovery_attempts: Annotated[int, Field(ge=0)] = 0
    action_history: StrictStrTuple = ()
    elapsed_sec: Annotated[float, Field(ge=0.0)] = 0.0
    last_mutating_action_age_sec: Annotated[float, Field(ge=0.0)] | None = None
    recent_mutations_in_flap_window: Annotated[int, Field(ge=0)] = 0
    unit_cooldown_age_sec: dict[str, float] = Field(default_factory=dict)
    unit_flap_counts: dict[str, int] = Field(default_factory=dict)


def validated_incident_update(
    incident: IncidentRecord,
    **updates: object,
) -> IncidentRecord:
    """Update an IncidentRecord with full Pydantic field and extra='forbid' validation."""
    merged = incident.model_dump()
    merged.update(updates)
    return IncidentRecord.model_validate(merged)


class DiagnosisResult(BaseModel):
    """Deterministic or statistical diagnosis output separated from action selection."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    fault_class: FaultClass
    primary_suspect_unit: str
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    evidence_refs: StrictStrTuple = ()
    summary: str


class ActionProposal(BaseModel):
    """Untrusted candidate action proposal evaluated by the PolicyEngine."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    action_id: str
    target_unit: str | None = None
    parameters: dict[str, str] = Field(default_factory=dict)
    inferred_fault: FaultClass = FaultClass.UNKNOWN
    evidence_confidence: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0
    rationale: Annotated[str, Field(min_length=3, max_length=1000)]


class ApprovalToken(BaseModel):
    """Out-of-band HMAC-signed operator approval token bound to incident state."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    token_id: Annotated[str, Field(min_length=1, max_length=128)]
    incident_id: Annotated[str, Field(min_length=1, max_length=128)]
    action_id: str
    target_unit: str | None = None
    state_hash: Annotated[str, Field(min_length=64, max_length=64)]
    expires_at_utc: str
    hmac_signature: Annotated[str, Field(min_length=64, max_length=64)]


class PolicyDecision(BaseModel):
    """Deterministic authorization decision produced by the PolicyEngine."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    approved: bool
    action_id: str
    target_unit: str | None = None
    rejection_codes: tuple[PolicyRejectionCode, ...] = ()
    notes: StrictStrTuple = ()


class AuthorizedActionCapability(BaseModel):
    """Unforgeable single-use execution capability minted exclusively by PolicyEngine."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    capability_id: Annotated[str, Field(min_length=1, max_length=128)]
    incident_id: Annotated[str, Field(min_length=1, max_length=128)]
    action_id: ActionId
    target_unit: str | None = None
    proposal: ActionProposal
    decision: PolicyDecision
    state_hash: Annotated[str, Field(min_length=64, max_length=64)]
    requires_approval_token: bool = False
    approval_token_id: str | None = None
    issued_at_utc: str
    expires_at_utc: str
    mac_signature: Annotated[str, Field(min_length=64, max_length=64)]


class ExecutionResult(BaseModel):
    """Bounded subprocess execution record (exit code 0 never implies recovery)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    action_id: ActionId
    target_unit: str | None = None
    argv: StrictStrTuple
    exit_code: int
    timed_out: bool = False
    duration_sec: Annotated[float, Field(ge=0.0)]
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""


class VerificationReport(BaseModel):
    """Independent outcome verification report checking target and dependent units.

    Note on `measured_unavailability_sec` / `in_window_unavailability_sec` (D3):
    This field records **in-window unavailability** during the post-action verification
    soak window—an upper bound quantized at `verification_poll_interval_sec` poll
    granularity. End-to-end MTTR / total incident unavailability comes from the
    experiment harness (`TrialOutcome.service_unavailability_sec`), not this field.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    status: VerificationStatus
    target_unit: str
    target_healthy: bool
    soak_duration_sec: Annotated[float, Field(ge=0.0)]
    samples_collected: Annotated[int, Field(ge=0)] = 1
    first_healthy_at_sec: Annotated[float, Field(ge=0.0)] | None = None
    first_failed_at_sec: Annotated[float, Field(ge=0.0)] | None = None
    measured_unavailability_sec: Annotated[float, Field(ge=0.0)] = 0.0
    collateral_failures: StrictStrTuple = ()
    details: str

    @property
    def in_window_unavailability_sec(self) -> float:
        """Return in-window soak unavailability upper bound at poll granularity."""
        return self.measured_unavailability_sec


class EscalationAlert(BaseModel):
    """Structured operator handoff alert emitted when the controller abstains or fails."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    alert_id: str
    incident_id: str
    target_unit: str
    emitted_at_utc: str
    diagnosed_fault: FaultClass
    rationale: str
    rejection_codes: tuple[PolicyRejectionCode, ...] = ()
    notes: StrictStrTuple = ()


class AuditRecord(BaseModel):
    """Tamper-evident JSONL audit record supporting write-ahead intent and completion."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = SCHEMA_VERSION
    audit_stage: Literal["intent", "completed"] = "completed"
    incident_id: str
    recorded_at_utc: str
    controller_mode: str
    diagnosis: DiagnosisResult
    evaluated_proposals: tuple[ActionProposal, ...]
    policy_decisions: tuple[PolicyDecision, ...]
    selected_proposal: ActionProposal | None = None
    capability_id: str | None = None
    execution_result: ExecutionResult | None = None
    verification_report: VerificationReport | None = None
    abstained: bool = False
    escalated: bool = False
    prev_record_hash: str = GENESIS_RECORD_HASH
    record_hash: str = ""
