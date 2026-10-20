"""Immutable domain schemas for GateHeal."""

from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


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

    INSPECT_SERVICE_STATUS = "inspect_service_status"
    VALIDATE_SERVICE_CONFIG = "validate_service_config"
    CHECK_DEPENDENCY_HEALTH = "check_dependency_health"
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
    INVALID_CONFIG = "invalid_config"
    DEPENDENCY_FAILURE = "dependency_failure"
    PERSISTENT_FAILURE = "persistent_failure"
    UNKNOWN = "unknown"


class PolicyRejectionCode(StrEnum):
    """Deterministic rejection codes emitted by the independent PolicyEngine."""

    ERR_UNREGISTERED_ACTION = "ERR_UNREGISTERED_ACTION"
    ERR_UNAUTHORIZED_TARGET = "ERR_UNAUTHORIZED_TARGET"
    ERR_MALFORMED_ARGUMENTS = "ERR_MALFORMED_ARGUMENTS"
    ERR_PRECONDITION_FAILED = "ERR_PRECONDITION_FAILED"
    ERR_INSUFFICIENT_PERMISSION = "ERR_INSUFFICIENT_PERMISSION"
    ERR_UPSTREAM_DEPENDENCY_UNHEALTHY = "ERR_UPSTREAM_DEPENDENCY_UNHEALTHY"
    ERR_TIME_BUDGET_EXCEEDED = "ERR_TIME_BUDGET_EXCEEDED"
    ERR_RETRY_LIMIT_EXHAUSTED = "ERR_RETRY_LIMIT_EXHAUSTED"
    ERR_IMPACT_TIER_EXCEEDED = "ERR_IMPACT_TIER_EXCEEDED"
    ERR_HUMAN_APPROVAL_REQUIRED = "ERR_HUMAN_APPROVAL_REQUIRED"
    ERR_INSUFFICIENT_EVIDENCE = "ERR_INSUFFICIENT_EVIDENCE"


class VerificationStatus(StrEnum):
    """Independent post-action recovery verification outcomes."""

    RECOVERED_CLEAN = "recovered_clean"
    RECOVERED_WITH_COLLATERAL_FAILURE = "recovered_with_collateral_failure"
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
    sanitized_logs: StrictStrTuple = ()


class IncidentRecord(BaseModel):
    """Structured incident context collected from the isolated lab environment."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    incident_id: str
    target_unit: str
    collected_at_utc: str
    services: dict[str, ServiceEvidence]
    prior_diagnostic_attempts: Annotated[int, Field(ge=0)] = 0
    prior_recovery_attempts: Annotated[int, Field(ge=0)] = 0
    action_history: StrictStrTuple = ()
    elapsed_sec: Annotated[float, Field(ge=0.0)] = 0.0


class DiagnosisResult(BaseModel):
    """Deterministic or statistical diagnosis output separated from action selection."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    fault_class: FaultClass
    primary_suspect_unit: str
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    evidence_refs: StrictStrTuple = ()
    summary: str


class ActionProposal(BaseModel):
    """Candidate action proposal evaluated by the PolicyEngine."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    action_id: str
    target_unit: str | None = None
    parameters: dict[str, str] = Field(default_factory=dict)
    inferred_fault: FaultClass = FaultClass.UNKNOWN
    evidence_confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    rationale: Annotated[str, Field(min_length=3, max_length=1000)]
    human_approved: bool = False


class PolicyDecision(BaseModel):
    """Deterministic authorization decision produced by the PolicyEngine."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    approved: bool
    action_id: str
    target_unit: str | None = None
    rejection_codes: tuple[PolicyRejectionCode, ...] = ()
    notes: StrictStrTuple = ()


class ExecutionResult(BaseModel):
    """Bounded subprocess execution record (exit code 0 never implies recovery)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    action_id: ActionId
    target_unit: str | None = None
    argv: StrictStrTuple
    exit_code: int
    timed_out: bool = False
    duration_sec: Annotated[float, Field(ge=0.0)]
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""


class VerificationReport(BaseModel):
    """Independent outcome verification report checking target and dependent units."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    status: VerificationStatus
    target_unit: str
    target_healthy: bool
    soak_duration_sec: Annotated[float, Field(ge=0.0)]
    collateral_failures: StrictStrTuple = ()
    details: str


class AuditRecord(BaseModel):
    """Structured JSONL audit record for experimental reproducibility."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    incident_id: str
    recorded_at_utc: str
    controller_mode: str
    diagnosis: DiagnosisResult
    evaluated_proposals: tuple[ActionProposal, ...]
    policy_decisions: tuple[PolicyDecision, ...]
    selected_proposal: ActionProposal | None = None
    execution_result: ExecutionResult | None = None
    verification_report: VerificationReport | None = None
    abstained: bool = False
