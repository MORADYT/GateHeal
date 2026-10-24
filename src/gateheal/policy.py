"""Independent safety policy gate, capability authority, and minimal-impact selector.

Prototype Note: In this single-process prototype, the operator HMAC key loaded via
GATEHEAL_APPROVAL_KEY_FILE or GATEHEAL_APPROVAL_HMAC_KEY resides in the same OS
process memory space as PolicyEngine and ExecutionController.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from collections import deque
from collections.abc import Callable, Mapping, Sequence, Set
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict, ValidationError

from gateheal.actions import DEFAULT_ACTION_CATALOGUE, UNIT_NAME_RE, ActionSpec
from gateheal.config import GateHealConfig
from gateheal.diagnosis import DiagnosisEngine
from gateheal.models import (
    ActionId,
    ActionProposal,
    ApprovalToken,
    AuthorizedActionCapability,
    DiagnosisResult,
    FaultClass,
    ImpactTier,
    IncidentRecord,
    PermissionTier,
    PolicyDecision,
    PolicyRejectionCode,
    ServiceEvidence,
)

MIN_HMAC_KEY_BYTES = 32
DEFAULT_CAPABILITY_TTL_SEC = 60.0

DEFAULT_GRANTED_PERMISSIONS: frozenset[PermissionTier] = frozenset(
    {
        PermissionTier.READ_ONLY,
        PermissionTier.SERVICE_OPERATOR,
        PermissionTier.HUMAN_ESCALATION,
    }
)

READ_ONLY_DIAGNOSTIC_ACTIONS: frozenset[ActionId] = frozenset(
    {
        ActionId.INSPECT_SERVICE_STATUS,
        ActionId.VALIDATE_SERVICE_CONFIG,
        ActionId.CHECK_DEPENDENCY_HEALTH,
    }
)

FAULT_ACTION_COMPATIBILITY: Mapping[FaultClass, frozenset[ActionId]] = MappingProxyType(
    {
        FaultClass.HEALTHY: frozenset({ActionId.NO_OP}),
        FaultClass.UNKNOWN: READ_ONLY_DIAGNOSTIC_ACTIONS
        | frozenset({ActionId.ABSTAIN_AND_ESCALATE}),
        FaultClass.PERSISTENT_FAILURE: frozenset({ActionId.ABSTAIN_AND_ESCALATE}),
        FaultClass.PROCESS_CRASH: READ_ONLY_DIAGNOSTIC_ACTIONS
        | frozenset({ActionId.RESTART_SERVICE, ActionId.ABSTAIN_AND_ESCALATE}),
        FaultClass.DEGRADED_RUNNING: READ_ONLY_DIAGNOSTIC_ACTIONS
        | frozenset(
            {
                ActionId.RELOAD_SERVICE,
                ActionId.RESTART_SERVICE,
                ActionId.ABSTAIN_AND_ESCALATE,
            }
        ),
        FaultClass.INVALID_CONFIG: READ_ONLY_DIAGNOSTIC_ACTIONS
        | frozenset(
            {
                ActionId.RESTORE_LAST_KNOWN_GOOD_CONFIG,
                ActionId.ABSTAIN_AND_ESCALATE,
            }
        ),
        FaultClass.DEPENDENCY_FAILURE: READ_ONLY_DIAGNOSTIC_ACTIONS
        | frozenset(
            {
                ActionId.RELOAD_SERVICE,
                ActionId.RESTART_SERVICE,
                ActionId.ABSTAIN_AND_ESCALATE,
            }
        ),
    }
)


class EffectiveActionImpact(BaseModel):
    """Single-source effective tier and blast-radius computation for an action."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    base_tier: ImpactTier
    effective_tier: ImpactTier
    healthy_dependents: tuple[str, ...] = ()
    blast_radius_weight: float = 0.0
    blast_radius_exceeded: bool = False
    exceeds_impact_ceiling: bool = False
    requires_approval_token: bool = False


def is_unit_currently_healthy(ev: ServiceEvidence | None) -> bool:
    """Return True iff the unit is active, running, and passing its health probe."""
    return bool(
        ev is not None
        and ev.active_state == "active"
        and ev.sub_state == "running"
        and ev.health_probe_ok
    )


def collect_transitive_downstream_dependents(
    config: GateHealConfig,
    root_unit: str,
) -> tuple[str, ...]:
    """Return sorted tuple of all transitive downstream dependents (excluding root_unit)."""
    visited: set[str] = {root_unit}
    dependents: set[str] = set()
    queue: deque[str] = deque([root_unit])
    services_cfg = config.inventory.services

    while queue:
        current = queue.popleft()
        cfg_item = services_cfg.get(current)
        if cfg_item is None:
            continue
        for dep in cfg_item.downstream_dependents:
            if dep not in visited:
                visited.add(dep)
                dependents.add(dep)
                queue.append(dep)
    return tuple(sorted(dependents))


def compute_effective_impact_and_blast_radius(
    proposal: ActionProposal,
    incident: IncidentRecord,
    config: GateHealConfig,
    spec: ActionSpec,
) -> EffectiveActionImpact:
    """Compute effective impact tier, healthy-path blast radius, and token requirement."""
    base_tier = spec.impact_tier
    target_unit = proposal.target_unit
    services_cfg = config.inventory.services

    healthy_deps: list[str] = []
    blast_weight = 0.0

    if (
        spec.action_id == ActionId.RESTART_SERVICE
        and target_unit is not None
        and target_unit in services_cfg
    ):
        target_ev = incident.services.get(target_unit)
        if target_ev is not None and target_ev.active_state == "active":
            visited: set[str] = {target_unit}
            queue: deque[str] = deque()
            for direct_dep in services_cfg[target_unit].downstream_dependents:
                if direct_dep not in visited:
                    visited.add(direct_dep)
                    queue.append(direct_dep)

            while queue:
                curr = queue.popleft()
                curr_ev = incident.services.get(curr)
                if not is_unit_currently_healthy(curr_ev):
                    continue
                healthy_deps.append(curr)
                curr_cfg = services_cfg.get(curr)
                if curr_cfg is not None:
                    blast_weight += curr_cfg.criticality_weight
                    for next_dep in curr_cfg.downstream_dependents:
                        if next_dep not in visited:
                            visited.add(next_dep)
                            queue.append(next_dep)

    healthy_deps_tuple = tuple(sorted(healthy_deps))
    blast_exceeded = (
        blast_weight > config.platform.max_unapproved_blast_radius_weight
    )
    effective_tier = (
        ImpactTier(max(int(base_tier), int(ImpactTier.SHARED_OR_CASCADE_RESTART)))
        if blast_exceeded
        else base_tier
    )
    exceeds_ceiling = (
        int(effective_tier) > config.platform.max_allowed_impact_tier
    )
    requires_token = (
        spec.requires_human_approval or blast_exceeded or exceeds_ceiling
    )

    return EffectiveActionImpact(
        base_tier=base_tier,
        effective_tier=effective_tier,
        healthy_dependents=healthy_deps_tuple,
        blast_radius_weight=blast_weight,
        blast_radius_exceeded=blast_exceeded,
        exceeds_impact_ceiling=exceeds_ceiling,
        requires_approval_token=requires_token,
    )


def _check_fault_action_compatibility(
    action_enum: ActionId,
    target_unit: str | None,
    diag: DiagnosisResult,
    incident: IncidentRecord,
) -> tuple[bool, str]:
    """Verify whether (action_enum, target_unit) is compatible with diag.fault_class."""
    allowed_set = FAULT_ACTION_COMPATIBILITY.get(diag.fault_class, frozenset())
    if action_enum not in allowed_set:
        return (
            False,
            f"Action {action_enum.value!r} is incompatible with authoritative "
            f"diagnosis fault_class={diag.fault_class.value!r}.",
        )

    if action_enum == ActionId.NO_OP:
        if target_unit not in (None, incident.target_unit):
            return (
                False,
                f"no_op target_unit {target_unit!r} must match incident target "
                f"{incident.target_unit!r} or be None.",
            )
        return True, ""

    if action_enum in (
        ActionId.RELOAD_SERVICE,
        ActionId.RESTART_SERVICE,
        ActionId.RESTORE_LAST_KNOWN_GOOD_CONFIG,
    ):
        if target_unit != diag.primary_suspect_unit:
            return (
                False,
                f"Mutating action {action_enum.value!r} targets {target_unit!r}, "
                f"but authoritative primary_suspect_unit is {diag.primary_suspect_unit!r}.",
            )

    return True, ""


def load_operator_hmac_key(
    key_env_var: str = "GATEHEAL_APPROVAL_HMAC_KEY",
    key_file_env_var: str = "GATEHEAL_APPROVAL_KEY_FILE",
) -> bytes | None:
    """Load the operator HMAC secret key from a file or environment variable."""
    key_file = os.environ.get(key_file_env_var)
    if key_file:
        path = Path(key_file)
        if path.is_file():
            raw = path.read_text(encoding="utf-8").strip()
            if raw:
                return raw.encode("utf-8")
    raw_env = os.environ.get(key_env_var, "").strip()
    if raw_env:
        return raw_env.encode("utf-8")
    return None


def _collect_target_and_dependents(
    config: GateHealConfig,
    root_unit: str,
) -> tuple[str, ...]:
    """Return sorted tuple of root_unit and its transitive downstream_dependents."""
    return tuple(
        sorted({root_unit, *collect_transitive_downstream_dependents(config, root_unit)})
    )


def compute_incident_state_hash(
    incident: IncidentRecord,
    config: GateHealConfig,
    target_unit: str | None = None,
) -> str:
    """Compute SHA-256 hash over decision-relevant fields of target and dependents."""
    root_unit = target_unit or incident.target_unit
    relevant_units = _collect_target_and_dependents(config, root_unit)
    unit_states: dict[str, dict[str, object] | None] = {}

    for unit in relevant_units:
        ev = incident.services.get(unit)
        if ev is None:
            unit_states[unit] = None
        else:
            unit_states[unit] = {
                "active_state": ev.active_state,
                "config_valid": ev.config_valid,
                "health_probe_ok": ev.health_probe_ok,
                "n_restarts": ev.n_restarts,
                "sub_state": ev.sub_state,
            }

    canonical_payload = json.dumps(
        {
            "incident_id": incident.incident_id,
            "target_unit": root_unit,
            "unit_states": unit_states,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical_payload).hexdigest()


def _compute_token_hmac(
    *,
    token_id: str,
    incident_id: str,
    action_id: str,
    target_unit: str | None,
    state_hash: str,
    expires_at_utc: str,
    hmac_key: bytes,
) -> str:
    signing_bytes = json.dumps(
        {
            "action_id": action_id,
            "expires_at_utc": expires_at_utc,
            "incident_id": incident_id,
            "state_hash": state_hash,
            "target_unit": target_unit,
            "token_id": token_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(hmac_key, signing_bytes, hashlib.sha256).hexdigest()


def _compute_proposal_decision_digest(
    proposal: ActionProposal,
    decision: PolicyDecision,
) -> str:
    canonical = json.dumps(
        {
            "decision": decision.model_dump(mode="json"),
            "proposal": proposal.model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _compute_capability_mac(
    *,
    capability_id: str,
    incident_id: str,
    action_id: str,
    target_unit: str | None,
    proposal: ActionProposal,
    decision: PolicyDecision,
    state_hash: str,
    requires_approval_token: bool,
    approval_token_id: str | None,
    issued_at_utc: str,
    expires_at_utc: str,
    secret_key: bytes,
) -> str:
    pd_digest = _compute_proposal_decision_digest(proposal, decision)
    signing_bytes = json.dumps(
        {
            "action_id": action_id,
            "approval_token_id": approval_token_id,
            "capability_id": capability_id,
            "expires_at_utc": expires_at_utc,
            "incident_id": incident_id,
            "issued_at_utc": issued_at_utc,
            "proposal_decision_digest": pd_digest,
            "requires_approval_token": requires_approval_token,
            "state_hash": state_hash,
            "target_unit": target_unit,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(secret_key, signing_bytes, hashlib.sha256).hexdigest()


def mint_approval_token(
    *,
    token_id: str,
    incident: IncidentRecord,
    config: GateHealConfig,
    action_id: str,
    target_unit: str | None,
    expires_at_utc: str,
    hmac_key: bytes,
) -> ApprovalToken:
    """Mint an out-of-band operator ApprovalToken bound to incident state."""
    if len(hmac_key) < MIN_HMAC_KEY_BYTES:
        raise ValueError(
            f"Operator HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes."
        )
    state_hash = compute_incident_state_hash(incident, config, target_unit)
    signature = _compute_token_hmac(
        token_id=token_id,
        incident_id=incident.incident_id,
        action_id=action_id,
        target_unit=target_unit,
        state_hash=state_hash,
        expires_at_utc=expires_at_utc,
        hmac_key=hmac_key,
    )
    return ApprovalToken(
        token_id=token_id,
        incident_id=incident.incident_id,
        action_id=action_id,
        target_unit=target_unit,
        state_hash=state_hash,
        expires_at_utc=expires_at_utc,
        hmac_signature=signature,
    )


def verify_approval_token(
    token: ApprovalToken,
    *,
    proposal: ActionProposal,
    incident: IncidentRecord,
    config: GateHealConfig,
    consumed_tokens: Set[str],
    hmac_key: bytes | None,
    clock_utc: Callable[[], datetime],
) -> tuple[bool, str]:
    """Verify an ApprovalToken without consuming it (side-effect free)."""
    if hmac_key is None:
        return False, "No operator HMAC key configured to verify ApprovalToken."

    if len(hmac_key) < MIN_HMAC_KEY_BYTES:
        return (
            False,
            f"Operator HMAC key is shorter than minimum {MIN_HMAC_KEY_BYTES} bytes.",
        )

    if token.token_id in consumed_tokens:
        return False, f"ApprovalToken {token.token_id!r} has already been consumed."

    if token.incident_id != incident.incident_id:
        return False, "ApprovalToken incident_id does not match current incident."

    if token.action_id != proposal.action_id or token.target_unit != proposal.target_unit:
        return False, "ApprovalToken action_id or target_unit mismatch."

    expected_state_hash = compute_incident_state_hash(
        incident, config, proposal.target_unit
    )
    if not hmac.compare_digest(token.state_hash, expected_state_hash):
        return False, "ApprovalToken state_hash mismatch (TOCTOU state change)."

    try:
        expires_dt = datetime.fromisoformat(token.expires_at_utc)
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=UTC)
    except ValueError:
        return False, "ApprovalToken expires_at_utc is not a valid ISO-8601 timestamp."

    if expires_dt <= clock_utc():
        return False, "ApprovalToken has expired according to controller clock."

    expected_sig = _compute_token_hmac(
        token_id=token.token_id,
        incident_id=token.incident_id,
        action_id=token.action_id,
        target_unit=token.target_unit,
        state_hash=token.state_hash,
        expires_at_utc=token.expires_at_utc,
        hmac_key=hmac_key,
    )
    if not hmac.compare_digest(token.hmac_signature, expected_sig):
        return False, "ApprovalToken HMAC signature verification failed."

    return True, "ApprovalToken verified."


class PolicyEngine:
    """Deterministic Runtime Assurance gate and sole capability minting authority."""

    def __init__(
        self,
        config: GateHealConfig,
        catalogue: Mapping[ActionId, ActionSpec] | None = None,
        granted_permissions: frozenset[PermissionTier] | None = None,
        *,
        diagnosis_engine: DiagnosisEngine | None = None,
        consumed_tokens: set[str] | None = None,
        clock_utc: Callable[[], datetime] | None = None,
        hmac_key_loader: Callable[[], bytes | None] | None = None,
        capability_ttl_sec: float = DEFAULT_CAPABILITY_TTL_SEC,
    ) -> None:
        self._config = config
        self._catalogue: Mapping[ActionId, ActionSpec] = (
            DEFAULT_ACTION_CATALOGUE
            if catalogue is None
            else MappingProxyType(dict(catalogue))
        )
        self._granted_permissions: frozenset[PermissionTier] = (
            DEFAULT_GRANTED_PERMISSIONS
            if granted_permissions is None
            else frozenset(granted_permissions)
        )
        self._diagnosis_engine: DiagnosisEngine = (
            DiagnosisEngine(config)
            if diagnosis_engine is None
            else diagnosis_engine
        )
        self._consumed_tokens: set[str] = (
            set() if consumed_tokens is None else consumed_tokens
        )
        self._consumed_capabilities: set[str] = set()
        self.__capability_secret: bytes = os.urandom(32)
        self._capability_ttl_sec: float = capability_ttl_sec
        self._clock_utc: Callable[[], datetime] = (
            (lambda: datetime.now(UTC)) if clock_utc is None else clock_utc
        )
        self._hmac_key_loader: Callable[[], bytes | None] = (
            load_operator_hmac_key
            if hmac_key_loader is None
            else hmac_key_loader
        )

    @property
    def config(self) -> GateHealConfig:
        """Return the GateHealConfig bound to this policy engine."""
        return self._config

    @property
    def catalogue(self) -> Mapping[ActionId, ActionSpec]:
        """Return the immutable action catalogue used by this policy engine."""
        return self._catalogue

    @property
    def diagnosis_engine(self) -> DiagnosisEngine:
        """Return the DiagnosisEngine bound to this policy engine."""
        return self._diagnosis_engine

    @property
    def consumed_tokens_store(self) -> set[str]:
        """Return the shared consumed-token store for binding to ExecutionController."""
        return self._consumed_tokens

    def mint_capability(
        self,
        proposal: ActionProposal,
        incident: IncidentRecord,
        *,
        approval_token: ApprovalToken | None = None,
        ttl_sec: float | None = None,
    ) -> AuthorizedActionCapability:
        """Evaluate proposal and mint a single-use capability if and only if approved."""
        decision = self.evaluate(
            proposal, incident, approval_token=approval_token
        )
        if not decision.approved:
            codes = [c.value for c in decision.rejection_codes]
            raise PermissionError(
                f"PolicyEngine refused to mint capability for {proposal.action_id!r} "
                f"on {proposal.target_unit!r}: {codes}"
            )

        action_enum = ActionId(proposal.action_id)
        spec = self._catalogue[action_enum]
        if action_enum in (ActionId.NO_OP, ActionId.ABSTAIN_AND_ESCALATE):
            requires_tok = False
        else:
            impact = compute_effective_impact_and_blast_radius(
                proposal, incident, self._config, spec
            )
            requires_tok = impact.requires_approval_token

        tok_id = (
            approval_token.token_id
            if (requires_tok and approval_token is not None)
            else None
        )
        state_hash = compute_incident_state_hash(
            incident, self._config, proposal.target_unit
        )
        cap_id = f"cap-{uuid.uuid4().hex}"
        now_dt = self._clock_utc()
        issued_at = now_dt.isoformat()
        effective_ttl = self._capability_ttl_sec if ttl_sec is None else ttl_sec
        expires_at = (now_dt + timedelta(seconds=effective_ttl)).isoformat()
        mac = _compute_capability_mac(
            capability_id=cap_id,
            incident_id=incident.incident_id,
            action_id=action_enum.value,
            target_unit=proposal.target_unit,
            proposal=proposal,
            decision=decision,
            state_hash=state_hash,
            requires_approval_token=requires_tok,
            approval_token_id=tok_id,
            issued_at_utc=issued_at,
            expires_at_utc=expires_at,
            secret_key=self.__capability_secret,
        )
        return AuthorizedActionCapability(
            capability_id=cap_id,
            incident_id=incident.incident_id,
            action_id=action_enum,
            target_unit=proposal.target_unit,
            proposal=proposal,
            decision=decision,
            state_hash=state_hash,
            requires_approval_token=requires_tok,
            approval_token_id=tok_id,
            issued_at_utc=issued_at,
            expires_at_utc=expires_at,
            mac_signature=mac,
        )

    def verify_and_consume_capability(
        self,
        capability: AuthorizedActionCapability,
        current_incident: IncidentRecord,
        *,
        approval_token: ApprovalToken | None = None,
    ) -> None:
        """Verify MAC, expiry, TOCTOU state hash, re-evaluate policy (R1-R3), and consume."""
        if not capability.decision.approved:
            raise PermissionError("Capability carries an unapproved PolicyDecision.")

        if capability.capability_id in self._consumed_capabilities:
            raise PermissionError(
                f"Capability {capability.capability_id!r} has already been consumed."
            )

        if (
            capability.proposal.action_id != capability.action_id.value
            or capability.proposal.target_unit != capability.target_unit
            or capability.decision.action_id != capability.action_id.value
            or capability.decision.target_unit != capability.target_unit
        ):
            raise PermissionError("Capability internal proposal/decision mismatch.")

        expected_mac = _compute_capability_mac(
            capability_id=capability.capability_id,
            incident_id=capability.incident_id,
            action_id=capability.action_id.value,
            target_unit=capability.target_unit,
            proposal=capability.proposal,
            decision=capability.decision,
            state_hash=capability.state_hash,
            requires_approval_token=capability.requires_approval_token,
            approval_token_id=capability.approval_token_id,
            issued_at_utc=capability.issued_at_utc,
            expires_at_utc=capability.expires_at_utc,
            secret_key=self.__capability_secret,
        )
        if not hmac.compare_digest(capability.mac_signature, expected_mac):
            raise PermissionError(
                "Capability MAC verification failed (untrusted or forged capability)."
            )

        try:
            expires_dt = datetime.fromisoformat(capability.expires_at_utc)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=UTC)
        except ValueError as exc:
            raise PermissionError(
                "Capability expires_at_utc is not a valid ISO-8601 timestamp."
            ) from exc

        if expires_dt <= self._clock_utc():
            raise PermissionError(
                "Capability has expired according to controller clock."
            )

        if capability.incident_id != current_incident.incident_id:
            raise PermissionError(
                "Capability incident_id does not match current_incident."
            )

        current_state_hash = compute_incident_state_hash(
            current_incident, self._config, capability.target_unit
        )
        if not hmac.compare_digest(capability.state_hash, current_state_hash):
            raise PermissionError(
                "TOCTOU state_hash mismatch between capability issuance and execution."
            )

        # R1-R3: Re-run full PolicyEngine.evaluate() against current_incident at execution time
        recheck_decision = self.evaluate(
            capability.proposal,
            current_incident,
            approval_token=approval_token,
        )
        if not recheck_decision.approved:
            codes = [c.value for c in recheck_decision.rejection_codes]
            notes_str = "; ".join(recheck_decision.notes)
            raise PermissionError(
                f"Execution blocked by execution-time policy re-evaluation: "
                f"{codes} ({notes_str})"
            )

        if capability.requires_approval_token:
            if (
                approval_token is None
                or approval_token.token_id != capability.approval_token_id
            ):
                raise PermissionError(
                    f"Action {capability.action_id.value!r} requires matching "
                    "ApprovalToken at execution time."
                )
            ok, msg = verify_approval_token(
                approval_token,
                proposal=capability.proposal,
                incident=current_incident,
                config=self._config,
                consumed_tokens=self._consumed_tokens,
                hmac_key=self._hmac_key_loader(),
                clock_utc=self._clock_utc,
            )
            if not ok:
                raise PermissionError(f"Execution blocked by token verification: {msg}")
            self._consumed_tokens.add(approval_token.token_id)

        self._consumed_capabilities.add(capability.capability_id)

    def evaluate_raw(
        self,
        raw_payload: Mapping[str, object] | str,
        incident: IncidentRecord,
        *,
        approval_token: ApprovalToken | None = None,
    ) -> PolicyDecision:
        """Validate an untrusted dict or JSON string payload and evaluate policy."""
        try:
            json_str = (
                raw_payload
                if isinstance(raw_payload, str)
                else json.dumps(raw_payload)
            )
            proposal = ActionProposal.model_validate_json(json_str)
        except (ValidationError, TypeError, ValueError) as exc:
            if isinstance(raw_payload, Mapping):
                raw_action = str(raw_payload.get("action_id", "<malformed>"))
                raw_target = (
                    str(raw_payload["target_unit"])
                    if isinstance(raw_payload.get("target_unit"), str)
                    else None
                )
            else:
                raw_action = "<malformed>"
                raw_target = None
            return PolicyDecision(
                approved=False,
                action_id=raw_action,
                target_unit=raw_target,
                rejection_codes=(PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS,),
                notes=(f"Schema validation failed: {exc}",),
            )
        return self.evaluate(proposal, incident, approval_token=approval_token)

    def evaluate(
        self,
        proposal: ActionProposal,
        incident: IncidentRecord,
        *,
        approval_token: ApprovalToken | None = None,
    ) -> PolicyDecision:
        """Deterministically evaluate all safety policy invariants (side-effect free)."""
        rejections: list[PolicyRejectionCode] = []
        notes: list[str] = []

        diag = self._diagnosis_engine.diagnose(incident)
        if proposal.inferred_fault != diag.fault_class:
            notes.append(
                f"AUDIT_SIGNAL: proposer inferred_fault={proposal.inferred_fault.value!r} "
                f"mismatched authoritative diagnosis={diag.fault_class.value!r}."
            )

        # 1. Catalogue membership and enabled check
        try:
            action_enum = ActionId(proposal.action_id)
        except ValueError:
            return PolicyDecision(
                approved=False,
                action_id=proposal.action_id,
                target_unit=proposal.target_unit,
                rejection_codes=(PolicyRejectionCode.ERR_UNREGISTERED_ACTION,),
                notes=(
                    *notes,
                    f"Action {proposal.action_id!r} is not in the registered catalogue.",
                ),
            )

        spec = self._catalogue.get(action_enum)
        if spec is None:
            return PolicyDecision(
                approved=False,
                action_id=proposal.action_id,
                target_unit=proposal.target_unit,
                rejection_codes=(PolicyRejectionCode.ERR_UNREGISTERED_ACTION,),
                notes=(
                    *notes,
                    f"Action {proposal.action_id!r} is not present in active catalogue.",
                ),
            )

        if not spec.enabled:
            rejections.append(PolicyRejectionCode.ERR_ACTION_DISABLED)
            notes.append(
                f"Action {proposal.action_id!r} is disabled in active catalogue."
            )

        # 2. Target format and inventory authorization check
        target_unit = proposal.target_unit
        if spec.requires_target_unit:
            if target_unit is None or not UNIT_NAME_RE.fullmatch(target_unit):
                rejections.append(PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS)
                notes.append(f"Target unit {target_unit!r} failed strict unit regex check.")
            elif target_unit not in self._config.inventory.services:
                rejections.append(PolicyRejectionCode.ERR_UNAUTHORIZED_TARGET)
                notes.append(f"Target unit {target_unit!r} is not in approved inventory.")
        elif target_unit is not None and not UNIT_NAME_RE.fullmatch(target_unit):
            rejections.append(PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS)
            notes.append(f"Target unit {target_unit!r} failed strict unit regex check.")

        # 3. Allowed parameter schema check
        unexpected_keys = set(proposal.parameters.keys()) - set(spec.allowed_parameter_keys)
        if unexpected_keys:
            rejections.append(PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS)
            notes.append(f"Disallowed parameter keys: {sorted(unexpected_keys)}.")

        # 4. Permission check
        if spec.required_permission not in self._granted_permissions:
            rejections.append(PolicyRejectionCode.ERR_INSUFFICIENT_PERMISSION)
            notes.append(f"Missing required permission: {spec.required_permission}.")

        # 5. Fault-to-Action Compatibility Matrix check
        compat_ok, compat_msg = _check_fault_action_compatibility(
            action_enum, target_unit, diag, incident
        )
        if not compat_ok:
            rejections.append(PolicyRejectionCode.ERR_INCOMPATIBLE_FAULT_ACTION)
            notes.append(compat_msg)

        # Fast return for terminal non-mutating NO_OP or ABSTAIN_AND_ESCALATE
        if action_enum in (ActionId.NO_OP, ActionId.ABSTAIN_AND_ESCALATE):
            if not rejections:
                notes.append(f"{action_enum.value} is permitted for {diag.fault_class.value}.")
            return PolicyDecision(
                approved=len(rejections) == 0,
                action_id=proposal.action_id,
                target_unit=proposal.target_unit,
                rejection_codes=tuple(dict.fromkeys(rejections)),
                notes=tuple(notes),
            )

        # 6. Single-source effective impact tier, blast-radius, and ApprovalToken gate
        impact = compute_effective_impact_and_blast_radius(
            proposal, incident, self._config, spec
        )
        max_tier = self._config.platform.max_allowed_impact_tier

        if impact.requires_approval_token:
            if approval_token is None:
                if impact.blast_radius_exceeded:
                    rejections.append(PolicyRejectionCode.ERR_BLAST_RADIUS_EXCEEDED)
                    notes.append(
                        f"Blast radius weight {impact.blast_radius_weight:.2f} "
                        f"across healthy dependents {list(impact.healthy_dependents)} "
                        "exceeds unapproved ceiling "
                        f"{self._config.platform.max_unapproved_blast_radius_weight:.2f}."
                    )
                if spec.requires_human_approval or impact.blast_radius_exceeded:
                    rejections.append(PolicyRejectionCode.ERR_HUMAN_APPROVAL_REQUIRED)
                    notes.append(
                        "Action requires a valid out-of-band operator ApprovalToken."
                    )
                if impact.exceeds_impact_ceiling:
                    rejections.append(PolicyRejectionCode.ERR_IMPACT_TIER_EXCEEDED)
                    notes.append(
                        f"Effective impact tier {int(impact.effective_tier)} "
                        f"exceeds ceiling {max_tier}."
                    )
            else:
                token_valid, token_msg = verify_approval_token(
                    approval_token,
                    proposal=proposal,
                    incident=incident,
                    config=self._config,
                    consumed_tokens=self._consumed_tokens,
                    hmac_key=self._hmac_key_loader(),
                    clock_utc=self._clock_utc,
                )
                if not token_valid:
                    rejections.append(PolicyRejectionCode.ERR_INVALID_APPROVAL_TOKEN)
                    notes.append(token_msg)
                    if impact.blast_radius_exceeded:
                        rejections.append(PolicyRejectionCode.ERR_BLAST_RADIUS_EXCEEDED)
                    if spec.requires_human_approval or impact.blast_radius_exceeded:
                        rejections.append(PolicyRejectionCode.ERR_HUMAN_APPROVAL_REQUIRED)
                    if impact.exceeds_impact_ceiling:
                        rejections.append(PolicyRejectionCode.ERR_IMPACT_TIER_EXCEEDED)
                else:
                    if impact.blast_radius_exceeded or impact.exceeds_impact_ceiling:
                        notes.append(
                            "BREAK_GLASS_OVERRIDE: valid ApprovalToken authorized "
                            f"effective_tier={int(impact.effective_tier)} "
                            f"(blast_radius_weight={impact.blast_radius_weight:.2f}, "
                            f"max_allowed_impact_tier={max_tier})."
                        )

        # 7. Time budget check
        remaining_sec = (
            self._config.budgets.total_incident_timeout_sec - incident.elapsed_sec
        )
        effective_timeout = min(
            spec.timeout_sec, self._config.budgets.per_action_timeout_sec
        )
        if effective_timeout > remaining_sec:
            rejections.append(PolicyRejectionCode.ERR_TIME_BUDGET_EXCEEDED)
            notes.append(
                f"Action timeout ({effective_timeout:.1f}s) exceeds remaining budget "
                f"({remaining_sec:.1f}s)."
            )

        # 8. Retry, cooldown (R6 mutated-unit aware), and flap budget checks
        is_mutating = spec.impact_tier >= ImpactTier.GRACEFUL_RELOAD_OR_RESTORE
        if is_mutating:
            if incident.prior_recovery_attempts >= self._config.budgets.max_recovery_attempts:
                rejections.append(PolicyRejectionCode.ERR_RETRY_LIMIT_EXHAUSTED)
                notes.append("Maximum incident recovery attempts exhausted.")

            cooldown_sec = self._config.budgets.cooldown_sec
            mutated_unit_age = (
                incident.unit_cooldown_age_sec.get(target_unit)
                if target_unit is not None
                else None
            )
            effective_age = (
                mutated_unit_age
                if mutated_unit_age is not None
                else (
                    incident.last_mutating_action_age_sec
                    if target_unit in (None, incident.target_unit)
                    else None
                )
            )
            if effective_age is not None and effective_age < cooldown_sec:
                rejections.append(PolicyRejectionCode.ERR_COOLDOWN_ACTIVE)
                notes.append(
                    f"Cooldown active for {target_unit}: last mutation was "
                    f"{effective_age:.1f}s ago (< {cooldown_sec:.1f}s)."
                )

            flap_max = self._config.budgets.flap_max_restarts
            mutated_flap_count = (
                incident.unit_flap_counts.get(target_unit)
                if target_unit is not None
                else None
            )
            effective_flaps = (
                mutated_flap_count
                if mutated_flap_count is not None
                else (
                    incident.recent_mutations_in_flap_window
                    if target_unit in (None, incident.target_unit)
                    else 0
                )
            )
            if effective_flaps >= flap_max:
                rejections.append(PolicyRejectionCode.ERR_FLAPPING_DETECTED)
                notes.append(
                    f"Flapping detected for {target_unit}: "
                    f"{effective_flaps} mutations within "
                    f"flap_window_sec ({self._config.budgets.flap_window_sec:.1f}s)."
                )
        else:
            if incident.prior_diagnostic_attempts >= self._config.budgets.max_diagnostic_attempts:
                rejections.append(PolicyRejectionCode.ERR_RETRY_LIMIT_EXHAUSTED)
                notes.append("Maximum incident diagnostic attempts exhausted.")

        action_key = f"{proposal.action_id}:{target_unit or ''}"
        prior_same_action = sum(1 for item in incident.action_history if item == action_key)
        if prior_same_action >= spec.max_retries_per_incident:
            if PolicyRejectionCode.ERR_RETRY_LIMIT_EXHAUSTED not in rejections:
                rejections.append(PolicyRejectionCode.ERR_RETRY_LIMIT_EXHAUSTED)
            notes.append(
                f"Action {action_key} reached per-incident limit "
                f"({spec.max_retries_per_incident})."
            )

        # 9. Authoritative DiagnosisEngine confidence threshold for mutating actions
        if is_mutating:
            min_conf = self._config.platform.min_confidence_for_mutation
            if diag.confidence < min_conf:
                rejections.append(PolicyRejectionCode.ERR_INSUFFICIENT_EVIDENCE)
                notes.append(
                    f"Authoritative diagnosis confidence {diag.confidence:.2f} is below "
                    f"threshold {min_conf:.2f} for mutating actions."
                )

        # 10 & 11. Target preconditions, fail-closed config check, and upstream dependencies
        if target_unit and target_unit in self._config.inventory.services:
            service_cfg = self._config.inventory.services[target_unit]
            target_ev = incident.services.get(target_unit)

            has_cfg_check = (
                service_cfg.config_check_mode == "argv"
                and bool(service_cfg.config_check_argv)
            )
            if action_enum == ActionId.VALIDATE_SERVICE_CONFIG and not has_cfg_check:
                rejections.append(PolicyRejectionCode.ERR_PRECONDITION_FAILED)
                notes.append(f"Unit {target_unit} has no configuration validation command.")

            if spec.requires_supports_reload:
                supports_reload = service_cfg.supports_reload and (
                    target_ev.can_reload if target_ev is not None else True
                )
                if not supports_reload:
                    rejections.append(PolicyRejectionCode.ERR_PRECONDITION_FAILED)
                    notes.append(f"Unit {target_unit} does not support graceful reload.")
                if target_ev is not None and target_ev.active_state != "active":
                    rejections.append(PolicyRejectionCode.ERR_PRECONDITION_FAILED)
                    notes.append(f"Cannot reload non-active unit {target_unit}.")

            if spec.requires_valid_config:
                if service_cfg.config_check_mode == "acknowledged_none":
                    if target_ev is not None and target_ev.config_valid is False:
                        rejections.append(PolicyRejectionCode.ERR_PRECONDITION_FAILED)
                        notes.append(
                            f"CONFIG_CHECK_INVALID: unit {target_unit} reported "
                            "config_valid=False."
                        )
                    else:
                        notes.append(
                            f"CONFIG_CHECK_ACKNOWLEDGED_NONE: unit {target_unit} "
                            "explicitly configured with config_check_mode='acknowledged_none'."
                        )
                else:
                    if target_ev is None or target_ev.config_valid is None:
                        rejections.append(PolicyRejectionCode.ERR_PRECONDITION_FAILED)
                        notes.append(
                            f"CONFIG_CHECK_UNKNOWN: validator for {target_unit} "
                            "timed out, errored, or did not run (config_valid=None); "
                            "failing closed."
                        )
                    elif target_ev.config_valid is False:
                        rejections.append(PolicyRejectionCode.ERR_PRECONDITION_FAILED)
                        notes.append(
                            f"CONFIG_CHECK_INVALID: unit {target_unit} failed "
                            "configuration validation (config_valid=False)."
                        )

            if spec.requires_healthy_upstream:
                for upstream_unit in service_cfg.upstream_dependencies:
                    up_ev = incident.services.get(upstream_unit)
                    if not is_unit_currently_healthy(up_ev):
                        rejections.append(PolicyRejectionCode.ERR_UPSTREAM_DEPENDENCY_UNHEALTHY)
                        notes.append(
                            f"Upstream dependency {upstream_unit} is unhealthy or unknown."
                        )

        return PolicyDecision(
            approved=len(rejections) == 0,
            action_id=proposal.action_id,
            target_unit=proposal.target_unit,
            rejection_codes=tuple(dict.fromkeys(rejections)),
            notes=tuple(notes),
        )


class MinimalImpactSelector:
    """Selects the least disruptive PolicyEngine-approved action or abstains."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        catalogue: Mapping[ActionId, ActionSpec] | None = None,
    ) -> None:
        self._policy = policy_engine
        self._catalogue: Mapping[ActionId, ActionSpec] = (
            policy_engine.catalogue
            if catalogue is None
            else MappingProxyType(dict(catalogue))
        )

    def select(
        self,
        candidates: Sequence[ActionProposal],
        incident: IncidentRecord,
        *,
        approval_token: ApprovalToken | None = None,
    ) -> tuple[ActionProposal, tuple[PolicyDecision, ...]]:
        """Evaluate all candidates and return the minimal-impact approved proposal."""
        decisions: list[PolicyDecision] = []
        approved_triples: list[
            tuple[ActionProposal, ActionSpec, EffectiveActionImpact]
        ] = []

        for proposal in candidates:
            decision = self._policy.evaluate(
                proposal, incident, approval_token=approval_token
            )
            decisions.append(decision)
            if decision.approved:
                spec = self._catalogue[ActionId(proposal.action_id)]
                impact = compute_effective_impact_and_blast_radius(
                    proposal, incident, self._policy.config, spec
                )
                approved_triples.append((proposal, spec, impact))

        active_approved = [
            triple
            for triple in approved_triples
            if triple[1].action_id != ActionId.ABSTAIN_AND_ESCALATE
        ]
        if active_approved:
            active_approved.sort(
                key=lambda triple: (
                    int(triple[2].effective_tier),
                    triple[2].blast_radius_weight,
                    0 if triple[1].reversible else 1,
                    triple[1].timeout_sec,
                    triple[1].action_id.value,
                    triple[0].target_unit or "",
                )
            )
            return active_approved[0][0], tuple(decisions)

        diag = self._policy.diagnosis_engine.diagnose(incident)
        if diag.fault_class == FaultClass.HEALTHY:
            noop_fallback = ActionProposal(
                action_id=ActionId.NO_OP.value,
                target_unit=incident.target_unit,
                inferred_fault=FaultClass.HEALTHY,
                rationale="Target service is healthy; no operation required.",
            )
            noop_decision = self._policy.evaluate(noop_fallback, incident)
            if noop_decision.approved:
                decisions.append(noop_decision)
                return noop_fallback, tuple(decisions)

        fallback = ActionProposal(
            action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
            target_unit=incident.target_unit,
            rationale="No candidate action satisfied all safety policy constraints; abstaining.",
        )
        fallback_decision = self._policy.evaluate(fallback, incident)
        decisions.append(fallback_decision)
        return fallback, tuple(decisions)
