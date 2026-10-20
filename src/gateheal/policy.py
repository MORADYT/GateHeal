"""Independent safety policy gate and minimal-impact action selector."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from pydantic import ValidationError

from gateheal.actions import DEFAULT_ACTION_CATALOGUE, UNIT_NAME_RE, ActionSpec
from gateheal.config import GateHealConfig
from gateheal.models import (
    ActionId,
    ActionProposal,
    ImpactTier,
    IncidentRecord,
    PermissionTier,
    PolicyDecision,
    PolicyRejectionCode,
)


class PolicyEngine:
    """Deterministic Runtime Assurance gate that validates every candidate action."""

    def __init__(
        self,
        config: GateHealConfig,
        catalogue: Mapping[ActionId, ActionSpec] | None = None,
        granted_permissions: frozenset[PermissionTier] | None = None,
    ) -> None:
        self._config = config
        self._catalogue = dict(catalogue or DEFAULT_ACTION_CATALOGUE)
        self._granted_permissions = granted_permissions or frozenset(
            {
                PermissionTier.READ_ONLY,
                PermissionTier.SERVICE_OPERATOR,
                PermissionTier.HUMAN_ESCALATION,
            }
        )

    def evaluate_raw(
        self,
        raw_payload: Mapping[str, object],
        incident: IncidentRecord,
    ) -> PolicyDecision:
        """Validate an untrusted dictionary payload and evaluate policy invariants."""
        try:
            proposal = ActionProposal.model_validate(raw_payload)
        except ValidationError as exc:
            raw_action = str(raw_payload.get("action_id", "<malformed>"))
            raw_target = (
                str(raw_payload["target_unit"])
                if isinstance(raw_payload.get("target_unit"), str)
                else None
            )
            return PolicyDecision(
                approved=False,
                action_id=raw_action,
                target_unit=raw_target,
                rejection_codes=(PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS,),
                notes=(f"Schema validation failed: {exc.error_count()} error(s).",),
            )
        return self.evaluate(proposal, incident)

    def evaluate(
        self,
        proposal: ActionProposal,
        incident: IncidentRecord,
    ) -> PolicyDecision:
        """Deterministically evaluate all 11 safety policy invariants."""
        rejections: list[PolicyRejectionCode] = []
        notes: list[str] = []

        # 1. Catalogue membership check
        try:
            action_enum = ActionId(proposal.action_id)
        except ValueError:
            return PolicyDecision(
                approved=False,
                action_id=proposal.action_id,
                target_unit=proposal.target_unit,
                rejection_codes=(PolicyRejectionCode.ERR_UNREGISTERED_ACTION,),
                notes=(f"Action {proposal.action_id!r} is not in the registered catalogue.",),
            )

        spec = self._catalogue.get(action_enum)
        if spec is None:
            return PolicyDecision(
                approved=False,
                action_id=proposal.action_id,
                target_unit=proposal.target_unit,
                rejection_codes=(PolicyRejectionCode.ERR_UNREGISTERED_ACTION,),
                notes=(f"Action {proposal.action_id!r} is disabled in active catalogue.",),
            )

        # Abstention is always safe and permitted if arguments are not malformed
        if action_enum == ActionId.ABSTAIN_AND_ESCALATE:
            if proposal.parameters:
                return PolicyDecision(
                    approved=False,
                    action_id=proposal.action_id,
                    target_unit=proposal.target_unit,
                    rejection_codes=(PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS,),
                    notes=("Abstention action does not accept parameters.",),
                )
            return PolicyDecision(
                approved=True,
                action_id=proposal.action_id,
                target_unit=proposal.target_unit,
                rejection_codes=(),
                notes=("Abstention is unconditionally safe.",),
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

        # 3. Allowed parameter schema check
        unexpected_keys = set(proposal.parameters.keys()) - set(spec.allowed_parameter_keys)
        if unexpected_keys:
            rejections.append(PolicyRejectionCode.ERR_MALFORMED_ARGUMENTS)
            notes.append(f"Disallowed parameter keys: {sorted(unexpected_keys)}.")

        # 4. Permission check
        if spec.required_permission not in self._granted_permissions:
            rejections.append(PolicyRejectionCode.ERR_INSUFFICIENT_PERMISSION)
            notes.append(f"Missing required permission: {spec.required_permission}.")

        # 5. Impact ceiling check
        if int(spec.impact_tier) > self._config.platform.max_allowed_impact_tier:
            rejections.append(PolicyRejectionCode.ERR_IMPACT_TIER_EXCEEDED)
            notes.append(
                f"Impact tier {int(spec.impact_tier)} exceeds ceiling "
                f"{self._config.platform.max_allowed_impact_tier}."
            )

        # 6. Human approval gate
        if spec.requires_human_approval and not proposal.human_approved:
            rejections.append(PolicyRejectionCode.ERR_HUMAN_APPROVAL_REQUIRED)
            notes.append("Action requires explicit human approval token.")

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

        # 8. Retry and attempt budget check
        is_mutating = spec.impact_tier >= ImpactTier.GRACEFUL_RELOAD_OR_RESTORE
        if is_mutating:
            if incident.prior_recovery_attempts >= self._config.budgets.max_recovery_attempts:
                rejections.append(PolicyRejectionCode.ERR_RETRY_LIMIT_EXHAUSTED)
                notes.append("Maximum incident recovery attempts exhausted.")
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

        # 9. Evidence confidence threshold for mutating actions
        if is_mutating:
            min_conf = self._config.platform.min_confidence_for_mutation
            if proposal.evidence_confidence < min_conf:
                rejections.append(PolicyRejectionCode.ERR_INSUFFICIENT_EVIDENCE)
                notes.append(
                    f"Evidence confidence {proposal.evidence_confidence:.2f} is below "
                    f"threshold {min_conf:.2f} for mutating actions."
                )

        # 10 & 11. Target preconditions and upstream dependency health checks
        if target_unit and target_unit in self._config.inventory.services:
            service_cfg = self._config.inventory.services[target_unit]
            target_ev = incident.services.get(target_unit)

            has_cfg_check = bool(service_cfg.config_check_argv)
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

            if spec.requires_valid_config and has_cfg_check:
                if target_ev is None or target_ev.config_valid is not True:
                    rejections.append(PolicyRejectionCode.ERR_PRECONDITION_FAILED)
                    notes.append(
                        f"Unit {target_unit} requires verified valid config before "
                        f"{proposal.action_id}."
                    )

            if spec.requires_healthy_upstream:
                for upstream_unit in service_cfg.upstream_dependencies:
                    up_ev = incident.services.get(upstream_unit)
                    if up_ev is None or up_ev.active_state != "active" or not up_ev.health_probe_ok:
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
        self._catalogue = dict(catalogue or DEFAULT_ACTION_CATALOGUE)

    def select(
        self,
        candidates: Sequence[ActionProposal],
        incident: IncidentRecord,
    ) -> tuple[ActionProposal, tuple[PolicyDecision, ...]]:
        """Evaluate all candidates and return the minimal-impact approved proposal."""
        decisions: list[PolicyDecision] = []
        approved_pairs: list[tuple[ActionProposal, ActionSpec]] = []

        for proposal in candidates:
            decision = self._policy.evaluate(proposal, incident)
            decisions.append(decision)
            if decision.approved:
                spec = self._catalogue[ActionId(proposal.action_id)]
                approved_pairs.append((proposal, spec))

        non_abstain = [
            pair
            for pair in approved_pairs
            if pair[1].action_id != ActionId.ABSTAIN_AND_ESCALATE
        ]
        if non_abstain:
            non_abstain.sort(
                key=lambda pair: (
                    int(pair[1].impact_tier),
                    0 if pair[1].reversible else 1,
                    pair[1].timeout_sec,
                    -pair[0].evidence_confidence,
                )
            )
            return non_abstain[0][0], tuple(decisions)

        fallback = ActionProposal(
            action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
            target_unit=incident.target_unit,
            evidence_confidence=1.0,
            rationale="No candidate action satisfied all safety policy constraints; abstaining.",
        )
        fallback_decision = self._policy.evaluate(fallback, incident)
        decisions.append(fallback_decision)
        return fallback, tuple(decisions)
