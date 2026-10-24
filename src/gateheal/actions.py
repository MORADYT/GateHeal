"""Predefined, typed recovery action catalogue with fixed argv builders."""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict, Field

from gateheal.config import ServiceInventoryItem
from gateheal.models import ActionId, ImpactTier, PermissionTier

UNIT_NAME_RE = re.compile(r"^[a-z0-9_-]+\.service$")


class ActionSpec(BaseModel):
    """Static metadata and safety rules for a registered recovery action."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    action_id: ActionId
    enabled: bool = True
    impact_tier: ImpactTier
    required_permission: PermissionTier
    requires_target_unit: bool = True
    allowed_parameter_keys: tuple[str, ...] = ()
    requires_valid_config: bool = False
    requires_supports_reload: bool = False
    requires_healthy_upstream: bool = False
    reversible: bool = True
    requires_human_approval: bool = False
    timeout_sec: float = Field(gt=0.0, default=10.0)
    max_retries_per_incident: int = Field(ge=1, default=1)
    description: str

    def build_argv(
        self,
        target_unit: str | None,
        service_spec: ServiceInventoryItem | None,
    ) -> tuple[str, ...]:
        """Construct a safe argument vector without shell interpolation."""
        if self.action_id in (ActionId.NO_OP, ActionId.ABSTAIN_AND_ESCALATE):
            return ()

        if not self.enabled:
            raise ValueError(f"Action {self.action_id} is disabled and has no argv.")

        if target_unit is None or not UNIT_NAME_RE.fullmatch(target_unit):
            raise ValueError(f"Invalid or missing systemd unit name: {target_unit!r}")

        if self.action_id == ActionId.INSPECT_SERVICE_STATUS:
            return (
                "systemctl",
                "show",
                target_unit,
                "--property=ActiveState,SubState,Result,NRestarts,CanReload",
            )

        if self.action_id == ActionId.VALIDATE_SERVICE_CONFIG:
            if service_spec is None or not service_spec.config_check_argv:
                raise ValueError(f"Unit {target_unit} has no registered config_check_argv.")
            return service_spec.config_check_argv

        if self.action_id == ActionId.CHECK_DEPENDENCY_HEALTH:
            return (
                "systemctl",
                "is-active",
                target_unit,
            )

        if self.action_id == ActionId.RELOAD_SERVICE:
            return ("sudo", "-n", "/usr/bin/systemctl", "reload", target_unit)

        if self.action_id == ActionId.RESTART_SERVICE:
            return ("sudo", "-n", "/usr/bin/systemctl", "restart", target_unit)

        raise ValueError(f"Unsupported action_id: {self.action_id}")


_CATALOGUE_ENTRIES: dict[ActionId, ActionSpec] = {
    ActionId.NO_OP: ActionSpec(
        action_id=ActionId.NO_OP,
        enabled=True,
        impact_tier=ImpactTier.READ_ONLY_DIAGNOSTIC,
        required_permission=PermissionTier.READ_ONLY,
        requires_target_unit=False,
        reversible=True,
        timeout_sec=1.0,
        max_retries_per_incident=5,
        description="Explicit no-operation when target service is verified healthy.",
    ),
    ActionId.INSPECT_SERVICE_STATUS: ActionSpec(
        action_id=ActionId.INSPECT_SERVICE_STATUS,
        enabled=True,
        impact_tier=ImpactTier.READ_ONLY_DIAGNOSTIC,
        required_permission=PermissionTier.READ_ONLY,
        requires_target_unit=True,
        reversible=True,
        timeout_sec=5.0,
        max_retries_per_incident=3,
        description="Read structured systemd unit properties without mutating state.",
    ),
    ActionId.VALIDATE_SERVICE_CONFIG: ActionSpec(
        action_id=ActionId.VALIDATE_SERVICE_CONFIG,
        enabled=True,
        impact_tier=ImpactTier.READ_ONLY_DIAGNOSTIC,
        required_permission=PermissionTier.READ_ONLY,
        requires_target_unit=True,
        reversible=True,
        timeout_sec=5.0,
        max_retries_per_incident=2,
        description="Run the service's registered read-only configuration validator.",
    ),
    ActionId.CHECK_DEPENDENCY_HEALTH: ActionSpec(
        action_id=ActionId.CHECK_DEPENDENCY_HEALTH,
        enabled=True,
        impact_tier=ImpactTier.READ_ONLY_DIAGNOSTIC,
        required_permission=PermissionTier.READ_ONLY,
        requires_target_unit=True,
        reversible=True,
        timeout_sec=5.0,
        max_retries_per_incident=3,
        description="Check whether a declared upstream dependency unit is active.",
    ),
    ActionId.RESTORE_LAST_KNOWN_GOOD_CONFIG: ActionSpec(
        action_id=ActionId.RESTORE_LAST_KNOWN_GOOD_CONFIG,
        enabled=False,
        impact_tier=ImpactTier.GRACEFUL_RELOAD_OR_RESTORE,
        required_permission=PermissionTier.SERVICE_OPERATOR,
        requires_target_unit=True,
        reversible=True,
        timeout_sec=5.0,
        max_retries_per_incident=1,
        description="Disabled until atomic hash-verified file restore executor exists.",
    ),
    ActionId.RELOAD_SERVICE: ActionSpec(
        action_id=ActionId.RELOAD_SERVICE,
        enabled=True,
        impact_tier=ImpactTier.GRACEFUL_RELOAD_OR_RESTORE,
        required_permission=PermissionTier.SERVICE_OPERATOR,
        requires_target_unit=True,
        requires_valid_config=True,
        requires_supports_reload=True,
        requires_healthy_upstream=True,
        reversible=True,
        timeout_sec=8.0,
        max_retries_per_incident=1,
        description="Gracefully reload service configuration in place without dropping PID.",
    ),
    ActionId.RESTART_SERVICE: ActionSpec(
        action_id=ActionId.RESTART_SERVICE,
        enabled=True,
        impact_tier=ImpactTier.TARGETED_RESTART,
        required_permission=PermissionTier.SERVICE_OPERATOR,
        requires_target_unit=True,
        requires_valid_config=True,
        requires_healthy_upstream=True,
        reversible=False,
        timeout_sec=10.0,
        max_retries_per_incident=1,
        description="Restart a specific systemd service after verifying config and dependencies.",
    ),
    ActionId.ABSTAIN_AND_ESCALATE: ActionSpec(
        action_id=ActionId.ABSTAIN_AND_ESCALATE,
        enabled=True,
        impact_tier=ImpactTier.READ_ONLY_DIAGNOSTIC,
        required_permission=PermissionTier.HUMAN_ESCALATION,
        requires_target_unit=False,
        reversible=True,
        timeout_sec=1.0,
        max_retries_per_incident=5,
        description="Stop automated mutation and escalate the incident for human review.",
    ),
}

DEFAULT_ACTION_CATALOGUE: Mapping[ActionId, ActionSpec] = MappingProxyType(
    _CATALOGUE_ENTRIES
)
