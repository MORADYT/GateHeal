"""Configuration schemas and YAML loader for GateHeal."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field

from gateheal.models import StrictStrTuple


class PlatformSettings(BaseModel):
    """Top-level controller mode and safety threshold settings."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    controller_mode: str = "deterministic"
    max_allowed_impact_tier: Annotated[int, Field(ge=0, le=3)] = 2
    min_confidence_for_mutation: Annotated[float, Field(ge=0.0, le=1.0)] = 0.70


class ExecutionBudgets(BaseModel):
    """Explicit execution, retry, and payload budgets enforced by application code."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    per_action_timeout_sec: Annotated[float, Field(gt=0.0, le=300.0)] = 10.0
    total_incident_timeout_sec: Annotated[float, Field(gt=0.0, le=600.0)] = 45.0
    max_diagnostic_attempts: Annotated[int, Field(ge=1, le=20)] = 4
    max_recovery_attempts: Annotated[int, Field(ge=1, le=10)] = 2
    max_llm_requests: Annotated[int, Field(ge=0, le=20)] = 0
    max_agent_rounds: Annotated[int, Field(ge=0, le=10)] = 0
    max_evidence_bytes: Annotated[int, Field(ge=1024, le=131072)] = 16384
    max_log_lines: Annotated[int, Field(ge=5, le=500)] = 50
    verification_soak_sec: Annotated[float, Field(ge=0.0, le=120.0)] = 5.0


class ServiceInventoryItem(BaseModel):
    """Approved systemd unit definition and dependency links."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    unit_name: Annotated[str, Field(pattern=r"^[a-z0-9_-]+\.service$")]
    health_check_http_url: str | None = None
    health_check_tcp_port: Annotated[int, Field(ge=1, le=65535)] | None = None
    supports_reload: bool = False
    config_check_argv: StrictStrTuple = ()
    upstream_dependencies: StrictStrTuple = ()
    downstream_dependents: StrictStrTuple = ()


class InventoryConfig(BaseModel):
    """Approved service inventory mapping."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    services: dict[str, ServiceInventoryItem]


class GateHealConfig(BaseModel):
    """Root validated configuration object."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    platform: PlatformSettings
    budgets: ExecutionBudgets
    inventory: InventoryConfig


def load_config(path: Path) -> GateHealConfig:
    """Load and strictly validate a YAML configuration file."""
    raw_text = path.read_text(encoding="utf-8")
    loaded = yaml.safe_load(raw_text)
    if not isinstance(loaded, dict):
        raise ValueError(f"Configuration file {path} must contain a YAML mapping.")
    return GateHealConfig.model_validate(loaded)
