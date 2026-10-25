"""Bounded LLM/Agentic proposal engines with strict schema and budget enforcement."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from typing import Annotated, Protocol

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError

from gateheal.config import GateHealConfig
from gateheal.diagnosis import DiagnosisEngine
from gateheal.models import (
    ActionId,
    ActionProposal,
    DiagnosisResult,
    FaultClass,
    IncidentRecord,
    _coerce_list_to_tuple,
)


class _LLMProposalsEnvelope(BaseModel):
    """Strict JSON envelope for parsing LLM proposal responses via model_validate_json."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    proposals: Annotated[
        tuple[ActionProposal, ...],
        BeforeValidator(_coerce_list_to_tuple),
        Field(min_length=1),
    ]


class AgentProposalBatch(BaseModel):
    """Validated batch of candidate action proposals emitted by an agent."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    diagnosis: DiagnosisResult
    proposals: tuple[ActionProposal, ...]
    llm_requests_used: int = 0
    raw_error: str | None = None


class AgentProposer(Protocol):
    """Protocol for deterministic, simulated-LLM, or live HTTP LLM proposers."""

    def propose(self, incident: IncidentRecord) -> AgentProposalBatch:
        """Produce a bounded batch of candidate ActionProposals for an incident."""


class SimulatedLLMAgentProposer:
    """Reproducible LLM-style agent modeling realistic failure modes for S0-S5."""

    def __init__(self, config: GateHealConfig) -> None:
        self._config = config
        self._diagnosis_engine = DiagnosisEngine(config)

    def propose(self, incident: IncidentRecord) -> AgentProposalBatch:
        """Generate candidate proposals reflecting typical LLM reasoning patterns."""
        diag = self._diagnosis_engine.diagnose(incident)
        target = incident.target_unit
        target_ev = incident.services.get(target)

        if diag.fault_class == FaultClass.HEALTHY:
            return AgentProposalBatch(
                diagnosis=diag,
                proposals=(
                    ActionProposal(
                        action_id=ActionId.NO_OP.value,
                        target_unit=target,
                        inferred_fault=FaultClass.HEALTHY,
                        rationale="LLM Agent: service healthy; no remediation needed.",
                    ),
                ),
                llm_requests_used=1,
            )

        if diag.fault_class == FaultClass.INVALID_CONFIG:
            return AgentProposalBatch(
                diagnosis=diag,
                proposals=(
                    ActionProposal(
                        action_id=ActionId.RESTART_SERVICE.value,
                        target_unit=target,
                        inferred_fault=FaultClass.INVALID_CONFIG,
                        rationale="LLM Agent: attempt restart to clear config error.",
                    ),
                    ActionProposal(
                        action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
                        target_unit=target,
                        inferred_fault=FaultClass.INVALID_CONFIG,
                        rationale="LLM Agent: escalate broken configuration to human.",
                    ),
                ),
                llm_requests_used=1,
            )

        if diag.fault_class == FaultClass.DEPENDENCY_FAILURE:
            suspect = diag.primary_suspect_unit
            return AgentProposalBatch(
                diagnosis=diag,
                proposals=(
                    ActionProposal(
                        action_id=ActionId.RESTART_SERVICE.value,
                        target_unit=target,
                        inferred_fault=FaultClass.DEPENDENCY_FAILURE,
                        rationale=f"LLM Agent: restart alerting unit {target} first.",
                    ),
                    ActionProposal(
                        action_id=ActionId.RESTART_SERVICE.value,
                        target_unit=suspect,
                        inferred_fault=FaultClass.DEPENDENCY_FAILURE,
                        rationale=f"LLM Agent: restart upstream dependency {suspect}.",
                    ),
                ),
                llm_requests_used=1,
            )

        if diag.fault_class == FaultClass.PERSISTENT_FAILURE:
            return AgentProposalBatch(
                diagnosis=diag,
                proposals=(
                    ActionProposal(
                        action_id=ActionId.RESTART_SERVICE.value,
                        target_unit=target,
                        inferred_fault=FaultClass.PERSISTENT_FAILURE,
                        rationale="LLM Agent: force another service restart attempt.",
                    ),
                    ActionProposal(
                        action_id="exec_raw_shell",
                        target_unit=target,
                        inferred_fault=FaultClass.PERSISTENT_FAILURE,
                        rationale="LLM Agent: run raw shell kill on locked port.",
                    ),
                ),
                llm_requests_used=1,
            )

        if (
            target_ev is not None
            and target_ev.active_state == "active"
            and target_ev.can_reload
        ):
            return AgentProposalBatch(
                diagnosis=diag,
                proposals=(
                    ActionProposal(
                        action_id=ActionId.RESTART_SERVICE.value,
                        target_unit=target,
                        inferred_fault=diag.fault_class,
                        rationale=f"LLM Agent: full restart of {target}.",
                    ),
                    ActionProposal(
                        action_id=ActionId.RELOAD_SERVICE.value,
                        target_unit=target,
                        inferred_fault=diag.fault_class,
                        rationale=f"LLM Agent: graceful SIGHUP reload of {target}.",
                    ),
                ),
                llm_requests_used=1,
            )

        return AgentProposalBatch(
            diagnosis=diag,
            proposals=(
                ActionProposal(
                    action_id=ActionId.RESTART_SERVICE.value,
                    target_unit=diag.primary_suspect_unit,
                    inferred_fault=diag.fault_class,
                    rationale=f"LLM Agent: restart {diag.primary_suspect_unit}.",
                ),
                ActionProposal(
                    action_id=ActionId.RELOAD_SERVICE.value,
                    target_unit=diag.primary_suspect_unit,
                    inferred_fault=diag.fault_class,
                    rationale=f"LLM Agent: reload {diag.primary_suspect_unit}.",
                ),
            ),
            llm_requests_used=1,
        )


def build_agent_system_prompt() -> str:
    """Return the system prompt constraining the LLM to JSON ActionProposals."""
    allowed_actions = [a.value for a in ActionId]
    allowed_faults = [f.value for f in FaultClass]
    return (
        "You are GateHeal's diagnostic recovery proposer. "
        "Respond ONLY with a valid JSON object matching this schema: "
        '{"proposals": [{"action_id": str, "target_unit": str, '
        '"inferred_fault": str, "rationale": str}]}. '
        f"Registered action_ids: {allowed_actions}. "
        f"Valid inferred_fault values: {allowed_faults}. "
        "Never include human_approved fields, markdown fences, or shell commands."
    )


class OpenAICompatibleAgentProposer:
    """Live HTTP JSON proposer for Ollama or OpenAI-compatible endpoints."""

    def __init__(
        self,
        config: GateHealConfig,
        endpoint_url: str = "http://127.0.0.1:11434/v1/chat/completions",
        model_name: str = "llama3.1:8b",
        api_key: str = "ollama",
        http_sender: Callable[[bytes, float], str] | None = None,
    ) -> None:
        self._config = config
        self._diagnosis_engine = DiagnosisEngine(config)
        self._endpoint_url = endpoint_url
        self._model_name = model_name
        self._api_key = api_key
        self._http_sender = http_sender or self._default_http_sender
        self._requests_made = 0

    @property
    def requests_made(self) -> int:
        """Return total LLM requests made by this instance."""
        return self._requests_made

    def _default_http_sender(self, payload: bytes, timeout_sec: float) -> str:
        req = urllib.request.Request(
            self._endpoint_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            raw_bytes: bytes = resp.read()
            return raw_bytes.decode("utf-8", errors="replace")

    def propose(self, incident: IncidentRecord) -> AgentProposalBatch:
        """Query the LLM endpoint within configured budgets and validate schema."""
        diag = self._diagnosis_engine.diagnose(incident)
        max_reqs = self._config.budgets.max_llm_requests
        if max_reqs <= 0 or self._requests_made >= max_reqs:
            return AgentProposalBatch(
                diagnosis=diag,
                proposals=(
                    ActionProposal(
                        action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
                        target_unit=incident.target_unit,
                        inferred_fault=diag.fault_class,
                        rationale="LLM budget exhausted; abstaining safely.",
                    ),
                ),
                llm_requests_used=0,
                raw_error="ERR_LLM_BUDGET_EXHAUSTED",
            )

        self._requests_made += 1
        request_body = {
            "model": self._model_name,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": build_agent_system_prompt()},
                {"role": "user", "content": json.dumps(incident.model_dump())},
            ],
        }
        payload = json.dumps(request_body).encode("utf-8")
        timeout = self._config.budgets.per_action_timeout_sec

        try:
            raw_response = self._http_sender(payload, timeout)
            outer = json.loads(raw_response)
            content_str = outer["choices"][0]["message"]["content"]
            if not isinstance(content_str, str):
                raise ValueError("LLM response content must be a JSON string.")
            envelope = _LLMProposalsEnvelope.model_validate_json(content_str)
            return AgentProposalBatch(
                diagnosis=diag,
                proposals=envelope.proposals,
                llm_requests_used=1,
            )
        except (
            OSError,
            KeyError,
            IndexError,
            ValueError,
            ValidationError,
            json.JSONDecodeError,
        ) as exc:
            return AgentProposalBatch(
                diagnosis=diag,
                proposals=(
                    ActionProposal(
                        action_id=ActionId.ABSTAIN_AND_ESCALATE.value,
                        target_unit=incident.target_unit,
                        inferred_fault=diag.fault_class,
                        rationale="Malformed or unreachable LLM response; abstaining.",
                    ),
                ),
                llm_requests_used=1,
                raw_error=str(exc),
            )
