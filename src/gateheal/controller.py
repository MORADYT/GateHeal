"""Execution controller, independent outcome verifier, and audit recorder."""

from __future__ import annotations

from pathlib import Path

from gateheal.actions import DEFAULT_ACTION_CATALOGUE
from gateheal.config import GateHealConfig
from gateheal.models import (
    ActionId,
    ActionProposal,
    AuditRecord,
    ExecutionResult,
    IncidentRecord,
    VerificationReport,
    VerificationStatus,
)
from gateheal.transport import CommandTransport, SimulatedLabTransport


class ExecutionController:
    """Executes approved action argv through an isolated CommandTransport."""

    def __init__(
        self,
        config: GateHealConfig,
        transport: CommandTransport | None = None,
    ) -> None:
        self._config = config
        self._transport: CommandTransport = transport or SimulatedLabTransport()

    def execute(self, proposal: ActionProposal) -> ExecutionResult:
        """Validate action spec and execute via the configured transport."""
        action_enum = ActionId(proposal.action_id)
        spec = DEFAULT_ACTION_CATALOGUE.get(action_enum)
        if spec is None:
            raise ValueError(f"Unregistered action {proposal.action_id}")

        services_map = self._config.inventory.services
        service_spec = (
            services_map.get(proposal.target_unit)
            if proposal.target_unit
            else None
        )
        argv = spec.build_argv(proposal.target_unit, service_spec)

        if not argv:
            return ExecutionResult(
                action_id=action_enum,
                target_unit=proposal.target_unit,
                argv=(),
                exit_code=0,
                duration_sec=0.0,
                stdout_excerpt="Abstention action executed.",
            )

        timeout_sec = min(
            spec.timeout_sec,
            self._config.budgets.per_action_timeout_sec,
        )
        res = self._transport.run(argv, timeout_sec)
        return ExecutionResult(
            action_id=action_enum,
            target_unit=proposal.target_unit,
            argv=argv,
            exit_code=res.exit_code,
            timed_out=res.timed_out,
            duration_sec=res.duration_sec,
            stdout_excerpt=res.stdout_excerpt,
            stderr_excerpt=res.stderr_excerpt,
        )


class OutcomeVerifier:
    """Independently verifies recovery success, recurrence, and collateral health."""

    def __init__(self, config: GateHealConfig) -> None:
        self._config = config

    def verify(
        self,
        proposal: ActionProposal,
        execution_result: ExecutionResult,
        post_incident: IncidentRecord,
        pre_incident: IncidentRecord | None = None,
    ) -> VerificationReport:
        """Perform post-execution verification across target and dependents."""
        target = proposal.target_unit
        target_ev = post_incident.services.get(target) if target else None
        is_target_up = bool(
            target_ev is not None
            and target_ev.active_state == "active"
            and target_ev.sub_state == "running"
            and target_ev.health_probe_ok
        )

        if proposal.action_id == ActionId.ABSTAIN_AND_ESCALATE.value:
            return VerificationReport(
                status=(
                    VerificationStatus.RECOVERED_CLEAN
                    if is_target_up
                    else VerificationStatus.NOT_RECOVERED
                ),
                target_unit=target or "none",
                target_healthy=is_target_up,
                soak_duration_sec=0.0,
                details="Controller abstained safely; escalated for human review.",
            )

        if execution_result.timed_out:
            return VerificationReport(
                status=VerificationStatus.OUTCOME_UNCERTAIN,
                target_unit=target or "none",
                target_healthy=False,
                soak_duration_sec=0.0,
                details="Execution timed out; post-action state is uncertain.",
            )

        if target is None:
            return VerificationReport(
                status=VerificationStatus.VERIFICATION_FAILED,
                target_unit="none",
                target_healthy=False,
                soak_duration_sec=0.0,
                details="Action required a target unit but none supplied.",
            )

        if target_ev is None:
            return VerificationReport(
                status=VerificationStatus.OUTCOME_UNCERTAIN,
                target_unit=target,
                target_healthy=False,
                soak_duration_sec=0.0,
                details=f"Target unit {target} missing from post-evidence.",
            )

        soak_sec = self._config.budgets.verification_soak_sec

        # Check if service crashed again during the soak window (n_restarts increased)
        if pre_incident is not None:
            pre_ev = pre_incident.services.get(target)
            if pre_ev is not None and target_ev.n_restarts > pre_ev.n_restarts:
                recur_msg = (
                    f"Target unit {target} experienced crash recurrence during "
                    f"soak window (n_restarts {pre_ev.n_restarts} -> "
                    f"{target_ev.n_restarts})."
                )
                return VerificationReport(
                    status=VerificationStatus.NOT_RECOVERED,
                    target_unit=target,
                    target_healthy=False,
                    soak_duration_sec=soak_sec,
                    details=recur_msg,
                )

        collateral_failures: list[str] = []
        service_cfg = self._config.inventory.services.get(target)
        if service_cfg is not None:
            for dependent in service_cfg.downstream_dependents:
                dep_ev = post_incident.services.get(dependent)
                if dep_ev is not None and (
                    dep_ev.active_state != "active"
                    or not dep_ev.health_probe_ok
                ):
                    collateral_failures.append(dependent)

        if not is_target_up:
            detail_msg = (
                f"Target unit {target} is not healthy after execution "
                f"(exit_code={execution_result.exit_code})."
            )
            return VerificationReport(
                status=VerificationStatus.NOT_RECOVERED,
                target_unit=target,
                target_healthy=False,
                soak_duration_sec=soak_sec,
                details=detail_msg,
            )

        if collateral_failures:
            detail_msg = (
                "Target recovered but collateral failure detected "
                f"in: {collateral_failures}."
            )
            return VerificationReport(
                status=VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE,
                target_unit=target,
                target_healthy=True,
                soak_duration_sec=soak_sec,
                collateral_failures=tuple(collateral_failures),
                details=detail_msg,
            )

        detail_msg = (
            f"Target {target} successfully recovered with zero collateral."
        )
        return VerificationReport(
            status=VerificationStatus.RECOVERED_CLEAN,
            target_unit=target,
            target_healthy=True,
            soak_duration_sec=soak_sec,
            details=detail_msg,
        )


class AuditRecorder:
    """Persists structured JSONL audit records for reproducibility."""

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, audit_record: AuditRecord) -> None:
        """Append an audit record to the JSONL log file."""
        line = audit_record.model_dump_json()
        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
