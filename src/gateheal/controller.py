"""Capability-bound execution controller, independent soak verifier, escalation, and WAL audit."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

from gateheal.actions import ActionSpec
from gateheal.collector import (
    parse_invocation_and_start_usec,
    parse_systemctl_show,
    redact_secrets_text,
)
from gateheal.config import GateHealConfig
from gateheal.models import (
    GENESIS_RECORD_HASH,
    ActionId,
    ActionProposal,
    ApprovalToken,
    AuditRecord,
    AuthorizedActionCapability,
    EscalationAlert,
    ExecutionResult,
    IncidentRecord,
    ServiceEvidence,
    VerificationReport,
    VerificationStatus,
)
from gateheal.policy import (
    READ_ONLY_DIAGNOSTIC_ACTIONS,
    PolicyEngine,
    collect_transitive_downstream_dependents,
    is_unit_currently_healthy,
)
from gateheal.transport import CommandTransport, SimulatedLabTransport

NON_SOAKING_ACTION_VALUES: frozenset[str] = frozenset(
    {
        ActionId.ABSTAIN_AND_ESCALATE.value,
        ActionId.NO_OP.value,
        *(act.value for act in READ_ONLY_DIAGNOSTIC_ACTIONS),
    }
)


def default_artifacts_dir() -> Path:
    """Resolve the non-CWD-relative default artifacts directory."""
    env_dir = os.environ.get("GATEHEAL_ARTIFACTS_DIR", "").strip()
    if env_dir:
        return Path(env_dir).resolve()
    return (Path(__file__).resolve().parents[2] / "artifacts").resolve()


def load_audit_hmac_key(
    env_var: str = "GATEHEAL_AUDIT_HMAC_KEY",
) -> bytes | None:
    """Load optional operator HMAC key for cryptographic audit chaining."""
    raw = os.environ.get(env_var, "").strip()
    if raw:
        return raw.encode("utf-8")
    return None


def compute_audit_record_hash(
    record: AuditRecord,
    *,
    hmac_key: bytes | None = None,
) -> str:
    """Compute deterministic SHA-256 (or HMAC-SHA256 if keyed) over an AuditRecord."""
    payload = record.model_dump(mode="json")
    payload["record_hash"] = ""
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if hmac_key is not None:
        return hmac.new(hmac_key, canonical, hashlib.sha256).hexdigest()
    return hashlib.sha256(canonical).hexdigest()


class ExecutionController:
    """Executes action argv strictly when presented with a PolicyEngine capability."""

    def __init__(
        self,
        config: GateHealConfig,
        transport: CommandTransport | None = None,
        *,
        policy_engine: PolicyEngine | None = None,
        catalogue: Mapping[ActionId, ActionSpec] | None = None,
        consumed_tokens: set[str] | None = None,
        clock_utc: Callable[[], datetime] | None = None,
        hmac_key_loader: Callable[[], bytes | None] | None = None,
        pre_execute_hook: Callable[[AuthorizedActionCapability], None] | None = None,
    ) -> None:
        self._config = config
        self._transport: CommandTransport = (
            SimulatedLabTransport() if transport is None else transport
        )
        self._policy_engine: PolicyEngine = (
            PolicyEngine(
                config,
                catalogue=catalogue,
                consumed_tokens=consumed_tokens,
                clock_utc=clock_utc,
                hmac_key_loader=hmac_key_loader,
            )
            if policy_engine is None
            else policy_engine
        )
        self._catalogue: Mapping[ActionId, ActionSpec] = (
            self._policy_engine.catalogue
            if catalogue is None
            else MappingProxyType(dict(catalogue))
        )
        self._pre_execute_hook = pre_execute_hook

    @property
    def policy_engine(self) -> PolicyEngine:
        """Return the PolicyEngine bound to this controller."""
        return self._policy_engine

    @property
    def consumed_tokens(self) -> frozenset[str]:
        """Return frozenset of consumed ApprovalToken IDs."""
        return frozenset(self._policy_engine.consumed_tokens_store)

    def execute(
        self,
        capability: AuthorizedActionCapability,
        *,
        current_incident: IncidentRecord,
        approval_token: ApprovalToken | None = None,
    ) -> ExecutionResult:
        """Verify PolicyEngine capability, check TOCTOU state hash, consume, and execute."""
        if not isinstance(capability, AuthorizedActionCapability):
            raise PermissionError(
                "ExecutionController.execute() requires an AuthorizedActionCapability "
                "minted by PolicyEngine; raw ActionProposal objects are rejected."
            )

        self._policy_engine.verify_and_consume_capability(
            capability,
            current_incident,
            approval_token=approval_token,
        )

        action_enum = capability.action_id
        spec = self._catalogue.get(action_enum)
        if spec is None or not spec.enabled:
            raise ValueError(f"Unregistered or disabled action {action_enum.value}")

        if self._pre_execute_hook is not None:
            self._pre_execute_hook(capability)

        services_map = self._config.inventory.services
        service_spec = (
            services_map.get(capability.target_unit)
            if capability.target_unit
            else None
        )
        argv = spec.build_argv(capability.target_unit, service_spec)

        if not argv:
            msg = (
                "No-op action executed."
                if action_enum == ActionId.NO_OP
                else "Abstention action executed."
            )
            return ExecutionResult(
                action_id=action_enum,
                target_unit=capability.target_unit,
                argv=(),
                exit_code=0,
                duration_sec=0.0,
                stdout_excerpt=msg,
            )

        timeout_sec = min(
            spec.timeout_sec,
            self._config.budgets.per_action_timeout_sec,
        )
        res = self._transport.run(argv, timeout_sec)
        return ExecutionResult(
            action_id=action_enum,
            target_unit=capability.target_unit,
            argv=argv,
            exit_code=res.exit_code,
            timed_out=res.timed_out,
            duration_sec=res.duration_sec,
            stdout_excerpt=redact_secrets_text(res.stdout_excerpt),
            stderr_excerpt=redact_secrets_text(res.stderr_excerpt),
        )


def _detect_target_recurrence(
    target: str,
    proposal: ActionProposal,
    pre_ev: ServiceEvidence | None,
    samples: Sequence[ServiceEvidence],
) -> tuple[bool, str]:
    """Check NRestarts, InvocationID, ExecMainStartTimestamp, and active->failed transitions."""
    if not samples:
        return False, ""

    first_ev = samples[0]
    saw_healthy = False

    for idx, curr_ev in enumerate(samples, start=1):
        if pre_ev is not None and curr_ev.n_restarts > pre_ev.n_restarts:
            return (
                True,
                f"Target unit {target} experienced crash recurrence during soak "
                f"(n_restarts {pre_ev.n_restarts} -> {curr_ev.n_restarts} at sample {idx}).",
            )
        if curr_ev.n_restarts > first_ev.n_restarts:
            return (
                True,
                f"Target unit {target} experienced crash recurrence during soak "
                f"(n_restarts {first_ev.n_restarts} -> {curr_ev.n_restarts} at sample {idx}).",
            )

        if (
            proposal.action_id == ActionId.RELOAD_SERVICE.value
            and pre_ev is not None
        ):
            if (
                pre_ev.invocation_id is not None
                and curr_ev.invocation_id is not None
                and curr_ev.invocation_id != pre_ev.invocation_id
            ):
                return (
                    True,
                    f"Target unit {target} changed InvocationID during in-place reload "
                    f"({pre_ev.invocation_id!r} -> {curr_ev.invocation_id!r}).",
                )
            if (
                pre_ev.exec_main_start_timestamp_usec is not None
                and curr_ev.exec_main_start_timestamp_usec is not None
                and curr_ev.exec_main_start_timestamp_usec
                != pre_ev.exec_main_start_timestamp_usec
            ):
                return (
                    True,
                    f"Target unit {target} changed ExecMainStartTimestamp during reload "
                    f"({pre_ev.exec_main_start_timestamp_usec} -> "
                    f"{curr_ev.exec_main_start_timestamp_usec}).",
                )

        if idx >= 2:
            if (
                first_ev.invocation_id is not None
                and curr_ev.invocation_id is not None
                and curr_ev.invocation_id != first_ev.invocation_id
            ):
                return (
                    True,
                    f"Target unit {target} experienced mid-soak InvocationID change "
                    f"({first_ev.invocation_id!r} -> {curr_ev.invocation_id!r} at sample {idx}).",
                )
            if (
                first_ev.exec_main_start_timestamp_usec is not None
                and curr_ev.exec_main_start_timestamp_usec is not None
                and curr_ev.exec_main_start_timestamp_usec
                != first_ev.exec_main_start_timestamp_usec
            ):
                return (
                    True,
                    f"Target unit {target} experienced mid-soak ExecMainStartTimestamp "
                    f"change ({first_ev.exec_main_start_timestamp_usec} -> "
                    f"{curr_ev.exec_main_start_timestamp_usec} at sample {idx}).",
                )

        curr_healthy = is_unit_currently_healthy(curr_ev)
        if curr_healthy:
            saw_healthy = True
        elif saw_healthy:
            return (
                True,
                f"Target unit {target} regressed from healthy to unhealthy "
                f"at soak sample {idx} (state={curr_ev.active_state}/{curr_ev.sub_state}, "
                f"probe_ok={curr_ev.health_probe_ok}).",
            )

    return False, ""


class OutcomeVerifier:
    """Independently verifies recovery success, recurrence, and collateral health (WP4).

    Policy Notes:
    - D1: Non-mutating actions (`NO_OP`, `ABSTAIN_AND_ESCALATE`, and all
      `READ_ONLY_DIAGNOSTIC_ACTIONS`) skip the soak window (`soak_duration_sec=0.0`,
      `samples_collected=1`).
    - D2: Enforces the strict all-samples-healthy soak rule across samples 1..N,
      trading potential false escalations on slow-starting services for safety.
    - D3: `measured_unavailability_sec` records in-window soak unavailability (an
      upper bound at poll granularity); end-to-end MTTR comes from the experiment
      harness (`TrialOutcome.service_unavailability_sec`).
    """

    def __init__(
        self,
        config: GateHealConfig,
        *,
        monotonic_clock: Callable[[], float] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
        default_poll_interval_sec: float = 1.0,
    ) -> None:
        self._config = config
        self._monotonic_clock: Callable[[], float] = (
            time.monotonic if monotonic_clock is None else monotonic_clock
        )
        self._sleep_fn: Callable[[float], None] = (
            time.sleep if sleep_fn is None else sleep_fn
        )
        self._default_poll_interval_sec = default_poll_interval_sec

    def _probe_unit_oracle(
        self,
        unit_name: str,
        transport: CommandTransport,
        timeout_sec: float,
    ) -> tuple[ServiceEvidence | None, str | None]:
        """Independently probe a single systemd unit via transport without IncidentCollector."""
        item = self._config.inventory.services.get(unit_name)
        show_arg = (
            "--property=ActiveState,SubState,Result,NRestarts,CanReload,"
            "InvocationID,ExecMainStartTimestampMonotonic"
        )
        show_res = transport.run(
            ("systemctl", "show", unit_name, show_arg),
            timeout_sec=timeout_sec,
        )
        if show_res.timed_out:
            return None, f"Oracle systemctl show timed out for {unit_name}."

        props = parse_systemctl_show(show_res.stdout_excerpt)
        active_state = props.get("ActiveState", "unknown")
        sub_state = props.get("SubState", "unknown")
        result_prop = props.get("Result", "unknown")
        try:
            n_restarts = max(0, int(props.get("NRestarts", "0")))
        except ValueError:
            n_restarts = 0
        can_reload = props.get("CanReload", "no").lower() == "yes"
        invocation_id, exec_start_usec = parse_invocation_and_start_usec(props)

        config_valid: bool | None = None
        if item is not None and item.config_check_mode == "argv" and item.config_check_argv:
            cfg_res = transport.run(item.config_check_argv, timeout_sec=timeout_sec)
            if cfg_res.timed_out:
                return None, f"Oracle config check timed out for {unit_name}."
            if cfg_res.exit_code == 0:
                config_valid = True
            elif cfg_res.exit_code == item.config_invalid_exit_code:
                config_valid = False

        probe_ok = active_state == "active" and sub_state == "running"
        if item is not None and probe_ok:
            if item.health_check_http_url:
                http_res = transport.run(
                    ("curl", "-fsS", "--max-time", "2", item.health_check_http_url),
                    timeout_sec=timeout_sec,
                )
                if http_res.timed_out:
                    return None, f"Oracle HTTP health probe timed out for {unit_name}."
                probe_ok = http_res.exit_code == 0
            elif item.health_check_tcp_port is not None:
                tcp_res = transport.run(
                    (
                        "/usr/bin/python3",
                        "-m",
                        "gateheal.lab_daemons",
                        "--check-tcp",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(item.health_check_tcp_port),
                    ),
                    timeout_sec=timeout_sec,
                )
                if tcp_res.timed_out:
                    return None, f"Oracle TCP health probe timed out for {unit_name}."
                probe_ok = tcp_res.exit_code == 0

        return (
            ServiceEvidence(
                unit_name=unit_name,
                active_state=active_state,
                sub_state=sub_state,
                result=result_prop,
                n_restarts=n_restarts,
                can_reload=can_reload,
                health_probe_ok=probe_ok,
                config_valid=config_valid,
                invocation_id=invocation_id,
                exec_main_start_timestamp_usec=exec_start_usec,
            ),
            None,
        )

    def verify_with_transport(
        self,
        proposal: ActionProposal,
        execution_result: ExecutionResult,
        pre_incident: IncidentRecord,
        transport: CommandTransport,
    ) -> tuple[VerificationReport, IncidentRecord]:
        """Poll target and dependents N times across verification_soak_sec via transport."""
        target = proposal.target_unit or pre_incident.target_unit
        if execution_result.timed_out:
            rep = VerificationReport(
                status=VerificationStatus.OUTCOME_UNCERTAIN,
                target_unit=target or "none",
                target_healthy=False,
                soak_duration_sec=0.0,
                samples_collected=0,
                details="Execution timed out; post-action state is uncertain.",
            )
            return rep, pre_incident

        # D1: Skip soak for read-only diagnostics, no_op, and abstain_and_escalate
        skip_soak = proposal.action_id in NON_SOAKING_ACTION_VALUES
        soak_sec = (
            0.0
            if skip_soak
            else self._config.budgets.verification_soak_sec
        )
        poll_interval = (
            self._config.budgets.verification_poll_interval_sec
            or self._default_poll_interval_sec
        )
        num_samples = (
            1
            if (skip_soak or soak_sec <= 0.0)
            else max(1, int(math.ceil(soak_sec / poll_interval)))
        )
        cmd_timeout = min(5.0, self._config.budgets.per_action_timeout_sec)

        units_to_poll = tuple(self._config.inventory.services.keys())
        sample_records: list[IncidentRecord] = []
        sample_times: list[float] = []
        start_mono = self._monotonic_clock()

        for sample_idx in range(1, num_samples + 1):
            if not skip_soak and soak_sec > 0.0:
                self._sleep_fn(poll_interval)
            sample_offset = max(
                float(sample_idx) * poll_interval
                if (not skip_soak and soak_sec > 0.0)
                else 0.0,
                self._monotonic_clock() - start_mono,
            )

            polled_services: dict[str, ServiceEvidence] = {}
            for unit_name in units_to_poll:
                ev, timeout_err = self._probe_unit_oracle(
                    unit_name, transport, cmd_timeout
                )
                if timeout_err is not None or ev is None:
                    uncertain_rep = VerificationReport(
                        status=VerificationStatus.OUTCOME_UNCERTAIN,
                        target_unit=target or "none",
                        target_healthy=False,
                        soak_duration_sec=sample_offset,
                        samples_collected=sample_idx - 1,
                        details=(
                            f"Mid-soak probe timeout at sample {sample_idx}: "
                            f"{timeout_err}"
                        ),
                    )
                    last_inc = sample_records[-1] if sample_records else pre_incident
                    return uncertain_rep, last_inc
                polled_services[unit_name] = ev

            snap_inc = pre_incident.model_copy(
                update={
                    "incident_id": f"{pre_incident.incident_id}-soak-{sample_idx}",
                    "services": polled_services,
                }
            )
            sample_records.append(snap_inc)
            sample_times.append(sample_offset)

        final_post = sample_records[-1]
        report = self.verify(
            proposal,
            execution_result,
            final_post,
            pre_incident=pre_incident,
            soak_samples=tuple(sample_records),
            sample_offsets_sec=tuple(sample_times),
        )
        return report, final_post

    def verify(
        self,
        proposal: ActionProposal,
        execution_result: ExecutionResult,
        post_incident: IncidentRecord,
        pre_incident: IncidentRecord | None = None,
        *,
        soak_samples: Sequence[IncidentRecord] | None = None,
        sample_offsets_sec: Sequence[float] | None = None,
    ) -> VerificationReport:
        """Verify recovery, crash recurrence, and collateral health across soak samples."""
        target = proposal.target_unit or post_incident.target_unit

        if execution_result.timed_out:
            return VerificationReport(
                status=VerificationStatus.OUTCOME_UNCERTAIN,
                target_unit=target or "none",
                target_healthy=False,
                soak_duration_sec=0.0,
                samples_collected=0,
                details="Execution timed out; post-action state is uncertain.",
            )

        if not target:
            return VerificationReport(
                status=VerificationStatus.VERIFICATION_FAILED,
                target_unit="none",
                target_healthy=False,
                soak_duration_sec=0.0,
                samples_collected=0,
                details="No target unit available for verification.",
            )

        samples_seq: tuple[IncidentRecord, ...] = (
            tuple(soak_samples)
            if soak_samples
            else (post_incident,)
        )
        num_samples = len(samples_seq)
        poll_interval = (
            self._config.budgets.verification_poll_interval_sec
            or self._default_poll_interval_sec
        )
        offsets: tuple[float, ...] = (
            tuple(sample_offsets_sec)
            if (sample_offsets_sec and len(sample_offsets_sec) == num_samples)
            else tuple(float(i) * poll_interval for i in range(1, num_samples + 1))
        )

        target_ev_list: list[ServiceEvidence] = []
        for s_inc in samples_seq:
            tev = s_inc.services.get(target)
            if tev is None:
                return VerificationReport(
                    status=VerificationStatus.OUTCOME_UNCERTAIN,
                    target_unit=target,
                    target_healthy=False,
                    soak_duration_sec=0.0,
                    samples_collected=len(target_ev_list),
                    details=f"Target unit {target} missing from post-evidence.",
                )
            target_ev_list.append(tev)

        skip_soak = proposal.action_id in NON_SOAKING_ACTION_VALUES
        soak_sec = (
            0.0
            if skip_soak
            else self._config.budgets.verification_soak_sec
        )

        first_healthy_at: float | None = None
        first_failed_at: float | None = None
        unavail_sec = 0.0
        prev_t = 0.0

        for tev, t_sec in zip(target_ev_list, offsets, strict=True):
            dt = max(0.0, t_sec - prev_t)
            if is_unit_currently_healthy(tev):
                if first_healthy_at is None:
                    first_healthy_at = t_sec
                    if (
                        pre_incident is not None
                        and not is_unit_currently_healthy(
                            pre_incident.services.get(target)
                        )
                    ):
                        unavail_sec += dt
            else:
                if first_failed_at is None:
                    first_failed_at = t_sec
                unavail_sec += dt
            prev_t = t_sec

        collateral_set: list[str] = []
        transitive_dependents = collect_transitive_downstream_dependents(
            self._config, target
        )
        for dependent in transitive_dependents:
            was_healthy_before = (
                is_unit_currently_healthy(pre_incident.services.get(dependent))
                if pre_incident is not None
                else True
            )
            if not was_healthy_before:
                continue
            for s_inc in samples_seq:
                dep_ev = s_inc.services.get(dependent)
                if dep_ev is not None and not is_unit_currently_healthy(dep_ev):
                    if dependent not in collateral_set:
                        collateral_set.append(dependent)
                    break

        pre_target_ev = (
            pre_incident.services.get(target)
            if pre_incident is not None
            else None
        )
        recurred, recur_msg = _detect_target_recurrence(
            target, proposal, pre_target_ev, target_ev_list
        )
        if recurred:
            return VerificationReport(
                status=VerificationStatus.NOT_RECOVERED,
                target_unit=target,
                target_healthy=False,
                soak_duration_sec=soak_sec,
                samples_collected=num_samples,
                first_healthy_at_sec=first_healthy_at,
                first_failed_at_sec=first_failed_at,
                measured_unavailability_sec=unavail_sec,
                collateral_failures=tuple(collateral_set),
                details=recur_msg,
            )

        all_samples_healthy = all(
            is_unit_currently_healthy(tev) for tev in target_ev_list
        )
        final_target_ev = target_ev_list[-1]

        if not all_samples_healthy:
            detail_msg = (
                f"Target unit {target} failed health check during soak "
                f"(exit_code={execution_result.exit_code})."
            )
            return VerificationReport(
                status=VerificationStatus.NOT_RECOVERED,
                target_unit=target,
                target_healthy=False,
                soak_duration_sec=soak_sec,
                samples_collected=num_samples,
                first_healthy_at_sec=first_healthy_at,
                first_failed_at_sec=first_failed_at,
                measured_unavailability_sec=unavail_sec,
                collateral_failures=tuple(collateral_set),
                details=detail_msg,
            )

        if collateral_set:
            detail_msg = (
                "Target is up but collateral failure detected "
                f"in: {collateral_set}."
            )
            return VerificationReport(
                status=VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE,
                target_unit=target,
                target_healthy=True,
                soak_duration_sec=soak_sec,
                samples_collected=num_samples,
                first_healthy_at_sec=first_healthy_at,
                first_failed_at_sec=first_failed_at,
                measured_unavailability_sec=unavail_sec,
                collateral_failures=tuple(collateral_set),
                details=detail_msg,
            )

        upstream_unhealthy = False
        service_cfg = self._config.inventory.services.get(target)
        if service_cfg is not None:
            for upstream in service_cfg.upstream_dependencies:
                up_ev = samples_seq[-1].services.get(upstream)
                if not is_unit_currently_healthy(up_ev):
                    upstream_unhealthy = True
                    break

        if final_target_ev.config_valid is False or upstream_unhealthy:
            return VerificationReport(
                status=VerificationStatus.FAULT_PERSISTS_SERVICE_UP,
                target_unit=target,
                target_healthy=True,
                soak_duration_sec=soak_sec,
                samples_collected=num_samples,
                first_healthy_at_sec=first_healthy_at,
                first_failed_at_sec=first_failed_at,
                measured_unavailability_sec=unavail_sec,
                details=(
                    f"Target {target} remains up, but underlying fault persists "
                    "in observed post-state."
                ),
            )

        detail_msg = (
            f"Target {target} verified healthy across {num_samples} soak sample(s) "
            "with zero collateral disruption."
        )
        return VerificationReport(
            status=VerificationStatus.RECOVERED_CLEAN,
            target_unit=target,
            target_healthy=True,
            soak_duration_sec=soak_sec,
            samples_collected=num_samples,
            first_healthy_at_sec=first_healthy_at,
            first_failed_at_sec=first_failed_at,
            measured_unavailability_sec=unavail_sec,
            details=detail_msg,
        )


class EscalationSink:
    """Persists fsynced operator escalation alerts when GateHeal abstains or fails."""

    def __init__(self, alert_log_path: Path | None = None) -> None:
        self._path = (
            (default_artifacts_dir() / "escalation_alerts.jsonl")
            if alert_log_path is None
            else alert_log_path.resolve()
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.emitted_alerts: list[EscalationAlert] = []

    @property
    def alert_log_path(self) -> Path:
        """Return resolved path to the escalation JSONL file."""
        return self._path

    def emit(self, alert: EscalationAlert) -> None:
        """Append and fsync an EscalationAlert record."""
        self.emitted_alerts.append(alert)
        line = alert.model_dump_json()
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


class AuditRecorder:
    """Write-ahead, fsynced, hash-chained, rotatable JSONL audit recorder."""

    def __init__(
        self,
        log_path: Path | None = None,
        *,
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 3,
        clock_utc: Callable[[], datetime] | None = None,
        hmac_key: bytes | None = None,
    ) -> None:
        self._log_path = (
            (default_artifacts_dir() / "audit.jsonl")
            if log_path is None
            else log_path.resolve()
        )
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._clock_utc: Callable[[], datetime] = (
            (lambda: datetime.now(UTC)) if clock_utc is None else clock_utc
        )
        self._hmac_key = load_audit_hmac_key() if hmac_key is None else hmac_key
        self._anchor_path = self._log_path.with_suffix(".anchor")
        self._last_hash = self._read_tail_hash()

    @property
    def log_path(self) -> Path:
        """Return resolved path to the active audit JSONL file."""
        return self._log_path

    @property
    def last_record_hash(self) -> str:
        """Return the hash of the most recently written AuditRecord."""
        return self._last_hash

    def ordered_log_paths(self) -> tuple[Path, ...]:
        """Return existing rotated backup files and active log file in chronological order."""
        paths: list[Path] = []
        for idx in range(self._backup_count, 0, -1):
            candidate = self._log_path.with_suffix(f".jsonl.{idx}")
            if candidate.is_file():
                paths.append(candidate)
        if self._log_path.is_file():
            paths.append(self._log_path)
        return tuple(paths)

    def _read_tail_hash(self) -> str:
        for candidate in reversed(self.ordered_log_paths()):
            lines = [
                ln.strip()
                for ln in candidate.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            if lines:
                last_rec = AuditRecord.model_validate_json(lines[-1])
                if last_rec.record_hash:
                    return last_rec.record_hash
        if self._anchor_path.is_file():
            anchor = self._anchor_path.read_text(encoding="utf-8").strip()
            if anchor:
                return anchor
        return GENESIS_RECORD_HASH

    def _rotate_if_needed(self, incoming_len: int) -> None:
        if not self._log_path.is_file():
            return
        if self._log_path.stat().st_size + incoming_len <= self._max_bytes:
            return

        oldest = self._log_path.with_suffix(f".jsonl.{self._backup_count}")
        if oldest.is_file():
            oldest_lines = [
                ln.strip()
                for ln in oldest.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            if oldest_lines:
                evicted_rec = AuditRecord.model_validate_json(oldest_lines[-1])
                with self._anchor_path.open("w", encoding="utf-8") as af:
                    af.write(evicted_rec.record_hash + "\n")
                    af.flush()
                    os.fsync(af.fileno())

        for idx in range(self._backup_count, 0, -1):
            src = (
                self._log_path
                if idx == 1
                else self._log_path.with_suffix(f".jsonl.{idx - 1}")
            )
            dst = self._log_path.with_suffix(f".jsonl.{idx}")
            if src.is_file():
                os.replace(src, dst)

    def record(self, audit_record: AuditRecord) -> AuditRecord:
        """Stamp prev_record_hash and record_hash, rotate if needed, and fsync to disk."""
        chained_draft = audit_record.model_copy(
            update={
                "prev_record_hash": self._last_hash,
                "record_hash": "",
            }
        )
        digest = compute_audit_record_hash(
            chained_draft, hmac_key=self._hmac_key
        )
        final_rec = chained_draft.model_copy(update={"record_hash": digest})
        line_bytes = (final_rec.model_dump_json() + "\n").encode("utf-8")

        self._rotate_if_needed(len(line_bytes))
        with self._log_path.open("ab") as f:
            f.write(line_bytes)
            f.flush()
            os.fsync(f.fileno())

        self._last_hash = digest
        return final_rec

    @staticmethod
    def verify_chain(
        paths: Path | tuple[Path, ...],
        *,
        hmac_key: bytes | None = None,
    ) -> tuple[bool, int, str]:
        """Verify hash chain integrity across rotated and active audit files (R8)."""
        resolved_key = load_audit_hmac_key() if hmac_key is None else hmac_key
        if isinstance(paths, Path):
            base = paths.resolve()
            discovered: list[Path] = []
            for idx in range(20, 0, -1):
                cand = base.with_suffix(f".jsonl.{idx}")
                if cand.is_file():
                    discovered.append(cand)
            if base.is_file():
                discovered.append(base)
            file_list = tuple(discovered) if discovered else (base,)
            anchor_file: Path | None = base.with_suffix(".anchor")
        else:
            file_list = paths
            anchor_file = (
                file_list[-1].resolve().with_suffix(".anchor")
                if file_list
                else None
            )

        expected_prev = GENESIS_RECORD_HASH
        if anchor_file is not None and anchor_file.is_file():
            anchor_val = anchor_file.read_text(encoding="utf-8").strip()
            if anchor_val:
                expected_prev = anchor_val

        total_checked = 0
        for path in file_list:
            if not path.is_file():
                continue
            for raw_line in path.read_text(encoding="utf-8").splitlines():
                stripped = raw_line.strip()
                if not stripped:
                    continue
                total_checked += 1
                try:
                    rec = AuditRecord.model_validate_json(stripped)
                except Exception as exc:
                    return (
                        False,
                        total_checked,
                        f"Malformed JSON at record {total_checked}: {exc}",
                    )
                if rec.prev_record_hash != expected_prev:
                    return (
                        False,
                        total_checked,
                        f"Broken prev_record_hash link at record {total_checked}.",
                    )
                recomputed = compute_audit_record_hash(
                    rec, hmac_key=resolved_key
                )
                if rec.record_hash != recomputed:
                    return (
                        False,
                        total_checked,
                        f"Record hash mismatch at record {total_checked}.",
                    )
                expected_prev = rec.record_hash

        return True, total_checked, "Audit hash chain verified."
