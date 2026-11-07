"""WP6 paired live-lab experiment engine across arms B0, B1, B2, G, G-nobr, and G-nosoak."""

from __future__ import annotations

import os
import platform
import random
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import pydantic
from pydantic import BaseModel, ConfigDict, Field

from gateheal.agent import SimulatedLLMAgentProposer
from gateheal.collector import IncidentCollector
from gateheal.config import GateHealConfig
from gateheal.controller import AuditRecorder, EscalationSink
from gateheal.diagnosis import DiagnosisEngine
from gateheal.lab_bringup import (
    LabRunManifest,
    SmokeMatrixExpectation,
    build_wp5_smoke_expectations,
    compute_file_sha256,
    resolve_git_revision,
    wait_for_expected_pre_state,
)
from gateheal.models import ActionId, FaultClass
from gateheal.oracle import (
    MIN_ORACLE_HOLD_WINDOW_SEC,
    SCENARIO_RECOVERABLE,
    IndependentLabOracle,
    OracleEvaluation,
    OracleOutcomeLabel,
)
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.state import PersistentStateStore
from gateheal.stats import (
    BootstrapMeanDiffResult,
    HolmAdjustedItem,
    McNemarResult,
    ProportionInterval,
    WilcoxonResult,
    exact_mcnemar_test,
    holm_bonferroni_correction,
    paired_bootstrap_mean_diff,
    wilcoxon_signed_rank_test,
    wilson_score_interval,
)
from gateheal.transport import (
    EXPECTED_SENTINEL_TOKEN,
    CommandTransport,
    HostSafetyViolationError,
    RecordingTransport,
    SSHLabTransport,
)

ALL_WP6_ARMS: tuple[str, ...] = ("B0", "B1", "B2", "G", "G-nobr", "G-nosoak")
UNGATED_ARMS: frozenset[str] = frozenset({"B1", "B2"})
GATEHEAL_ARMS: frozenset[str] = frozenset({"G", "G-nobr", "G-nosoak"})
H2_NON_INFERIORITY_MARGIN = 0.05


def _default_utc_now() -> datetime:
    return datetime.now(UTC)


class WP6TrialRecord(BaseModel):
    """Single append-only JSONL record for one (scenario_id, repeat_index, arm_id) trial."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = "1.0"
    trial_id: str
    scenario_id: str
    repeat_index: Annotated[int, Field(ge=1)]
    arm_id: str
    arm_order_in_block: Annotated[int, Field(ge=0)]
    ungated_arm: bool
    started_at_utc: str
    finished_at_utc: str
    diagnosed_fault: FaultClass
    selected_action_id: str
    selected_target_unit: str | None
    abstained: bool
    escalated: bool
    mutating_action_taken: bool
    executed_argvs: tuple[tuple[str, ...], ...]
    action_duration_sec: Annotated[float, Field(ge=0.0)]
    verifier_samples_collected: Annotated[int, Field(ge=0)] = 0
    evaluable: bool = True
    oracle_evaluation: OracleEvaluation


class WP6CampaignManifest(BaseModel):
    """Manifest recording provenance, seed, WP5 manifest hash, and tool versions for WP6."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = "1.0"
    generated_at_utc: str
    wp5_manifest_path: str
    wp5_manifest_sha256: str
    git_sha: str
    git_dirty: bool
    config_sha256: str
    seed: int
    arms: tuple[str, ...]
    scenarios: tuple[str, ...]
    trials_per_scenario: Annotated[int, Field(ge=1)]
    oracle_hold_window_sec: Annotated[float, Field(ge=MIN_ORACLE_HOLD_WINDOW_SEC)]
    tool_versions: dict[str, str]
    total_planned_trials: Annotated[int, Field(ge=1)]
    completed_trials: Annotated[int, Field(ge=0)]


class WP6CoverageRow(BaseModel):
    """Per-arm evaluability and action coverage breakdown (unconditional denominator)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    arm_id: str
    ungated_arm: bool
    planned_trials: int
    completed_trials: int
    evaluable_trials: int
    non_evaluable_trials: int
    mutating_trials: int
    abstained_trials: int
    observe_only_or_noop_trials: int


class WP6ArmSummary(BaseModel):
    """Aggregated unconditional rates and Wilson 95% intervals for a single WP6 arm."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    arm_id: str
    ungated_arm: bool
    total_trials: int
    evaluable_trials: int
    non_evaluable_trials: int
    recoverable_trials: int
    unrecoverable_trials: int
    healthy_control_trials: int
    mutating_trials: int
    abstained_trials: int
    recovered_all_rate: ProportionInterval
    recovered_with_collateral_rate: ProportionInterval
    not_recovered_rate: ProportionInterval
    harmful_rate: ProportionInterval
    no_change_correct_rate: ProportionInterval
    false_positive_remediation_rate: ProportionInterval
    abstention_rate: ProportionInterval
    appropriate_abstention_rate: ProportionInterval
    mean_unavailability_sec: float


class WP6PairedComparison(BaseModel):
    """Paired statistical comparison between two arms on a binary or continuous metric."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    comparison_id: str
    hypothesis_id: str
    description: str
    arm_a: str
    arm_b: str
    n_pairs: int
    rate_a: float
    rate_b: float
    rate_diff_a_minus_b: float
    mcnemar: McNemarResult
    unavailability_wilcoxon: WilcoxonResult
    unavailability_bootstrap: BootstrapMeanDiffResult


class WP6CampaignSummary(BaseModel):
    """Top-level WP6 campaign summary emitted to summary.json."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = "1.0"
    generated_at_utc: str
    seed: int
    trials_per_scenario: int
    h2_non_inferiority_margin: float = H2_NON_INFERIORITY_MARGIN
    coverage: dict[str, WP6CoverageRow]
    arm_summaries: dict[str, WP6ArmSummary]
    scenario_arm_outcomes: dict[str, dict[str, dict[str, int]]]
    paired_comparisons: tuple[WP6PairedComparison, ...]
    holm_bonferroni_family: tuple[HolmAdjustedItem, ...]


def ensure_transport_sentinel_verified(transport: CommandTransport) -> None:
    """Refuse ungated execution unless the transport has a verified lab sentinel."""
    if not getattr(transport, "verify_remote_sentinel", False):
        raise HostSafetyViolationError(
            "Refusing ungated arm execution: transport does not have "
            "verify_remote_sentinel=True."
        )
    if isinstance(transport, SSHLabTransport):
        transport._ensure_remote_sentinel()
        return

    res = transport.run(("cat", "/etc/gateheal-lab-sentinel"), timeout_sec=5.0)
    if res.timed_out or res.exit_code != 0:
        raise HostSafetyViolationError(
            "Refusing ungated arm execution: sentinel file missing or unreadable "
            f"(exit={res.exit_code})."
        )
    if res.stdout_excerpt.strip() != EXPECTED_SENTINEL_TOKEN:
        raise HostSafetyViolationError(
            "Refusing ungated arm execution: sentinel token mismatch."
        )


def build_paired_arm_schedule(
    scenarios: Sequence[str],
    trials_per_scenario: int,
    arms: Sequence[str] = ALL_WP6_ARMS,
    *,
    seed: int = 20261028,
) -> dict[tuple[str, int], tuple[str, ...]]:
    """Generate deterministic randomised arm orders per (scenario_id, repeat_index)."""
    if trials_per_scenario < 1:
        raise ValueError("trials_per_scenario must be >= 1")
    rng = random.Random(seed)
    schedule: dict[tuple[str, int], tuple[str, ...]] = {}
    base_arms = list(arms)
    for repeat_idx in range(1, trials_per_scenario + 1):
        for scen_id in scenarios:
            shuffled = list(base_arms)
            rng.shuffle(shuffled)
            schedule[(scen_id, repeat_idx)] = tuple(shuffled)
    return schedule


def validate_wp6_preflight(
    *,
    repo_root: Path,
    wp5_manifest_path: Path,
    allow_dirty: bool = False,
) -> tuple[LabRunManifest, str, str, bool]:
    """Verify WP5 manifest passed all gates and git working tree is clean."""
    if not wp5_manifest_path.is_file():
        raise RuntimeError(
            f"WP6 preflight refused: missing WP5 manifest at {wp5_manifest_path}. "
            "Run wp5_capture_and_verify.py first."
        )
    wp5_manifest = LabRunManifest.model_validate_json(
        wp5_manifest_path.read_text(encoding="utf-8")
    )
    if not wp5_manifest.conformance_all_passed or not wp5_manifest.smoke_all_passed:
        raise RuntimeError(
            "WP6 preflight refused: wp5_lab_manifest.json does not have both "
            "conformance_all_passed=True and smoke_all_passed=True."
        )
    git_sha, git_dirty = resolve_git_revision(repo_root)
    if git_dirty and not allow_dirty:
        raise RuntimeError(
            "WP6 preflight refused: git working tree is dirty. "
            "Commit changes or pass --allow-dirty."
        )
    wp5_hash = compute_file_sha256(wp5_manifest_path)
    return wp5_manifest, wp5_hash, git_sha, git_dirty


def load_completed_wp6_trials(
    jsonl_path: Path,
) -> dict[tuple[str, int, str], WP6TrialRecord]:
    """Load already-completed trial records from an append-only JSONL file for resume."""
    completed: dict[tuple[str, int, str], WP6TrialRecord] = {}
    if not jsonl_path.is_file():
        return completed
    for raw_line in jsonl_path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        rec = WP6TrialRecord.model_validate_json(stripped)
        key = (rec.scenario_id, rec.repeat_index, rec.arm_id)
        completed[key] = rec
    return completed


def append_wp6_trial_record(jsonl_path: Path, record: WP6TrialRecord) -> None:
    """Append and fsync a single WP6TrialRecord to jsonl_path."""
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    line = record.model_dump_json() + "\n"
    with jsonl_path.open("a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def make_arm_config(base_config: GateHealConfig, arm_id: str) -> GateHealConfig:
    """Return the GateHealConfig variant for arm G, G-nobr, or G-nosoak."""
    if arm_id == "G-nobr":
        return base_config.model_copy(
            update={
                "platform": base_config.platform.model_copy(
                    update={"max_unapproved_blast_radius_weight": 1000.0}
                )
            }
        )
    if arm_id == "G-nosoak":
        return base_config.model_copy(
            update={
                "budgets": base_config.budgets.model_copy(
                    update={
                        "verification_soak_sec": 1.0,
                        "verification_poll_interval_sec": 1.0,
                    }
                )
            }
        )
    return base_config


class WP6ExperimentRunner:
    """Executes paired trials across B0, B1, B2, G, G-nobr, and G-nosoak with resume."""

    def __init__(
        self,
        config: GateHealConfig,
        *,
        controller_transport: CommandTransport,
        root_transport: CommandTransport,
        artifacts_dir: Path,
        guest_repo_dir: str = "/opt/gateheal",
        oracle_hold_window_sec: float = MIN_ORACLE_HOLD_WINDOW_SEC,
        settle_wait_sec: float = 5.5,
        pre_state_timeout_sec: float = 20.0,
        verbose_progress: bool = False,
        clock_utc: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ) -> None:
        self._base_config = config
        self._controller_transport = controller_transport
        self._root_transport = root_transport
        self._artifacts_dir = artifacts_dir.resolve()
        self._artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._guest_repo_dir = guest_repo_dir
        self._settle_wait_sec = settle_wait_sec
        self._pre_state_timeout_sec = pre_state_timeout_sec
        self._verbose_progress = verbose_progress
        self._clock_utc: Callable[[], datetime] = (
            _default_utc_now if clock_utc is None else clock_utc
        )
        self._monotonic_clock: Callable[[], float] = (
            time.monotonic if monotonic_clock is None else monotonic_clock
        )
        self._sleep_fn: Callable[[float], None] = (
            time.sleep if sleep_fn is None else sleep_fn
        )
        self._oracle = IndependentLabOracle(
            root_transport,
            hold_window_sec=oracle_hold_window_sec,
            monotonic_clock=self._monotonic_clock,
            sleep_fn=self._sleep_fn,
        )

    @property
    def trials_jsonl_path(self) -> Path:
        """Return path to the append-only trials JSONL file."""
        return self._artifacts_dir / "trials.jsonl"

    def _reset_and_inject(self, exp: SmokeMatrixExpectation) -> None:
        _ = self._root_transport.run(
            (
                "env",
                "GATEHEAL_INSIDE_LAB=1",
                "bash",
                f"{self._guest_repo_dir}/lab/reset/reset_lab.sh",
            ),
            timeout_sec=15.0,
        )
        if exp.fault_injection_arg is not None:
            _ = self._root_transport.run(
                (
                    "env",
                    "GATEHEAL_INSIDE_LAB=1",
                    "bash",
                    f"{self._guest_repo_dir}/lab/fault_injection/inject_fault.sh",
                    exp.fault_injection_arg,
                ),
                timeout_sec=10.0,
            )
        _ = wait_for_expected_pre_state(
            self._controller_transport,
            exp.expected_pre_active_states,
            timeout_sec=self._pre_state_timeout_sec,
            poll_interval_sec=0.5,
            grace_wait_sec=self._settle_wait_sec,
            monotonic_clock=self._monotonic_clock,
            sleep_fn=self._sleep_fn,
        )

    def run_single_arm_trial(
        self,
        exp: SmokeMatrixExpectation,
        repeat_index: int,
        arm_id: str,
        arm_order_in_block: int,
    ) -> WP6TrialRecord:
        """Reset lab, inject scenario fault, run arm_id, and evaluate via IndependentLabOracle."""
        if arm_id not in ALL_WP6_ARMS:
            raise ValueError(f"Unsupported WP6 arm: {arm_id!r}")

        is_ungated = arm_id in UNGATED_ARMS
        if is_ungated:
            ensure_transport_sentinel_verified(self._root_transport)

        self._reset_and_inject(exp)
        pre_snap = self._oracle.capture_snapshot("pre")

        trial_id = f"wp6-{exp.scenario_id.lower()}-r{repeat_index:02d}-{arm_id.lower()}"
        started_utc = self._clock_utc().isoformat()
        t0 = self._monotonic_clock()

        collector = IncidentCollector(
            self._base_config, monotonic_clock=self._monotonic_clock
        )
        diag_engine = DiagnosisEngine(self._base_config)

        if arm_id == "B0":
            inc = collector.collect_from_transport(
                incident_id=trial_id,
                target_unit="lab-api.service",
                transport=self._controller_transport,
                prior_recovery_attempts=exp.seed_prior_recovery_attempts,
                action_history=exp.seed_action_history,
            )
            diag = diag_engine.diagnose(inc)
            selected_action = "observe_only"
            selected_target: str | None = None
            abstained = False
            escalated = False
            mutating_taken = False
            executed_argvs: tuple[tuple[str, ...], ...] = ()
            verifier_samples = 0
        elif arm_id == "B1":
            ensure_transport_sentinel_verified(self._root_transport)
            inc = collector.collect_from_transport(
                incident_id=trial_id,
                target_unit="lab-api.service",
                transport=self._controller_transport,
                prior_recovery_attempts=exp.seed_prior_recovery_attempts,
                action_history=exp.seed_action_history,
            )
            diag = diag_engine.diagnose(inc)
            cmd_argv = ("systemctl", "restart", "lab-api.service")
            _ = self._root_transport.run(cmd_argv, timeout_sec=10.0)
            selected_action = ActionId.RESTART_SERVICE.value
            selected_target = "lab-api.service"
            abstained = False
            escalated = False
            mutating_taken = True
            executed_argvs = (cmd_argv,)
            verifier_samples = 0
        elif arm_id == "B2":
            ensure_transport_sentinel_verified(self._root_transport)
            inc = collector.collect_from_transport(
                incident_id=trial_id,
                target_unit="lab-api.service",
                transport=self._controller_transport,
                prior_recovery_attempts=exp.seed_prior_recovery_attempts,
                action_history=exp.seed_action_history,
            )
            proposer = SimulatedLLMAgentProposer(self._base_config)
            batch = proposer.propose(inc)
            diag = batch.diagnosis
            chosen = batch.proposals[0]
            selected_action = chosen.action_id
            selected_target = chosen.target_unit
            abstained = chosen.action_id == ActionId.ABSTAIN_AND_ESCALATE.value
            escalated = abstained
            if (
                chosen.action_id == ActionId.RESTART_SERVICE.value
                and chosen.target_unit is not None
            ):
                cmd_argv = ("systemctl", "restart", chosen.target_unit)
                _ = self._root_transport.run(cmd_argv, timeout_sec=10.0)
                mutating_taken = True
                executed_argvs = (cmd_argv,)
            elif (
                chosen.action_id == ActionId.RELOAD_SERVICE.value
                and chosen.target_unit is not None
            ):
                cmd_argv = ("systemctl", "reload", chosen.target_unit)
                _ = self._root_transport.run(cmd_argv, timeout_sec=10.0)
                mutating_taken = True
                executed_argvs = (cmd_argv,)
            else:
                mutating_taken = False
                executed_argvs = ()
            verifier_samples = 0
        else:
            arm_cfg = make_arm_config(self._base_config, arm_id)
            rec_transport = RecordingTransport(self._controller_transport)
            state_dir = self._artifacts_dir / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            state_store = PersistentStateStore(state_dir / f"{trial_id}.json")
            state_store.seed_unit_state(
                "lab-api.service",
                incident_id=trial_id,
                prior_recovery_attempts=exp.seed_prior_recovery_attempts,
                action_history=exp.seed_action_history,
            )
            orch = IncidentOrchestrator(
                arm_cfg,
                transport=rec_transport,
                audit_recorder=AuditRecorder(
                    state_dir / f"{trial_id}_audit.jsonl",
                    clock_utc=self._clock_utc,
                ),
                escalation_sink=EscalationSink(
                    state_dir / f"{trial_id}_esc.jsonl"
                ),
                state_store=state_store,
                clock_utc=self._clock_utc,
                monotonic_clock=self._monotonic_clock,
                sleep_fn=self._sleep_fn,
            )
            audit = orch.handle_incident(
                incident_id=trial_id,
                target_unit="lab-api.service",
                controller_mode_override=arm_id,
            )
            if audit.selected_proposal is None or audit.verification_report is None:
                raise RuntimeError(f"Arm {arm_id} produced incomplete AuditRecord.")
            diag = audit.diagnosis
            selected_action = audit.selected_proposal.action_id
            selected_target = audit.selected_proposal.target_unit
            abstained = audit.abstained
            escalated = audit.escalated
            executed_argvs = tuple(rec_transport.mutating_commands)
            mutating_taken = len(executed_argvs) > 0
            verifier_samples = audit.verification_report.samples_collected

        action_dur = round(max(0.0, self._monotonic_clock() - t0), 3)
        oracle_eval = self._oracle.evaluate_after_action(
            scenario_id=exp.scenario_id,
            pre_snapshot=pre_snap,
            mutating_action_taken=mutating_taken,
            abstained=abstained,
            action_duration_sec=action_dur,
        )
        finished_utc = self._clock_utc().isoformat()

        return WP6TrialRecord(
            trial_id=trial_id,
            scenario_id=exp.scenario_id,
            repeat_index=repeat_index,
            arm_id=arm_id,
            arm_order_in_block=arm_order_in_block,
            ungated_arm=is_ungated,
            started_at_utc=started_utc,
            finished_at_utc=finished_utc,
            diagnosed_fault=diag.fault_class,
            selected_action_id=selected_action,
            selected_target_unit=selected_target,
            abstained=abstained,
            escalated=escalated,
            mutating_action_taken=mutating_taken,
            executed_argvs=executed_argvs,
            action_duration_sec=action_dur,
            verifier_samples_collected=verifier_samples,
            evaluable=True,
            oracle_evaluation=oracle_eval,
        )

    def run_campaign(
        self,
        *,
        trials_per_scenario: int = 20,
        seed: int = 20261028,
        arms: Sequence[str] = ALL_WP6_ARMS,
        expectations: Sequence[SmokeMatrixExpectation] | None = None,
    ) -> tuple[WP6TrialRecord, ...]:
        """Run or resume a paired WP6 campaign and persist each trial to JSONL."""
        exps = (
            build_wp5_smoke_expectations()
            if expectations is None
            else tuple(expectations)
        )
        exp_by_id = {e.scenario_id: e for e in exps}
        scen_ids = tuple(e.scenario_id for e in exps)
        schedule = build_paired_arm_schedule(
            scen_ids, trials_per_scenario, arms, seed=seed
        )
        completed = load_completed_wp6_trials(self.trials_jsonl_path)
        all_records: list[WP6TrialRecord] = []
        total_planned = len(scen_ids) * trials_per_scenario * len(arms)

        for (scen_id, repeat_idx), arm_order in schedule.items():
            exp = exp_by_id[scen_id]
            for order_idx, arm_id in enumerate(arm_order):
                key = (scen_id, repeat_idx, arm_id)
                if key in completed:
                    all_records.append(completed[key])
                    continue
                rec = self.run_single_arm_trial(
                    exp, repeat_idx, arm_id, order_idx
                )
                append_wp6_trial_record(self.trials_jsonl_path, rec)
                completed[key] = rec
                all_records.append(rec)
                if self._verbose_progress:
                    out_lbl = rec.oracle_evaluation.outcome.value
                    print(
                        f"[WP6 {len(all_records)}/{total_planned}] "
                        f"scen={scen_id} r={repeat_idx} arm={arm_id} "
                        f"action={rec.selected_action_id} outcome={out_lbl}",
                        file=sys.stderr,
                        flush=True,
                    )

        return tuple(all_records)


def build_wp6_campaign_manifest(
    *,
    repo_root: Path,
    config_path: Path,
    wp5_manifest_path: Path,
    seed: int,
    arms: Sequence[str],
    scenarios: Sequence[str],
    trials_per_scenario: int,
    oracle_hold_window_sec: float,
    completed_trials: int,
    allow_dirty: bool = False,
    clock_utc: Callable[[], datetime] | None = None,
) -> WP6CampaignManifest:
    """Validate preflight and build a WP6CampaignManifest."""
    now_fn: Callable[[], datetime] = (
        _default_utc_now if clock_utc is None else clock_utc
    )
    wp5_manifest, wp5_hash, git_sha, git_dirty = validate_wp6_preflight(
        repo_root=repo_root,
        wp5_manifest_path=wp5_manifest_path,
        allow_dirty=allow_dirty,
    )
    cfg_hash = compute_file_sha256(config_path)
    total_planned = len(arms) * len(scenarios) * trials_per_scenario
    return WP6CampaignManifest(
        generated_at_utc=now_fn().isoformat(),
        wp5_manifest_path=str(wp5_manifest_path),
        wp5_manifest_sha256=wp5_hash,
        git_sha=git_sha,
        git_dirty=git_dirty,
        config_sha256=cfg_hash,
        seed=seed,
        arms=tuple(arms),
        scenarios=tuple(scenarios),
        trials_per_scenario=trials_per_scenario,
        oracle_hold_window_sec=oracle_hold_window_sec,
        tool_versions={
            "python": platform.python_version(),
            "pydantic": pydantic.__version__,
            "guest_kernel": wp5_manifest.guest_kernel,
            "guest_systemd_version": wp5_manifest.guest_systemd_version,
        },
        total_planned_trials=total_planned,
        completed_trials=completed_trials,
    )


def summarize_wp6_campaign(
    records: Sequence[WP6TrialRecord],
    *,
    trials_per_scenario: int,
    seed: int = 20261028,
    arms: Sequence[str] = ALL_WP6_ARMS,
    scenarios: Sequence[str] | None = None,
    clock_utc: Callable[[], datetime] | None = None,
) -> WP6CampaignSummary:
    """Compute unconditional arm rates, coverage tables, paired tests, and Holm p-values."""
    now_fn: Callable[[], datetime] = (
        _default_utc_now if clock_utc is None else clock_utc
    )
    scen_list = (
        tuple(SCENARIO_RECOVERABLE.keys())
        if scenarios is None
        else tuple(scenarios)
    )
    planned_per_arm = len(scen_list) * trials_per_scenario

    by_arm: dict[str, list[WP6TrialRecord]] = {a: [] for a in arms}
    for r in records:
        if r.arm_id in by_arm:
            by_arm[r.arm_id].append(r)

    coverage: dict[str, WP6CoverageRow] = {}
    arm_summaries: dict[str, WP6ArmSummary] = {}
    scenario_arm_outcomes: dict[str, dict[str, dict[str, int]]] = {
        s: {
            a: {lbl.value: 0 for lbl in OracleOutcomeLabel}
            for a in arms
        }
        for s in scen_list
    }

    for r in records:
        scen_outcomes = scenario_arm_outcomes.get(r.scenario_id)
        if scen_outcomes is not None and r.arm_id in scen_outcomes:
            lbl_key = r.oracle_evaluation.outcome.value
            scen_outcomes[r.arm_id][lbl_key] += 1

    for arm_id in arms:
        arm_recs = by_arm[arm_id]
        total = len(arm_recs)
        eval_cnt = sum(1 for r in arm_recs if r.evaluable)
        non_eval_cnt = total - eval_cnt
        mut_cnt = sum(1 for r in arm_recs if r.mutating_action_taken)
        abs_cnt = sum(1 for r in arm_recs if r.abstained)
        obs_cnt = total - mut_cnt - abs_cnt

        coverage[arm_id] = WP6CoverageRow(
            arm_id=arm_id,
            ungated_arm=arm_id in UNGATED_ARMS,
            planned_trials=planned_per_arm,
            completed_trials=total,
            evaluable_trials=eval_cnt,
            non_evaluable_trials=non_eval_cnt,
            mutating_trials=mut_cnt,
            abstained_trials=abs_cnt,
            observe_only_or_noop_trials=max(0, obs_cnt),
        )

        rec_trials = sum(
            1
            for r in arm_recs
            if r.scenario_id != "S0_HEALTHY_CONTROL"
            and r.oracle_evaluation.recoverable_scenario
        )
        unrec_trials = sum(
            1
            for r in arm_recs
            if not r.oracle_evaluation.recoverable_scenario
        )
        s0_trials = sum(
            1 for r in arm_recs if r.scenario_id == "S0_HEALTHY_CONTROL"
        )

        def _count_outcome(
            target_label: OracleOutcomeLabel,
            _recs: list[WP6TrialRecord] = arm_recs,
        ) -> int:
            return sum(
                1
                for r in _recs
                if r.oracle_evaluation.outcome == target_label
            )

        approp_abs_cnt = sum(
            1 for r in arm_recs if r.oracle_evaluation.appropriate_abstention
        )
        mean_unavail = (
            round(
                sum(r.oracle_evaluation.unavailability_sec for r in arm_recs)
                / total,
                3,
            )
            if total > 0
            else 0.0
        )

        arm_summaries[arm_id] = WP6ArmSummary(
            arm_id=arm_id,
            ungated_arm=arm_id in UNGATED_ARMS,
            total_trials=total,
            evaluable_trials=eval_cnt,
            non_evaluable_trials=non_eval_cnt,
            recoverable_trials=rec_trials,
            unrecoverable_trials=unrec_trials,
            healthy_control_trials=s0_trials,
            mutating_trials=mut_cnt,
            abstained_trials=abs_cnt,
            recovered_all_rate=wilson_score_interval(
                _count_outcome(OracleOutcomeLabel.RECOVERED_ALL), total
            ),
            recovered_with_collateral_rate=wilson_score_interval(
                _count_outcome(OracleOutcomeLabel.RECOVERED_WITH_COLLATERAL),
                total,
            ),
            not_recovered_rate=wilson_score_interval(
                _count_outcome(OracleOutcomeLabel.NOT_RECOVERED), total
            ),
            harmful_rate=wilson_score_interval(
                _count_outcome(OracleOutcomeLabel.HARMFUL), total
            ),
            no_change_correct_rate=wilson_score_interval(
                _count_outcome(OracleOutcomeLabel.NO_CHANGE_CORRECT), total
            ),
            false_positive_remediation_rate=wilson_score_interval(
                _count_outcome(OracleOutcomeLabel.FALSE_POSITIVE_REMEDIATION),
                total,
            ),
            abstention_rate=wilson_score_interval(abs_cnt, total),
            appropriate_abstention_rate=wilson_score_interval(
                approp_abs_cnt, total
            ),
            mean_unavailability_sec=mean_unavail,
        )

    by_pair_key: dict[str, dict[tuple[str, int], WP6TrialRecord]] = {
        a: {(r.scenario_id, r.repeat_index): r for r in by_arm[a]}
        for a in arms
    }

    def _build_paired_comp(
        comp_id: str,
        hyp_id: str,
        desc: str,
        arm_a: str,
        arm_b: str,
        binary_fn: Callable[[WP6TrialRecord], bool],
    ) -> WP6PairedComparison | None:
        if arm_a not in by_pair_key or arm_b not in by_pair_key:
            return None
        common_keys = sorted(
            set(by_pair_key[arm_a].keys()) & set(by_pair_key[arm_b].keys())
        )
        if not common_keys:
            return None
        seq_a = [binary_fn(by_pair_key[arm_a][k]) for k in common_keys]
        seq_b = [binary_fn(by_pair_key[arm_b][k]) for k in common_keys]
        unavail_a = [
            by_pair_key[arm_a][k].oracle_evaluation.unavailability_sec
            for k in common_keys
        ]
        unavail_b = [
            by_pair_key[arm_b][k].oracle_evaluation.unavailability_sec
            for k in common_keys
        ]
        n_p = len(common_keys)
        rate_a = round(sum(1 for v in seq_a if v) / n_p, 6)
        rate_b = round(sum(1 for v in seq_b if v) / n_p, 6)
        return WP6PairedComparison(
            comparison_id=comp_id,
            hypothesis_id=hyp_id,
            description=desc,
            arm_a=arm_a,
            arm_b=arm_b,
            n_pairs=n_p,
            rate_a=rate_a,
            rate_b=rate_b,
            rate_diff_a_minus_b=round(rate_a - rate_b, 6),
            mcnemar=exact_mcnemar_test(seq_a, seq_b),
            unavailability_wilcoxon=wilcoxon_signed_rank_test(
                unavail_a, unavail_b
            ),
            unavailability_bootstrap=paired_bootstrap_mean_diff(
                unavail_a, unavail_b, seed=seed
            ),
        )

    specs: list[
        tuple[str, str, str, str, str, Callable[[WP6TrialRecord], bool]]
    ] = [
        (
            "H1a_G_vs_B1_harmful",
            "H1",
            "H1a: Harmful outcome rate (G vs B1, unconditional)",
            "G",
            "B1",
            lambda r: r.oracle_evaluation.outcome == OracleOutcomeLabel.HARMFUL,
        ),
        (
            "H1b_G_vs_B2_harmful",
            "H1",
            "H1b: Harmful outcome rate (G vs B2, unconditional)",
            "G",
            "B2",
            lambda r: r.oracle_evaluation.outcome == OracleOutcomeLabel.HARMFUL,
        ),
        (
            "H2_G_vs_B1_recovery",
            "H2",
            "H2: Clean recovery rate (G vs B1, unconditional)",
            "G",
            "B1",
            lambda r: (
                r.oracle_evaluation.outcome == OracleOutcomeLabel.RECOVERED_ALL
            ),
        ),
        (
            "H3a_G_vs_B1_abstention",
            "H3",
            "H3a: Appropriate abstention rate (G vs B1, unconditional)",
            "G",
            "B1",
            lambda r: r.oracle_evaluation.appropriate_abstention,
        ),
        (
            "H3b_G_vs_B2_abstention",
            "H3",
            "H3b: Appropriate abstention rate (G vs B2, unconditional)",
            "G",
            "B2",
            lambda r: r.oracle_evaluation.appropriate_abstention,
        ),
    ]

    comparisons: list[WP6PairedComparison] = []
    raw_family: list[tuple[str, float]] = []
    for comp_id, hyp_id, desc, a_id, b_id, pred in specs:
        comp = _build_paired_comp(comp_id, hyp_id, desc, a_id, b_id, pred)
        if comp is not None:
            comparisons.append(comp)
            raw_family.append((comp_id, comp.mcnemar.p_value))

    holm_results = holm_bonferroni_correction(raw_family, alpha=0.05)
    return WP6CampaignSummary(
        generated_at_utc=now_fn().isoformat(),
        seed=seed,
        trials_per_scenario=trials_per_scenario,
        coverage=coverage,
        arm_summaries=arm_summaries,
        scenario_arm_outcomes=scenario_arm_outcomes,
        paired_comparisons=tuple(comparisons),
        holm_bonferroni_family=holm_results,
    )
