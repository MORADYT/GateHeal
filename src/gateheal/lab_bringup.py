"""WP5 real-lab conformance parser, SSH latency profiler, S0-S5B smoke matrix, and manifest."""

from __future__ import annotations

import hashlib
import statistics
import subprocess
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from gateheal.collector import parse_systemctl_show
from gateheal.models import ActionId, FaultClass, VerificationStatus
from gateheal.transport import CommandTransport

DEFAULT_PINNED_UBUNTU_RELEASE = "release-20250219"


class ConformanceFactResult(BaseModel):
    """Single parsed PASS/FAIL line from `lab/scripts/check_conformance.sh`."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    fact_id: str
    passed: bool
    details: str


class SSHLatencyProfile(BaseModel):
    """Measured SSH command round-trip latency statistics in milliseconds."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    samples: Annotated[int, Field(ge=1)]
    min_ms: Annotated[float, Field(ge=0.0)]
    mean_ms: Annotated[float, Field(ge=0.0)]
    p95_ms: Annotated[float, Field(ge=0.0)]
    max_ms: Annotated[float, Field(ge=0.0)]


class SmokeMatrixExpectation(BaseModel):
    """Expected controller decision and verification outcome for a live lab scenario."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    scenario_id: str
    fault_injection_arg: str | None
    seed_prior_recovery_attempts: int = 0
    seed_action_history: tuple[str, ...] = ()
    requires_approval_token: bool = False
    expected_pre_active_states: dict[str, str] = Field(
        default_factory=lambda: {
            "lab-redis.service": "active",
            "lab-api.service": "active",
            "lab-worker.service": "active",
        }
    )
    expected_fault_classes: tuple[FaultClass, ...]
    expected_action_id: ActionId
    expected_target_unit: str
    expected_verification_status: VerificationStatus
    expected_collateral_failures: tuple[str, ...] = ()
    expected_escalated: bool
    expected_mutating_commands: int = 1


class SmokeScenarioRunResult(BaseModel):
    """Recorded live execution result for a single S0-S5B smoke scenario run."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    scenario_id: str
    repeat_index: int = 1
    diagnosed_fault: FaultClass
    selected_action_id: str
    selected_target_unit: str | None
    verification_status: VerificationStatus
    collateral_failures: tuple[str, ...] = ()
    samples_collected: int
    soak_wall_clock_sec: float
    soak_budget_ok: bool = True
    ssh_command_count: int = 0
    mutating_commands_executed: int = 0
    escalated: bool
    matched_expectation: bool


class LabRunManifest(BaseModel):
    """Machine-readable WP5 lab bring-up and verification manifest."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schema_version: str = "1.0"
    generated_at_utc: str
    git_sha: str
    git_dirty: bool
    config_sha256: str
    sudoers_sha256: str
    base_image_release: str = DEFAULT_PINNED_UBUNTU_RELEASE
    base_image_sha256: str | None = None
    base_image_upstream_sha256: str | None = None
    overlay_image_sha256: str | None = None
    guest_kernel: str = "unknown"
    guest_systemd_version: str = "unknown"
    guest_machine_id_sha256: str | None = None
    controller_key_root_login_denied: bool = False
    nrestarts_manual_restart_observation: str = "unknown"
    ssh_latency: SSHLatencyProfile
    ssh_latency_multiplexed: SSHLatencyProfile | None = None
    conformance_facts: tuple[ConformanceFactResult, ...]
    conformance_all_passed: bool
    repeats: int = 1
    flake_count: int = 0
    soak_budget_ok: bool = True
    smoke_matrix: tuple[SmokeScenarioRunResult, ...]
    smoke_all_passed: bool


def compute_file_sha256(path: Path) -> str:
    """Compute hex SHA-256 digest of a file on disk."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def resolve_git_revision(repo_root: Path) -> tuple[str, bool]:
    """Return (git_commit_sha, is_working_tree_dirty) for repo_root."""
    try:
        sha_proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root.resolve()),
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        sha = sha_proc.stdout.strip() if sha_proc.returncode == 0 else "unknown"
        status_proc = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo_root.resolve()),
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        dirty = bool(status_proc.stdout.strip())
        return sha or "unknown", dirty
    except OSError:
        return "unknown", False


def parse_conformance_output(raw_stdout: str) -> tuple[ConformanceFactResult, ...]:
    """Parse PASS/FAIL lines emitted by `lab/scripts/check_conformance.sh`."""
    results: list[ConformanceFactResult] = []
    for raw_line in raw_stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("PASS: ") or line.startswith("FAIL: "):
            passed = line.startswith("PASS: ")
            body = line[6:]
            if " :: " in body:
                fact_id, details = body.split(" :: ", 1)
            else:
                fact_id, details = body, ""
            results.append(
                ConformanceFactResult(
                    fact_id=fact_id.strip(),
                    passed=passed,
                    details=details.strip(),
                )
            )
    return tuple(results)


def extract_nrestarts_observation(
    conformance_facts: Sequence[ConformanceFactResult],
) -> str:
    """Extract `observed=<preserved|reset>` from FACT_5B_MANUAL_RESTART_NRESTARTS."""
    for fact in conformance_facts:
        if fact.fact_id == "FACT_5B_MANUAL_RESTART_NRESTARTS":
            for token in fact.details.split():
                if token.startswith("observed="):
                    val = token.split("=", 1)[1].strip()
                    if val:
                        return val
    return "unknown"


def measure_transport_latency(
    transport: CommandTransport,
    *,
    samples: int = 10,
    monotonic_clock: Callable[[], float] = time.monotonic,
) -> SSHLatencyProfile:
    """Measure round-trip execution latency over transport in milliseconds."""
    if samples < 1:
        raise ValueError("samples must be >= 1")
    durations_ms: list[float] = []
    for _ in range(samples):
        t0 = monotonic_clock()
        res = transport.run(("systemctl", "--version"), timeout_sec=5.0)
        elapsed_ms = max(0.0, (monotonic_clock() - t0) * 1000.0)
        if res.timed_out or res.exit_code != 0:
            raise RuntimeError(
                f"Transport latency probe failed (exit={res.exit_code}, "
                f"timed_out={res.timed_out})."
            )
        durations_ms.append(elapsed_ms)

    sorted_ms = sorted(durations_ms)
    p95_idx = min(len(sorted_ms) - 1, max(0, int(round(0.95 * (len(sorted_ms) - 1)))))
    return SSHLatencyProfile(
        samples=samples,
        min_ms=round(sorted_ms[0], 3),
        mean_ms=round(statistics.fmean(sorted_ms), 3),
        p95_ms=round(sorted_ms[p95_idx], 3),
        max_ms=round(sorted_ms[-1], 3),
    )


def wait_for_expected_pre_state(
    transport: CommandTransport,
    expected_active_states: dict[str, str],
    *,
    timeout_sec: float = 20.0,
    poll_interval_sec: float = 0.5,
    grace_wait_sec: float = 5.5,
    monotonic_clock: Callable[[], float] = time.monotonic,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> float:
    """Poll until all units reach their expected pre-state, then sleep grace_wait_sec."""
    start = monotonic_clock()
    last_observed: dict[str, str] = {}

    while True:
        all_matched = True
        for unit_name, expected_state in expected_active_states.items():
            res = transport.run(
                ("systemctl", "show", unit_name, "--property=ActiveState,SubState"),
                timeout_sec=5.0,
            )
            props = parse_systemctl_show(res.stdout_excerpt)
            actual_state = props.get("ActiveState", "unknown").strip()
            last_observed[unit_name] = actual_state
            if actual_state != expected_state:
                all_matched = False

        if all_matched:
            if grace_wait_sec > 0.0:
                sleep_fn(grace_wait_sec)
            return max(0.0, monotonic_clock() - start)

        if monotonic_clock() - start >= timeout_sec:
            raise RuntimeError(
                f"Timed out after {timeout_sec}s waiting for expected unit "
                f"pre-states {expected_active_states}; last_observed={last_observed}"
            )
        sleep_fn(poll_interval_sec)


def build_wp5_smoke_expectations() -> tuple[SmokeMatrixExpectation, ...]:
    """Return the canonical 7-scenario S0-S5B smoke matrix expectations for WP5."""
    return (
        SmokeMatrixExpectation(
            scenario_id="S0_HEALTHY_CONTROL",
            fault_injection_arg=None,
            expected_pre_active_states={
                "lab-redis.service": "active",
                "lab-api.service": "active",
                "lab-worker.service": "active",
            },
            expected_fault_classes=(FaultClass.HEALTHY,),
            expected_action_id=ActionId.NO_OP,
            expected_target_unit="lab-api.service",
            expected_verification_status=VerificationStatus.RECOVERED_CLEAN,
            expected_collateral_failures=(),
            expected_escalated=False,
            expected_mutating_commands=0,
        ),
        SmokeMatrixExpectation(
            scenario_id="S1_SERVICE_CRASH",
            fault_injection_arg="S1_SERVICE_CRASH",
            expected_pre_active_states={
                "lab-redis.service": "active",
                "lab-api.service": "failed",
                "lab-worker.service": "active",
            },
            expected_fault_classes=(FaultClass.PROCESS_CRASH,),
            expected_action_id=ActionId.RESTART_SERVICE,
            expected_target_unit="lab-api.service",
            expected_verification_status=VerificationStatus.RECOVERED_CLEAN,
            expected_collateral_failures=(),
            expected_escalated=False,
            expected_mutating_commands=1,
        ),
        SmokeMatrixExpectation(
            scenario_id="S2_INVALID_CONFIG",
            fault_injection_arg="S2_INVALID_CONFIG",
            expected_pre_active_states={
                "lab-redis.service": "active",
                "lab-api.service": "active",
                "lab-worker.service": "active",
            },
            expected_fault_classes=(FaultClass.INVALID_CONFIG,),
            expected_action_id=ActionId.ABSTAIN_AND_ESCALATE,
            expected_target_unit="lab-api.service",
            expected_verification_status=VerificationStatus.FAULT_PERSISTS_SERVICE_UP,
            expected_collateral_failures=(),
            expected_escalated=True,
            expected_mutating_commands=0,
        ),
        SmokeMatrixExpectation(
            scenario_id="S3_DEPENDENCY_FAILURE",
            fault_injection_arg="S3_DEPENDENCY_FAILURE",
            expected_pre_active_states={
                "lab-redis.service": "failed",
                "lab-api.service": "active",
                "lab-worker.service": "active",
            },
            expected_fault_classes=(FaultClass.DEPENDENCY_FAILURE,),
            expected_action_id=ActionId.RESTART_SERVICE,
            expected_target_unit="lab-redis.service",
            expected_verification_status=VerificationStatus.RECOVERED_CLEAN,
            expected_collateral_failures=(),
            expected_escalated=False,
            expected_mutating_commands=1,
        ),
        SmokeMatrixExpectation(
            scenario_id="S4_PERSISTENT_FAILURE",
            fault_injection_arg="S4_PERSISTENT_FAILURE",
            seed_prior_recovery_attempts=1,
            seed_action_history=("restart_service:lab-api.service",),
            expected_pre_active_states={
                "lab-redis.service": "active",
                "lab-api.service": "failed",
                "lab-worker.service": "active",
            },
            expected_fault_classes=(
                FaultClass.PERSISTENT_FAILURE,
                FaultClass.INVALID_CONFIG,
            ),
            expected_action_id=ActionId.ABSTAIN_AND_ESCALATE,
            expected_target_unit="lab-api.service",
            expected_verification_status=VerificationStatus.NOT_RECOVERED,
            expected_collateral_failures=(),
            expected_escalated=True,
            expected_mutating_commands=0,
        ),
        SmokeMatrixExpectation(
            scenario_id="S5_COLLATERAL_TRAP",
            fault_injection_arg="S5_COLLATERAL_TRAP",
            expected_pre_active_states={
                "lab-redis.service": "active",
                "lab-api.service": "active",
                "lab-worker.service": "active",
            },
            expected_fault_classes=(FaultClass.DEGRADED_RUNNING,),
            expected_action_id=ActionId.RELOAD_SERVICE,
            expected_target_unit="lab-api.service",
            expected_verification_status=VerificationStatus.RECOVERED_CLEAN,
            expected_collateral_failures=(),
            expected_escalated=False,
            expected_mutating_commands=1,
        ),
        SmokeMatrixExpectation(
            scenario_id="S5B_COLLATERAL_FORCED_RESTART",
            fault_injection_arg="S5_COLLATERAL_TRAP",
            seed_prior_recovery_attempts=1,
            seed_action_history=("reload_service:lab-api.service",),
            requires_approval_token=True,
            expected_pre_active_states={
                "lab-redis.service": "active",
                "lab-api.service": "active",
                "lab-worker.service": "active",
            },
            expected_fault_classes=(FaultClass.DEGRADED_RUNNING,),
            expected_action_id=ActionId.RESTART_SERVICE,
            expected_target_unit="lab-api.service",
            expected_verification_status=(
                VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE
            ),
            expected_collateral_failures=("lab-worker.service",),
            expected_escalated=True,
            expected_mutating_commands=1,
        ),
    )


def _default_utc_now() -> datetime:
    return datetime.now(UTC)


def build_lab_run_manifest(
    *,
    repo_root: Path,
    config_path: Path,
    sudoers_path: Path,
    ssh_latency: SSHLatencyProfile,
    ssh_latency_multiplexed: SSHLatencyProfile | None = None,
    conformance_facts: Sequence[ConformanceFactResult],
    smoke_matrix: Sequence[SmokeScenarioRunResult],
    guest_kernel: str = "unknown",
    guest_systemd_version: str = "unknown",
    guest_machine_id_sha256: str | None = None,
    controller_key_root_login_denied: bool = False,
    nrestarts_manual_restart_observation: str | None = None,
    base_image_release: str = DEFAULT_PINNED_UBUNTU_RELEASE,
    base_image_upstream_sha256: str | None = None,
    base_image_path: Path | None = None,
    overlay_image_path: Path | None = None,
    repeats: int = 1,
    clock_utc: Callable[[], datetime] | None = None,
) -> LabRunManifest:
    """Construct a validated LabRunManifest with git SHA and artifact hashes."""
    now_fn: Callable[[], datetime] = (
        _default_utc_now if clock_utc is None else clock_utc
    )
    git_sha, git_dirty = resolve_git_revision(repo_root)
    cfg_hash = compute_file_sha256(config_path)
    sudo_hash = compute_file_sha256(sudoers_path)
    base_hash = (
        compute_file_sha256(base_image_path)
        if base_image_path is not None and base_image_path.is_file()
        else None
    )
    ovl_hash = (
        compute_file_sha256(overlay_image_path)
        if overlay_image_path is not None and overlay_image_path.is_file()
        else None
    )
    facts_tuple = tuple(conformance_facts)
    smoke_tuple = tuple(smoke_matrix)
    flake_count = sum(1 for s in smoke_tuple if not s.matched_expectation)
    all_soak_budget_ok = bool(smoke_tuple) and all(
        s.soak_budget_ok for s in smoke_tuple
    )
    observed_d4 = (
        extract_nrestarts_observation(facts_tuple)
        if nrestarts_manual_restart_observation is None
        else nrestarts_manual_restart_observation
    )
    return LabRunManifest(
        generated_at_utc=now_fn().isoformat(),
        git_sha=git_sha,
        git_dirty=git_dirty,
        config_sha256=cfg_hash,
        sudoers_sha256=sudo_hash,
        base_image_release=base_image_release,
        base_image_upstream_sha256=base_image_upstream_sha256,
        base_image_sha256=base_hash,
        overlay_image_sha256=ovl_hash,
        guest_kernel=guest_kernel,
        guest_systemd_version=guest_systemd_version,
        guest_machine_id_sha256=guest_machine_id_sha256,
        controller_key_root_login_denied=controller_key_root_login_denied,
        nrestarts_manual_restart_observation=observed_d4,
        ssh_latency=ssh_latency,
        ssh_latency_multiplexed=ssh_latency_multiplexed,
        conformance_facts=facts_tuple,
        conformance_all_passed=bool(facts_tuple)
        and all(f.passed for f in facts_tuple),
        repeats=repeats,
        flake_count=flake_count,
        soak_budget_ok=all_soak_budget_ok,
        smoke_matrix=smoke_tuple,
        smoke_all_passed=bool(smoke_tuple)
        and flake_count == 0
        and all_soak_budget_ok,
    )
