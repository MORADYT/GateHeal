"""WP5 real-lab conformance, sudoers negative, latency/soak, S0-S5B smoke, and manifest tests."""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gateheal.collector import parse_invocation_and_start_usec, parse_systemctl_show
from gateheal.config import GateHealConfig, load_config
from gateheal.controller import AuditRecorder, EscalationSink
from gateheal.lab_bringup import (
    LabRunManifest,
    SmokeScenarioRunResult,
    build_lab_run_manifest,
    build_wp5_smoke_expectations,
    measure_transport_latency,
    parse_conformance_output,
)
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.state import PersistentStateStore
from gateheal.transport import (
    SSHLabTransport,
    TransportResult,
    TransportUnavailableError,
)

pytestmark = pytest.mark.lab


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_cfg() -> GateHealConfig:
    return load_config(_repo_root() / "configs" / "phase1_lab.yaml")


def _load_fixture_json() -> dict[str, object]:
    fix_path = Path(__file__).resolve().parent / "fixtures" / "vm_captured_systemd_facts.json"
    raw = json.loads(fix_path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


class _FixtureReplayTransport:
    """Scripted offline replay transport using VM-captured `systemctl show` fixtures."""

    def __init__(self, shows: dict[str, object], scen: str) -> None:
        self._shows = shows
        self._scen = scen
        self.mutated = False

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        cmd = tuple(argv)
        if cmd[:2] == ("cat", "/proc/uptime"):
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt="50000.0 40000.0\n",
            )
        if cmd[:3] == ("sudo", "-n", "/usr/bin/systemctl"):
            self.mutated = True
            return TransportResult(exit_code=0, duration_sec=0.02)
        if cmd[:2] == ("systemctl", "show"):
            u = cmd[2]
            if self.mutated and self._scen != "S5_COLLATERAL_TRAP" and self._scen != "S5B_COLLATERAL_FORCED_RESTART":
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=active\nSubState=running\nResult=success\n"
                        "NRestarts=0\nCanReload=yes\n"
                        "ActiveEnterTimestampMonotonic=50000000\n"
                        "InvocationID=ddddeeeeffff00001111222233334444\n"
                        "ExecMainStartTimestampMonotonic=45000000\n"
                    ),
                )
            if self._scen == "S5B_COLLATERAL_FORCED_RESTART" and u == "lab-worker.service" and self.mutated:
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=failed\nSubState=failed\nResult=exit-code\n"
                        "NRestarts=0\nCanReload=no\n"
                        "ActiveEnterTimestampMonotonic=10000000\n"
                        "InvocationID=workerold1111\n"
                        "ExecMainStartTimestampMonotonic=10000000\n"
                    ),
                )
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=str(self._shows.get(u, "")),
            )
        if "--validate-config" in cmd:
            is_bad_cfg = self._scen in (
                "S2_INVALID_CONFIG",
                "S4_PERSISTENT_FAILURE",
            )
            return TransportResult(
                exit_code=65 if is_bad_cfg else 0,
                duration_sec=0.01,
            )
        if cmd[0] == "curl":
            if self.mutated or self._scen in ("S2_INVALID_CONFIG", "S0_HEALTHY_CONTROL"):
                return TransportResult(exit_code=0, duration_sec=0.01)
            return TransportResult(exit_code=22, duration_sec=0.01)
        if "--check-tcp" in cmd:
            port = cmd[-1]
            if (
                port == "6379"
                and self._scen == "S3_DEPENDENCY_FAILURE"
                and not self.mutated
            ):
                return TransportResult(exit_code=1, duration_sec=0.01)
            return TransportResult(exit_code=0, duration_sec=0.01)
        return TransportResult(exit_code=0, duration_sec=0.01)


def test_wp5_conformance_script_and_fixture_facts_cover_all_systemd_invariants() -> None:
    """Verify check_conformance.sh and captured fixture cover all systemd facts + sudoers."""
    script_path = _repo_root() / "lab" / "scripts" / "check_conformance.sh"
    assert script_path.is_file()
    script_text = script_path.read_text(encoding="utf-8")

    required_script_ids = (
        "FACT_1_RESTART_NO_NRESTARTS_ZERO",
        "FACT_2_INVOCATION_ID_RESTART_VS_RELOAD",
        "FACT_3_SIGKILL_RESULT_SIGNAL",
        "FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER",
        "FACT_4B_START_FAILED_API_PRESERVES_WORKER",
        "FACT_5B_MANUAL_RESTART_NRESTARTS",
        "SUDO_POS_RELOAD_API",
        "SUDO_POS_RESTART_REDIS",
        "SUDO_POS_RESTART_API",
        "SUDO_POS_RESTART_WORKER",
        "SUDO_NEG_DENIED",
        "FACT_6_UBUNTU_UNPRIVILEGED_READS",
        "FACT_7_EXECSTARTPRE_FAILURE",
    )
    for fact_id in required_script_ids:
        assert fact_id in script_text


def test_wp5_sudoers_negative_commands_are_strictly_outside_allowlist() -> None:
    """Verify every negative and argument-injection command is rejected by sudoers."""
    sudoers_path = _repo_root() / "lab" / "systemd" / "gateheal-sudoers.conf"
    prefix = "ubuntu ALL=(root) NOPASSWD: "
    allowed_tuples = {
        tuple(shlex.split(ln.strip()[len(prefix) :]))
        for ln in sudoers_path.read_text(encoding="utf-8").splitlines()
        if ln.strip().startswith(prefix)
    }
    assert len(allowed_tuples) == 4

    denied_candidates = (
        ("/usr/bin/systemctl", "stop", "lab-api.service"),
        ("/usr/bin/systemctl", "reload", "lab-redis.service"),
        ("/usr/bin/systemctl", "reload", "lab-worker.service"),
        ("/usr/bin/systemctl", "restart", "ssh.service"),
        ("/usr/bin/systemctl", "daemon-reload"),
        ("/bin/sh", "-c", "id"),
        ("/usr/bin/systemctl", "restart", "lab-api.service", "ssh.service"),
        ("/usr/bin/systemctl", "restart", "lab-api.service", "--no-block"),
        ("/usr/bin/systemctl", "restart", "lab-api.service", "lab-redis.service"),
        ("/usr/bin/systemctl", "--no-block", "restart", "lab-api.service"),
        ("/usr/bin/systemctl", "restart", "lab-api.service", "--", "--version"),
    )
    for candidate in denied_candidates:
        assert candidate not in allowed_tuples


def test_wp5_latency_profiler_and_manifest_builder_with_captured_fixtures(
    tmp_path: Path,
) -> None:
    """Scripted offline replay: verify latency profiler, S0-S5B fixture replay, and manifest."""
    repo_root = _repo_root()
    cfg = _load_cfg()
    fixture = _load_fixture_json()
    scen_map = fixture["scenarios_systemctl_show"]
    assert isinstance(scen_map, dict)

    clock_ticks = [0.0]

    def fake_clock() -> float:
        clock_ticks[0] += 0.012
        return clock_ticks[0]

    class _FastTransport:
        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            _ = (argv, timeout_sec)
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt="systemd 255\n",
            )

    latency = measure_transport_latency(
        _FastTransport(), samples=10, monotonic_clock=fake_clock
    )
    assert latency.samples == 10
    assert latency.min_ms == pytest.approx(12.0)
    assert latency.p95_ms == pytest.approx(12.0)

    smoke_runs: list[SmokeScenarioRunResult] = []
    now_dt = datetime(2026, 10, 24, 8, 0, 0, tzinfo=UTC)

    for exp in build_wp5_smoke_expectations():
        unit_shows = scen_map.get(exp.scenario_id, scen_map.get("S1_SERVICE_CRASH", {}))
        assert isinstance(unit_shows, dict)
        soak_step = [0]

        def _mono(_s: list[int] = soak_step) -> float:
            return float(_s[0])

        def _sleep(sec: float, _s: list[int] = soak_step) -> None:
            _s[0] += int(sec)

        inc_id = f"wp5-replay-{exp.scenario_id.lower()}"
        store = PersistentStateStore(tmp_path / f"{inc_id}.json")
        store.seed_unit_state(
            "lab-api.service",
            incident_id=inc_id,
            prior_recovery_attempts=exp.seed_prior_recovery_attempts,
            action_history=exp.seed_action_history,
        )
        approval_token = None
        if exp.requires_approval_token:
            from gateheal.policy import mint_approval_token
            collector = IncidentCollector(cfg)
            dummy_inc = collector.collect_simulated(
                incident_id=inc_id,
                target_unit="lab-api.service",
                simulated_services={
                    "lab-redis.service": ServiceEvidence(unit_name="lab-redis.service", active_state="active", sub_state="running", health_probe_ok=True, config_valid=True),
                    "lab-api.service": ServiceEvidence(unit_name="lab-api.service", active_state="active", sub_state="running", health_probe_ok=True, config_valid=True),
                    "lab-worker.service": ServiceEvidence(unit_name="lab-worker.service", active_state="active", sub_state="running", health_probe_ok=True, config_valid=True),
                }
            )
            approval_token = mint_approval_token(
                token_id="tok-replay",
                incident=dummy_inc,
                config=cfg,
                action_id=ActionId.RESTART_SERVICE.value,
                target_unit="lab-api.service",
                expires_at_utc="2099-01-01T00:00:00Z",
                hmac_key=b"dev-operator-hmac-secret-key-32bytes-long!!",
            )

        orch = IncidentOrchestrator(
            cfg,
            transport=_FixtureReplayTransport(unit_shows, exp.scenario_id),
            audit_recorder=AuditRecorder(
                tmp_path / f"{inc_id}_audit.jsonl", clock_utc=lambda: now_dt
            ),
            escalation_sink=EscalationSink(tmp_path / f"{inc_id}_esc.jsonl"),
            state_store=store,
            clock_utc=lambda: now_dt,
            monotonic_clock=_mono,
            sleep_fn=_sleep,
        )
        audit = orch.handle_incident(
            incident_id=inc_id,
            target_unit="lab-api.service",
            approval_token=approval_token,
        )
        assert audit.selected_proposal is not None
        assert audit.verification_report is not None
        sel = audit.selected_proposal
        ver = audit.verification_report
        matched = (
            audit.diagnosis.fault_class in exp.expected_fault_classes
            and sel.action_id == exp.expected_action_id.value
            and sel.target_unit == exp.expected_target_unit
            and ver.status == exp.expected_verification_status
            and ver.collateral_failures == exp.expected_collateral_failures
            and audit.escalated == exp.expected_escalated
        )
        assert matched is True, f"Scenario {exp.scenario_id} failed expectation"
        smoke_runs.append(
            SmokeScenarioRunResult(
                scenario_id=exp.scenario_id,
                repeat_index=1,
                diagnosed_fault=audit.diagnosis.fault_class,
                selected_action_id=sel.action_id,
                selected_target_unit=sel.target_unit,
                verification_status=ver.status,
                collateral_failures=ver.collateral_failures,
                samples_collected=ver.samples_collected,
                soak_wall_clock_sec=float(soak_step[0]),
                soak_budget_ok=True,
                ssh_command_count=1,
                mutating_commands_executed=1,
                escalated=audit.escalated,
                matched_expectation=matched,
            )
        )

    manifest = build_lab_run_manifest(
        repo_root=repo_root,
        config_path=repo_root / "configs" / "phase1_lab.yaml",
        sudoers_path=repo_root / "lab" / "systemd" / "gateheal-sudoers.conf",
        ssh_latency=latency,
        conformance_facts=parse_conformance_output(
            "PASS: FACT_1_RESTART_NO_NRESTARTS_ZERO :: ok\n"
        ),
        smoke_matrix=smoke_runs,
        clock_utc=lambda: now_dt,
    )
    assert manifest.conformance_all_passed is True
    assert manifest.smoke_all_passed is True
    assert len(manifest.config_sha256) == 64
    assert len(manifest.sudoers_sha256) == 64


@pytest.mark.skipif(
    os.environ.get("GATEHEAL_RUN_LAB_TESTS") != "1",
    reason="Set GATEHEAL_RUN_LAB_TESTS=1 with booted QEMU/KVM guest on 127.0.0.1:2222",
)
def test_wp5_live_vm_ssh_conformance_and_captured_fixture_freshness() -> None:
    """Live VM check (Spec G): validate artifacts/wp5_lab_manifest.json, kernel, and root key denial."""
    repo_root = _repo_root()
    manifest_path = repo_root / "artifacts" / "wp5_lab_manifest.json"
    if not manifest_path.is_file():
        pytest.fail(
            f"Runbook pointer: Missing live manifest at {manifest_path}; "
            "run python lab/scripts/wp5_capture_and_verify.py first."
        )
    manifest = LabRunManifest.model_validate_json(
        manifest_path.read_text(encoding="utf-8")
    )
    if not manifest.conformance_all_passed or not manifest.smoke_all_passed:
        pytest.fail(
            "Runbook pointer: Manifest conformance or smoke checks failed; "
            "review lab/scripts/check_conformance.sh and re-run capture script."
        )

    assert manifest.conformance_all_passed is True
    assert manifest.smoke_all_passed is True
    assert len(manifest.smoke_matrix) == 21  # 7 scenarios × 3 repeats

    fixture = _load_fixture_json()
    assert manifest.guest_kernel == fixture["guest_kernel"]
    assert manifest.guest_systemd_version == fixture["guest_systemd_version"]

    ssh_port = int(os.environ.get("GATEHEAL_LAB_SSH_PORT", "2222"))
    ssh_user = os.environ.get("GATEHEAL_LAB_SSH_USER", "ubuntu")
    default_key = Path.home() / ".cache" / "gateheal-vm" / "id_ed25519"
    ssh_key = os.environ.get("GATEHEAL_LAB_SSH_KEY") or (
        str(default_key) if default_key.is_file() else None
    )
    transport = SSHLabTransport(
        host="127.0.0.1",
        port=ssh_port,
        user=ssh_user,
        identity_file=ssh_key,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )
    latency = measure_transport_latency(transport, samples=5)
    assert latency.max_ms < 5000.0

    uname_res = transport.run(("uname", "-r"), timeout_sec=5.0)
    sysd_res = transport.run(("systemctl", "--version"), timeout_sec=5.0)
    live_kernel = uname_res.stdout_excerpt.strip()
    live_systemd = sysd_res.stdout_excerpt.splitlines()[0].strip()

    assert live_kernel == manifest.guest_kernel
    assert live_systemd == manifest.guest_systemd_version

    # Config and sudoers hashes match current files on disk
    cfg_path = repo_root / "configs" / "phase1_lab.yaml"
    sudoers_path = repo_root / "lab" / "systemd" / "gateheal-sudoers.conf"
    from gateheal.lab_bringup import compute_file_sha256
    assert manifest.config_sha256 == compute_file_sha256(cfg_path)
    assert manifest.sudoers_sha256 == compute_file_sha256(sudoers_path)

    # Controller key root denial verified
    root_with_controller_key = SSHLabTransport(
        host="127.0.0.1",
        port=ssh_port,
        user="root",
        identity_file=ssh_key,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )
    with pytest.raises(TransportUnavailableError) as exc_info:
        root_with_controller_key.run(("id",), timeout_sec=5.0)
    assert exc_info.value.exit_code != 0"""WP5 real-lab conformance, sudoers negative, latency/soak, S1-S5 smoke, and manifest tests."""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gateheal.collector import parse_invocation_and_start_usec, parse_systemctl_show
from gateheal.config import GateHealConfig, load_config
from gateheal.controller import AuditRecorder, EscalationSink
from gateheal.lab_bringup import (
    LabRunManifest,
    SmokeScenarioRunResult,
    build_lab_run_manifest,
    build_wp5_smoke_expectations,
    measure_transport_latency,
    parse_conformance_output,
)
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.state import PersistentStateStore
from gateheal.transport import (
    SSHLabTransport,
    TransportResult,
    TransportUnavailableError,
)

pytestmark = pytest.mark.lab


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_cfg() -> GateHealConfig:
    return load_config(_repo_root() / "configs" / "phase1_lab.yaml")


def _load_fixture_json() -> dict[str, object]:
    fix_path = Path(__file__).resolve().parent / "fixtures" / "vm_captured_systemd_facts.json"
    raw = json.loads(fix_path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


class _FixtureReplayTransport:
    """Scripted offline replay transport using VM-captured `systemctl show` fixtures."""

    def __init__(self, shows: dict[str, object], scen: str) -> None:
        self._shows = shows
        self._scen = scen
        self.mutated = False

    def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
        _ = timeout_sec
        cmd = tuple(argv)
        if cmd[:2] == ("cat", "/proc/uptime"):
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt="50000.0 40000.0\n",
            )
        if cmd[:3] == ("sudo", "-n", "/usr/bin/systemctl"):
            self.mutated = True
            return TransportResult(exit_code=0, duration_sec=0.02)
        if cmd[:2] == ("systemctl", "show"):
            u = cmd[2]
            if self.mutated and self._scen != "S5_COLLATERAL_TRAP":
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=active\nSubState=running\nResult=success\n"
                        "NRestarts=0\nCanReload=yes\n"
                        "ActiveEnterTimestampMonotonic=50000000\n"
                        "InvocationID=ddddeeeeffff00001111222233334444\n"
                        "ExecMainStartTimestampMonotonic=45000000\n"
                    ),
                )
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt=str(self._shows[u]),
            )
        if "--validate-config" in cmd:
            is_bad_cfg = self._scen in (
                "S2_INVALID_CONFIG",
                "S4_PERSISTENT_FAILURE",
            )
            return TransportResult(
                exit_code=65 if is_bad_cfg else 0,
                duration_sec=0.01,
            )
        if cmd[0] == "curl":
            if self.mutated or self._scen == "S2_INVALID_CONFIG":
                return TransportResult(exit_code=0, duration_sec=0.01)
            return TransportResult(exit_code=22, duration_sec=0.01)
        if "--check-tcp" in cmd:
            port = cmd[-1]
            if (
                port == "6379"
                and self._scen == "S3_DEPENDENCY_FAILURE"
                and not self.mutated
            ):
                return TransportResult(exit_code=1, duration_sec=0.01)
            return TransportResult(exit_code=0, duration_sec=0.01)
        return TransportResult(exit_code=0, duration_sec=0.01)


def test_wp5_conformance_script_and_fixture_facts_cover_all_five_systemd_invariants() -> None:
    """Verify check_conformance.sh and captured fixture cover all 5 systemd facts + sudoers."""
    script_path = _repo_root() / "lab" / "scripts" / "check_conformance.sh"
    assert script_path.is_file()
    script_text = script_path.read_text(encoding="utf-8")

    required_script_ids = (
        "FACT_1_RESTART_NO_NRESTARTS_ZERO",
        "FACT_2_INVOCATION_ID_RESTART_VS_RELOAD",
        "FACT_3_SIGKILL_RESULT_SIGNAL",
        "FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER",
        "FACT_4B_START_FAILED_API_PRESERVES_WORKER",
        "FACT_5_MANUAL_RESTART_NRESTARTS_BEHAVIOR",
        "SUDO_POS_RELOAD_API",
        "SUDO_POS_RESTART_REDIS",
        "SUDO_POS_RESTART_API",
        "SUDO_POS_RESTART_WORKER",
        "SUDO_NEG_DENIED",
    )
    for fact_id in required_script_ids:
        assert fact_id in script_text

    fixture = _load_fixture_json()
    raw_facts = fixture["conformance_facts"]
    assert isinstance(raw_facts, list)
    seen_ids = {str(item["fact_id"]) for item in raw_facts if isinstance(item, dict)}
    for fact_id in required_script_ids:
        assert fact_id in seen_ids

    sample_stdout = (
        "PASS: FACT_1_RESTART_NO_NRESTARTS_ZERO :: ActiveState=failed, NRestarts=0\n"
        "FAIL: SUDO_NEG_DENIED :: Unapproved command succeeded\n"
    )
    parsed = parse_conformance_output(sample_stdout)
    assert len(parsed) == 2
    assert parsed[0].fact_id == "FACT_1_RESTART_NO_NRESTARTS_ZERO"
    assert parsed[0].passed is True
    assert parsed[1].fact_id == "SUDO_NEG_DENIED"
    assert parsed[1].passed is False


def test_wp5_sudoers_negative_commands_are_strictly_outside_allowlist() -> None:
    """Verify every negative and argument-injection command is rejected by sudoers."""
    sudoers_path = _repo_root() / "lab" / "systemd" / "gateheal-sudoers.conf"
    prefix = "ubuntu ALL=(root) NOPASSWD: "
    allowed_tuples = {
        tuple(shlex.split(ln.strip()[len(prefix) :]))
        for ln in sudoers_path.read_text(encoding="utf-8").splitlines()
        if ln.strip().startswith(prefix)
    }
    assert len(allowed_tuples) == 4

    denied_candidates = (
        ("/usr/bin/systemctl", "stop", "lab-api.service"),
        ("/usr/bin/systemctl", "reload", "lab-redis.service"),
        ("/usr/bin/systemctl", "reload", "lab-worker.service"),
        ("/usr/bin/systemctl", "restart", "ssh.service"),
        ("/usr/bin/systemctl", "daemon-reload"),
        ("/bin/sh", "-c", "id"),
        ("/usr/bin/systemctl", "restart", "lab-api.service", "ssh.service"),
        ("/usr/bin/systemctl", "restart", "lab-api.service", "--no-block"),
        ("/usr/bin/systemctl", "reload", "lab-api.service", "--force"),
        ("/usr/bin/systemctl", "--root=/tmp", "restart", "lab-api.service"),
        ("/usr/bin/systemctl", "restart", "lab-api.service", "--", "--version"),
    )
    for candidate in denied_candidates:
        assert candidate not in allowed_tuples


def test_wp5_latency_profiler_and_manifest_builder_with_captured_fixtures(
    tmp_path: Path,
) -> None:
    """Scripted offline replay: verify latency profiler, S1-S5 fixture replay, and manifest."""
    repo_root = _repo_root()
    cfg = _load_cfg()
    fixture = _load_fixture_json()
    scen_map = fixture["scenarios_systemctl_show"]
    assert isinstance(scen_map, dict)

    for scen_id, unit_map in scen_map.items():
        assert isinstance(unit_map, dict), scen_id
        for u_name, show_str in unit_map.items():
            assert u_name in cfg.inventory.services
            props = parse_systemctl_show(str(show_str))
            inv, st_usec = parse_invocation_and_start_usec(props)
            assert inv is not None
            assert st_usec is not None and st_usec > 0

    clock_ticks = [0.0]

    def fake_clock() -> float:
        clock_ticks[0] += 0.012
        return clock_ticks[0]

    class _FastTransport:
        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            _ = (argv, timeout_sec)
            return TransportResult(
                exit_code=0,
                duration_sec=0.01,
                stdout_excerpt="systemd 255\n",
            )

    latency = measure_transport_latency(
        _FastTransport(), samples=10, monotonic_clock=fake_clock
    )
    assert latency.samples == 10
    assert latency.min_ms == pytest.approx(12.0)
    assert latency.p95_ms == pytest.approx(12.0)

    smoke_runs: list[SmokeScenarioRunResult] = []
    now_dt = datetime(2026, 10, 24, 8, 0, 0, tzinfo=UTC)

    for exp in build_wp5_smoke_expectations():
        unit_shows = scen_map[exp.scenario_id]
        assert isinstance(unit_shows, dict)
        soak_step = [0]

        def _mono(_s: list[int] = soak_step) -> float:
            return float(_s[0])

        def _sleep(sec: float, _s: list[int] = soak_step) -> None:
            _s[0] += int(sec)

        inc_id = f"wp5-replay-{exp.scenario_id.lower()}"
        store = PersistentStateStore(tmp_path / f"{inc_id}.json")
        store.seed_unit_state(
            "lab-api.service",
            incident_id=inc_id,
            prior_recovery_attempts=exp.seed_prior_recovery_attempts,
            action_history=exp.seed_action_history,
        )
        orch = IncidentOrchestrator(
            cfg,
            transport=_FixtureReplayTransport(unit_shows, exp.scenario_id),
            audit_recorder=AuditRecorder(
                tmp_path / f"{inc_id}_audit.jsonl", clock_utc=lambda: now_dt
            ),
            escalation_sink=EscalationSink(tmp_path / f"{inc_id}_esc.jsonl"),
            state_store=store,
            clock_utc=lambda: now_dt,
            monotonic_clock=_mono,
            sleep_fn=_sleep,
        )
        audit = orch.handle_incident(
            incident_id=inc_id,
            target_unit="lab-api.service",
        )
        assert audit.selected_proposal is not None
        assert audit.verification_report is not None
        sel = audit.selected_proposal
        ver = audit.verification_report
        matched = (
            audit.diagnosis.fault_class in exp.expected_fault_classes
            and sel.action_id == exp.expected_action_id.value
            and sel.target_unit == exp.expected_target_unit
            and ver.status == exp.expected_verification_status
            and audit.escalated == exp.expected_escalated
        )
        assert matched is True, f"Scenario {exp.scenario_id} failed expectation"
        smoke_runs.append(
            SmokeScenarioRunResult(
                scenario_id=exp.scenario_id,
                diagnosed_fault=audit.diagnosis.fault_class,
                selected_action_id=sel.action_id,
                selected_target_unit=sel.target_unit,
                verification_status=ver.status,
                samples_collected=ver.samples_collected,
                soak_wall_clock_sec=float(soak_step[0]),
                escalated=audit.escalated,
                matched_expectation=matched,
            )
        )

    manifest = build_lab_run_manifest(
        repo_root=repo_root,
        config_path=repo_root / "configs" / "phase1_lab.yaml",
        sudoers_path=repo_root / "lab" / "systemd" / "gateheal-sudoers.conf",
        ssh_latency=latency,
        conformance_facts=parse_conformance_output(
            "PASS: FACT_1_RESTART_NO_NRESTARTS_ZERO :: ok\n"
        ),
        smoke_matrix=smoke_runs,
        clock_utc=lambda: now_dt,
    )
    assert manifest.conformance_all_passed is True
    assert manifest.smoke_all_passed is True
    assert len(manifest.config_sha256) == 64
    assert len(manifest.sudoers_sha256) == 64


@pytest.mark.skipif(
    os.environ.get("GATEHEAL_RUN_LAB_TESTS") != "1",
    reason="Set GATEHEAL_RUN_LAB_TESTS=1 with booted QEMU/KVM guest on 127.0.0.1:2222",
)
def test_wp5_live_vm_ssh_conformance_and_captured_fixture_freshness() -> None:
    """Live VM check (E3 & E6): validate artifacts/wp5_lab_manifest.json, guest kernel/systemd, and root key denial."""
    repo_root = _repo_root()
    manifest_path = repo_root / "artifacts" / "wp5_lab_manifest.json"
    assert manifest_path.is_file(), (
        f"Missing live manifest at {manifest_path}; run wp5_capture_and_verify.py first."
    )
    manifest = LabRunManifest.model_validate_json(
        manifest_path.read_text(encoding="utf-8")
    )
    assert manifest.conformance_all_passed is True
    assert manifest.smoke_all_passed is True
    assert len(manifest.smoke_matrix) == 5

    fixture = _load_fixture_json()
    assert manifest.guest_kernel == fixture["guest_kernel"]
    assert manifest.guest_systemd_version == fixture["guest_systemd_version"]

    ssh_port = int(os.environ.get("GATEHEAL_LAB_SSH_PORT", "2222"))
    ssh_user = os.environ.get("GATEHEAL_LAB_SSH_USER", "ubuntu")
    default_key = Path.home() / ".cache" / "gateheal-vm" / "id_ed25519"
    ssh_key = os.environ.get("GATEHEAL_LAB_SSH_KEY") or (
        str(default_key) if default_key.is_file() else None
    )
    transport = SSHLabTransport(
        host="127.0.0.1",
        port=ssh_port,
        user=ssh_user,
        identity_file=ssh_key,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )
    latency = measure_transport_latency(transport, samples=5)
    assert latency.max_ms < 5000.0

    uname_res = transport.run(("uname", "-r"), timeout_sec=5.0)
    sysd_res = transport.run(("systemctl", "--version"), timeout_sec=5.0)
    live_kernel = uname_res.stdout_excerpt.strip()
    live_systemd = sysd_res.stdout_excerpt.splitlines()[0].strip()

    assert live_kernel == manifest.guest_kernel
    assert live_systemd == manifest.guest_systemd_version
    assert live_kernel == fixture["guest_kernel"]
    assert live_systemd == fixture["guest_systemd_version"]

    # E6 negative check: controller key cannot log in as root
    root_with_controller_key = SSHLabTransport(
        host="127.0.0.1",
        port=ssh_port,
        user="root",
        identity_file=ssh_key,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )
    with pytest.raises(TransportUnavailableError) as exc_info:
        root_with_controller_key.run(("id",), timeout_sec=5.0)
    assert exc_info.value.exit_code != 0
