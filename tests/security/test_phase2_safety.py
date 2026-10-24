"""Phase 2, WP2-fix, and WP3-fix security, containment, sudoers, collector, and transport tests."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from gateheal.actions import DEFAULT_ACTION_CATALOGUE
from gateheal.cli import main as cli_main
from gateheal.collector import (
    UNTRUSTED_LOG_PREFIX,
    IncidentCollector,
    redact_secrets_text,
)
from gateheal.config import GateHealConfig, load_config
from gateheal.controller import (
    AuditRecorder,
    EscalationSink,
    ExecutionController,
    OutcomeVerifier,
)
from gateheal.models import (
    ActionId,
    ActionProposal,
    FaultClass,
    IncidentRecord,
    PolicyRejectionCode,
    ServiceEvidence,
    VerificationStatus,
    validated_incident_update,
)
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.policy import MinimalImpactSelector, PolicyEngine
from gateheal.state import PersistentStateStore
from gateheal.transport import (
    EXPECTED_SENTINEL_TOKEN,
    HostSafetyViolationError,
    LocalLabSubprocessTransport,
    SSHLabTransport,
    TransportResult,
    run_isolated_process_group,
    truncate_output_tail,
)


def _load_lab_cfg() -> GateHealConfig:
    cfg_p = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    return load_config(cfg_p)


def test_validated_incident_update_rejects_unknown_field_names() -> None:
    inc = IncidentRecord(
        incident_id="inc-val-01",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-22T00:00:00Z",
        services={},
    )
    updated = validated_incident_update(
        inc, unit_flap_counts={"lab-redis.service": 2}
    )
    assert updated.unit_flap_counts == {"lab-redis.service": 2}

    with pytest.raises(ValidationError):
        validated_incident_update(
            inc,
            unit_recent_mutations_in_flap_window={"lab-redis.service": 2},
        )


def test_r6_mutated_unit_cooldown_and_flap_recorded_on_target_unit(
    tmp_path: Path,
) -> None:
    cfg = _load_lab_cfg()
    store = PersistentStateStore(tmp_path / "r6_state.json")
    now_dt = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)

    # Alerting unit is lab-api.service, but mutated unit is upstream lab-redis.service
    store.record_execution(
        incident_id="inc-s3-1",
        unit_name="lab-api.service",
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-redis.service",
        is_mutating=True,
        is_diagnostic=False,
        now_utc=now_dt,
        flap_window_sec=cfg.budgets.flap_window_sec,
        consumed_tokens=frozenset(),
    )

    _, redis_age, redis_flaps = store.compute_unit_runtime_counters(
        "lab-redis.service",
        now_utc=now_dt,
        flap_window_sec=cfg.budgets.flap_window_sec,
        incident_id="inc-s3-2",
    )
    assert redis_age == 0.0
    assert redis_flaps == 1

    # PolicyEngine must block a second restart of lab-redis.service during cooldown
    orchestrator = IncidentOrchestrator(
        cfg,
        state_store=store,
        audit_recorder=AuditRecorder(tmp_path / "r6_audit.jsonl", clock_utc=lambda: now_dt),
        escalation_sink=EscalationSink(tmp_path / "r6_esc.jsonl"),
        clock_utc=lambda: now_dt,
    )
    s3_services = {
        "lab-redis.service": ServiceEvidence(
            unit_name="lab-redis.service",
            active_state="failed",
            sub_state="failed",
            result="signal",
            health_probe_ok=False,
            config_valid=True,
        ),
        "lab-api.service": ServiceEvidence(
            unit_name="lab-api.service",
            active_state="active",
            sub_state="running",
            can_reload=True,
            health_probe_ok=False,
            config_valid=True,
        ),
        "lab-worker.service": ServiceEvidence(
            unit_name="lab-worker.service",
            active_state="active",
            sub_state="running",
            health_probe_ok=True,
            config_valid=True,
        ),
    }
    raw_inc = IncidentRecord(
        incident_id="inc-s3-2",
        target_unit="lab-api.service",
        collected_at_utc=now_dt.isoformat(),
        services=s3_services,
    )
    enriched = orchestrator._enrich_incident_from_store(
        raw_inc,
        incident_id="inc-s3-2",
        target_unit="lab-api.service",
        elapsed_sec=0.0,
        now_utc=now_dt,
    )
    assert enriched.unit_cooldown_age_sec.get("lab-redis.service") == 0.0
    assert enriched.unit_flap_counts.get("lab-redis.service") == 1

    prop = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-redis.service",
        inferred_fault=FaultClass.DEPENDENCY_FAILURE,
        rationale="Restart upstream redis during cooldown.",
    )
    dec = orchestrator.policy_engine.evaluate(prop, enriched)
    assert not dec.approved
    assert PolicyRejectionCode.ERR_COOLDOWN_ACTIVE in dec.rejection_codes


def test_sudoers_file_syntax_and_exact_mutating_argv_match() -> None:
    cfg = _load_lab_cfg()
    sudoers_path = (
        Path(__file__).resolve().parents[2]
        / "lab"
        / "systemd"
        / "gateheal-sudoers.conf"
    )
    raw_lines = [
        ln.strip()
        for ln in sudoers_path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    prefix = "ubuntu ALL=(root) NOPASSWD: "
    allowed_commands = {
        tuple(shlex.split(ln[len(prefix) :]))
        for ln in raw_lines
        if ln.startswith(prefix)
    }
    assert allowed_commands

    # Every mutating argv that the controller can emit for approved services must match
    for unit_name, svc_cfg in cfg.inventory.services.items():
        restart_argv = DEFAULT_ACTION_CATALOGUE[
            ActionId.RESTART_SERVICE
        ].build_argv(unit_name, svc_cfg)
        assert restart_argv[:2] == ("sudo", "-n")
        assert restart_argv[2].startswith("/")
        assert restart_argv[2:] in allowed_commands

        if svc_cfg.supports_reload:
            reload_argv = DEFAULT_ACTION_CATALOGUE[
                ActionId.RELOAD_SERVICE
            ].build_argv(unit_name, svc_cfg)
            assert reload_argv[:2] == ("sudo", "-n")
            assert reload_argv[2].startswith("/")
            assert reload_argv[2:] in allowed_commands

    visudo_bin = shutil.which("visudo") or (
        "/usr/sbin/visudo" if Path("/usr/sbin/visudo").is_file() else None
    )
    if visudo_bin is not None:
        proc = subprocess.run(
            [visudo_bin, "-cf", str(sudoers_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"visudo failed: {proc.stderr} {proc.stdout}"


def test_collector_runs_tcp_probe_and_reads_clock_via_guest_transport() -> None:
    cfg = _load_lab_cfg()
    # Host monotonic clock is skewed to 999,999.0s, while guest uptime is 102.0s
    # and ActiveEnterTimestampMonotonic is 100,000,000 us -> age is 2.0s (< 5.0s grace)
    collector = IncidentCollector(cfg, monotonic_clock=lambda: 999_999.0)

    executed_cmds: list[tuple[str, ...]] = []

    class _FakeGuestTransport:
        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            _ = timeout_sec
            cmd = tuple(argv)
            executed_cmds.append(cmd)
            if cmd == ("cat", "/proc/uptime"):
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt="102.00 200.00\n",
                )
            if cmd[:2] == ("systemctl", "show"):
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=active\nSubState=running\n"
                        "Result=success\nNRestarts=0\nCanReload=yes\n"
                        "ActiveEnterTimestampMonotonic=100000000\n"
                    ),
                )
            if "--check-tcp" in cmd:
                return TransportResult(exit_code=0, duration_sec=0.01)
            if cmd[0] == "curl":
                return TransportResult(exit_code=0, duration_sec=0.01)
            return TransportResult(exit_code=0, duration_sec=0.01, stdout_excerpt="ok")

    inc = collector.collect_from_transport(
        incident_id="inc-guest-clock-tcp",
        target_unit="lab-api.service",
        transport=_FakeGuestTransport(),
    )
    assert ("cat", "/proc/uptime") in executed_cmds
    assert any("--check-tcp" in c and "6379" in c for c in executed_cmds)
    assert any("--check-tcp" in c and "8081" in c for c in executed_cmds)
    assert inc.services["lab-redis.service"].health_probe_ok is True
    assert inc.services["lab-worker.service"].health_probe_ok is True
    assert inc.services["lab-api.service"].active_enter_age_sec == pytest.approx(2.0)


def test_local_lab_transport_requires_sentinel_and_virt_not_just_env_var(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("GATEHEAL_INSIDE_LAB", raising=False)
    transport = LocalLabSubprocessTransport()
    with pytest.raises(HostSafetyViolationError):
        transport.run(["systemctl", "restart", "lab-api.service"], timeout_sec=2.0)

    monkeypatch.setenv("GATEHEAL_INSIDE_LAB", "1")
    missing_sentinel = tmp_path / "nonexistent-sentinel"
    transport_no_sent = LocalLabSubprocessTransport(
        sentinel_path=missing_sentinel,
        virt_detector=lambda: "kvm",
    )
    with pytest.raises(HostSafetyViolationError, match="sentinel_ok=False"):
        transport_no_sent.run(["echo", "hello"], timeout_sec=2.0)

    valid_sentinel = tmp_path / "gateheal-lab-sentinel"
    valid_sentinel.write_text(EXPECTED_SENTINEL_TOKEN + "\n", encoding="utf-8")
    transport_bare_metal = LocalLabSubprocessTransport(
        sentinel_path=valid_sentinel,
        virt_detector=lambda: "none",
    )
    with pytest.raises(HostSafetyViolationError, match="virt='none'"):
        transport_bare_metal.run(["echo", "hello"], timeout_sec=2.0)


def test_ssh_transport_loopback_guard_sentinel_default_and_remote_timeout() -> None:
    ssh = SSHLabTransport(host="127.0.0.1", port=2222, user="ubuntu")
    assert ssh.verify_remote_sentinel is True
    argv = ssh.build_ssh_argv(["systemctl", "is-active", "lab-api.service"])
    assert argv[:4] == ("ssh", "-p", "2222", "-o")
    assert "BatchMode=yes" in argv
    assert argv[-3] == "--"
    assert argv[-2] == "ubuntu@127.0.0.1"
    assert argv[-1] == "systemctl is-active lab-api.service"

    scoped_ssh = SSHLabTransport(
        host="127.0.0.1",
        port=2222,
        user="ubuntu",
        identity_file="/tmp/lab_id_ed25519",
        use_systemd_scope=True,
        use_remote_timeout=True,
    )
    scoped_argv = scoped_ssh.build_ssh_argv(
        ["systemctl", "is-active", "lab-api.service"],
        remote_timeout_sec=8.0,
    )
    assert "-i" in scoped_argv
    assert "/tmp/lab_id_ed25519" in scoped_argv
    remote_cmd = scoped_argv[-1]
    assert remote_cmd.startswith("timeout --foreground --signal=TERM")
    expected_scope = (
        "/usr/bin/systemd-run --scope --collect -p MemoryMax=256M -p CPUQuota=50% --"
    )
    assert expected_scope in remote_cmd
    assert remote_cmd.endswith("systemctl is-active lab-api.service")

    with pytest.raises(HostSafetyViolationError, match="non-loopback"):
        SSHLabTransport(host="192.0.2.55", port=2222, user="ubuntu")

    with pytest.raises(ValueError, match="Invalid SSH username"):
        SSHLabTransport(host="127.0.0.1", port=2222, user="-oProxyCommand=evil")


def test_process_group_timeout_non_utf8_and_tail_truncation() -> None:
    res = run_isolated_process_group(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_sec=0.2,
    )
    assert res.timed_out is True
    assert res.exit_code == -999
    assert "process group terminated" in res.stderr_excerpt

    non_utf8_res = run_isolated_process_group(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'prefix-\\xff\\xfe-suffix\\n')",
        ],
        timeout_sec=2.0,
    )
    assert non_utf8_res.exit_code == 0
    assert "prefix-" in non_utf8_res.stdout_excerpt
    assert "-suffix" in non_utf8_res.stdout_excerpt

    long_out = ("OLD_HEAD_LINE\n" * 200) + "NEWEST_TAIL_EVENT_MARKER\n"
    truncated = truncate_output_tail(long_out, max_chars=256)
    assert len(truncated) <= 256
    assert "NEWEST_TAIL_EVENT_MARKER" in truncated
    assert truncated.startswith("[TRUNCATED_OLDEST_OUTPUT]\n")


def test_collector_redacts_truncated_pem_quoted_json_stripe_slack_and_frames_logs() -> None:
    cfg = _load_lab_cfg()
    collector = IncidentCollector(cfg)

    # Test truncated PEM (unterminated BEGIN and orphan END), JSON-quoted keys, sk_live_, xoxb-
    unterminated_pem = (
        "FATAL: key dump\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ=="
    )
    orphan_end_pem = (
        "MIIEpAIBAAKCAQEA7VJTUt9Us8cKjMzEfYyjiWA4R\n"
        "-----END RSA " + "PRIVATE KEY-----\nINFO: after key"
    )
    assert "b3BlbnNzaC1rZXktdjE" not in redact_secrets_text(unterminated_pem)
    assert "MIIEpAIBAAKCAQEA7VJT" not in redact_secrets_text(orphan_end_pem)

    secret_tail_lines = [
        '{"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}',
        "ERROR: stripe key " + "sk_live_" + "51NzSecretStripeKeyValue999999" + "",
        "WARN: slack bot token xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
        "ERROR: upstream auth failed with api_key='" + "AIzaSy" + "SecretKey1234567890" + "'",
        "WARN: header Authorization: Bearer=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "INFO: db connect password=my_super_secret_password_123",
        "WARN: session token=" + "ghp_" + "1234567890abcdefghijklmnopqrstuv" + "",
        "ERROR: client_secret: super_confidential_secret_val",
        "WARN: Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==",
        "ERROR: DSN postgres://admin:MyDbPass99!@127.0.0.1:5432/appdb failed",
        "WARN: leaked AWS key " + "AKIA" + "IOSFODNN7EXAMPLE" + " in env",
        "INFO: overlong line " + ("Z" * 700),
    ]
    noisy_logs = tuple(
        [f"log line {i}: " + ("X" * 400) for i in range(60)] + secret_tail_lines
    )

    raw_services = {
        "lab-api.service": ServiceEvidence(
            unit_name="lab-api.service",
            active_state="failed",
            sub_state="failed",
            health_probe_ok=False,
            config_valid=True,
            sanitized_logs=noisy_logs,
        ),
        "lab-worker.service": ServiceEvidence(
            unit_name="lab-worker.service",
            active_state="active",
            sub_state="running",
            health_probe_ok=True,
            config_valid=True,
            sanitized_logs=("Worker healthy heartbeat line.",),
        ),
    }
    incident = collector.collect_simulated(
        incident_id="inc-sec-logs",
        target_unit="lab-api.service",
        simulated_services=raw_services,
    )
    saved_logs = incident.services["lab-api.service"].sanitized_logs
    worker_logs = incident.services["lab-worker.service"].sanitized_logs

    assert any("Worker healthy heartbeat line." in ln for ln in worker_logs)

    non_marker_logs = [
        ln for ln in saved_logs if ln != "[TRUNCATED_MAX_BYTES_EXCEEDED]"
    ]
    assert len(saved_logs) <= cfg.budgets.max_log_lines + 1
    for ln in non_marker_logs:
        assert ln.startswith(UNTRUSTED_LOG_PREFIX)
        assert len(ln.encode("utf-8")) <= cfg.budgets.max_log_line_bytes + len(
            UNTRUSTED_LOG_PREFIX
        )

    joined = "\n".join(saved_logs)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in joined
    assert "" + "sk_live_" + "51NzSecretStripeKeyValue999999" + "" not in joined
    assert "xoxb-123456789012" not in joined
    assert "" + "AIzaSy" + "SecretKey1234567890" + "" not in joined
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in joined
    assert "my_super_secret_password_123" not in joined
    assert "" + "ghp_" + "1234567890abcdefghijklmnopqrstuv" + "" not in joined
    assert "super_confidential_secret_val" not in joined
    assert "dXNlcjpwYXNzd29yZDEyMw==" not in joined
    assert "MyDbPass99!" not in joined
    assert "" + "AKIA" + "IOSFODNN7EXAMPLE" + "" not in joined
    assert "[REDACTED_STRIPE_KEY]" in joined
    assert "[REDACTED_SLACK_TOKEN]" in joined
    assert "[REDACTED_AWS_KEY]" in joined
    assert "...[LINE_TRUNCATED]" in joined
    assert "[TRUNCATED_MAX_BYTES_EXCEEDED]" in joined


def test_execution_controller_redacts_secrets_in_stdout_and_stderr() -> None:
    cfg = _load_lab_cfg()

    class _SecretLeakingTransport:
        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            _ = (argv, timeout_sec)
            return TransportResult(
                exit_code=0,
                duration_sec=0.02,
                stdout_excerpt="restarted with token=secret_tok_9876543210",
                stderr_excerpt="warning: url redis://default:TopSecretPw@127.0.0.1:6379",
            )

    policy = PolicyEngine(cfg)
    controller = ExecutionController(
        cfg, transport=_SecretLeakingTransport(), policy_engine=policy
    )
    incident = IncidentRecord(
        incident_id="inc-exec-redact",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:00Z",
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                result="exit-code",
                health_probe_ok=False,
                config_valid=True,
            ),
        },
    )
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        rationale="Restart crashed service.",
    )
    cap = policy.mint_capability(proposal, incident)
    exec_res = controller.execute(cap, current_incident=incident)
    assert "secret_tok_9876543210" not in exec_res.stdout_excerpt
    assert "[REDACTED_SECRET]" in exec_res.stdout_excerpt
    assert "TopSecretPw" not in exec_res.stderr_excerpt
    assert "[REDACTED_SECRET]" in exec_res.stderr_excerpt


def test_cli_recover_ssh_uses_real_collect_from_transport_and_waits_soak(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import gateheal.cli as cli_mod

    sleep_calls: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleep_calls.append(s))

    class _FakeLiveSSHTransport:
        def __init__(self) -> None:
            self.restarted = False
            self.commands: list[tuple[str, ...]] = []

        def run(self, argv: Sequence[str], timeout_sec: float) -> TransportResult:
            _ = timeout_sec
            cmd = tuple(argv)
            self.commands.append(cmd)
            if cmd == ("sudo", "-n", "/usr/bin/systemctl", "restart", "lab-api.service"):
                self.restarted = True
                return TransportResult(exit_code=0, duration_sec=0.05)
            if cmd[:2] == ("systemctl", "show"):
                unit = cmd[2]
                if unit == "lab-api.service" and not self.restarted:
                    return TransportResult(
                        exit_code=0,
                        duration_sec=0.01,
                        stdout_excerpt=(
                            "ActiveState=failed\nSubState=failed\n"
                            "Result=exit-code\nNRestarts=0\nCanReload=yes\n"
                        ),
                    )
                return TransportResult(
                    exit_code=0,
                    duration_sec=0.01,
                    stdout_excerpt=(
                        "ActiveState=active\nSubState=running\n"
                        "Result=success\nNRestarts=0\nCanReload=yes\n"
                    ),
                )
            if cmd[0] == "curl":
                return TransportResult(
                    exit_code=0 if self.restarted else 22,
                    duration_sec=0.01,
                )
            return TransportResult(exit_code=0, duration_sec=0.01, stdout_excerpt="ok")

    fake_ssh = _FakeLiveSSHTransport()
    monkeypatch.setattr(
        cli_mod, "_resolve_transport_from_args", lambda _args: fake_ssh
    )

    cfg_path = Path(__file__).resolve().parents[2] / "configs" / "phase1_lab.yaml"
    state_file = tmp_path / "ssh_state.json"
    audit_file = tmp_path / "ssh_audit.jsonl"

    rc = cli_main(
        [
            "recover",
            "--config",
            str(cfg_path),
            "--target",
            "lab-api.service",
            "--incident-id",
            "inc-ssh-live-001",
            "--transport",
            "ssh",
            "--ssh-host",
            "127.0.0.1",
            "--ssh-port",
            "2222",
            "--systemd-scope",
            "--state-file",
            str(state_file),
            "--audit-log",
            str(audit_file),
        ]
    )
    assert rc == 0
    out_json = json.loads(capsys.readouterr().out)
    assert out_json["verification_report"]["status"] == "recovered_clean"
    assert sleep_calls == [1.0, 1.0, 1.0, 1.0, 1.0]
    assert sum(sleep_calls) == 5.0
    assert (
        "sudo",
        "-n",
        "/usr/bin/systemctl",
        "restart",
        "lab-api.service",
    ) in fake_ssh.commands


def test_missing_config_evidence_blocks_mutating_actions() -> None:
    cfg = _load_lab_cfg()
    engine = PolicyEngine(cfg)

    incident = IncidentRecord(
        incident_id="inc-missing-ev",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:00Z",
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                result="exit-code",
                health_probe_ok=False,
                config_valid=None,
            ),
        },
    )
    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.90,
        rationale="Attempt restart without first validating config.",
    )
    decision = engine.evaluate(proposal, incident)
    assert not decision.approved
    assert PolicyRejectionCode.ERR_PRECONDITION_FAILED in decision.rejection_codes


def test_verifier_detects_persistent_crash_recurrence_and_collateral_disruption() -> None:
    cfg = _load_lab_cfg()
    policy_engine = PolicyEngine(cfg)
    controller = ExecutionController(cfg, policy_engine=policy_engine)
    verifier = OutcomeVerifier(cfg)
    selector = MinimalImpactSelector(policy_engine)

    proposal = ActionProposal(
        action_id=ActionId.RESTART_SERVICE.value,
        target_unit="lab-api.service",
        inferred_fault=FaultClass.PROCESS_CRASH,
        evidence_confidence=0.95,
        rationale="Restart crashed lab-api.service.",
    )

    initial_incident = IncidentRecord(
        incident_id="inc-init",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:00Z",
        services={
            "lab-redis.service": ServiceEvidence(
                unit_name="lab-redis.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="failed",
                sub_state="failed",
                result="exit-code",
                n_restarts=1,
                health_probe_ok=False,
                config_valid=True,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="active",
                sub_state="running",
                health_probe_ok=True,
            ),
        },
    )
    cap = policy_engine.mint_capability(proposal, initial_incident)
    exec_result = controller.execute(cap, current_incident=initial_incident)

    pre_incident = initial_incident.model_copy(
        update={
            "incident_id": "inc-pre",
            "prior_recovery_attempts": 1,
            "action_history": ("restart_service:lab-api.service",),
        }
    )

    post_recurrence = IncidentRecord(
        incident_id="inc-post-recur",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:05Z",
        services={
            **pre_incident.services,
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                n_restarts=2,
                health_probe_ok=True,
                config_valid=True,
            ),
        },
    )
    report_recur = verifier.verify(
        proposal, exec_result, post_recurrence, pre_incident=pre_incident
    )
    assert report_recur.status == VerificationStatus.NOT_RECOVERED

    next_chosen, _ = selector.select([proposal], pre_incident)
    assert next_chosen.action_id == ActionId.ABSTAIN_AND_ESCALATE.value
    abstain_cap = policy_engine.mint_capability(next_chosen, pre_incident)
    abstain_exec = controller.execute(abstain_cap, current_incident=pre_incident)
    abstain_report = verifier.verify(
        next_chosen, abstain_exec, pre_incident, pre_incident=pre_incident
    )
    assert abstain_report.status == VerificationStatus.NOT_RECOVERED
    assert not abstain_report.target_healthy

    post_collateral = IncidentRecord(
        incident_id="inc-post-collat",
        target_unit="lab-api.service",
        collected_at_utc="2026-10-20T00:00:05Z",
        services={
            "lab-redis.service": pre_incident.services["lab-redis.service"],
            "lab-api.service": ServiceEvidence(
                unit_name="lab-api.service",
                active_state="active",
                sub_state="running",
                n_restarts=1,
                health_probe_ok=True,
                config_valid=True,
            ),
            "lab-worker.service": ServiceEvidence(
                unit_name="lab-worker.service",
                active_state="failed",
                sub_state="failed",
                health_probe_ok=False,
            ),
        },
    )
    report_collat = verifier.verify(
        proposal, exec_result, post_collateral, pre_incident=pre_incident
    )
    assert (
        report_collat.status
        == VerificationStatus.RECOVERED_WITH_COLLATERAL_FAILURE
    )
    assert report_collat.collateral_failures == ("lab-worker.service",)
