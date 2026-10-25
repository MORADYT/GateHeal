#!/usr/bin/env python3
"""Host-side WP5 runner: executes conformance, multiplexed latency, S0-S5B smoke matrix, and manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

from gateheal.config import load_config
from gateheal.controller import AuditRecorder, EscalationSink, default_artifacts_dir
from gateheal.lab_bringup import (
    ConformanceFactResult,
    SmokeScenarioRunResult,
    build_lab_run_manifest,
    build_wp5_smoke_expectations,
    measure_transport_latency,
    parse_conformance_output,
    wait_for_expected_pre_state,
)
from gateheal.models import ActionId
from gateheal.orchestrator import IncidentOrchestrator
from gateheal.state import PersistentStateStore
from gateheal.transport import SSHLabTransport, TransportUnavailableError, RecordingTransport


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp5_capture_and_verify",
        description="Run WP5 real-lab conformance, S0-S5B smoke matrix with --repeats, and capture fixtures.",
    )
    repo_root = Path(__file__).resolve().parents[2]
    vm_dir = Path(os.environ.get("GATEHEAL_VM_DIR", str(Path.home() / ".cache" / "gateheal-vm")))
    parser.add_argument(
        "--config",
        type=Path,
        default=repo_root / "configs" / "phase1_lab.yaml",
    )
    parser.add_argument("--ssh-host", type=str, default="127.0.0.1")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--ssh-user", type=str, default="ubuntu")
    parser.add_argument(
        "--ssh-identity-file",
        type=str,
        default=str(vm_dir / "id_ed25519"),
        help="Unprivileged controller SSH key (authorized only for ubuntu).",
    )
    parser.add_argument(
        "--harness-identity-file",
        type=str,
        default=str(vm_dir / "id_harness_ed25519"),
        help="Dedicated harness SSH key (authorized for root fault injection/reset).",
    )
    parser.add_argument(
        "--guest-repo-dir",
        type=str,
        default="/opt/gateheal",
        help="Path to GateHeal repo inside the guest VM.",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="Number of times to run each smoke scenario.",
    )
    parser.add_argument(
        "--fixtures-out",
        type=Path,
        default=repo_root / "tests" / "lab" / "fixtures" / "vm_captured_systemd_facts.json",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=default_artifacts_dir() / "wp5_lab_manifest.json",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[2]
    cfg = load_config(args.config)

    transport = SSHLabTransport(
        host=args.ssh_host,
        port=args.ssh_port,
        user=args.ssh_user,
        identity_file=args.ssh_identity_file,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )
    transport_mux = SSHLabTransport(
        host=args.ssh_host,
        port=args.ssh_port,
        user=args.ssh_user,
        identity_file=args.ssh_identity_file,
        ssh_multiplex=True,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )
    root_harness = SSHLabTransport(
        host=args.ssh_host,
        port=args.ssh_port,
        user="root",
        identity_file=args.harness_identity_file,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )

    bad_root_transport = SSHLabTransport(
        host=args.ssh_host,
        port=args.ssh_port,
        user="root",
        identity_file=args.ssh_identity_file,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )
    try:
        bad_root_transport.run(("id",), timeout_sec=3.0)
        controller_key_root_denied = False
        e6_fact = ConformanceFactResult(
            fact_id="SSH_NEG_CONTROLLER_KEY_DENIED_ROOT",
            passed=False,
            details="SECURITY FAILURE: Controller key allowed to log in as root",
        )
    except TransportUnavailableError as exc:
        controller_key_root_denied = exc.exit_code != 0
        e6_fact = ConformanceFactResult(
            fact_id="SSH_NEG_CONTROLLER_KEY_DENIED_ROOT",
            passed=controller_key_root_denied,
            details=(
                f"Controller key correctly rejected for root@{args.ssh_host} "
                f"(exit_code={exc.exit_code})"
            ),
        )

    try:
        uname_res = transport.run(("uname", "-r"), timeout_sec=5.0)
        sysd_res = transport.run(("systemctl", "--version"), timeout_sec=5.0)
        machine_res = transport.run(("cat", "/etc/machine-id"), timeout_sec=5.0)
    except TransportUnavailableError as exc:
        print(f"ERROR: SSH transport unavailable: {exc}", file=sys.stderr)
        print("Troubleshooting: Refer to docs/lab-runbook.md for troubleshooting.", file=sys.stderr)
        return 2

    guest_kernel = uname_res.stdout_excerpt.strip() or "unknown"
    guest_systemd_version = (
        sysd_res.stdout_excerpt.splitlines()[0].strip()
        if sysd_res.stdout_excerpt.strip()
        else "unknown"
    )
    raw_machine_id = machine_res.stdout_excerpt.strip()
    guest_machine_id_sha256 = (
        hashlib.sha256(raw_machine_id.encode("utf-8")).hexdigest()
        if raw_machine_id
        else None
    )

    latency_profile = measure_transport_latency(transport, samples=10)
    latency_mux_profile = measure_transport_latency(transport_mux, samples=10)

    try:
        conf_res = root_harness.run(
            (
                "env",
                "GATEHEAL_INSIDE_LAB=1",
                "bash",
                f"{args.guest_repo_dir}/lab/scripts/check_conformance.sh",
            ),
            timeout_sec=45.0,
        )
    except TransportUnavailableError as exc:
        print(f"ERROR: Harness transport unavailable during conformance: {exc}", file=sys.stderr)
        return 2

    conformance_facts = (*parse_conformance_output(conf_res.stdout_excerpt), e6_fact)
    conformance_all_passed = bool(conformance_facts) and all(f.passed for f in conformance_facts)

    smoke_results: list[SmokeScenarioRunResult] = []
    captured_show_outputs: dict[str, dict[str, str]] = {}
    scenarios_probes_data: dict[str, dict[str, object]] = {}

    recording_transport = RecordingTransport(transport)

    try:
        with tempfile.TemporaryDirectory() as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            for exp in build_wp5_smoke_expectations():
                for repeat_idx in range(1, args.repeats + 1):
                    _ = root_harness.run(
                        (
                            "env",
                            "GATEHEAL_INSIDE_LAB=1",
                            "bash",
                            f"{args.guest_repo_dir}/lab/reset/reset_lab.sh",
                        ),
                        timeout_sec=15.0,
                    )
                    if exp.fault_injection_arg is not None:
                        _ = root_harness.run(
                            (
                                "env",
                                "GATEHEAL_INSIDE_LAB=1",
                                "bash",
                                f"{args.guest_repo_dir}/lab/fault_injection/inject_fault.sh",
                                exp.fault_injection_arg,
                            ),
                            timeout_sec=10.0,
                        )
                    if exp.scenario_id == "S5_COLLATERAL_TRAP" and exp.seed_prior_recovery_attempts == 0:
                        _ = root_harness.run(
                            ("systemctl", "restart", "lab-api.service", "lab-worker.service"),
                            timeout_sec=10.0,
                        )

                    recording_transport.reset_counts()
                    _ = wait_for_expected_pre_state(
                        recording_transport,
                        exp.expected_pre_active_states,
                        timeout_sec=20.0,
                        poll_interval_sec=0.5,
                        grace_wait_sec=5.5,
                    )

                    scen_captures: dict[str, str] = {}
                    for unit_name in cfg.inventory.services:
                        show_r = recording_transport.run(
                            (
                                "systemctl",
                                "show",
                                unit_name,
                                "--property=ActiveState,SubState,Result,NRestarts,CanReload,"
                                "ActiveEnterTimestampMonotonic,InvocationID,ExecMainStartTimestampMonotonic",
                            ),
                            timeout_sec=5.0,
                        )
                        scen_captures[unit_name] = show_r.stdout_excerpt
                    if repeat_idx == 1:
                        captured_show_outputs[exp.scenario_id] = scen_captures

                    uptime_r = recording_transport.run(("cat", "/proc/uptime"), timeout_sec=3.0)
                    jnl_r = recording_transport.run(
                        (
                            "journalctl", "-u", "lab-api.service", "-n", "20",
                            "--no-pager", "-o", "short-monotonic",
                        ),
                        timeout_sec=5.0,
                    )
                    curl_r = recording_transport.run(
                        (
                            "curl", "-sS", "-w", r" HTTP=%{http_code}",
                            "http://127.0.0.1:8080/healthz",
                        ),
                        timeout_sec=5.0,
                    )
                    tcp_6379_r = recording_transport.run(
                        (
                            "/usr/bin/python3", "-m", "gateheal.lab_daemons",
                            "--check-tcp", "--host", "127.0.0.1", "--port", "6379",
                        ),
                        timeout_sec=3.0,
                    )
                    tcp_8081_r = recording_transport.run(
                        (
                            "/usr/bin/python3", "-m", "gateheal.lab_daemons",
                            "--check-tcp", "--host", "127.0.0.1", "--port", "8081",
                        ),
                        timeout_sec=3.0,
                    )
                    val_cfg_r = recording_transport.run(
                        (
                            "/usr/bin/python3", "-m", "gateheal.lab_daemons",
                            "--validate-config", "/etc/lab-api/config.yaml",
                        ),
                        timeout_sec=3.0,
                    )
                    if repeat_idx == 1:
                        scenarios_probes_data[exp.scenario_id] = {
                            "uptime": uptime_r.stdout_excerpt,
                            "journal_api": jnl_r.stdout_excerpt,
                            "curl_healthz": curl_r.stdout_excerpt,
                            "tcp_6379_exit": tcp_6379_r.exit_code,
                            "tcp_8081_exit": tcp_8081_r.exit_code,
                            "validate_config_exit": val_cfg_r.exit_code,
                        }

                    inc_id = f"wp5-smoke-{exp.scenario_id.lower()}-r{repeat_idx}"
                    state_store = PersistentStateStore(tmp_dir / f"{inc_id}.json")
                    state_store.seed_unit_state(
                        "lab-api.service",
                        incident_id=inc_id,
                        prior_recovery_attempts=exp.seed_prior_recovery_attempts,
                        action_history=exp.seed_action_history,
                    )
                    approval_token = None
                    if exp.requires_approval_token:
                        from gateheal.policy import mint_approval_token, load_operator_hmac_key
                        hmac_k = load_operator_hmac_key() or b"dev-operator-hmac-secret-key-32bytes-long!!"
                        from gateheal.collector import IncidentCollector
                        collector = IncidentCollector(cfg)
                        collected_inc = collector.collect_from_transport(
                            incident_id=inc_id,
                            target_unit="lab-api.service",
                            transport=recording_transport,
                        )
                        approval_token = mint_approval_token(
                            token_id=f"tok-{repeat_idx}",
                            incident=collected_inc,
                            config=cfg,
                            action_id=ActionId.RESTART_SERVICE.value,
                            target_unit="lab-api.service",
                            expires_at_utc="2099-01-01T00:00:00Z",
                            hmac_key=hmac_k,
                        )

                    orchestrator = IncidentOrchestrator(
                        cfg,
                        transport=recording_transport,
                        audit_recorder=AuditRecorder(tmp_dir / f"{inc_id}_audit.jsonl"),
                        escalation_sink=EscalationSink(tmp_dir / f"{inc_id}_esc.jsonl"),
                        state_store=state_store,
                    )

                    t_start = time.monotonic()
                    audit = orchestrator.handle_incident(
                        incident_id=inc_id,
                        target_unit="lab-api.service",
                        approval_token=approval_token,
                    )
                    wall_sec = round(max(0.0, time.monotonic() - t_start), 3)

                    if audit.selected_proposal is None or audit.verification_report is None:
                        raise RuntimeError(f"Scenario {exp.scenario_id} produced incomplete audit.")

                    sel = audit.selected_proposal
                    ver = audit.verification_report
                    mut_exec = recording_transport.mutating_commands_executed
                    total_cmds = recording_transport.ssh_command_count

                    matched = (
                        audit.diagnosis.fault_class in exp.expected_fault_classes
                        and sel.action_id == exp.expected_action_id.value
                        and sel.target_unit == exp.expected_target_unit
                        and ver.status == exp.expected_verification_status
                        and ver.collateral_failures == exp.expected_collateral_failures
                        and audit.escalated == exp.expected_escalated
                        and mut_exec == exp.expected_mutating_commands
                    )
                    budget_ok = wall_sec < cfg.budgets.total_incident_timeout_sec

                    smoke_results.append(
                        SmokeScenarioRunResult(
                            scenario_id=exp.scenario_id,
                            repeat_index=repeat_idx,
                            diagnosed_fault=audit.diagnosis.fault_class,
                            selected_action_id=sel.action_id,
                            selected_target_unit=sel.target_unit,
                            verification_status=ver.status,
                            collateral_failures=ver.collateral_failures,
                            samples_collected=ver.samples_collected,
                            soak_wall_clock_sec=wall_sec,
                            soak_budget_ok=budget_ok,
                            ssh_command_count=total_cmds,
                            mutating_commands_executed=mut_exec,
                            escalated=audit.escalated,
                            matched_expectation=matched,
                        )
                    )
        try:
            root_harness.run(
                (
                    "env", "GATEHEAL_INSIDE_LAB=1", "bash",
                    f"{args.guest_repo_dir}/lab/reset/reset_lab.sh",
                ),
                timeout_sec=15.0,
            )
        except TransportUnavailableError:
            pass

    except TransportUnavailableError as exc:
        print(f"ERROR: Transport unavailable during smoke execution: {exc}", file=sys.stderr)
        print("Troubleshooting: Refer to docs/lab-runbook.md for troubleshooting.", file=sys.stderr)
        return 2

    vm_dir = Path(os.environ.get("GATEHEAL_VM_DIR", str(Path.home() / ".cache" / "gateheal-vm")))
    manifest = build_lab_run_manifest(
        repo_root=repo_root,
        config_path=args.config,
        sudoers_path=repo_root / "lab" / "systemd" / "gateheal-sudoers.conf",
        ssh_latency=latency_profile,
        ssh_latency_multiplexed=latency_mux_profile,
        conformance_facts=conformance_facts,
        smoke_matrix=smoke_results,
        guest_kernel=guest_kernel,
        guest_systemd_version=guest_systemd_version,
        guest_machine_id_sha256=guest_machine_id_sha256,
        controller_key_root_login_denied=controller_key_root_denied,
        base_image_path=vm_dir / "ubuntu-24.04-base.qcow2",
        overlay_image_path=vm_dir / "lab-overlay.qcow2",
        repeats=args.repeats,
    )

    args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_out.write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )

    if conformance_all_passed:
        fixture_payload = {
            "capture_source": "LIVE_QEMU_KVM_GUEST",
            "capture_id": uuid.uuid4().hex,
            "captured_at_utc": manifest.generated_at_utc,
            "guest_kernel": guest_kernel,
            "guest_systemd_version": guest_systemd_version,
            "guest_machine_id_sha256": guest_machine_id_sha256,
            "conformance_facts": [f.model_dump() for f in conformance_facts],
            "scenarios_systemctl_show": captured_show_outputs,
            "scenarios_probes": scenarios_probes_data,
        }
        args.fixtures_out.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_fix_path = tempfile.mkstemp(dir=str(args.fixtures_out.parent), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tf:
                json.dump(fixture_payload, tf, indent=2)
                tf.write("\n")
            os.replace(tmp_fix_path, args.fixtures_out)
        finally:
            if os.path.exists(tmp_fix_path):
                try:
                    os.unlink(tmp_fix_path)
                except OSError:
                    pass

    print(manifest.model_dump_json(indent=2))
    return 0 if (manifest.conformance_all_passed and manifest.smoke_all_passed) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TransportUnavailableError as exc:
        print(f"ERROR: SSH to {exc} failed. Troubleshooting: see docs/lab-runbook.md.", file=sys.stderr)
        sys.exit(2)
