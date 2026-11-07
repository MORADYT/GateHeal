"""WP6 opt-in live QEMU/KVM test running one paired trial per arm (GATEHEAL_RUN_LAB_TESTS=1)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from gateheal.config import load_config
from gateheal.lab_bringup import build_wp5_smoke_expectations
from gateheal.oracle import MIN_ORACLE_HOLD_WINDOW_SEC, OracleEvaluation, OracleOutcomeLabel
from gateheal.reporting import WP6ReportGenerator
from gateheal.transport import SSHLabTransport, TransportUnavailableError
from gateheal.wp6_engine import (
    ALL_WP6_ARMS,
    UNGATED_ARMS,
    WP6ExperimentRunner,
    summarize_wp6_campaign,
)

pytestmark = pytest.mark.lab


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.mark.skipif(
    os.environ.get("GATEHEAL_RUN_LAB_TESTS") != "1",
    reason=(
        "Set GATEHEAL_RUN_LAB_TESTS=1 with booted QEMU/KVM guest on "
        "127.0.0.1:2222"
    ),
)
def test_wp6_live_one_paired_trial_per_arm_on_s1_service_crash(
    tmp_path: Path,
) -> None:
    """Run 1 paired trial across all 6 arms (B0, B1, B2, G, G-nobr, G-nosoak) on live VM."""
    repo_root = _repo_root()
    cfg = load_config(repo_root / "configs" / "phase1_lab.yaml")

    ssh_port = int(os.environ.get("GATEHEAL_LAB_SSH_PORT", "2222"))
    ssh_user = os.environ.get("GATEHEAL_LAB_SSH_USER", "ubuntu")
    vm_dir = Path(
        os.environ.get(
            "GATEHEAL_VM_DIR", str(Path.home() / ".cache" / "gateheal-vm")
        )
    )
    ctrl_key = os.environ.get("GATEHEAL_LAB_SSH_KEY") or str(
        vm_dir / "id_ed25519"
    )
    harness_key = os.environ.get("GATEHEAL_LAB_HARNESS_KEY") or str(
        vm_dir / "id_harness_ed25519"
    )
    guest_repo_dir = os.environ.get("GATEHEAL_GUEST_REPO_DIR", "/opt/gateheal")

    controller_transport = SSHLabTransport(
        host="127.0.0.1",
        port=ssh_port,
        user=ssh_user,
        identity_file=ctrl_key,
        ssh_multiplex=True,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )

    def make_root_transport() -> SSHLabTransport:
        return SSHLabTransport(
            host="127.0.0.1",
            port=ssh_port,
            user="root",
            identity_file=harness_key,
            ssh_multiplex=True,
            use_remote_timeout=True,
            verify_remote_sentinel=True,
        )

    root_transport = make_root_transport()

    s1_exp = [
        e
        for e in build_wp5_smoke_expectations()
        if e.scenario_id == "S1_SERVICE_CRASH"
    ][0]
    out_dir = tmp_path / "wp6_live_smoke"

    runner = WP6ExperimentRunner(
        cfg,
        controller_transport=controller_transport,
        root_transport=root_transport,
        monitor_transport_factory=make_root_transport,
        artifacts_dir=out_dir,
        guest_repo_dir=guest_repo_dir,
        oracle_hold_window_sec=MIN_ORACLE_HOLD_WINDOW_SEC,
        settle_wait_sec=2.0,
    )

    try:
        records = runner.run_campaign(
            trials_per_scenario=1,
            seed=20261028,
            arms=ALL_WP6_ARMS,
            expectations=(s1_exp,),
        )
    except TransportUnavailableError as exc:
        pytest.fail(
            f"Runbook pointer (docs/lab-runbook.md ## Troubleshooting): "
            f"Live SSH transport unavailable during WP6 test: {exc}"
        )
    finally:
        try:
            _ = root_transport.run(
                (
                    "env",
                    "GATEHEAL_INSIDE_LAB=1",
                    "bash",
                    f"{guest_repo_dir}/lab/reset/reset_lab.sh",
                ),
                timeout_sec=15.0,
            )
        except TransportUnavailableError:
            pass

    assert len(records) == len(ALL_WP6_ARMS)
    by_arm = {r.arm_id: r for r in records}
    assert set(by_arm.keys()) == set(ALL_WP6_ARMS)

    def evaluation(arm: str) -> OracleEvaluation:
        ev = by_arm[arm].oracle_evaluation
        assert ev is not None, f"{arm} trial was not evaluable: {by_arm[arm].invalid_reason}"
        return ev

    for arm_id, rec in by_arm.items():
        assert rec.ungated_arm is (arm_id in UNGATED_ARMS)
        assert evaluation(arm_id).hold_window_sec >= MIN_ORACLE_HOLD_WINDOW_SEC

    assert evaluation("B0").outcome == OracleOutcomeLabel.NOT_RECOVERED
    for recovering_arm in ("B1", "B2", "G", "G-nobr", "G-nosoak"):
        assert evaluation(recovering_arm).outcome == OracleOutcomeLabel.RECOVERED_ALL
        assert len(by_arm[recovering_arm].executed_argvs) == 1

    summary = summarize_wp6_campaign(
        records,
        trials_per_scenario=1,
        seed=20261028,
        arms=ALL_WP6_ARMS,
        scenarios=("S1_SERVICE_CRASH",),
    )
    reporter = WP6ReportGenerator(summary)
    sum_p, md_p, tex_p = reporter.write_artifacts(out_dir)
    assert sum_p.is_file()
    assert md_p.is_file()
    assert tex_p.is_file()
