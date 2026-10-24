"""Command-line interface for GateHeal."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from gateheal.actions import DEFAULT_ACTION_CATALOGUE
from gateheal.collector import IncidentCollector
from gateheal.config import GateHealConfig, load_config
from gateheal.controller import AuditRecorder, default_artifacts_dir
from gateheal.diagnosis import DiagnosisEngine
from gateheal.experiments import (
    ExperimentRunner,
    build_default_scenarios,
    compute_campaign_metrics,
)
from gateheal.models import (
    ActionId,
    ActionProposal,
    DiagnosisResult,
    ExecutionResult,
    IncidentRecord,
    ServiceEvidence,
)
from gateheal.orchestrator import (
    IncidentOrchestrator,
    build_default_deterministic_candidates,
)
from gateheal.state import PersistentStateStore
from gateheal.transport import (
    CommandTransport,
    LocalLabSubprocessTransport,
    SimulatedLabTransport,
    SSHLabTransport,
)


def _build_simulated_services(
    cfg: GateHealConfig,
    target: str,
    *,
    target_active: str = "failed",
    target_probe_ok: bool = False,
    target_config_valid: bool = True,
) -> dict[str, ServiceEvidence]:
    services: dict[str, ServiceEvidence] = {
        target: ServiceEvidence(
            unit_name=target,
            active_state=target_active,
            sub_state="running" if target_active == "active" else "failed",
            result="exit-code" if target_active != "active" else "success",
            can_reload=True,
            health_probe_ok=target_probe_ok,
            config_valid=target_config_valid,
        )
    }
    for unit in cfg.inventory.services:
        if unit != target:
            services[unit] = ServiceEvidence(
                unit_name=unit,
                active_state="active",
                sub_state="running",
                can_reload=cfg.inventory.services[unit].supports_reload,
                health_probe_ok=True,
                config_valid=True,
            )
    return services


def _add_transport_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--transport",
        choices=["simulated", "ssh", "local-lab"],
        default="simulated",
        help="Execution transport (default: simulated for host safety).",
    )
    parser.add_argument(
        "--ssh-host",
        type=str,
        default="127.0.0.1",
        help="Loopback SSH host for isolated lab VM (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=2222,
        help="SSH port for isolated lab VM (default: 2222).",
    )
    parser.add_argument(
        "--ssh-user",
        type=str,
        default="ubuntu",
        help="SSH username for isolated lab VM (default: ubuntu).",
    )
    parser.add_argument(
        "--ssh-identity-file",
        type=str,
        default=None,
        help="Optional path to SSH private key file for lab VM.",
    )
    parser.add_argument(
        "--systemd-scope",
        action="store_true",
        help="Wrap non-sudo lab commands in transient cgroup v2 `systemd-run --scope`.",
    )


def _resolve_transport_from_args(args: argparse.Namespace) -> CommandTransport:
    mode = str(args.transport)
    if mode == "simulated":
        return SimulatedLabTransport()
    if mode == "ssh":
        return SSHLabTransport(
            host=str(args.ssh_host),
            port=int(args.ssh_port),
            user=str(args.ssh_user),
            identity_file=args.ssh_identity_file,
            use_systemd_scope=bool(args.systemd_scope),
            use_remote_timeout=True,
            verify_remote_sentinel=True,
        )
    if mode == "local-lab":
        return LocalLabSubprocessTransport(
            use_systemd_scope=bool(args.systemd_scope)
        )
    raise ValueError(f"Unsupported transport mode: {mode}")


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="gateheal",
        description="GateHeal: Policy-gated Linux self-healing controller.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    val_parser = subparsers.add_parser(
        "validate-config",
        help="Validate GateHeal YAML config and inventory.",
    )
    val_parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Path to YAML config file.",
    )

    subparsers.add_parser(
        "list-actions",
        help="List registered actions in ActionCatalogue.",
    )

    insp_parser = subparsers.add_parser(
        "inspect",
        help="Collect and print a bounded IncidentRecord and DiagnosisResult.",
    )
    insp_parser.add_argument(
        "--config", type=Path, required=True, help="Path to YAML config."
    )
    insp_parser.add_argument(
        "--target", type=str, required=True, help="Target systemd unit."
    )
    _add_transport_arguments(insp_parser)

    rec_parser = subparsers.add_parser(
        "recover",
        help="Run deterministic recovery controller on a target unit.",
    )
    rec_parser.add_argument(
        "--config", type=Path, required=True, help="Path to YAML config."
    )
    rec_parser.add_argument(
        "--target", type=str, required=True, help="Target systemd unit."
    )
    rec_parser.add_argument(
        "--incident-id", type=str, default="inc-cli-001", help="Incident ID."
    )
    _add_transport_arguments(rec_parser)
    rec_parser.add_argument(
        "--propose-action",
        type=str,
        default=None,
        help="Optional explicit action_id to test policy gate approval/rejection.",
    )
    rec_parser.add_argument(
        "--state-file",
        type=Path,
        default=None,
        help="Optional path to persistent incident state JSON file.",
    )
    rec_parser.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help="Optional path to tamper-evident JSONL audit log.",
    )

    exp_parser = subparsers.add_parser(
        "run-experiment",
        help="Run repeatable campaign comparing Config A, B, C, and D.",
    )
    exp_parser.add_argument(
        "--config", type=Path, required=True, help="Path to YAML config."
    )
    exp_parser.add_argument(
        "--trials",
        type=int,
        default=5,
        help="Number of repeated trials per scenario (default: 5).",
    )
    exp_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to write JSON experiment summary.",
    )

    rep_parser = subparsers.add_parser(
        "export-metrics",
        help="Export experiment summaries to Markdown, LaTeX, and CSV.",
    )
    rep_parser.add_argument(
        "--summary-json",
        type=Path,
        default=None,
        help="Path to JSON summary.",
    )
    rep_parser.add_argument(
        "--format",
        choices=["markdown", "latex", "csv"],
        default="markdown",
        help="Output format.",
    )
    rep_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output file path.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate-config":
        cfg = load_config(args.config)
        summary = {
            "status": "valid",
            "controller_mode": cfg.platform.controller_mode,
            "services": list(cfg.inventory.services.keys()),
            "max_recovery_attempts": cfg.budgets.max_recovery_attempts,
        }
        print(json.dumps(summary, indent=2))
        return 0

    if args.command == "list-actions":
        catalogue_out = [
            {
                "action_id": spec.action_id.value,
                "enabled": spec.enabled,
                "impact_tier": int(spec.impact_tier),
                "permission": spec.required_permission.value,
                "reversible": spec.reversible,
                "timeout_sec": spec.timeout_sec,
            }
            for spec in DEFAULT_ACTION_CATALOGUE.values()
        ]
        print(json.dumps(catalogue_out, indent=2))
        return 0

    if args.command == "inspect":
        cfg = load_config(args.config)
        collector = IncidentCollector(cfg)
        diagnosis_engine = DiagnosisEngine(cfg)
        transport = _resolve_transport_from_args(args)
        if args.transport == "simulated":
            simulated = _build_simulated_services(cfg, args.target)
            incident = collector.collect_simulated(
                incident_id="inc-inspect-001",
                target_unit=args.target,
                simulated_services=simulated,
            )
        else:
            incident = collector.collect_from_transport(
                incident_id="inc-inspect-001",
                target_unit=args.target,
                transport=transport,
            )
        diag = diagnosis_engine.diagnose(incident)
        out = {
            "incident": incident.model_dump(),
            "diagnosis": diag.model_dump(),
        }
        print(json.dumps(out, indent=2))
        return 0

    if args.command == "recover":
        cfg = load_config(args.config)
        collector = IncidentCollector(cfg)
        transport = _resolve_transport_from_args(args)
        state_path = (
            args.state_file
            if args.state_file is not None
            else (
                default_artifacts_dir() / f"state_{args.incident_id}.json"
                if args.transport == "simulated"
                else default_artifacts_dir() / "incident_state.json"
            )
        )
        state_store = PersistentStateStore(state_path)
        if args.transport == "simulated" and args.state_file is None:
            state_store.seed_unit_state(args.target, incident_id=args.incident_id)

        recorder = AuditRecorder(args.audit_log)
        orchestrator = IncidentOrchestrator(
            cfg,
            transport=transport,
            collector=collector,
            audit_recorder=recorder,
            state_store=state_store,
        )

        def _sim_evidence(
            inc_id: str,
            unit: str,
            d_att: int,
            r_att: int,
            hist: tuple[str, ...],
            elap: float,
        ) -> IncidentRecord:
            sim = _build_simulated_services(cfg, unit)
            return collector.collect_simulated(
                incident_id=inc_id,
                target_unit=unit,
                simulated_services=sim,
                prior_diagnostic_attempts=d_att,
                prior_recovery_attempts=r_att,
                action_history=hist,
                elapsed_sec=elap,
            )

        def _sim_post_evidence(
            chosen: ActionProposal,
            exec_res: ExecutionResult,
            _pre_inc: IncidentRecord,
            elap: float,
        ) -> IncidentRecord:
            abstained = chosen.action_id in (
                ActionId.ABSTAIN_AND_ESCALATE.value,
                ActionId.NO_OP.value,
            )
            post_sim = _build_simulated_services(
                cfg,
                args.target,
                target_active="failed" if abstained else "active",
                target_probe_ok=(not abstained and exec_res.exit_code == 0),
            )
            return collector.collect_simulated(
                incident_id=f"{args.incident_id}-post",
                target_unit=args.target,
                simulated_services=post_sim,
                elapsed_sec=elap,
            )

        def _candidate_supplier(
            inc: IncidentRecord, diag: DiagnosisResult
        ) -> Sequence[ActionProposal]:
            if args.propose_action is not None:
                return (
                    ActionProposal(
                        action_id=args.propose_action,
                        target_unit=args.target,
                        inferred_fault=diag.fault_class,
                        rationale=f"Explicit CLI proposal: {args.propose_action}.",
                    ),
                )
            return build_default_deterministic_candidates(inc, diag)

        use_sim = args.transport == "simulated"
        audit_rec = orchestrator.handle_incident(
            incident_id=args.incident_id,
            target_unit=args.target,
            evidence_supplier=_sim_evidence if use_sim else None,
            post_evidence_supplier=_sim_post_evidence if use_sim else None,
            candidate_supplier=_candidate_supplier,
        )
        print(json.dumps(audit_rec.model_dump(), indent=2))
        return 0

    if args.command == "export-metrics":
        from gateheal.reporting import ThesisReportGenerator

        summary_path = args.summary_json or (
            default_artifacts_dir() / "phase3_pilot_summary.json"
        )
        generator = ThesisReportGenerator(summary_path)
        if args.format == "markdown":
            out_str = generator.render_markdown_table()
        elif args.format == "latex":
            out_str = generator.render_latex_table()
        else:
            csv_path = args.output or (
                default_artifacts_dir() / "thesis_metrics.csv"
            )
            generator.export_csv(csv_path)
            out_str = f"Exported CSV metrics to {csv_path}"

        if args.output and args.format != "csv":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(out_str, encoding="utf-8")
        print(out_str)
        return 0

    if args.command == "run-experiment":
        cfg = load_config(args.config)
        scenarios = build_default_scenarios()
        scenarios_by_id = {s.scenario_id: s for s in scenarios}
        runner = ExperimentRunner(
            cfg,
            audit_path=default_artifacts_dir() / "phase3_experiment_audit.jsonl",
        )

        summaries: dict[str, object] = {}
        for mode in (
            "config_a_fixed_runbook",
            "config_b_deterministic_risk_aware",
            "config_c_ungated_llm_agent",
            "config_d_policy_gated_llm_agent",
        ):
            mode_outcomes = []
            for trial_idx in range(1, args.trials + 1):
                for scen in scenarios:
                    outcome = runner.run_single_trial(
                        scen,
                        config_name=mode,
                        trial_index=trial_idx,
                    )
                    mode_outcomes.append(outcome)
            metrics = compute_campaign_metrics(mode, mode_outcomes, scenarios_by_id)
            summaries[mode] = metrics.model_dump()

        out_path = args.output or (
            default_artifacts_dir() / "phase3_pilot_summary.json"
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(summaries, indent=2),
            encoding="utf-8",
        )
        print(json.dumps(summaries, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
