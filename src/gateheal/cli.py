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
from gateheal.controller import (
    AuditRecorder,
    ExecutionController,
    OutcomeVerifier,
)
from gateheal.diagnosis import DiagnosisEngine
from gateheal.experiments import (
    ExperimentRunner,
    build_default_scenarios,
    compute_campaign_metrics,
)
from gateheal.models import (
    ActionId,
    ActionProposal,
    AuditRecord,
    ServiceEvidence,
)
from gateheal.policy import MinimalImpactSelector, PolicyEngine
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


def _resolve_transport(mode: str) -> CommandTransport:
    if mode == "simulated":
        return SimulatedLabTransport()
    if mode == "ssh":
        return SSHLabTransport()
    if mode == "local-lab":
        return LocalLabSubprocessTransport()
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
    rec_parser.add_argument(
        "--transport",
        choices=["simulated", "ssh", "local-lab"],
        default="simulated",
        help="Execution transport (default: simulated for host safety).",
    )
    rec_parser.add_argument(
        "--propose-action",
        type=str,
        default=None,
        help="Optional explicit action_id to test policy gate approval/rejection.",
    )

    exp_parser = subparsers.add_parser(
        "run-experiment",
        help="Run repeatable Phase 3 pilot campaign comparing Config A vs Config B.",
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
        default=Path("artifacts/phase3_pilot_summary.json"),
        help="Path to write JSON experiment summary.",
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
        simulated = _build_simulated_services(cfg, args.target)
        incident = collector.collect_simulated(
            incident_id="inc-inspect-001",
            target_unit=args.target,
            simulated_services=simulated,
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
        diagnosis_engine = DiagnosisEngine(cfg)
        policy_engine = PolicyEngine(cfg)
        selector = MinimalImpactSelector(policy_engine)
        transport = _resolve_transport(args.transport)
        controller = ExecutionController(cfg, transport=transport)
        verifier = OutcomeVerifier(cfg)
        recorder = AuditRecorder(Path("artifacts/audit.jsonl"))

        simulated = _build_simulated_services(cfg, args.target)
        incident = collector.collect_simulated(
            incident_id=args.incident_id,
            target_unit=args.target,
            simulated_services=simulated,
        )
        diagnosis = diagnosis_engine.diagnose(incident)

        if args.propose_action is not None:
            candidates = [
                ActionProposal(
                    action_id=args.propose_action,
                    target_unit=args.target,
                    inferred_fault=diagnosis.fault_class,
                    evidence_confidence=diagnosis.confidence,
                    rationale=f"Explicit CLI proposal: {args.propose_action}.",
                )
            ]
        else:
            candidates = [
                ActionProposal(
                    action_id=ActionId.RESTART_SERVICE.value,
                    target_unit=args.target,
                    inferred_fault=diagnosis.fault_class,
                    evidence_confidence=diagnosis.confidence,
                    rationale=f"Deterministic recovery for {diagnosis.fault_class}.",
                ),
                ActionProposal(
                    action_id=ActionId.RELOAD_SERVICE.value,
                    target_unit=args.target,
                    inferred_fault=diagnosis.fault_class,
                    evidence_confidence=diagnosis.confidence,
                    rationale="Graceful reload attempt.",
                ),
            ]

        chosen, decisions = selector.select(candidates, incident)
        abstained = chosen.action_id == ActionId.ABSTAIN_AND_ESCALATE.value

        exec_result = controller.execute(chosen)
        post_simulated = _build_simulated_services(
            cfg,
            args.target,
            target_active="failed" if abstained else "active",
            target_probe_ok=(not abstained and exec_result.exit_code == 0),
        )
        post_incident = collector.collect_simulated(
            incident_id=f"{args.incident_id}-post",
            target_unit=args.target,
            simulated_services=post_simulated,
        )
        ver_report = verifier.verify(
            chosen,
            exec_result,
            post_incident,
            pre_incident=incident,
        )

        audit_rec = AuditRecord(
            incident_id=incident.incident_id,
            recorded_at_utc=incident.collected_at_utc,
            controller_mode=cfg.platform.controller_mode,
            diagnosis=diagnosis,
            evaluated_proposals=tuple(candidates),
            policy_decisions=decisions,
            selected_proposal=chosen,
            execution_result=exec_result,
            verification_report=ver_report,
            abstained=abstained,
        )
        recorder.record(audit_rec)
        print(json.dumps(audit_rec.model_dump(), indent=2))
        return 0

    if args.command == "run-experiment":
        cfg = load_config(args.config)
        scenarios = build_default_scenarios()
        scenarios_by_id = {s.scenario_id: s for s in scenarios}
        runner = ExperimentRunner(
            cfg,
            audit_path=Path("artifacts/phase3_experiment_audit.jsonl"),
        )

        summaries: dict[str, object] = {}
        for mode in (
            "config_a_fixed_runbook",
            "config_b_deterministic_risk_aware",
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

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(summaries, indent=2),
            encoding="utf-8",
        )
        print(json.dumps(summaries, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
