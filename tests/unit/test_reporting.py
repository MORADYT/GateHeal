"""Unit tests for ThesisReportGenerator export formats."""

from __future__ import annotations

import json
from pathlib import Path

from gateheal.reporting import ThesisReportGenerator


def test_thesis_report_generator(tmp_path: Path) -> None:
    summary_json = tmp_path / "summary.json"
    payload = {
        "config_a_fixed_runbook": {
            "config_name": "config_a_fixed_runbook",
            "total_trials": 6,
            "recoverable_trials": 3,
            "unrecoverable_trials": 2,
            "healthy_control_trials": 1,
            "diagnosis_accuracy": 0.833,
            "verified_recovery_rate": 0.666,
            "collateral_failure_rate": 0.333,
            "unsafe_proposal_rate": 0.0,
            "unsafe_executed_action_rate": 0.333,
            "policy_rejection_rate": 0.0,
            "unnecessary_recovery_rate": 0.166,
            "appropriate_abstention_rate": 0.0,
            "false_positive_remediation_rate": 0.0,
            "mean_unavailability_sec": 8.5,
        }
    }
    summary_json.write_text(json.dumps(payload), encoding="utf-8")

    generator = ThesisReportGenerator(summary_json)
    md = generator.render_markdown_table()
    assert "config_a_fixed_runbook" in md
    assert "8.50s" in md

    latex = generator.render_latex_table()
    assert r"\begin{table*}" in latex
    assert "config\\_a\\_fixed\\_runbook" in latex

    csv_path = tmp_path / "out.csv"
    generator.export_csv(csv_path)
    assert csv_path.exists()
    assert "config_a_fixed_runbook" in csv_path.read_text(encoding="utf-8")
