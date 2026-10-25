"""Thesis report generator exporting campaign metrics into Markdown, LaTeX, and CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from gateheal.experiments import CampaignSummaryMetrics


class ThesisReportGenerator:
    """Generates formatted academic tables from experiment campaign summaries."""

    def __init__(self, summaries_json_path: Path) -> None:
        self._path = summaries_json_path
        self._data: dict[str, dict[str, object]] = {}
        if summaries_json_path.exists():
            raw = summaries_json_path.read_text(encoding="utf-8")
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                self._data = loaded

    def render_markdown_table(self) -> str:
        """Render campaign comparison metrics as an academic Markdown table."""
        lines = [
            (
                "| Configuration | Trials | Diag Acc (%) | "
                "Recov Rate (%) | Unsafe Exec (%) | Policy Rej (%) | Mean Down (s) |"
            ),
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for mode, raw_metrics in self._data.items():
            metrics = CampaignSummaryMetrics.model_validate(raw_metrics)
            lines.append(
                f"| `{mode}` | {metrics.total_trials} | "
                f"{metrics.diagnosis_accuracy * 100:.1f}% | "
                f"{metrics.verified_recovery_rate * 100:.1f}% | "
                f"{metrics.unsafe_executed_action_rate * 100:.1f}% | "
                f"{metrics.policy_rejection_rate * 100:.1f}% | "
                f"{metrics.mean_unavailability_sec:.2f}s |"
            )
        return "\n".join(lines)

    def render_latex_table(self) -> str:
        """Render campaign comparison metrics as a LaTeX table for your thesis."""
        lines = [
            r"\begin{table*}[htbp]",
            r"  \centering",
            r"  \caption{GateHeal Experimental Evaluation Campaign Summary}",
            r"  \label{tab:gateheal_results}",
            r"  \begin{tabular}{lcccccc}",
            r"    \toprule",
            r"    \textbf{Configuration Mode} & \textbf{Trials} & "
            r"\textbf{Diag. Acc.} & \textbf{Recov. Rate} & "
            r"\textbf{Unsafe Exec.} & \textbf{Policy Rej.} & \textbf{Mean Downtime} \\",
            r"    \midrule",
        ]
        for mode, raw_metrics in self._data.items():
            metrics = CampaignSummaryMetrics.model_validate(raw_metrics)
            clean_mode = mode.replace("_", r"\_")
            lines.append(
                f"    {clean_mode} & {metrics.total_trials} & "
                f"{metrics.diagnosis_accuracy * 100:.1f}\\% & "
                f"{metrics.verified_recovery_rate * 100:.1f}\\% & "
                f"{metrics.unsafe_executed_action_rate * 100:.1f}\\% & "
                f"{metrics.policy_rejection_rate * 100:.1f}\\% & "
                f"{metrics.mean_unavailability_sec:.2f}s \\\\"
            )
        lines.extend([
            r"    \bottomrule",
            r"  \end{tabular}",
            r"\end{table*}",
        ])
        return "\n".join(lines)

    def export_csv(self, output_csv_path: Path) -> None:
        """Export raw metrics into a CSV file for plotting."""
        output_csv_path.parent.mkdir(parents=True, exist_ok=True)
        with output_csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "config_name",
                "total_trials",
                "diagnosis_accuracy",
                "verified_recovery_rate",
                "collateral_failure_rate",
                "unsafe_proposal_rate",
                "unsafe_executed_action_rate",
                "policy_rejection_rate",
                "mean_unavailability_sec",
            ])
            for _mode, raw_metrics in self._data.items():
                m = CampaignSummaryMetrics.model_validate(raw_metrics)
                writer.writerow([
                    m.config_name,
                    m.total_trials,
                    m.diagnosis_accuracy,
                    m.verified_recovery_rate,
                    m.collateral_failure_rate,
                    m.unsafe_proposal_rate,
                    m.unsafe_executed_action_rate,
                    m.policy_rejection_rate,
                    m.mean_unavailability_sec,
                ])
