"""Thesis report generator exporting Phase 3 and WP6 campaign metrics."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from gateheal.experiments import CampaignSummaryMetrics
from gateheal.oracle import OracleOutcomeLabel
from gateheal.wp6_engine import WP6CampaignSummary


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


class WP6ReportGenerator:
    """Emits WP6 summary.json, report.md, and LaTeX tables with paired statistics."""

    def __init__(self, summary: WP6CampaignSummary) -> None:
        self._summary = summary

    @property
    def summary(self) -> WP6CampaignSummary:
        """Return the underlying WP6CampaignSummary."""
        return self._summary

    def render_latex_table(self) -> str:
        """Render WP6 arm summary, scenario breakdown, and Holm p-values in LaTeX."""
        holm_map = {
            h.hypothesis_id: h for h in self._summary.holm_bonferroni_family
        }
        lines = [
            r"\begin{table*}[htbp]",
            r"  \centering",
            (
                r"  \caption{WP6 Paired Live-Lab Evaluation "
                r"(Unconditional Denominators, 95\% Wilson CIs)}"
            ),
            r"  \label{tab:wp6_paired_results}",
            r"  \begin{tabular}{lccccccc}",
            r"    \toprule",
            r"    \textbf{Arm} & \textbf{Ungated} & \textbf{Trials ($N$)} & "
            r"\textbf{Recovered All} & \textbf{Collateral} & \textbf{Harmful} & "
            r"\textbf{Approp. Abstain} & \textbf{Mean Unavail. (s)} \\",
            r"    \midrule",
        ]
        for arm_id, s in self._summary.arm_summaries.items():
            clean_arm = arm_id.replace("_", r"\_")
            ung = "Yes" if s.ungated_arm else "No"
            rec_ci = s.recovered_all_rate
            col_ci = s.recovered_with_collateral_rate
            hrm_ci = s.harmful_rate
            abs_ci = s.appropriate_abstention_rate
            lines.append(
                f"    {clean_arm} & {ung} & {s.total_trials} & "
                f"{rec_ci.proportion * 100:.1f}\\% "
                f"[{rec_ci.lower * 100:.1f}, {rec_ci.upper * 100:.1f}] & "
                f"{col_ci.proportion * 100:.1f}\\% & "
                f"{hrm_ci.proportion * 100:.1f}\\% "
                f"[{hrm_ci.lower * 100:.1f}, {hrm_ci.upper * 100:.1f}] & "
                f"{abs_ci.proportion * 100:.1f}\\% & "
                f"{s.mean_unavailability_sec:.2f}s \\\\"
            )
        lines.extend([
            r"    \midrule",
            (
                r"    \multicolumn{8}{l}{\textbf{Paired Hypothesis Tests "
                r"(Holm--Bonferroni Adjusted)}} \\"
            ),
        ])
        for comp in self._summary.paired_comparisons:
            h_item = holm_map.get(comp.comparison_id)
            adj_p = (
                h_item.adjusted_p_value
                if h_item is not None
                else comp.mcnemar.p_value
            )
            clean_id = comp.comparison_id.replace("_", r"\_")
            b_ci = comp.unavailability_bootstrap
            lines.append(
                f"    \\multicolumn{{8}}{{l}}{{{clean_id}: "
                f"$\\Delta p = {comp.rate_diff_a_minus_b:+.3f}$, "
                f"$p_{{\\text{{raw}}}} = {comp.mcnemar.p_value:.4g}$, "
                f"$p_{{\\text{{Holm}}}} = {adj_p:.4g}$, "
                f"$\\Delta \\text{{unavail}} = {b_ci.mean_diff:+.2f}$s "
                f"[{b_ci.ci_lower:+.2f}, {b_ci.ci_upper:+.2f}]}} \\\\"
            )
        lines.extend([
            r"    \bottomrule",
            r"  \end{tabular}",
            r"\end{table*}",
        ])
        return "\n".join(lines)

    def render_markdown_report(self) -> str:
        """Render complete WP6 Markdown report with coverage, outcomes, and paired tests."""
        holm_map = {
            h.hypothesis_id: h for h in self._summary.holm_bonferroni_family
        }
        lines = [
            "# GateHeal WP6 Live-Lab Paired Experiment Report",
            "",
            f"- **Generated (UTC):** `{self._summary.generated_at_utc}`",
            f"- **Randomisation Seed:** `{self._summary.seed}`",
            f"- **Trials per Scenario per Arm:** `{self._summary.trials_per_scenario}`",
            f"- **H2 Non-Inferiority Margin:** `{self._summary.h2_non_inferiority_margin:.2f}`",
            "",
            "## 1. Coverage & Evaluability Table (Unconditional Denominators)",
            "",
            (
                "| Arm | Ungated | Planned | Completed | Evaluable | "
                "Non-Evaluable | Mutating | Abstained | Observe/No-Op |"
            ),
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for arm_id, cov in self._summary.coverage.items():
            lines.append(
                f"| `{arm_id}` | `{str(cov.ungated_arm).lower()}` | {cov.planned_trials} | "
                f"{cov.completed_trials} | {cov.evaluable_trials} | "
                f"{cov.non_evaluable_trials} | {cov.mutating_trials} | "
                f"{cov.abstained_trials} | {cov.observe_only_or_noop_trials} |"
            )

        lines.extend([
            "",
            "## 2. Arm Summary Rates & 95% Wilson Intervals",
            "",
            (
                "| Arm | Ungated | N | Recovered All [95% CI] | Collateral | "
                "Harmful [95% CI] | No-Change Correct | FP Remediation | "
                "Approp. Abstain [95% CI] | Mean Unavail (s) |"
            ),
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ])
        for arm_id, s in self._summary.arm_summaries.items():
            r_all = s.recovered_all_rate
            r_col = s.recovered_with_collateral_rate
            r_hrm = s.harmful_rate
            r_ncc = s.no_change_correct_rate
            r_fpr = s.false_positive_remediation_rate
            r_abs = s.appropriate_abstention_rate
            lines.append(
                f"| `{arm_id}` | `{str(s.ungated_arm).lower()}` | {s.total_trials} | "
                f"{r_all.proportion * 100:.1f}% "
                f"[{r_all.lower * 100:.1f}, {r_all.upper * 100:.1f}] | "
                f"{r_col.proportion * 100:.1f}% | "
                f"{r_hrm.proportion * 100:.1f}% "
                f"[{r_hrm.lower * 100:.1f}, {r_hrm.upper * 100:.1f}] | "
                f"{r_ncc.proportion * 100:.1f}% | "
                f"{r_fpr.proportion * 100:.1f}% | "
                f"{r_abs.proportion * 100:.1f}% "
                f"[{r_abs.lower * 100:.1f}, {r_abs.upper * 100:.1f}] | "
                f"{s.mean_unavailability_sec:.2f}s |"
            )

        lines.extend([
            "",
            "## 3. Arm × Scenario Oracle Outcome Counts",
            "",
            (
                "| Scenario | Arm | Recov. All | Collateral | Not Recov. | "
                "Harmful | No-Change Correct | FP Remediation |"
            ),
            "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        ])
        for scen_id, arm_map in self._summary.scenario_arm_outcomes.items():
            for arm_id, counts in arm_map.items():
                c_all = counts.get(OracleOutcomeLabel.RECOVERED_ALL.value, 0)
                c_col = counts.get(
                    OracleOutcomeLabel.RECOVERED_WITH_COLLATERAL.value, 0
                )
                c_not = counts.get(OracleOutcomeLabel.NOT_RECOVERED.value, 0)
                c_hrm = counts.get(OracleOutcomeLabel.HARMFUL.value, 0)
                c_ncc = counts.get(
                    OracleOutcomeLabel.NO_CHANGE_CORRECT.value, 0
                )
                c_fpr = counts.get(
                    OracleOutcomeLabel.FALSE_POSITIVE_REMEDIATION.value, 0
                )
                lines.append(
                    f"| `{scen_id}` | `{arm_id}` | {c_all} | {c_col} | "
                    f"{c_not} | {c_hrm} | {c_ncc} | {c_fpr} |"
                )

        lines.extend([
            "",
            "## 4. Paired Hypothesis Tests & Holm–Bonferroni Adjustment",
            "",
            (
                "| Comparison ID | Hypothesis | Pairs | Rate A | Rate B | "
                "Diff (A-B) | McNemar p (raw) | Holm p (adj) | Rejected | "
                "Wilcoxon p | Bootstrap Unavail Diff [95% CI] |"
            ),
            (
                "| :--- | :---: | :---: | :---: | :---: | "
                "| :---: | :---: | :---: | :---: | :---: | :---: |"
            ),
        ])
        for comp in self._summary.paired_comparisons:
            h_item = holm_map.get(comp.comparison_id)
            adj_p = (
                h_item.adjusted_p_value
                if h_item is not None
                else comp.mcnemar.p_value
            )
            rej = h_item.rejected if h_item is not None else False
            boot = comp.unavailability_bootstrap
            lines.append(
                f"| `{comp.comparison_id}` | `{comp.hypothesis_id}` | {comp.n_pairs} | "
                f"{comp.rate_a:.3f} | {comp.rate_b:.3f} | "
                f"{comp.rate_diff_a_minus_b:+.3f} | "
                f"{comp.mcnemar.p_value:.4g} | {adj_p:.4g} | `{str(rej).lower()}` | "
                f"{comp.unavailability_wilcoxon.p_value:.4g} | "
                f"{boot.mean_diff:+.2f}s [{boot.ci_lower:+.2f}, {boot.ci_upper:+.2f}] |"
            )

        lines.extend([
            "",
            "## 5. LaTeX Table",
            "",
            "```latex",
            self.render_latex_table(),
            "```",
            "",
        ])
        return "\n".join(lines)

    def write_artifacts(self, output_dir: Path) -> tuple[Path, Path, Path]:
        """Write summary.json, report.md, and table.tex into output_dir."""
        output_dir.mkdir(parents=True, exist_ok=True)
        summary_path = output_dir / "summary.json"
        report_md_path = output_dir / "report.md"
        latex_path = output_dir / "table.tex"

        summary_path.write_text(
            self._summary.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        report_md_path.write_text(
            self.render_markdown_report(), encoding="utf-8"
        )
        latex_path.write_text(
            self.render_latex_table() + "\n", encoding="utf-8"
        )
        return summary_path, report_md_path, latex_path
