"""Thesis report generator exporting Phase 3 and WP6 campaign metrics."""

from __future__ import annotations

import csv
import json
from collections.abc import Sequence
from pathlib import Path

from gateheal.experiments import CampaignSummaryMetrics
from gateheal.oracle import OracleOutcomeLabel
from gateheal.stats import HolmAdjustedItem, ProportionInterval
from gateheal.wp6_engine import NON_EVALUABLE_KEY, WP6CampaignSummary


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


def render_markdown_table(
    headers: Sequence[str], rows: Sequence[Sequence[str]], *, left_aligned: int = 1
) -> list[str]:
    """Render a GitHub-flavoured table whose every row has exactly len(headers) cells."""
    width = len(headers)
    if width < 1:
        raise ValueError("a table needs at least one column")
    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(":---" if i < left_aligned else ":---:" for i in range(width)) + " |",
    ]
    for row in rows:
        if len(row) != width:
            raise ValueError(f"table row has {len(row)} cells, expected {width}: {row!r}")
        if any("|" in cell or "\n" in cell for cell in row):
            raise ValueError(f"table cell contains '|' or a newline: {row!r}")
        out.append("| " + " | ".join(row) + " |")
    return out


def _pct(ci: ProportionInterval, *, with_ci: bool = True) -> str:
    """Format a Wilson interval as 'k/n = x% [lo, hi]' (or 'n/a' when the denominator is 0)."""
    if ci.total == 0:
        return "n/a (0)"
    text = f"{ci.successes}/{ci.total} = {ci.proportion * 100:.1f}%"
    if with_ci:
        text += f" [{ci.lower * 100:.1f}, {ci.upper * 100:.1f}]"
    return text


def _latex_escape(text: str) -> str:
    return text.replace("\\", r"\textbackslash{}").replace("_", r"\_").replace("%", r"\%")


_OUTCOME_COLUMNS: tuple[tuple[str, str], ...] = (
    ("Recov. all", OracleOutcomeLabel.RECOVERED_ALL.value),
    ("Recov. + collateral", OracleOutcomeLabel.RECOVERED_WITH_COLLATERAL.value),
    ("Not recov.", OracleOutcomeLabel.NOT_RECOVERED.value),
    ("Harmful", OracleOutcomeLabel.HARMFUL.value),
    ("No-change correct", OracleOutcomeLabel.NO_CHANGE_CORRECT.value),
    ("FP remediation", OracleOutcomeLabel.FALSE_POSITIVE_REMEDIATION.value),
    ("Non-evaluable", NON_EVALUABLE_KEY),
)


class WP6ReportGenerator:
    """Emits WP6 summary.json, report.md and a LaTeX table from a WP6CampaignSummary."""

    def __init__(self, summary: WP6CampaignSummary) -> None:
        self._summary = summary

    @property
    def summary(self) -> WP6CampaignSummary:
        """Return the underlying WP6CampaignSummary."""
        return self._summary

    def _holm_by_hypothesis(self) -> dict[str, HolmAdjustedItem]:
        return {h.hypothesis_id: h for h in self._summary.holm_bonferroni_family}

    def render_latex_table(self) -> str:
        """Render the arm table and the four pre-registered tests as one LaTeX table."""
        holm = self._holm_by_hypothesis()
        lines = [
            r"\begin{table*}[htbp]",
            r"  \centering",
            r"  \caption{WP6 paired live-lab evaluation (Wilson 95\% intervals; rates are over "
            r"evaluable trials of each family)}",
            r"  \label{tab:wp6_paired_results}",
            r"  \begin{tabular}{lcccccc}",
            r"    \toprule",
            r"    \textbf{Arm} & \textbf{Ungated} & \textbf{Evaluable} & "
            r"\textbf{Clean recovery (S1,S3,S5)} & \textbf{Harm event (S1--S5)} & "
            r"\textbf{Approp. abstention (S2,S4)} & \textbf{Mean unavail. S1,S3,S5 (s)} \\",
            r"    \midrule",
        ]
        for arm_id, s in self._summary.arm_summaries.items():
            lines.append(
                f"    {_latex_escape(arm_id)} & {'Yes' if s.ungated_arm else 'No'} & "
                f"{s.evaluable_trials} & {_latex_escape(_pct(s.recovery_rate))} & "
                f"{_latex_escape(_pct(s.harm_event_rate))} & "
                f"{_latex_escape(_pct(s.appropriate_abstention_rate))} & "
                f"{s.mean_unavailability_sec:.2f} \\\\"
            )
        lines += [
            r"    \midrule",
            r"    \multicolumn{7}{l}{\textbf{Pre-registered tests "
            r"(Holm--Bonferroni over four hypotheses)}} \\",
        ]
        for comp in self._summary.primary_comparisons:
            item = holm.get(comp.hypothesis_id)
            adj = f"{item.adjusted_p_value:.4g}" if item is not None else "n/a"
            decision = "rejected" if item is not None and item.rejected else "not rejected"
            lines.append(
                f"    \\multicolumn{{7}}{{l}}{{{_latex_escape(comp.comparison_id)}: "
                f"$n={comp.n_pairs}$, $\\Delta={comp.rate_diff_a_minus_b:+.3f}$, "
                f"$p_{{\\mathrm{{raw}}}}={comp.p_value:.4g}$, "
                f"$p_{{\\mathrm{{Holm}}({_latex_escape(comp.hypothesis_id)})}}={adj}$ "
                f"({decision})}} \\\\"
            )
        lines += [r"    \bottomrule", r"  \end{tabular}", r"\end{table*}"]
        return "\n".join(lines)

    def render_markdown_report(self) -> str:
        """Render the full Markdown report; every table is built by render_markdown_table."""
        s = self._summary
        holm = self._holm_by_hypothesis()
        lines = [
            "# GateHeal WP6 Live-Lab Paired Experiment Report",
            "",
            f"- **Generated (UTC):** `{s.generated_at_utc}`",
            f"- **Randomisation seed:** `{s.seed}`",
            f"- **Repeats per scenario per arm:** `{s.trials_per_scenario}`",
            f"- **H2 non-inferiority margin:** `{s.h2_non_inferiority_margin:.2f}`",
            f"- **Family-wise alpha (Holm-Bonferroni, 4 hypotheses):** `{s.family_alpha}`",
            "",
            "## 1. Families",
            "",
        ]
        lines += render_markdown_table(
            ["Family", "Scenarios"],
            [[f"`{name}`", ", ".join(f"`{x}`" for x in scen)] for name, scen in s.families.items()],
        )

        lines += ["", "## 2. Coverage and evaluability", ""]
        lines += render_markdown_table(
            [
                "Arm", "Ungated", "Planned", "Completed", "Evaluable", "Non-evaluable",
                "Not run", "Retried", "Mutating", "Abstained", "Observe/no-op",
                "LLM calls", "LLM tokens",
            ],
            [
                [
                    f"`{arm}`", str(c.ungated_arm).lower(), str(c.planned_trials),
                    str(c.completed_trials), str(c.evaluable_trials),
                    str(c.non_evaluable_trials), str(c.not_run_trials), str(c.retried_trials),
                    str(c.mutating_trials), str(c.abstained_trials),
                    str(c.observe_only_or_noop_trials), str(c.llm_calls), str(c.llm_tokens),
                ]
                for arm, c in s.coverage.items()
            ],
        )

        lines += ["", "## 3. Arm rates (Wilson 95% intervals, evaluable trials only)", ""]
        lines += render_markdown_table(
            [
                "Arm", "Ungated", "Clean recovery (S1,S3,S5)", "Harm event (S1-S5)",
                "False positive (S0)", "Approp. abstention (S2,S4)",
                "Mean unavail. S1,S3,S5 (s)",
                "Censored",
            ],
            [
                [
                    f"`{arm}`", str(a.ungated_arm).lower(), _pct(a.recovery_rate),
                    _pct(a.harm_event_rate), _pct(a.false_positive_rate, with_ci=False),
                    _pct(a.appropriate_abstention_rate), f"{a.mean_unavailability_sec:.2f}",
                    str(a.censored_trials),
                ]
                for arm, a in s.arm_summaries.items()
            ],
        )

        lines += ["", "## 4. Scenario x arm oracle outcome counts", ""]
        rows: list[list[str]] = []
        for scen, arm_map in s.scenario_arm_outcomes.items():
            for arm, counts in arm_map.items():
                cells = [str(counts.get(key, 0)) for _, key in _OUTCOME_COLUMNS]
                rows.append([f"`{scen}`", f"`{arm}`", *cells])
        lines += render_markdown_table(
            ["Scenario", "Arm", *(label for label, _ in _OUTCOME_COLUMNS)], rows, left_aligned=2
        )

        lines += ["", "## 5. Pre-registered primary tests (Holm-Bonferroni)", ""]
        lines += render_markdown_table(
            [
                "Comparison", "Hypothesis", "Test", "Pairs", "Dropped pairs", "Rate G",
                "Rate other", "Diff (G - other)", "p (raw)", "p (Holm, hypothesis)", "Rejected",
            ],
            [
                [
                    f"`{c.comparison_id}`", c.hypothesis_id, f"`{c.test}`", str(c.n_pairs),
                    str(c.n_dropped_pairs), f"{c.rate_a:.3f}", f"{c.rate_b:.3f}",
                    f"{c.rate_diff_a_minus_b:+.3f}", f"{c.p_value:.4g}",
                    f"{holm[c.hypothesis_id].adjusted_p_value:.4g}",
                    str(holm[c.hypothesis_id].rejected).lower(),
                ]
                for c in s.primary_comparisons
            ],
        )
        for c in s.primary_comparisons:
            if c.noninferiority is not None:
                ni = c.noninferiority
                lines += [
                    "",
                    f"H2 detail: difference {ni.difference:+.3f}, Newcombe lower bound "
                    f"{ni.lower_bound:+.3f}, margin -{ni.margin:.2f}, "
                    f"non-inferior = `{str(ni.non_inferior).lower()}`.",
                ]
        lines += [
            "",
            "H3 is rejected only if both of its comparisons are significant: its family p-value "
            "is the larger of the two.",
        ]

        lines += ["", "## 6. Secondary comparisons (uncorrected, descriptive)", ""]
        lines += render_markdown_table(
            [
                "Comparison", "Harm pairs", "Dropped pairs", "Harm rate (first arm)",
                "Harm rate (second arm)",
                "McNemar p (two-sided)", "Unavail. pairs", "Wilcoxon p (unavail.)",
                "Wilcoxon method", "Unavail. diff [95% CI] (s)",
            ],
            [
                [
                    f"`{c.comparison_id}`", str(c.n_pairs), str(c.n_dropped_pairs),
                    f"{c.harm_rate_a:.3f}", f"{c.harm_rate_b:.3f}",
                    f"{c.harm_mcnemar_two_sided.p_value:.4g}",
                    str(c.n_unavailability_pairs),
                    f"{c.unavailability_wilcoxon.p_value:.4g}",
                    c.unavailability_wilcoxon.method,
                    f"{c.unavailability_bootstrap.mean_diff:+.2f} "
                    f"[{c.unavailability_bootstrap.ci_lower:+.2f}, "
                    f"{c.unavailability_bootstrap.ci_upper:+.2f}]",
                ]
                for c in s.secondary_comparisons
            ],
        )

        lines += ["", "## 7. LaTeX table", "", "```latex", self.render_latex_table(), "```", ""]
        lines += self._render_llm_section()
        return "\n".join(lines)

    def _render_llm_section(self) -> list[str]:
        """Section 8: the WP7 LLM family. Empty when the campaign had no LLM arms."""
        s = self._summary
        if not s.llm_primary_comparisons:
            return []
        llm_holm = {h.hypothesis_id: h for h in s.llm_holm_family}
        lines = [
            "## 8. LLM family (WP7, pre-registered secondary family; Holm over H4a-H4c)",
            "",
            "Both LLM arms receive the identical prompt and model output; only the policy gate "
            "differs. These tests are separate from, and do not alter, the frozen H1-H3 family.",
            "",
        ]
        lines += render_markdown_table(
            [
                "Comparison", "Hypothesis", "Test", "Pairs", "Dropped pairs", "Rate G-LLM",
                "Rate B2-LLM", "Diff (G-LLM - B2-LLM)", "p (raw)", "p (Holm, family of 3)",
                "Rejected",
            ],
            [
                [
                    f"`{c.comparison_id}`", c.hypothesis_id, f"`{c.test}`", str(c.n_pairs),
                    str(c.n_dropped_pairs), f"{c.rate_a:.3f}", f"{c.rate_b:.3f}",
                    f"{c.rate_diff_a_minus_b:+.3f}", f"{c.p_value:.4g}",
                    f"{llm_holm[c.hypothesis_id].adjusted_p_value:.4g}",
                    str(llm_holm[c.hypothesis_id].rejected).lower(),
                ]
                for c in s.llm_primary_comparisons
            ],
        )
        for c in s.llm_primary_comparisons:
            if c.noninferiority is not None:
                ni = c.noninferiority
                lines += [
                    "",
                    f"H4b detail: difference {ni.difference:+.3f}, Newcombe lower bound "
                    f"{ni.lower_bound:+.3f}, margin -{ni.margin:.2f}, "
                    f"non-inferior = `{str(ni.non_inferior).lower()}`.",
                ]
        lines += [
            "",
            "G-LLM vs G and B2-LLM vs B2 appear in section 6 as descriptive comparisons. LLM "
            "latency counts toward measured unavailability.",
            "",
        ]
        return lines

    def write_artifacts(self, output_dir: Path) -> tuple[Path, Path, Path]:
        """Write summary.json, report.md and table.tex into output_dir."""
        output_dir.mkdir(parents=True, exist_ok=True)
        summary_path = output_dir / "summary.json"
        report_md_path = output_dir / "report.md"
        latex_path = output_dir / "table.tex"
        summary_path.write_text(self._summary.model_dump_json(indent=2) + "\n", encoding="utf-8")
        report_md_path.write_text(self.render_markdown_report(), encoding="utf-8")
        latex_path.write_text(self.render_latex_table() + "\n", encoding="utf-8")
        return summary_path, report_md_path, latex_path
