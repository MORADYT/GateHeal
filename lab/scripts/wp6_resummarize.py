#!/usr/bin/env python3
"""Rebuild the WP6 summary, report and LaTeX table from an existing trials.jsonl (no lab needed)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from gateheal.reporting import WP6ReportGenerator
from gateheal.wp6_engine import (
    ALL_WP6_ARMS,
    build_wp6_expectations,
    load_completed_wp6_trials,
    summarize_wp6_campaign,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wp6_resummarize", description=__doc__)
    parser.add_argument("--trials-jsonl", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261028)
    parser.add_argument(
        "--trials-per-scenario",
        type=int,
        default=None,
        help="Defaults to the highest repeat index found in the file.",
    )
    args = parser.parse_args(argv)

    records = tuple(load_completed_wp6_trials(args.trials_jsonl, repair=False).values())
    if not records:
        print(f"No trial records in {args.trials_jsonl}.", file=sys.stderr)
        return 2
    per_scenario = args.trials_per_scenario or max(r.repeat_index for r in records)
    summary = summarize_wp6_campaign(
        records,
        trials_per_scenario=per_scenario,
        seed=args.seed,
        arms=ALL_WP6_ARMS,
        scenarios=tuple(e.scenario_id for e in build_wp6_expectations()),
    )
    paths = WP6ReportGenerator(summary).write_artifacts(args.output_dir)
    for item in summary.holm_bonferroni_family:
        print(
            f"{item.hypothesis_id}: raw p={item.raw_p_value:.4g} "
            f"adjusted p={item.adjusted_p_value:.4g} rejected={item.rejected}"
        )
    print("Wrote " + ", ".join(str(p) for p in paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
