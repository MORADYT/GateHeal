#!/usr/bin/env python3
"""Host-side WP6 runner: executes paired live-lab campaign, oracle, and statistical reports."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from gateheal.config import load_config
from gateheal.controller import default_artifacts_dir
from gateheal.llm import (
    DEFAULT_API_KEY_ENV,
    DEFAULT_ENDPOINT_URL,
    DEFAULT_HTTP_TIMEOUT_SEC,
    DEFAULT_MAX_TOKENS,
    DEFAULT_MODEL_NAME,
    LLMBackend,
    LLMBudgetExceeded,
    LLMCassette,
    LLMFatalError,
    LLMMode,
    ResilientLLMSender,
    env_api_key_loader,
)
from gateheal.oracle import MIN_ORACLE_HOLD_WINDOW_SEC
from gateheal.reporting import WP6ReportGenerator
from gateheal.transport import SSHLabTransport, TransportUnavailableError
from gateheal.wp6_engine import (
    ALL_WP6_ARMS,
    DEFAULT_MAX_TRIAL_ATTEMPTS,
    KNOWN_ARMS,
    LLM_ARMS,
    WP6ExperimentRunner,
    build_wp6_campaign_manifest,
    build_wp6_expectations,
    count_planned_trials,
    load_completed_wp6_trials,
    summarize_wp6_campaign,
    validate_wp6_preflight,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wp6_run_campaign",
        description=(
            "Run a paired live-lab experiment campaign. Default arms: B0, B1, B2, G, G-nobr, "
            "G-nosoak. WP7 adds B2-LLM and G-LLM (select with --arms)."
        ),
    )
    repo_root = Path(__file__).resolve().parents[2]
    default_vm_dir = str(Path.home() / ".cache" / "gateheal-vm")
    vm_dir = Path(os.environ.get("GATEHEAL_VM_DIR", default_vm_dir))
    artifacts_root = default_artifacts_dir()

    parser.add_argument(
        "--config",
        type=Path,
        default=repo_root / "configs" / "phase1_lab.yaml",
    )
    parser.add_argument(
        "--wp5-manifest",
        type=Path,
        default=artifacts_root / "wp5_lab_manifest.json",
        help="Path to verified WP5 lab manifest required by preflight gate.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=artifacts_root / "wp6",
        help="Directory for WP6 JSONL trials, manifest, summary, and reports.",
    )
    parser.add_argument(
        "--trials-per-scenario",
        type=int,
        default=20,
        help="Number of paired repeats per scenario per arm (default: 20).",
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=None,
        help="Smoke mode override for --trials-per-scenario (e.g., --trials 3).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20261028,
        help="Random seed for within-block arm order randomisation.",
    )
    parser.add_argument(
        "--hold-window-sec",
        type=float,
        default=MIN_ORACLE_HOLD_WINDOW_SEC,
        help="Independent oracle post-action hold window in seconds (>= 15.0).",
    )
    parser.add_argument(
        "--oracle-sample-interval-sec",
        type=float,
        default=1.0,
        help="Independent oracle monitor sampling interval in seconds (0 < x <= 2.0).",
    )
    parser.add_argument(
        "--max-trial-attempts",
        type=int,
        default=DEFAULT_MAX_TRIAL_ATTEMPTS,
        help="Attempts per trial before it is recorded as non-evaluable.",
    )
    parser.add_argument(
        "--settle-wait-sec",
        type=float,
        default=5.5,
        help="Settle wait after reset_lab.sh and fault injection.",
    )
    parser.add_argument(
        "--arms",
        type=str,
        default=",".join(ALL_WP6_ARMS),
        help=(
            "Comma-separated arms to run (default: the six WP6 arms). "
            f"Known: {', '.join(KNOWN_ARMS)}. Use the same --seed and repeat count for a "
            "separate LLM campaign so its trials pair with the baseline ones."
        ),
    )
    parser.add_argument(
        "--llm-endpoint",
        type=str,
        default=DEFAULT_ENDPOINT_URL,
        help="OpenAI-compatible chat-completions URL (default: DeepSeek).",
    )
    parser.add_argument("--llm-model", type=str, default=DEFAULT_MODEL_NAME)
    parser.add_argument(
        "--llm-api-key-env",
        type=str,
        default=DEFAULT_API_KEY_ENV,
        help="Name of the environment variable holding the API key (the key is never stored).",
    )
    parser.add_argument(
        "--llm-mode",
        choices=("live", "record", "replay"),
        default="record",
        help="live: call the API, no cassette; record: call the API and append to the cassette; "
        "replay: answer only from the cassette, never call the API (default: record).",
    )
    parser.add_argument(
        "--llm-cassette",
        type=Path,
        default=None,
        help="Cassette JSONL (default: <output-dir>/llm_cassette.jsonl).",
    )
    parser.add_argument(
        "--llm-max-total-requests",
        type=int,
        default=1500,
        help="Hard cap on live HTTP requests (retries included) for this process.",
    )
    parser.add_argument(
        "--llm-max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help="Completion budget. Reasoning models spend part of it thinking; a response cut off "
        "at this limit is an invalid attempt, never an abstention.",
    )
    parser.add_argument(
        "--llm-http-timeout-sec",
        type=float,
        default=DEFAULT_HTTP_TIMEOUT_SEC,
        help="Per-request HTTP timeout. LLM latency counts toward measured unavailability.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow running on a dirty git working tree.",
    )
    parser.add_argument("--ssh-host", type=str, default="127.0.0.1")
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--ssh-user", type=str, default="ubuntu")
    parser.add_argument(
        "--ssh-identity-file",
        type=str,
        default=str(vm_dir / "id_ed25519"),
        help="Unprivileged controller SSH key (ubuntu).",
    )
    parser.add_argument(
        "--harness-identity-file",
        type=str,
        default=str(vm_dir / "id_harness_ed25519"),
        help="Dedicated harness SSH key (root).",
    )
    parser.add_argument(
        "--guest-repo-dir",
        type=str,
        default="/opt/gateheal",
        help="Path to GateHeal repository inside the guest VM.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    effective_trials = (
        args.trials if args.trials is not None else args.trials_per_scenario
    )
    if effective_trials < 1:
        raise ValueError("Number of trials per scenario must be >= 1.")
    if args.hold_window_sec < MIN_ORACLE_HOLD_WINDOW_SEC:
        raise ValueError(
            f"--hold-window-sec must be >= {MIN_ORACLE_HOLD_WINDOW_SEC}."
        )

    arms = tuple(a.strip() for a in str(args.arms).split(",") if a.strip())
    unknown = [a for a in arms if a not in KNOWN_ARMS]
    if not arms or unknown or len(set(arms)) != len(arms):
        raise ValueError(f"--arms must be distinct names from {KNOWN_ARMS}; got {args.arms!r}.")
    uses_llm = any(a in LLM_ARMS for a in arms)
    if uses_llm and args.llm_mode in ("live", "record"):
        if not os.environ.get(args.llm_api_key_env, "").strip():
            print(
                f"ERROR: environment variable {args.llm_api_key_env} is not set. "
                f"Run: export {args.llm_api_key_env}=... (do not put the key in a file).",
                file=sys.stderr,
            )
            return 2
    if args.llm_max_total_requests < 1 or args.llm_max_tokens < 1:
        raise ValueError("--llm-max-total-requests and --llm-max-tokens must be >= 1.")

    repo_root = Path(__file__).resolve().parents[2]
    _ = validate_wp6_preflight(
        repo_root=repo_root,
        wp5_manifest_path=args.wp5_manifest,
        allow_dirty=bool(args.allow_dirty),
    )

    cfg = load_config(args.config)

    def make_root_transport() -> SSHLabTransport:
        # The oracle monitor thread must not share a transport instance with the arm under test.
        return SSHLabTransport(
            host=args.ssh_host,
            port=args.ssh_port,
            user="root",
            identity_file=args.harness_identity_file,
            ssh_multiplex=True,
            use_remote_timeout=True,
            verify_remote_sentinel=True,
        )

    controller_transport = SSHLabTransport(
        host=args.ssh_host,
        port=args.ssh_port,
        user=args.ssh_user,
        identity_file=args.ssh_identity_file,
        ssh_multiplex=True,
        use_remote_timeout=True,
        verify_remote_sentinel=True,
    )
    root_transport = make_root_transport()

    expectations = build_wp6_expectations()
    scen_ids = tuple(e.scenario_id for e in expectations)
    out_dir: Path = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    llm_backend: LLMBackend | None = None
    if uses_llm:
        llm_mode: LLMMode = args.llm_mode
        cassette_path: Path = (
            args.llm_cassette if args.llm_cassette is not None else out_dir / "llm_cassette.jsonl"
        )
        sender = ResilientLLMSender(
            endpoint_url=args.llm_endpoint,
            model_name=args.llm_model,
            api_key_loader=env_api_key_loader(args.llm_api_key_env),
            mode=llm_mode,
            cassette=None if llm_mode == "live" else LLMCassette(cassette_path),
            http_timeout_sec=args.llm_http_timeout_sec,
            max_total_requests=args.llm_max_total_requests,
        )
        llm_backend = LLMBackend(
            sender=sender,
            model_name=args.llm_model,
            endpoint_url=args.llm_endpoint,
            max_tokens=args.llm_max_tokens,
        )

    runner = WP6ExperimentRunner(
        cfg,
        controller_transport=controller_transport,
        root_transport=root_transport,
        monitor_transport_factory=make_root_transport,
        artifacts_dir=out_dir,
        guest_repo_dir=args.guest_repo_dir,
        oracle_hold_window_sec=args.hold_window_sec,
        oracle_sample_interval_sec=args.oracle_sample_interval_sec,
        settle_wait_sec=args.settle_wait_sec,
        max_trial_attempts=args.max_trial_attempts,
        verbose_progress=True,
        llm_backend=llm_backend,
    )

    manifest_path = out_dir / "wp6_manifest.json"

    def write_manifest(completed: int) -> None:
        manifest = build_wp6_campaign_manifest(
            repo_root=repo_root,
            config_path=args.config,
            wp5_manifest_path=args.wp5_manifest,
            seed=args.seed,
            arms=arms,
            scenarios=scen_ids,
            trials_per_scenario=effective_trials,
            oracle_hold_window_sec=args.hold_window_sec,
            oracle_sample_interval_sec=args.oracle_sample_interval_sec,
            max_trial_attempts=args.max_trial_attempts,
            completed_trials=completed,
            allow_dirty=bool(args.allow_dirty),
            llm_info=None if llm_backend is None else llm_backend.describe(cfg),
        )
        manifest_path.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")

    # Written before the first trial so that an interrupted campaign still has its provenance.
    already_done = len(load_completed_wp6_trials(runner.trials_jsonl_path))
    write_manifest(already_done)
    planned = count_planned_trials(scen_ids, arms, effective_trials)
    print(
        f"WP6: {planned} planned trials, {already_done} already on disk (resume re-runs "
        "non-evaluable ones).",
        file=sys.stderr,
    )

    try:
        records = runner.run_campaign(
            trials_per_scenario=effective_trials,
            seed=args.seed,
            arms=arms,
            expectations=expectations,
        )
    except TransportUnavailableError as exc:
        print(
            f"ERROR: SSH transport unavailable during WP6 campaign: {exc}",
            file=sys.stderr,
        )
        print(
            "Troubleshooting: see docs/lab-runbook.md (## Troubleshooting).",
            file=sys.stderr,
        )
        return 2
    except LLMBudgetExceeded as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        print(
            "Completed trials are in trials.jsonl; re-run the same command (optionally with a "
            "higher --llm-max-total-requests) to resume.",
            file=sys.stderr,
        )
        return 3
    except LLMFatalError as exc:
        print(f"STOPPED: LLM provider problem: {exc}", file=sys.stderr)
        print(
            "Fix the key/balance and re-run the same command to resume; nothing was scored.",
            file=sys.stderr,
        )
        return 4
    except KeyboardInterrupt:
        print(
            "Interrupted. Completed trials are already in trials.jsonl; re-run the same command "
            "to resume.",
            file=sys.stderr,
        )
        return 130
    finally:
        try:
            _ = root_transport.run(
                (
                    "env",
                    "GATEHEAL_INSIDE_LAB=1",
                    "bash",
                    f"{args.guest_repo_dir}/lab/reset/reset_lab.sh",
                ),
                timeout_sec=15.0,
            )
        except TransportUnavailableError:
            pass

    write_manifest(len(records))

    summary = summarize_wp6_campaign(
        records,
        trials_per_scenario=effective_trials,
        seed=args.seed,
        arms=arms,
        scenarios=scen_ids,
    )
    reporter = WP6ReportGenerator(summary)
    reporter.write_artifacts(out_dir)

    print("\nArm coverage (evaluable / planned):")
    for arm_id, cov in summary.coverage.items():
        print(
            f"  {arm_id:9s} {cov.evaluable_trials}/{cov.planned_trials}  "
            f"non-evaluable={cov.non_evaluable_trials} not-run={cov.not_run_trials}"
        )
    print("\nPre-registered tests (Holm-adjusted):")
    for item in summary.holm_bonferroni_family:
        print(
            f"  {item.hypothesis_id}: raw p={item.raw_p_value:.4g} "
            f"adjusted p={item.adjusted_p_value:.4g} rejected={item.rejected}"
        )
    if summary.llm_holm_family:
        print("\nLLM family (H4a-H4c, Holm over three):")
        for item in summary.llm_holm_family:
            print(
                f"  {item.hypothesis_id}: raw p={item.raw_p_value:.4g} "
                f"adjusted p={item.adjusted_p_value:.4g} rejected={item.rejected}"
            )
    if llm_backend is not None:
        print(f"\nLive LLM requests this run: {llm_backend.sender.live_requests}")
    print(f"\nArtifacts written to {out_dir} (summary.json, report.md, table.tex).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TransportUnavailableError as exc:
        print(
            f"ERROR: SSH failed ({exc}). Troubleshooting: see docs/lab-runbook.md.",
            file=sys.stderr,
        )
        sys.exit(2)
