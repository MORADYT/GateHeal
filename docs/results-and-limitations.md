# Results and Limitations (thesis chapter skeleton)

This file is the working basis of the results chapter. Every number below is copied from the
accepted reports (`wp7_merged_report.md`, which contains the WP6 tables unchanged, and the WP7
results note). Text in `[TODO: ...]` brackets is for the author to fill in or to align with the
thesis template. Do not change a number without regenerating the report with
`lab/scripts/wp6_resummarize.py` (see `docs/lab-runbook.md`, section 11).

## 1. What was measured

Eight arms were run against the same scenarios (the healthy control S0, S1-S5 for every arm, and
S5B and S5U for the GateHeal family only) in one disposable Ubuntu 24.04 QEMU/KVM guest, with one independent oracle that is not part of the controller (arms and scenarios:
`docs/experiment-design.md` sections 2-3).

| Arm | What it is |
| :--- | :--- |
| B0 | Observe only (no action) |
| B1 | Ungated fixed runbook: always restart the alerting service |
| B2 | Ungated simulated agent (deterministic proposer): its first proposal is executed |
| G | GateHeal: diagnosis, minimal-impact selector, policy gate, capability, verified soak, audit |
| G-nobr, G-nosoak | G without the blast-radius gate / with the verifier reduced to one sample (ablations) |
| B2-LLM | Ungated: the model's first proposal is executed (restart or reload of lab units only) |
| G-LLM | The model's proposals go through exactly the G loop |

Scenarios: S0 healthy (false-positive control), S1 crash, S2 invalid configuration (unrecoverable),
S3 dependency failure, S4 persistent failure (unrecoverable), S5 collateral trap (a restart harms a
healthy dependent), S5B (restart forced with approval), S5U (the same without approval; GateHeal
family only).

Design: 20 paired repeats per scenario and arm, seed `20261028`, randomised arm order within each
block. Endpoints: clean recovery (all services healthy, nothing else harmed), harm event,
appropriate abstention on S2/S4, false positive on S0, and unavailability (truncated at 60 s).

## 2. Validity of the data

| | Baseline (WP6) | LLM campaign (WP7) |
| :--- | :--- | :--- |
| Trials | 840 (B0, B1, B2: 120 each; G, G-nobr, G-nosoak: 160 each) | 280 (B2-LLM 120, G-LLM 160) |
| Non-evaluable / retried | 0 / 0 | 0 / 0 |
| Duplicates | none | none |
| Other | host suspended during the run: wall-clock 43 h, trial time about 5.3 h (see Deviations) | 359 model calls, 357 valid JSON, 2 prose answers (0.6%); all finished with `finish_reason=stop`; 0 transport or truncation errors; 362 HTTP requests (3 absorbed retries), 1.44 M tokens; no harness refusal |

Model latency per call: mean 17.0 s, median 10.3 s, 95th percentile 51 s, maximum 165 s.
G-LLM used 1, 2 and 3 model calls in 98, 45 and 17 trials; B2-LLM always 1. No G-LLM trial was
aborted by the time budget or by the pre-execution recheck.

Wording for the model (use it as written): *the model served under the ID `deepseek-flash` by the
gateway `api.mayanext.com` on the date of the run*, with the prompt version `wp7-3`, temperature 0,
`max_tokens` 8000. The model behind a gateway cannot be verified.

The protocol was fixed before the data were analysed. Deviations (smoke-run corrections, the
p-value precision fix of 2026-11-10, the WP7 prompt and token-limit changes) are listed in
`docs/experiment-design.md`, section 8. None changed a hypothesis, an endpoint or a test.

## 3. Primary results: deterministic arms (H1-H3, Holm over 4)

| Hypothesis | Comparison | Pairs | G | Other | Difference | Raw p | Holm-adjusted p | Rejected |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| H1a | harm events, G vs B1 | 100 | 0.000 | 0.400 | -0.400 | 9.1e-13 | 2.7e-12 | yes |
| H1b | harm events, G vs B2 | 100 | 0.000 | 0.400 | -0.400 | 9.1e-13 | 2.7e-12 | yes |
| H2 | clean recovery, G not worse than B1 by more than 0.10 | 60 | 1.000 | 0.333 | +0.667 | 1.4e-21 | 5.5e-21 | yes (lower bound +0.527) |
| H3 | appropriate abstention on S2/S4, G vs B1 and G vs B2 | 40 | 1.000 | 0.000 | +1.000 | 9.1e-13 | 2.7e-12 | yes |

Rates with Wilson 95% intervals:

| Arm | Clean recovery (S1, S3, S5) | Harm event (S1-S5) | False positive (S0) | Appropriate abstention (S2, S4) | Mean unavailability S1, S3, S5 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| B0 | 0/60 [0.0, 6.0] | 0/100 [0.0, 3.7] | 0/20 | 0/40 [0.0, 8.8] | 60.00 s (always at the horizon) |
| B1 | 20/60 = 33.3% [22.7, 45.9] | 40/100 = 40.0% [30.9, 49.8] | 20/20 | 0/40 [0.0, 8.8] | 40.29 s |
| B2 | 20/60 = 33.3% [22.7, 45.9] | 40/100 = 40.0% [30.9, 49.8] | 0/20 | 0/40 [0.0, 8.8] | 40.29 s |
| G | 60/60 = 100% [94.0, 100] | 0/100 [0.0, 3.7] | 0/20 | 40/40 [91.2, 100] | 0.70 s |

How to read this honestly:

- The two ungated deterministic arms took a healthy dependent down in every S3 and S5 trial
  (40 of 100 harm events), because their restart disturbs a unit that other services rely on.
  GateHeal avoided all of it, recovered everything recoverable, and escalated on everything
  unrecoverable. The lowest p-values are the arithmetic floor when all 40 discordant pairs fall on
  one side (`0.5^40` is 9.1e-13), not a measure of the size of the effect.
  Report the rates and intervals first and the p-values second.
- B1 and B2 are identical on every endpoint except S0, where B1 restarts a healthy service on
  every trial (20/20 false positives). The scenarios were built with deterministic faults, so the
  design cannot separate arms whose only difference is how they decide under uncertainty.
- The unavailability difference (G about 0.7 s, B1 and B2 about 40 s) is mostly the ungated arms'
  own soak and retry waits. It is secondary and uncorrected.
- [TODO: one sentence connecting this to the research question in the thesis introduction.]

## 4. Ablations and descriptive secondary comparisons (uncorrected)

| Comparison | Result | Reading |
| :--- | :--- | :--- |
| G vs G-nobr, harm over S1-S5, S5B, S5U (140 pairs) | 0.143 vs 0.286, McNemar p = 1.9e-6 | Without the blast-radius rule the unapproved forced restart (S5U) goes through 20 times with collateral damage; G blocks 20/20. |
| G vs G-nosoak, same family | 0.143 vs 0.143, p = 1.0 | No difference. No scenario has an intermittent fault, so the soak cannot show its value here (stated in the design). Report as a null result, not as evidence the soak is useless. |
| G vs G-nobr, unavailability (100 pairs) | difference -0.01 s [-0.03, +0.00], Wilcoxon p = 0.36 | No cost difference. |
| G-nobr in S5U | 20 recovered with collateral; G: 20 not recovered (blocked); G-nosoak: 20 not recovered (blocked) | G-nosoak keeps the blast-radius rule, so it blocks too. |

G's 20/140 harm events are all S5B, where a human approval token was supplied on purpose: the gate
allowed an approved action with known collateral. That is the intended behaviour of the approval
path and should be described as such, not as a failure.

## 5. LLM family (H4, secondary, Holm over 3)

Both LLM arms receive the same incident record and prompt; only the gate differs.

| Hypothesis | Comparison | Pairs | G-LLM | B2-LLM | Difference | Raw p | Holm-adjusted p | Result |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| H4a | harm events, G-LLM fewer | 100 | 0/100 | 3/100 | -3.0 points | 0.125 | 0.205 | not significant |
| H4b | clean recovery not worse by more than 0.10 | 60 | 54/60 = 90.0% | 56/60 = 93.3% | -3.3 points, 95% Newcombe interval [-14.2, +6.7] | 0.103 | 0.205 | non-inferiority not shown (inconclusive; not shown to be inferior either) |
| H4c | appropriate abstention on S2/S4, G-LLM higher | 40 | 40/40 | 18/40 | +55 points | 2.4e-7 | 7.2e-7 | significant |

Other model-arm rates (Wilson 95%): G-LLM clean recovery 90.0% [79.9, 95.3], B2-LLM 93.3% [84.1, 97.4];
harm events 0/100 [0.0, 3.7] against 3/100 [1.0, 8.5]; mean unavailability on S1, S3, S5 29.45 s
against 19.14 s. Descriptive comparisons with the deterministic arms: G-LLM vs G, +28.7 s
unavailability [+24.1, +33.6] (Wilcoxon p = 1.6e-11); B2-LLM vs B2, harm 3% against 40% and
-21.2 s unavailability.

The independent recomputation of H4a (three B2-only discordant pairs, `0.5^3`), H4c (22 G-only
pairs, `0.5^22`) and the H4b lower bound (-0.142, Newcombe with continuity correction) reproduces
the report. Paired recovery in H4b: both clean 51, G-LLM only 3, B2-LLM only 5, neither 1.

### 5.1 What the data support

1. **The gate removed every harm the ungated model caused, but the model rarely caused harm.** The
   three B2-LLM harm events are all S5 restarts of `lab-api` with collateral on the worker. In S5
   the model's first proposal was a restart in 3 of 20 B2-LLM and 4 of 20 G-LLM trials; the gate
   blocked all four (`ERR_BLAST_RADIUS_EXCEEDED`, `ERR_HUMAN_APPROVAL_REQUIRED`,
   `ERR_IMPACT_TIER_EXCEEDED`), and S5U was blocked 20 of 20. With 100 pairs and an ungated harm rate
   of 3%, H4a cannot reach significance: the exact one-sided p is 0.125 even if G-LLM had zero harm
   by construction. The result is a direction and a number, not a test outcome.
2. **H4c is partly definitional.** B2-LLM acted in S2/S4 only once (a `reload_service` in S2,
   no recovery, no harm). Otherwise it proposed the read-only `validate_service_config`, which the
   ungated harness does not execute (21 times), or abstained (18 times). Outcome-wise 39 of 40
   B2-LLM S2/S4 trials were "no change, correct", like G-LLM's 40 of 40. The test shows that G-LLM
   always escalates; it does not show that B2-LLM damaged anything there. Say this in the text.
3. **G-LLM's six non-recoveries on S1/S3/S5 are not safety decisions in S1 and S3.** S3 repeat 1: the
   second answer was prose. S3 repeat 17: the model offered `restart_service lab-redis` plus a
   read-only diagnostic in each of three rounds, the selector chose the diagnostic each time, and
   the three-request budget ended the incident (no gate rejection recorded). S5 repeats 2, 17, 19
   and 20: the gate blocked a model restart, which is the correct outcome for the thesis claim and
   costs one clean-recovery point on the endpoint.
4. **The loop costs time.** G-LLM adds about 29 s of unavailability over deterministic G, mostly
   model latency and extra rounds. B2-LLM is 21 s faster than deterministic B2 because B2 includes
   soak waits. Model latency counts fully toward the oracle's unavailability for both LLM arms.

### 5.2 What the data do not support

- That G-LLM recovers as well as B2-LLM. H4b is inconclusive: the point estimate is -3.3 points and
  the interval reaches -14.2, beyond the 10-point margin. Do not write "no loss in availability".
- That the gate is necessary to make this model safe. The model proposed a harmful action in 3 to
  4 of 20 S5 trials and was harmless elsewhere.
- Any statement about other models, other prompts or other labs. One model, one prompt, one lab.

Suggested sentence for the abstract and conclusion:
*In a live three-service lab, the policy gate removed all harm events of an ungated deterministic
controller (0 of 100 against 40 of 100 trials) and, with a hosted reasoning model as the advisor,
removed the model's few harmful proposals and turned every unrecoverable case into an escalation
(40 of 40 against 18 of 40); whether it costs clean recoveries with the model could not be
established (90.0% against 93.3%, non-inferiority not shown).*

## 6. Limitations (state these in the thesis)

Experimental scope:
- One disposable Ubuntu 24.04 guest (kernel 6.8.0-147, systemd 255.4), three emulated lab services,
  a healthy control and seven fault scenarios with deterministic faults. It does not establish behaviour on other systemd
  versions, real services, intermittent faults, or load.
- Scenarios were chosen by the author, together with the controller. The oracle is independent code
  but shares the SSH transport and the `systemctl show` mechanism with the controller (threat model,
  D5).
- Horizon and resolution: unavailability is truncated at 60 s, and the oracle samples about once per
  second, so sub-second outages are not seen.
- The soak and blast-radius ablations are limited to these scenarios. The null result for the soak is
  a property of the scenario set.
- Twenty repeats give little power for rare events (a harm rate of 3%, recovery differences of 3
  points). The very small p-values of H1-H3 reflect complete separation, not a large sample.

LLM-specific:
- One model, one prompt (`wp7-3`), one provider path. The model is a reasoning model reached
  through a gateway whose backing model cannot be verified; its hidden reasoning spends tokens and
  adds seconds of latency.
- The ungated arm executes only the model's first proposal and only restart or reload of the three lab
  units; diagnostic proposals are not executed. That makes B2-LLM a deliberately simple control.
- Temperature 0 is not deterministic on a hosted model, and the cassette is an audit log, not a replay
  of a fresh run (requests contain an incident id and a timestamp).
- Incident records are sent to a third-party API. They contain no personal data.

Controller limitations are listed in `docs/threat-model.md` section 3 (D2 to D8): the strict
all-samples-healthy soak rule, in-window unavailability, the `NRestarts` reset, the shared transport,
the unauthenticated lab worker frame, the runtime-only S5 fault, and the live-lab scope.

## 7. Reproducibility

| Item | Where |
| :--- | :--- |
| Commands | `docs/lab-runbook.md` sections 9-11 |
| Per-trial records, manifest (commit, config and image hashes, prompt hash, model, budgets) | `artifacts/wp6/` and `artifacts/wp7_llm/` (`trials.jsonl`, `wp6_manifest.json`, `llm_cassette.jsonl`) |
| Merged report, summary, LaTeX table | `artifacts/wp7_merged/` (`report.md`, `summary.json`, `table.tex`) |
| Threat to control to test | `docs/threat-test-map.md` |
| Commit of the evaluated code | [TODO: fill in the tag or commit the campaigns ran on, from `wp6_manifest.json`] |

[TODO: decide whether the thesis archive includes `artifacts/` or only the merged report and tables;
`trials.jsonl` and the cassette are the raw evidence.]

## 8. Chapter outline to adapt

1. Evaluation setup (section 1 here; the arms and scenarios table).
2. Validity and deviations (section 2).
3. Results for the deterministic arms (section 3, the primary family).
4. Ablations (section 4).
5. Results with a language model (section 5, including 5.1 and 5.2).
6. Discussion and answer to the research question [TODO].
7. Threats to validity and limitations (section 6).

[TODO: map these to the department's template once available, and decide which tables become
figures. Suggested figures: harm rate per arm with Wilson intervals; per-scenario outcome stacks;
unavailability per arm as boxplots.]
