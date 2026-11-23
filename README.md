# GateHeal

A policy-gated, minimal-impact, risk-aware self-healing controller for Linux `systemd` services,
with optional LLM assistance. GateHeal is the software of a bachelor's thesis; the name is a
provisional working name.

The controller observes a failing service, diagnoses it deterministically, proposes recovery
actions, and executes one only after an independent policy gate has approved it. Afterwards a
separate oracle checks that the service really recovered and that nothing else was harmed. When
no safe action exists, it escalates to a human instead of acting.

> **Status:** implementation, live-lab evaluation (WP6), LLM evaluation (WP7) and the
> threat-to-test map (WP8) are done. The remaining work is the thesis text. Results:
> [`docs/results-and-limitations.md`](docs/results-and-limitations.md).

## Safety invariants

1. **Separation of concerns.** Diagnosis, action proposal, and authorization and execution are
   separate modules. The advisory plane (including any language model) has no execution authority.
2. **Independent policy gate.** Every candidate action must pass deterministic validation
   (closed action set, inventory allowlist, impact tier, blast radius, retry and flap budgets)
   before it runs. The gate issues a single-use, HMAC-signed capability, and execution re-checks
   it and the incident state hash (TOCTOU) immediately before acting.
3. **Lab isolation.** Destructive fault injection and recovery runs only inside a disposable
   QEMU/KVM guest, never on the host workstation. The transports refuse to run without the lab
   sentinel.
4. **Tamper-evident audit.** Every decision is written ahead of execution to a hash-chained log.

## Quickstart (development, no lab needed)

```bash
uv sync
bash check_repo_integrity.sh
uv run ruff check .
uv run mypy src tests
uv run pytest -q
uv run gateheal validate-config --config configs/phase1_lab.yaml
uv run gateheal list-actions
```

Two tests are skipped unless a lab guest is running (`GATEHEAL_RUN_LAB_TESTS=1`, see the runbook).
The CLI defaults to the simulated transport (`--transport simulated`), so `inspect`, `recover` and
`run-experiment` are safe on a workstation:

```bash
uv run gateheal run-experiment --config configs/phase1_lab.yaml --trials 5 --output /tmp/summary.json
uv run gateheal export-metrics --summary-json /tmp/summary.json --format markdown
```

## Repository layout

| Path | Contents |
| :--- | :--- |
| `src/gateheal/` | The controller: `collector` and `diagnosis` (observation), `policy` (gate, capabilities, selector), `controller` (execution, verifier, audit), `orchestrator`, `transport`, `agent` and `llm` (advisory plane), `oracle` (independent experiment oracle), `wp6_engine`, `stats` and `reporting` (experiments), `threatmap` (traceability) |
| `configs/` | Lab configuration and service inventory |
| `lab/` | QEMU/KVM manager, guest provisioning, systemd units and sudoers contract, fault injection and reset scripts, and the campaign and report scripts |
| `tests/` | `unit`, `security`, `experiments`, `integration`, and `lab` (live guest, opt-in) |
| `docs/` | Design, threat model, runbook, results, and the generated threat-to-test map |

## Documentation

- [`docs/experiment-design.md`](docs/experiment-design.md): question, arms, scenarios, oracle,
  hypotheses H1-H4 and every recorded deviation.
- [`docs/threat-model.md`](docs/threat-model.md): trust zones, mitigations, known limitations,
  and the LLM-assisted operation.
- [`docs/threat-test-map.md`](docs/threat-test-map.md): each threat, the controls that implement it,
  and the tests that pin it (generated; see the runbook).
- [`docs/lab-runbook.md`](docs/lab-runbook.md): booting the lab, the WP6 campaign, the live LLM run
  and the report commands.
- [`docs/results-and-limitations.md`](docs/results-and-limitations.md): results and limitations,
  as the basis of the thesis chapter.

## Running the experiments (needs the QEMU/KVM lab)

Follow sections 1-6 of the runbook once, then:

```bash
# WP6: six deterministic arms, 20 repeats per scenario
uv run python lab/scripts/wp6_run_campaign.py --output-dir artifacts/wp6

# WP7: B2-LLM and G-LLM against a hosted model (key only in the environment)
read -rsp "API key: " DEEPSEEK_API_KEY; echo; export DEEPSEEK_API_KEY
uv run python lab/scripts/wp6_run_campaign.py --arms B2-LLM,G-LLM \
  --llm-endpoint https://api.mayanext.com/v1/chat/completions --llm-model deepseek-flash \
  --output-dir artifacts/wp7_llm

# Merge and rebuild the report (no lab, no key)
uv run python lab/scripts/wp6_resummarize.py \
  --trials-jsonl artifacts/wp6/trials.jsonl artifacts/wp7_llm/trials.jsonl \
  --output-dir artifacts/wp7_merged
```

Never put an API key in a file, a command line, the repository or a chat message. Results under
`artifacts/` are not tracked by default.

## Scope and limits

The evidence is one disposable Ubuntu 24.04 guest with emulated lab daemons, one model and one
prompt. It is not a claim about other systemd versions, real services or other models. Details are
in the threat model and the results document.
