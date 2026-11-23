# GateHeal Lab Runbook (QEMU/KVM bring-up, WP6 campaign, WP7 LLM run)

## 1 Prerequisites
All destructive fault-injection and `systemd` mutation tests execute strictly inside a disposable Ubuntu 24.04 QEMU/KVM guest over loopback SSH (`127.0.0.1:2222`) with QEMU user-network `restrict=on` (blocking guest outbound access).

Required host packages and tools:
- `qemu-system-x86_64` and `qemu-img` with `/dev/kvm` read/write access
- `cloud-localds`, `xorriso`, `genisoimage`, or `mtools` + `dosfstools` (for cloud-init seed ISO creation)
- `openssh-client` (`ssh`, `ssh-keygen`, `scp`), `rsync`, `curl`, and `sha256sum`
- `uv` with Python 3.11+

Key and host-key isolation paths under `~/.cache/gateheal-vm` (overridable via `GATEHEAL_VM_DIR`):
- Controller SSH key (unprivileged `ubuntu` only): `~/.cache/gateheal-vm/id_ed25519` (`GATEHEAL_LAB_SSH_KEY`)
- Harness SSH key (`root` only, separate from controller key): `~/.cache/gateheal-vm/id_harness_ed25519` (`GATEHEAL_LAB_HARNESS_KEY`)
- Dedicated lab `known_hosts`: `~/.cache/gateheal-vm/known_hosts` (`GATEHEAL_LAB_KNOWN_HOSTS`)

## 2 Bootstrap
Download the version-pinned Ubuntu 24.04 cloud image (`release-20250219`), verify its digest against `SHA256SUMS` via `sha256sum -c`, record `base.pin`, generate the separated controller and harness SSH keys, and create a fresh qcow2 overlay:

```bash
bash lab/qemu/manage_vm.sh bootstrap-base
bash lab/qemu/manage_vm.sh create-overlay
```

## 3 Boot and wait-ssh
Boot the QEMU/KVM virtual machine in the background with user-mode networking (`restrict=on`, port forwarding `127.0.0.1:2222 -> :22`) and wait until loopback SSH is reachable using the dedicated `~/.cache/gateheal-vm/known_hosts` file:

```bash
bash lab/qemu/manage_vm.sh boot-vm
bash lab/qemu/manage_vm.sh wait-ssh
```

On the first boot of an overlay backed by `lab-golden.qcow2` (or immediately after provisioning), verify that `/etc/gateheal-lab-sentinel` is present inside the guest:

```bash
ssh -p 2222 -i ~/.cache/gateheal-vm/id_ed25519 \
  -o UserKnownHostsFile=~/.cache/gateheal-vm/known_hosts \
  -o StrictHostKeyChecking=accept-new \
  ubuntu@127.0.0.1 "cat /etc/gateheal-lab-sentinel"
```

## 4 Sync and provision
Use the `provision` action (which runs `sync-repo` and then executes `provision_guest.sh` as `root` idempotently), and optionally freeze `lab-golden.qcow2` via `build-golden` (which also runs `qemu-img check`) so future overlays do not need re-provisioning:

```bash
bash lab/qemu/manage_vm.sh provision
bash lab/qemu/manage_vm.sh build-golden
```

You can also invoke `sync-repo` and `provision_guest.sh` individually when iterating on guest scripts:

```bash
bash lab/qemu/manage_vm.sh sync-repo
ssh -p 2222 -i ~/.cache/gateheal-vm/id_harness_ed25519 \
  -o UserKnownHostsFile=~/.cache/gateheal-vm/known_hosts \
  -o StrictHostKeyChecking=accept-new \
  root@127.0.0.1 "bash /opt/gateheal/lab/scripts/provision_guest.sh"
```

## 5 Conformance
Run the empirical `systemd` conformance and sudoers verification suite (`check_conformance.sh`) inside the guest via the root harness key:

```bash
ssh -p 2222 -i ~/.cache/gateheal-vm/id_harness_ed25519 \
  -o UserKnownHostsFile=~/.cache/gateheal-vm/known_hosts \
  -o StrictHostKeyChecking=accept-new \
  root@127.0.0.1 "GATEHEAL_INSIDE_LAB=1 bash /opt/gateheal/lab/scripts/check_conformance.sh"
```

## 6 Capture and smoke
Execute the host-side WP5 runner (`wp5_capture_and_verify.py`) to measure standard and multiplexed SSH latency, run conformance, execute all 7 smoke scenarios (`S0_HEALTHY_CONTROL` through `S5B_COLLATERAL_FORCED_RESTART`) across `--repeats 3`, atomically update the captured fixture (`fixture_version: 2`) if conformance passes, and write `artifacts/wp5_lab_manifest.json`. Then run the live pytest gate:

```bash
PYTHONUNBUFFERED=1 uv run python lab/scripts/wp5_capture_and_verify.py --repeats 3
GATEHEAL_RUN_LAB_TESTS=1 uv run pytest -v -m lab
```

## 7 Reset between runs
For fast per-trial resets without rebooting the VM, invoke `reset_lab.sh` inside the guest via the root harness key (or `manage_vm.sh reset-guest`):

```bash
ssh -p 2222 -i ~/.cache/gateheal-vm/id_harness_ed25519 \
  -o UserKnownHostsFile=~/.cache/gateheal-vm/known_hosts \
  -o StrictHostKeyChecking=accept-new \
  root@127.0.0.1 "GATEHEAL_INSIDE_LAB=1 bash /opt/gateheal/lab/reset/reset_lab.sh"
```

For a full block-level disk reset between campaigns (automatically backed by `lab-golden.qcow2` if built, and clearing `~/.cache/gateheal-vm/known_hosts`):

```bash
bash lab/qemu/manage_vm.sh stop-vm
bash lab/qemu/manage_vm.sh reset-overlay
bash lab/qemu/manage_vm.sh boot-vm
bash lab/qemu/manage_vm.sh wait-ssh
```

## 8 Teardown
Stop the background QEMU/KVM process cleanly (graceful `systemctl poweroff` followed by process exit verification) when finished:

```bash
bash lab/qemu/manage_vm.sh stop-vm
```

## 9 WP6 baseline campaign
The paired campaign needs the lab from sections 1-6 (booted, provisioned, `artifacts/wp5_lab_manifest.json` written by the capture step). The runner checks that manifest in a preflight step and refuses to start without it. The experiment design (arms, scenarios, hypotheses) is in `docs/experiment-design.md`.

Smoke run first (3 repeats; the output is for checking the setup, not for the thesis):

```bash
uv run python lab/scripts/wp6_run_campaign.py --trials 3 --output-dir artifacts/wp6_smoke
```

Full campaign (20 repeats per scenario per arm, seed `20261028`, arms B0, B1, B2, G, G-nobr, G-nosoak; wall-clock is hours, and about 5 h of trial time was needed for the reported run). Keep the computer awake: a suspended host stretches wall-clock time, although the oracle uses a monotonic clock that does not advance while suspended:

```bash
PYTHONUNBUFFERED=1 uv run python lab/scripts/wp6_run_campaign.py --output-dir artifacts/wp6
```

The run is resumable: every finished trial is appended to `trials.jsonl`, and re-running the same command skips the trials already stored. The script refuses to run on a dirty git tree unless `--allow-dirty` is given, because the manifest records the commit. It writes `trials.jsonl`, `wp6_manifest.json`, `summary.json`, `report.md` and `table.tex` into `--output-dir`.

## 10 WP7 live LLM campaign (B2-LLM and G-LLM)
This is a separate run with the same seed and repeat count as section 9, so that its trials pair with the baseline ones. It needs the guest lab and Internet access from the **host** (the guest stays offline). Incident records (unit states and log excerpts of the lab VM, no personal data) are sent to the provider named by `--llm-endpoint`.

1. Put the key in an environment variable of the current shell only. Do not write it into a file, a command line, `.env`, the repository or the chat:

   ```bash
   read -rsp "API key: " DEEPSEEK_API_KEY; echo; export DEEPSEEK_API_KEY
   ```

2. Run the campaign. The run reported in the thesis used the reasoning model `deepseek-flash` through the OpenAI-compatible gateway `api.mayanext.com`; the code defaults (`https://api.deepseek.com/chat/completions`, `deepseek-chat`) are used when the two flags are left out:

   ```bash
   PYTHONUNBUFFERED=1 uv run python lab/scripts/wp6_run_campaign.py \
     --arms B2-LLM,G-LLM \
     --llm-endpoint https://api.mayanext.com/v1/chat/completions \
     --llm-model deepseek-flash \
     --llm-api-key-env DEEPSEEK_API_KEY \
     --llm-mode record \
     --output-dir artifacts/wp7_llm
   ```

   Useful options: `--trials 3` for a smoke run (use a different `--output-dir` and discard it), `--llm-max-total-requests` (hard cap on live HTTP requests, default 1500), `--llm-max-tokens` (default 8000), `--llm-http-timeout-sec` (default 300).

3. Modes. `record` (default) calls the API and appends every request and raw response to `<output-dir>/llm_cassette.jsonl`. `live` calls the API and writes no cassette. `replay` never calls the API and answers only from a cassette; a request that is not in it makes the attempt invalid. The cassette is an audit log, not a way to re-run a fresh campaign: each request contains the incident id and a collection timestamp, so only an exact repeat of a recorded run hits it. The key is never written to the cassette, the trial records or the manifest.

4. Exit codes. `2`: key variable not set or lab SSH transport unavailable. `3`: the request cap was reached. `4`: the provider rejected the key or the account (HTTP 401/402/403). In every case nothing was scored as an abstention; completed trials are in `trials.jsonl`, and re-running the same command resumes. Transport failures, timeouts and answers cut off at the token limit make the attempt invalid and it is retried; a trial that never gets an answer is stored as non-evaluable.

5. Revoke or rotate the key when the run is finished, and keep `artifacts/` out of version control unless you deliberately track results (it is not tracked by default).

## 11 Merge, summarise, and rebuild the report
`wp6_resummarize.py` needs no lab and no key. It merges one or more `trials.jsonl` files (a trial present in two files is an error) and rewrites `summary.json`, `report.md` and `table.tex`, including the secondary H4a-H4c family when LLM trials are present:

```bash
uv run python lab/scripts/wp6_resummarize.py \
  --trials-jsonl artifacts/wp6/trials.jsonl artifacts/wp7_llm/trials.jsonl \
  --output-dir artifacts/wp7_merged
```

Pass the same `--seed` as the campaigns when it was not the default.

## 12 Threat-to-test map
After a change to `docs/threat-model.md` or `docs/threat-test-map.yaml`, regenerate the map, check it (no flag), and list tests no threat references. The check is also part of `uv run pytest -q`:

```bash
uv run python lab/scripts/wp8_threat_map.py --write
uv run python lab/scripts/wp8_threat_map.py
uv run python lab/scripts/wp8_threat_map.py --unmapped
```

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `status STOPPED` (or `Connection refused` on port `2222`) | QEMU/KVM guest VM is not running. | Run `bash lab/qemu/manage_vm.sh boot-vm` and `bash lab/qemu/manage_vm.sh wait-ssh`. |
| `Permission denied (publickey)` | Wrong key used for SSH user, or controller key used for `root`. | Set `GATEHEAL_LAB_SSH_KEY` to `~/.cache/gateheal-vm/id_ed25519` for `ubuntu` or pass `--harness-identity-file ~/.cache/gateheal-vm/id_harness_ed25519` for `root`. |
| `Sentinel missing` (`HostSafetyViolationError` on `/etc/gateheal-lab-sentinel`) | Guest is unprovisioned, or overlay was recreated against raw base image without `lab-golden.qcow2`. | Run `bash lab/qemu/manage_vm.sh provision` (or `bash lab/qemu/manage_vm.sh build-golden`), then verify with `cat /etc/gateheal-lab-sentinel`. |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | Stale `known_hosts` entry after overlay recreation. | Delete `~/.cache/gateheal-vm/known_hosts` (or run `create-overlay` / `reset-overlay`) and re-run `bash lab/qemu/manage_vm.sh wait-ssh`. |
| Stale `seed.iso` (cloud-init keys out of sync after key regeneration) | `seed.iso` was built with older public keys or cloud-init `instance-id` already ran on the backing image. | Delete `~/.cache/gateheal-vm/seed.iso` and `~/.cache/gateheal-vm/seed.hash`, then run `bash lab/qemu/manage_vm.sh reset-overlay` and `bash lab/qemu/manage_vm.sh boot-vm`. |
| `MISMATCH S5B_...: status=not_recovered` while `lab-api` stays `degraded` after restart | The stale-pool fault was persisted in `/etc/lab-api/config.yaml`, so a restart re-read it and could never clear it. | Fixed: `inject_fault.sh S5_COLLATERAL_TRAP` now sends `SIGUSR1` (runtime-only flag, cleared by restart or `SIGHUP`). After pulling this change run `stop-vm`, `reset-overlay`, `boot-vm`, `wait-ssh`, `provision` (provision reinstalls `gateheal.lab_daemons` in the guest) and re-capture. |
| `ERROR: conformance output is incomplete ... missing fact ids` | The conformance output was truncated, or `check_conformance.sh` aborted before printing every fact. | Re-run the capture; the harness transport keeps up to 256 KiB of output. If it persists, run `check_conformance.sh` by hand inside the guest and compare with `REQUIRED_CONFORMANCE_FACT_IDS` in `src/gateheal/lab_bringup.py`. |
| `precondition not established; lab-api is not degraded after fault injection` | `SIGUSR1` arrived before the API installed its handler, or the API was not running. | `reset_lab.sh` then re-run; `inject_fault.sh` waits for port 8080 before signalling. Check `journalctl -u lab-api.service`. |
| `ERROR: environment variable DEEPSEEK_API_KEY is not set` (exit 2) | The key was exported in another shell, or under another variable name. | `export` it in the same shell, or pass `--llm-api-key-env NAME`. |
| `STOPPED: LLM provider problem` (exit 4) | The provider answered 401/402/403 (wrong key, no balance, or model not allowed for the key). | Fix the key or balance and re-run the same command; nothing was scored. |
| `STOPPED:` with the request cap (exit 3) | `--llm-max-total-requests` was reached. | Re-run with a higher cap; stored trials are kept. |
| Many answers reported as prose in the coverage table | The gateway or model ignored JSON mode. | This is model behaviour and is reported, not retried. Check the prompt version and the model name in `wp6_manifest.json`. |
