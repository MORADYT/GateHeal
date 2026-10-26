# GateHeal WP5 Real-Lab Runbook (QEMU/KVM Guest Bring-Up & Conformance)

## 1 Prerequisites
All destructive fault-injection and `systemd` mutation tests execute strictly inside a disposable Ubuntu 24.04 QEMU/KVM guest over loopback SSH (`127.0.0.1:2222`) with QEMU user-network `restrict=on` (blocking guest outbound access)[cite: 6].

Required host packages and tools[cite: 6]:
- `qemu-system-x86_64` and `qemu-img` with `/dev/kvm` read/write access[cite: 6]
- `cloud-localds`, `xorriso`, `genisoimage`, or `mtools` + `dosfstools` (for cloud-init seed ISO creation)[cite: 6]
- `openssh-client` (`ssh`, `ssh-keygen`, `scp`), `rsync`, `curl`, and `sha256sum`[cite: 6]
- `uv` with Python 3.11+[cite: 6]

Key and host-key isolation paths under `~/.cache/gateheal-vm` (overridable via `GATEHEAL_VM_DIR`)[cite: 6]:
- Controller SSH key (unprivileged `ubuntu` only): `~/.cache/gateheal-vm/id_ed25519` (`GATEHEAL_LAB_SSH_KEY`)[cite: 6]
- Harness SSH key (`root` only, separate from controller key): `~/.cache/gateheal-vm/id_harness_ed25519` (`GATEHEAL_LAB_HARNESS_KEY`)[cite: 6]
- Dedicated lab `known_hosts`: `~/.cache/gateheal-vm/known_hosts` (`GATEHEAL_LAB_KNOWN_HOSTS`)[cite: 6]

## 2 Bootstrap
Download the version-pinned Ubuntu 24.04 cloud image (`release-20250219`), verify its digest against `SHA256SUMS` via `sha256sum -c`, record `base.pin`, generate the separated controller and harness SSH keys, and create a fresh qcow2 overlay[cite: 6]:

```bash
bash lab/qemu/manage_vm.sh bootstrap-base
bash lab/qemu/manage_vm.sh create-overlay
```

## 3 Boot and wait-ssh
Boot the QEMU/KVM virtual machine in the background with user-mode networking (`restrict=on`, port forwarding `127.0.0.1:2222 -> :22`) and wait until loopback SSH is reachable using the dedicated `~/.cache/gateheal-vm/known_hosts` file[cite: 6]:

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
Use the `provision` action (which runs `sync-repo` and then executes `provision_guest.sh` as `root` idempotently), and optionally freeze `lab-golden.qcow2` via `build-golden` (which also runs `qemu-img check`) so future overlays do not need re-provisioning[cite: 6]:

```bash
bash lab/qemu/manage_vm.sh provision
bash lab/qemu/manage_vm.sh build-golden
```

You can also invoke `sync-repo` and `provision_guest.sh` individually when iterating on guest scripts[cite: 6]:

```bash
bash lab/qemu/manage_vm.sh sync-repo
ssh -p 2222 -i ~/.cache/gateheal-vm/id_harness_ed25519 \
  -o UserKnownHostsFile=~/.cache/gateheal-vm/known_hosts \
  -o StrictHostKeyChecking=accept-new \
  root@127.0.0.1 "bash /opt/gateheal/lab/scripts/provision_guest.sh"
```

## 5 Conformance
Run the empirical `systemd` conformance and sudoers verification suite (`check_conformance.sh`) inside the guest via the root harness key[cite: 6]:

```bash
ssh -p 2222 -i ~/.cache/gateheal-vm/id_harness_ed25519 \
  -o UserKnownHostsFile=~/.cache/gateheal-vm/known_hosts \
  -o StrictHostKeyChecking=accept-new \
  root@127.0.0.1 "GATEHEAL_INSIDE_LAB=1 bash /opt/gateheal/lab/scripts/check_conformance.sh"
```

## 6 Capture and smoke
Execute the host-side WP5 runner (`wp5_capture_and_verify.py`) to measure standard and multiplexed SSH latency, run conformance, execute all 7 smoke scenarios (`S0_HEALTHY_CONTROL` through `S5B_COLLATERAL_FORCED_RESTART`) across `--repeats 3`, atomically update the captured fixture (`fixture_version: 2`) if conformance passes, and write `artifacts/wp5_lab_manifest.json`[cite: 6]. Then run the live pytest gate[cite: 6]:

```bash
PYTHONUNBUFFERED=1 uv run python lab/scripts/wp5_capture_and_verify.py --repeats 3
GATEHEAL_RUN_LAB_TESTS=1 uv run pytest -v -m lab
```

## 7 Reset between runs
For fast per-trial resets without rebooting the VM, invoke `reset_lab.sh` inside the guest via the root harness key (or `manage_vm.sh reset-guest`)[cite: 6]:

```bash
ssh -p 2222 -i ~/.cache/gateheal-vm/id_harness_ed25519 \
  -o UserKnownHostsFile=~/.cache/gateheal-vm/known_hosts \
  -o StrictHostKeyChecking=accept-new \
  root@127.0.0.1 "GATEHEAL_INSIDE_LAB=1 bash /opt/gateheal/lab/reset/reset_lab.sh"
```

For a full block-level disk reset between campaigns (automatically backed by `lab-golden.qcow2` if built, and clearing `~/.cache/gateheal-vm/known_hosts`)[cite: 6]:

```bash
bash lab/qemu/manage_vm.sh stop-vm
bash lab/qemu/manage_vm.sh reset-overlay
bash lab/qemu/manage_vm.sh boot-vm
bash lab/qemu/manage_vm.sh wait-ssh
```

## 8 Teardown
Stop the background QEMU/KVM process cleanly (graceful `systemctl poweroff` followed by process exit verification) when finished[cite: 6]:

```bash
bash lab/qemu/manage_vm.sh stop-vm
```

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `status STOPPED` (or `Connection refused` on port `2222`) | QEMU/KVM guest VM is not running[cite: 6]. | Run `bash lab/qemu/manage_vm.sh boot-vm` and `bash lab/qemu/manage_vm.sh wait-ssh`[cite: 6]. |
| `Permission denied (publickey)` | Wrong key used for SSH user, or controller key used for `root`[cite: 6]. | Set `GATEHEAL_LAB_SSH_KEY` to `~/.cache/gateheal-vm/id_ed25519` for `ubuntu` or pass `--harness-identity-file ~/.cache/gateheal-vm/id_harness_ed25519` for `root`[cite: 6]. |
| `Sentinel missing` (`HostSafetyViolationError` on `/etc/gateheal-lab-sentinel`) | Guest is unprovisioned, or overlay was recreated against raw base image without `lab-golden.qcow2`[cite: 6]. | Run `bash lab/qemu/manage_vm.sh provision` (or `bash lab/qemu/manage_vm.sh build-golden`), then verify with `cat /etc/gateheal-lab-sentinel`[cite: 6]. |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | Stale `known_hosts` entry after overlay recreation[cite: 6]. | Delete `~/.cache/gateheal-vm/known_hosts` (or run `create-overlay` / `reset-overlay`) and re-run `bash lab/qemu/manage_vm.sh wait-ssh`[cite: 6]. |
| Stale `seed.iso` (cloud-init keys out of sync after key regeneration) | `seed.iso` was built with older public keys or cloud-init `instance-id` already ran on the backing image. | Delete `~/.cache/gateheal-vm/seed.iso` and `~/.cache/gateheal-vm/seed.hash`, then run `bash lab/qemu/manage_vm.sh reset-overlay` and `bash lab/qemu/manage_vm.sh boot-vm`. |
| `MISMATCH S5B_...: status=not_recovered` while `lab-api` stays `degraded` after restart | The stale-pool fault was persisted in `/etc/lab-api/config.yaml`, so a restart re-read it and could never clear it. | Fixed: `inject_fault.sh S5_COLLATERAL_TRAP` now sends `SIGUSR1` (runtime-only flag, cleared by restart or `SIGHUP`). After pulling this change run `stop-vm`, `reset-overlay`, `boot-vm`, `wait-ssh`, `provision` (provision reinstalls `gateheal.lab_daemons` in the guest) and re-capture. |
| `ERROR: conformance output is incomplete ... missing fact ids` | The conformance output was truncated, or `check_conformance.sh` aborted before printing every fact. | Re-run the capture; the harness transport keeps up to 256 KiB of output. If it persists, run `check_conformance.sh` by hand inside the guest and compare with `REQUIRED_CONFORMANCE_FACT_IDS` in `src/gateheal/lab_bringup.py`. |
| `precondition not established; lab-api is not degraded after fault injection` | `SIGUSR1` arrived before the API installed its handler, or the API was not running. | `reset_lab.sh` then re-run; `inject_fault.sh` waits for port 8080 before signalling. Check `journalctl -u lab-api.service`. |
