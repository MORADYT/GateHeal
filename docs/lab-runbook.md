# GateHeal WP5 Real-Lab Runbook (QEMU/KVM Guest Bring-Up & Conformance)

## 1 Prerequisites
All destructive fault-injection and `systemd` mutation tests execute strictly inside a disposable Ubuntu 24.04 QEMU/KVM guest over loopback SSH (`127.0.0.1:2222`) with QEMU user-network `restrict=on` (blocking guest outbound access).

Required host packages and tools:
- `qemu-system-x86_64` and `qemu-img` with `/dev/kvm` read/write access
- `cloud-localds`, `xorriso`, `genisoimage`, or `mtools` + `dosfstools` (for cloud-init seed ISO creation)
- `openssh-client` (`ssh`, `ssh-keygen`, `scp`), `rsync`, `curl`, and `sha256sum`
- `uv` with Python 3.11+

Key and host-key isolation paths under `~/.cache/gateheal-vm` (overridable via `GATEHEAL_VM_DIR`):
- Controller SSH key (unprivileged `ubuntu` only): `~/.cache/gateheal-vm/id_ed25519` (`GATEHEAL_LAB_SSH_KEY`)
- Harness SSH key (`root` from `127.0.0.1` only): `~/.cache/gateheal-vm/id_harness_ed25519` (`GATEHEAL_LAB_HARNESS_KEY`)
- Dedicated lab `known_hosts`: `~/.cache/gateheal-vm/known_hosts` (`GATEHEAL_LAB_KNOWN_HOSTS`)

## 2 Bootstrap
Download the version-pinned Ubuntu 24.04 cloud image (`release-YYYYMMDD`), verify its digest against `SHA256SUMS` via `sha256sum -c`, generate the separated controller and harness SSH keys, and create a fresh qcow2 overlay:

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

## 4 Sync and provision
Sync the repository to `/opt/gateheal` inside the guest and run `provision_guest.sh` as `root`. You can run `sync-repo` followed by `provision_guest.sh`, or invoke `provision` (which runs both idempotently), and then optionally freeze `lab-golden.qcow2` via `build-golden`:

```bash
bash lab/qemu/manage_vm.sh sync-repo
ssh -p 2222 -i ~/.cache/gateheal-vm/id_harness_ed25519 \
  -o UserKnownHostsFile=~/.cache/gateheal-vm/known_hosts \
  -o StrictHostKeyChecking=accept-new \
  root@127.0.0.1 "bash /opt/gateheal/lab/scripts/provision_guest.sh"
```

To run the combined idempotent action and freeze a golden backing image (`lab-golden.qcow2`) so future overlays do not need re-provisioning:

```bash
bash lab/qemu/manage_vm.sh provision
bash lab/qemu/manage_vm.sh build-golden
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
Execute the host-side WP5 runner (`wp5_capture_and_verify.py`) to measure standard and multiplexed SSH latency, run conformance, execute all 7 smoke scenarios (`S0_HEALTHY_CONTROL` through `S5B_COLLATERAL_FORCED_RESTART`) across `--repeats 3`, atomically update the captured fixture if conformance passes, and write `artifacts/wp5_lab_manifest.json`. Then run the live pytest gate:

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
Stop the background QEMU/KVM process cleanly when finished:

```bash
bash lab/qemu/manage_vm.sh stop-vm
```

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `status STOPPED` (or `Connection refused` on port `2222`) | QEMU/KVM guest VM is not running. | Run `bash lab/qemu/manage_vm.sh boot-vm` and `bash lab/qemu/manage_vm.sh wait-ssh`. |
| `Permission denied (publickey)` | Wrong key used for SSH user, or controller key used for `root`. | Set `GATEHEAL_LAB_SSH_KEY` to `~/.cache/gateheal-vm/id_ed25519` for `ubuntu` or pass `--harness-identity-file ~/.cache/gateheal-vm/id_harness_ed25519` for `root`. |
| `Sentinel missing` (`HostSafetyViolationError` on `/etc/gateheal-lab-sentinel`) | Guest is unprovisioned, or overlay was recreated against raw base image without `lab-golden.qcow2`. | Run `bash lab/qemu/manage_vm.sh provision` (or `bash lab/qemu/manage_vm.sh build-golden`). |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | Stale `known_hosts` entry after overlay recreation. | Delete `~/.cache/gateheal-vm/known_hosts` (or set `GATEHEAL_LAB_KNOWN_HOSTS`) and re-run `bash lab/qemu/manage_vm.sh wait-ssh`. |# GateHeal WP5 Real-Lab Runbook (QEMU/KVM Guest Bring-Up & Conformance)

## 1. Isolation Architecture & Dual-Key Privilege Separation
All destructive fault-injection and systemd mutation tests execute strictly inside an isolated Ubuntu 24.04 QEMU/KVM guest on loopback SSH (`127.0.0.1:2222`) with QEMU user-network `restrict=on` (blocking guest outbound access).

- **Host & SSH Guards (E1):** `LocalLabSubprocessTransport` and `lab/scripts/lab_guard.sh` refuse execution on the Omarchy workstation kernel, without `GATEHEAL_INSIDE_LAB=1`, without `/etc/gateheal-lab-sentinel`, or on bare metal. `SSHLabTransport._ensure_remote_sentinel()` raises `TransportUnavailableError` (with `exit_code` and `stderr_excerpt`) when SSH fails to connect, and `HostSafetyViolationError` when `/etc/gateheal-lab-sentinel` mismatches `GATEHEAL_ISOLATED_LAB_GUEST_V1`.
- **Dual SSH Key Separation (E6):**
  - **Controller Key (`~/.cache/gateheal-vm/id_ed25519`):** Authorized only for unprivileged `ubuntu@127.0.0.1`, restricted by `/etc/sudoers.d/gateheal-lab` to the 4 exact `systemctl reload|restart` commands. Explicitly denied for `root@127.0.0.1`.
  - **Harness Key (`~/.cache/gateheal-vm/id_ed25519_harness`):** Authorized for `root@127.0.0.1` strictly for test-harness fault injection (`inject_fault.sh`), lab resets (`reset_lab.sh`), and conformance checks (`check_conformance.sh`).

---

## 2. Step-by-Step Bring-Up, Provisioning, Golden Image & Execution

> **Warning on Overlays:** Running `manage_vm.sh create-overlay` or `reset-overlay` against the raw `ubuntu-24.04-base.qcow2` image erases all guest provisioning (`/etc/gateheal-lab-sentinel`, `/etc/sudoers.d/gateheal-lab`, systemd units, and `/opt/gateheal`). Either run `manage_vm.sh build-golden` once so future overlays are backed by the provisioned `ubuntu-24.04-golden.qcow2`, or use `manage_vm.sh reset-guest` for fast in-guest service resets between runs.

### Step 2.1 Bootstrap Base Image (`SHA256SUMS`), Create Overlay, Boot & Wait for SSH
```bash
bash lab/qemu/manage_vm.sh bootstrap-base
bash lab/qemu/manage_vm.sh create-overlay
bash lab/qemu/manage_vm.sh boot-vm
bash lab/qemu/manage_vm.sh wait-ssh
```

### Step 2.2 Sync Repository to `/opt/gateheal` & Provision Guest as Root
```bash
bash lab/scripts/sync_repo_to_guest.sh /opt/gateheal
ssh -p 2222 -i ~/.cache/gateheal-vm/id_ed25519_harness root@127.0.0.1 \
  "bash /opt/gateheal/lab/scripts/provision_guest.sh"
```
*(Optional E7 golden snapshot: run `bash lab/qemu/manage_vm.sh build-golden` to freeze the provisioned disk into `ubuntu-24.04-golden.qcow2`.)*

### Step 2.3 Run Empirical `systemd` Conformance & Sudoers Suite
```bash
ssh -p 2222 -i ~/.cache/gateheal-vm/id_ed25519_harness root@127.0.0.1 \
  "GATEHEAL_INSIDE_LAB=1 bash /opt/gateheal/lab/scripts/check_conformance.sh"
```

| Fact ID | Verified Property | Expected |
| :--- | :--- | :---: |
| `FACT_1_RESTART_NO_NRESTARTS_ZERO` | `Restart=no` leaves `NRestarts=0` after `SIGKILL` | `PASS` |
| `FACT_2_INVOCATION_ID_RESTART_VS_RELOAD` | `InvocationID` & `ExecMainStartTimestampMonotonic` stay identical on `reload` and change on `restart` | `PASS` |
| `FACT_3_SIGKILL_RESULT_SIGNAL` | `SIGKILL` on `lab-api.service` yields `ActiveState=failed`, `Result=signal` | `PASS` |
| `FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER` | Restarting active `lab-api.service` (`SIGTERM`) terminates coupled `lab-worker.service` | `PASS` |
| `FACT_4B_START_FAILED_API_PRESERVES_WORKER` | Starting failed `lab-api.service` preserves `lab-worker.service` (`active`) | `PASS` |
| `FACT_5_MANUAL_RESTART_NRESTARTS_BEHAVIOR` | Long-running probe unit killed once (`NRestarts=1`), manually restarted, and read after 1s resets `NRestarts=0` | `PASS` |
| `SUDO_POS_*` (4 checks) | `ubuntu` allowed to run all 4 exact `gateheal-sudoers.conf` commands | `PASS` |
| `SUDO_NEG_DENIED` (11 checks) | `ubuntu` denied on `stop`, `reload redis/worker`, `restart ssh`, `daemon-reload`, `/bin/sh`, and 5 argument-injection vectors | `PASS` |
| `SSH_NEG_CONTROLLER_KEY_DENIED_ROOT` | Controller key `id_ed25519` rejected for `root@127.0.0.1` (`exit=255`) | `PASS` |

### Step 2.4 Capture Live S1–S5 Smoke Matrix, Manifest & Run Live Pytest Gate
```bash
PYTHONUNBUFFERED=1 uv run python lab/scripts/wp5_capture_and_verify.py
GATEHEAL_RUN_LAB_TESTS=1 uv run pytest -v -m lab
```

| Scenario ID | Diagnosed Fault | Selected Action | Target Unit | Verification Status | Samples | Escalated |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| `S1_SERVICE_CRASH` | `process_crash` | `restart_service` | `lab-api.service` | `recovered_clean` | `5` | `false` |
| `S2_INVALID_CONFIG` | `invalid_config` | `abstain_and_escalate` | `lab-api.service` | `fault_persists_service_up` | `1` | `true` |
| `S3_DEPENDENCY_FAILURE` | `dependency_failure` | `restart_service` | `lab-redis.service` | `recovered_clean` | `5` | `false` |
| `S4_PERSISTENT_FAILURE` | `invalid_config` / `persistent_failure` | `abstain_and_escalate` | `lab-api.service` | `not_recovered` | `1` | `true` |
| `S5_COLLATERAL_TRAP` | `degraded_running` | `reload_service` | `lab-api.service` | `recovered_clean` | `5` | `false` |

### Step 2.5 In-Guest Reset & Teardown
```bash
# Fast in-guest reset without wiping overlay provisioning
bash lab/qemu/manage_vm.sh reset-guest

# Stop QEMU/KVM VM when finished
bash lab/qemu/manage_vm.sh stop-vm
```
