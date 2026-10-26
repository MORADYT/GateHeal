#!/usr/bin/env bash
# Provision an isolated Ubuntu 24.04 QEMU/KVM guest for GateHeal WP5 (idempotent).
set -euo pipefail

KERNEL_REL="$(uname -r | tr '[:upper:]' '[:lower:]')"
if [[ "$KERNEL_REL" == *"omarchy"* ]]; then
    echo "FATAL: Refusing to provision on Omarchy host kernel ($KERNEL_REL)." >&2
    exit 1
fi

VIRT_TYPE="$(systemd-detect-virt || true)"
if [[ "$VIRT_TYPE" == "none" ]] || [[ -z "$VIRT_TYPE" ]]; then
    echo "FATAL: systemd-detect-virt reported bare-metal host ($VIRT_TYPE)." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# 1. Install lab sentinel file
echo "GATEHEAL_ISOLATED_LAB_GUEST_V1" > /etc/gateheal-lab-sentinel
chmod 0644 /etc/gateheal-lab-sentinel

# 2. Export GATEHEAL_INSIDE_LAB=1 in /etc/environment
if ! grep -q '^GATEHEAL_INSIDE_LAB=1' /etc/environment 2>/dev/null; then
    echo "GATEHEAL_INSIDE_LAB=1" >> /etc/environment
fi

# 3. Install ONLY the dedicated harness public key for root (no from= prefix because QEMU SLIRP routes gateway connections)
mkdir -p /root/.ssh
chmod 0700 /root/.ssh
if [[ ! -f "${REPO_ROOT}/.harness_key.pub" ]]; then
    echo "FATAL: Missing ${REPO_ROOT}/.harness_key.pub; run 'bash lab/qemu/manage_vm.sh sync-repo' first." >&2
    exit 1
fi
RAW_HARNESS_PUB="$(sed 's/^from="[^"]*"[[:space:]]*//' "${REPO_ROOT}/.harness_key.pub" | tr -d '\r\n')"
if [[ -z "$RAW_HARNESS_PUB" ]]; then
    echo "FATAL: Empty harness public key in ${REPO_ROOT}/.harness_key.pub" >&2
    exit 1
fi
printf '%s\n' "$RAW_HARNESS_PUB" > /root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys

# Grant ubuntu read-only journal access for unprivileged diagnostics (FACT_6)
usermod -aG systemd-journal,adm ubuntu

# 4. Install strict sudoers for `ubuntu` and remove cloud-init blanket NOPASSWD:ALL
install -m 0440 "${REPO_ROOT}/lab/systemd/gateheal-sudoers.conf" /etc/sudoers.d/gateheal-lab
visudo -cf /etc/sudoers.d/gateheal-lab
rm -f /etc/sudoers.d/90-cloud-init-users

# 5. Make gateheal importable by /usr/bin/python3 for systemd services
SITE_PKGS="$(/usr/bin/python3 -c 'import site; print([p for p in site.getsitepackages() if "dist-packages" in p or "site-packages" in p][0])')"
echo "${REPO_ROOT}/src" > "${SITE_PKGS}/gateheal.pth"

# 6. Install systemd unit files
install -m 0644 "${REPO_ROOT}/lab/systemd/lab-redis.service" /etc/systemd/system/lab-redis.service
install -m 0644 "${REPO_ROOT}/lab/systemd/lab-api.service" /etc/systemd/system/lab-api.service
install -m 0644 "${REPO_ROOT}/lab/systemd/lab-worker.service" /etc/systemd/system/lab-worker.service
systemctl daemon-reload
systemctl enable lab-redis.service lab-api.service lab-worker.service >/dev/null 2>&1 || true

# 7. Initialize clean /etc/lab-api/config.yaml and start services
export GATEHEAL_INSIDE_LAB=1
bash "${REPO_ROOT}/lab/reset/reset_lab.sh"
chmod 0644 /etc/lab-api/config.yaml
echo "PROVISION_OK: GateHeal isolated lab guest is ready."
