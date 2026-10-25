#!/usr/bin/env bash
# Sync GateHeal repository to /opt/gateheal inside the guest VM.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM_DIR="${GATEHEAL_VM_DIR:-$HOME/.cache/gateheal-vm}"
SSH_PORT="${GATEHEAL_LAB_SSH_PORT:-2222}"
CONTROLLER_KEY="${GATEHEAL_LAB_SSH_KEY:-${VM_DIR}/id_ed25519}"
HARNESS_KEY="${GATEHEAL_LAB_HARNESS_KEY:-${VM_DIR}/id_ed25519_harness}"
GUEST_DIR="${1:-/opt/gateheal}"

if [[ ! -f "${HARNESS_KEY}.pub" ]]; then
    ssh-keygen -t ed25519 -N "" -f "$HARNESS_KEY" -C "gateheal-harness-root" >/dev/null
fi

SSH_OPTS="-p ${SSH_PORT} -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5"

if ssh ${SSH_OPTS} -i "$HARNESS_KEY" root@127.0.0.1 "true" >/dev/null 2>&1; then
    ssh ${SSH_OPTS} -i "$HARNESS_KEY" root@127.0.0.1 \
        "mkdir -p ${GUEST_DIR} && chown ubuntu:ubuntu ${GUEST_DIR}"
elif ssh ${SSH_OPTS} -i "$CONTROLLER_KEY" ubuntu@127.0.0.1 "sudo -n true" >/dev/null 2>&1; then
    ssh ${SSH_OPTS} -i "$CONTROLLER_KEY" ubuntu@127.0.0.1 \
        "sudo -n mkdir -p ${GUEST_DIR} && sudo -n chown ubuntu:ubuntu ${GUEST_DIR}"
fi

rsync -az --delete \
    --exclude '.venv' \
    --exclude 'artifacts' \
    --exclude '.git' \
    --exclude '.mypy_cache' \
    --exclude '.pytest_cache' \
    --exclude '.ruff_cache' \
    -e "ssh ${SSH_OPTS} -i ${CONTROLLER_KEY}" \
    "${REPO_ROOT}/" "ubuntu@127.0.0.1:${GUEST_DIR}/"

scp -P "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -i "$CONTROLLER_KEY" "${HARNESS_KEY}.pub" "ubuntu@127.0.0.1:${GUEST_DIR}/.harness_key.pub" >/dev/null

echo "SYNC_OK: Synced repo and harness public key to ubuntu@127.0.0.1:${GUEST_DIR}"
