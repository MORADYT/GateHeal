#!/usr/bin/env bash
# Host-side helper to manage disposable QEMU/KVM qcow2 overlays safely.
set -euo pipefail

ACTION="${1:-help}"
BASE_IMAGE="${GATEHEAL_BASE_IMAGE:-artifacts/vm/ubuntu-24.04-base.qcow2}"
OVERLAY_IMAGE="${GATEHEAL_OVERLAY_IMAGE:-artifacts/vm/lab-overlay.qcow2}"
SSH_PORT="${GATEHEAL_LAB_SSH_PORT:-2222}"

case "$ACTION" in
    create-overlay|reset-overlay)
        if [[ ! -f "$BASE_IMAGE" ]]; then
            echo "Base image not found at $BASE_IMAGE." >&2
            exit 1
        fi
        rm -f "$OVERLAY_IMAGE"
        qemu-img create -f qcow2 -b "$(realpath "$BASE_IMAGE")" -F qcow2 "$OVERLAY_IMAGE"
        echo "Created clean copy-on-write overlay at $OVERLAY_IMAGE"
        ;;
    boot-vm)
        exec qemu-system-x86_64 \
            -enable-kvm \
            -m 2048 \
            -smp 2 \
            -drive "file=${OVERLAY_IMAGE},format=qcow2,if=virtio" \
            -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
            -device virtio-net-pci,netdev=net0 \
            -display none \
            -daemonize
        ;;
    *)
        echo "Usage: $0 {create-overlay|reset-overlay|boot-vm}"
        ;;
esac
