#!/usr/bin/env bash
# Mandatory host-protection guard for all destructive lab scripts.
set -euo pipefail

KERNEL_REL="$(uname -r | tr '[:upper:]' '[:lower:]')"
if [[ "$KERNEL_REL" == *"omarchy"* ]]; then
    echo "FATAL: Refusing to run destructive lab script on Omarchy host kernel ($KERNEL_REL)." >&2
    exit 1
fi

if [[ "${GATEHEAL_INSIDE_LAB:-0}" != "1" ]]; then
    echo "FATAL: GATEHEAL_INSIDE_LAB=1 is not set. Run this script only inside the isolated VM." >&2
    exit 1
fi

SENTINEL_FILE="${GATEHEAL_SENTINEL_FILE:-/etc/gateheal-lab-sentinel}"
if [[ ! -f "$SENTINEL_FILE" ]] || [[ "$(cat "$SENTINEL_FILE")" != "GATEHEAL_ISOLATED_LAB_GUEST_V1" ]]; then
    echo "FATAL: Lab sentinel file $SENTINEL_FILE missing or invalid." >&2
    exit 1
fi

if command -v systemd-detect-virt >/dev/null 2>&1; then
    VIRT_TYPE="$(systemd-detect-virt || true)"
    if [[ "$VIRT_TYPE" == "none" ]] || [[ -z "$VIRT_TYPE" ]]; then
        echo "FATAL: systemd-detect-virt reported bare-metal host ($VIRT_TYPE)." >&2
        exit 1
    fi
fi
