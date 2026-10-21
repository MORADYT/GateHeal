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
