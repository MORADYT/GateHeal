#!/usr/bin/env bash
# Controlled fault injector executed inside the isolated lab VM.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../scripts/lab_guard.sh
source "${SCRIPT_DIR}/../scripts/lab_guard.sh"

SCENARIO="${1:-}"
case "$SCENARIO" in
    S1_SERVICE_CRASH)
        systemctl kill -s SIGKILL lab-api.service
        ;;
    S2_INVALID_CONFIG)
        echo "invalid_yaml: [unclosed" > /etc/lab-api/config.yaml
        ;;
    S3_DEPENDENCY_FAILURE)
        systemctl stop lab-redis.service
        ;;
    S4_PERSISTENT_FAILURE)
        echo "listen_port: 'not_an_int'" > /etc/lab-api/config.yaml
        systemctl kill -s SIGKILL lab-api.service
        ;;
    S5_COLLATERAL_TRAP)
        sed -i 's/worker_pool_stale: false/worker_pool_stale: true/' /etc/lab-api/config.yaml
        ;;
    *)
        echo "Usage: $0 {S1_SERVICE_CRASH|S2_INVALID_CONFIG|S3_DEPENDENCY_FAILURE|S4_PERSISTENT_FAILURE|S5_COLLATERAL_TRAP}" >&2
        exit 2
        ;;
esac
