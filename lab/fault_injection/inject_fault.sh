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
        systemctl kill -s SIGKILL lab-redis.service
        ;;
    S4_PERSISTENT_FAILURE)
        echo "listen_port: 'not_an_int'" > /etc/lab-api/config.yaml
        systemctl kill -s SIGKILL lab-api.service
        ;;
    S5_COLLATERAL_TRAP)
        # Runtime-only fault: a restart or SIGHUP clears it. It must NOT be written to the
        # config file, or a restart would re-read it and the service could never recover.
        # Wait until the API socket is listening: the SIGUSR1 handler is installed before
        # the HTTP server binds, and an unhandled SIGUSR1 would terminate the daemon.
        api_up=0
        for _ in $(seq 1 50); do
            if curl -sS -o /dev/null --max-time 1 http://127.0.0.1:8080/healthz 2>/dev/null; then
                api_up=1
                break
            fi
            sleep 0.2
        done
        if [[ "$api_up" != "1" ]]; then
            echo "FATAL: lab-api did not start listening on 127.0.0.1:8080" >&2
            exit 3
        fi
        systemctl kill -s SIGUSR1 lab-api.service
        ;;
    *)
        echo "Usage: $0 {S1_SERVICE_CRASH|S2_INVALID_CONFIG|S3_DEPENDENCY_FAILURE|S4_PERSISTENT_FAILURE|S5_COLLATERAL_TRAP}" >&2
        exit 2
        ;;
esac
