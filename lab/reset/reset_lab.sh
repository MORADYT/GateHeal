#!/usr/bin/env bash
# Deterministic reset script executed inside the isolated lab VM.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../scripts/lab_guard.sh
source "${SCRIPT_DIR}/../scripts/lab_guard.sh"

mkdir -p /etc/lab-api
cat <<'YAML' > /etc/lab-api/config.yaml
listen_host: "127.0.0.1"
listen_port: 8080
redis_host: "127.0.0.1"
redis_port: 6379
worker_pool_stale: false
YAML

systemctl stop lab-worker.service lab-api.service lab-redis.service || true
systemctl reset-failed lab-worker.service lab-api.service lab-redis.service || true
systemctl start lab-redis.service
systemctl start lab-api.service
systemctl start lab-worker.service
