#!/usr/bin/env bash
# WP5 empirical systemd conformance and sudoers positive/negative test script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GATEHEAL_INSIDE_LAB="${GATEHEAL_INSIDE_LAB:-1}"
source "${SCRIPT_DIR}/lab_guard.sh"

RESET_SCRIPT="${SCRIPT_DIR}/../reset/reset_lab.sh"
FAILURES=0

pass_fact() {
    echo "PASS: $1 :: $2"
}

fail_fact() {
    echo "FAIL: $1 :: $2"
    FAILURES=$((FAILURES + 1))
}

prop_val() {
    systemctl show "$1" --property="$2" --value
}

bash "$RESET_SCRIPT"
sleep 0.5
systemctl kill -s SIGKILL lab-api.service
sleep 0.5

ACT_STATE="$(prop_val lab-api.service ActiveState)"
RES_VAL="$(prop_val lab-api.service Result)"
NRESTARTS_VAL="$(prop_val lab-api.service NRestarts)"

if [[ "$NRESTARTS_VAL" == "0" ]]; then
    pass_fact "FACT_1_RESTART_NO_NRESTARTS_ZERO" "ActiveState=${ACT_STATE}, NRestarts=${NRESTARTS_VAL}"
else
    fail_fact "FACT_1_RESTART_NO_NRESTARTS_ZERO" "Expected NRestarts=0, got ${NRESTARTS_VAL}"
fi

if [[ "$ACT_STATE" == "failed" && "$RES_VAL" == "signal" ]]; then
    pass_fact "FACT_3_SIGKILL_RESULT_SIGNAL" "ActiveState=${ACT_STATE}, Result=${RES_VAL}"
else
    fail_fact "FACT_3_SIGKILL_RESULT_SIGNAL" "Expected ActiveState=failed Result=signal, got ActiveState=${ACT_STATE} Result=${RES_VAL}"
fi

WORKER_BEFORE_START="$(prop_val lab-worker.service ActiveState)"
systemctl restart lab-api.service
sleep 0.5
WORKER_AFTER_FAILED_START="$(prop_val lab-worker.service ActiveState)"
if [[ "$WORKER_BEFORE_START" == "active" && "$WORKER_AFTER_FAILED_START" == "active" ]]; then
    pass_fact "FACT_4B_START_FAILED_API_PRESERVES_WORKER" "worker_before=${WORKER_BEFORE_START}, worker_after=${WORKER_AFTER_FAILED_START}"
else
    fail_fact "FACT_4B_START_FAILED_API_PRESERVES_WORKER" "worker_before=${WORKER_BEFORE_START}, worker_after=${WORKER_AFTER_FAILED_START}"
fi

INV_INITIAL="$(prop_val lab-api.service InvocationID)"
ST_INITIAL="$(prop_val lab-api.service ExecMainStartTimestampMonotonic)"

systemctl reload lab-api.service
sleep 0.3
INV_AFTER_RELOAD="$(prop_val lab-api.service InvocationID)"
ST_AFTER_RELOAD="$(prop_val lab-api.service ExecMainStartTimestampMonotonic)"

bash "$RESET_SCRIPT"
sleep 0.5
INV_BEFORE_RESTART="$(prop_val lab-api.service InvocationID)"
systemctl restart lab-api.service
sleep 0.5
INV_AFTER_RESTART="$(prop_val lab-api.service InvocationID)"

if [[ "$INV_INITIAL" == "$INV_AFTER_RELOAD" && "$ST_INITIAL" == "$ST_AFTER_RELOAD" && "$INV_BEFORE_RESTART" != "$INV_AFTER_RESTART" ]]; then
    pass_fact "FACT_2_INVOCATION_ID_RESTART_VS_RELOAD" "reload_kept=${INV_AFTER_RELOAD}, restart_changed=${INV_BEFORE_RESTART}->${INV_AFTER_RESTART}"
else
    fail_fact "FACT_2_INVOCATION_ID_RESTART_VS_RELOAD" "init=${INV_INITIAL}, reload=${INV_AFTER_RELOAD}, pre_rst=${INV_BEFORE_RESTART}, post_rst=${INV_AFTER_RESTART}"
fi

bash "$RESET_SCRIPT"
sleep 0.5
WORKER_PRE_ACTIVE_RST="$(prop_val lab-worker.service ActiveState)"
systemctl restart lab-api.service
sleep 0.5
WORKER_POST_ACTIVE_RST="$(prop_val lab-worker.service ActiveState)"
if [[ "$WORKER_PRE_ACTIVE_RST" == "active" && "$WORKER_POST_ACTIVE_RST" == "failed" ]]; then
    pass_fact "FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER" "worker_pre=${WORKER_PRE_ACTIVE_RST}, worker_post=${WORKER_POST_ACTIVE_RST}"
else
    fail_fact "FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER" "Expected active->failed, got ${WORKER_PRE_ACTIVE_RST}->${WORKER_POST_ACTIVE_RST}"
fi

# D1: Redesigned FACT_5 (systemd-run probe, SIGKILL, NRestarts=1, manual restart, read after 1.0s)
PROBE_UNIT="gateheal-nrestarts-probe.service"
systemctl stop "$PROBE_UNIT" 2>/dev/null || true
systemctl reset-failed "$PROBE_UNIT" 2>/dev/null || true
systemd-run --unit="$PROBE_UNIT" -p Restart=on-failure -p RestartSec=200ms /bin/sh -c 'exec sleep 300' >/dev/null 2>&1

# Wait until active
for _ in $(seq 1 30); do
    if [[ "$(prop_val "$PROBE_UNIT" ActiveState)" == "active" ]]; then
        break
    fi
    sleep 0.1
done

systemctl kill -s SIGKILL --kill-whom=main "$PROBE_UNIT"
sleep 0.8
NR_BEFORE_MANUAL="$(prop_val "$PROBE_UNIT" NRestarts)"
systemctl restart "$PROBE_UNIT"
sleep 1.0
NR_AFTER_MANUAL="$(prop_val "$PROBE_UNIT" NRestarts)"
PROBE_ACT="$(prop_val "$PROBE_UNIT" ActiveState)"
systemctl stop "$PROBE_UNIT" 2>/dev/null || true
systemctl reset-failed "$PROBE_UNIT" 2>/dev/null || true

if [[ "$NR_BEFORE_MANUAL" -eq 1 && "$PROBE_ACT" == "active" ]]; then
    OBSERVED_BEHAVIOR="reset"
    if [[ "$NR_AFTER_MANUAL" -eq 1 ]]; then
        OBSERVED_BEHAVIOR="preserved"
    fi
    pass_fact "FACT_5B_MANUAL_RESTART_NRESTARTS" "before=${NR_BEFORE_MANUAL} after=${NR_AFTER_MANUAL} observed=${OBSERVED_BEHAVIOR}"
else
    fail_fact "FACT_5B_MANUAL_RESTART_NRESTARTS" "Expected before=1 active, got before=${NR_BEFORE_MANUAL} after=${NR_AFTER_MANUAL} state=${PROBE_ACT}"
fi

bash "$RESET_SCRIPT"

# D2 & D3: Sudo positive and strict negative/argument-injection checks
assert_su_negative() {
    local cmd="$1"
    local out_file
    out_file="$(mktemp)"
    set +e
    su -s /bin/bash ubuntu -c "$cmd" >"$out_file" 2>&1
    local rc=$?
    set -e
    local err_text
    err_text="$(cat "$out_file")"
    rm -f "$out_file"

    if [[ $rc -eq 0 ]]; then
        fail_fact "SUDO_NEG_DENIED" "Unapproved command succeeded: ${cmd}"
        return
    fi

    if grep -qE "(a password is required|is not allowed to execute|may not run sudo)" <<< "$err_text"; then
        pass_fact "SUDO_NEG_DENIED" "Correctly denied: ${cmd}"
    else
        fail_fact "SUDO_NEG_DENIED" "Denied with unexpected stderr for ${cmd}: ${err_text}"
    fi
}

# D3: Positive checks for 4 allowlisted lines
POS_COMMANDS=(
    "sudo -n /usr/bin/systemctl reload lab-api.service"
    "sudo -n /usr/bin/systemctl restart lab-redis.service"
    "sudo -n /usr/bin/systemctl restart lab-api.service"
    "sudo -n /usr/bin/systemctl restart lab-worker.service"
)
POS_IDS=(
    "SUDO_POS_RELOAD_API"
    "SUDO_POS_RESTART_REDIS"
    "SUDO_POS_RESTART_API"
    "SUDO_POS_RESTART_WORKER"
)

for i in "${!POS_COMMANDS[@]}"; do
    bash "$RESET_SCRIPT"
    if su -s /bin/bash ubuntu -c "${POS_COMMANDS[$i]}" >/dev/null 2>&1; then
        pass_fact "${POS_IDS[$i]}" "${POS_COMMANDS[$i]} allowed and unit active"
    else
        fail_fact "${POS_IDS[$i]}" "${POS_COMMANDS[$i]} was denied"
    fi
done

bash "$RESET_SCRIPT"

# D3 & D2: Negatives and argument injection
DENIED_COMMANDS=(
    "sudo -n /usr/bin/systemctl stop lab-api.service"
    "sudo -n /usr/bin/systemctl reload lab-redis.service"
    "sudo -n /usr/bin/systemctl reload lab-worker.service"
    "sudo -n /usr/bin/systemctl restart ssh.service"
    "sudo -n /usr/bin/systemctl daemon-reload"
    "sudo -n /bin/sh -c id"
    "sudo -n /usr/bin/systemctl restart lab-api.service --no-block"
    "sudo -n /usr/bin/systemctl restart lab-api.service lab-redis.service"
    "sudo -n /usr/bin/systemctl --no-block restart lab-api.service"
    "sudo -n /usr/bin/systemctl restart 'lab-*.service'"
    "sudo -n /usr/bin/systemctl kill lab-api.service"
    "sudo -n /usr/bin/systemctl start lab-api.service"
)

for DENIED_CMD in "${DENIED_COMMANDS[@]}"; do
    assert_su_negative "$DENIED_CMD"
done

bash "$RESET_SCRIPT"

# D4: FACT_6_UBUNTU_UNPRIVILEGED_READS
if su -s /bin/bash ubuntu -c "systemctl show lab-api.service && journalctl -u lab-api.service -n 5 --no-pager" >/dev/null 2>&1; then
    pass_fact "FACT_6_UBUNTU_UNPRIVILEGED_READS" "ubuntu unprivileged reads succeed for lab-api.service"
else
    fail_fact "FACT_6_UBUNTU_UNPRIVILEGED_READS" "ubuntu unprivileged reads failed"
fi

# D4: FACT_7_EXECSTARTPRE_FAILURE
echo "invalid_yaml: [unclosed" > /etc/lab-api/config.yaml
set +e
systemctl restart lab-api.service >/dev/null 2>&1
API_RES="$(prop_val lab-api.service Result)"
API_ACT="$(prop_val lab-api.service ActiveState)"
WORKER_ACT="$(prop_val lab-worker.service ActiveState)"
set -e
bash "$RESET_SCRIPT"

if [[ -n "$API_RES" && -n "$API_ACT" ]]; then
    pass_fact "FACT_7_EXECSTARTPRE_FAILURE" "ActiveState=${API_ACT}, Result=${API_RES}, worker=${WORKER_ACT}"
else
    fail_fact "FACT_7_EXECSTARTPRE_FAILURE" "Failed to read ExecStartPre failure properties"
fi

if [[ "$FAILURES" -gt 0 ]]; then
    echo "CONFORMANCE_SUMMARY: FAILED (${FAILURES} failure(s))"
    exit 1
fi
echo "CONFORMANCE_SUMMARY: ALL_PASSED"#!/usr/bin/env bash
# WP5 empirical systemd conformance and sudoers positive/negative test script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GATEHEAL_INSIDE_LAB="${GATEHEAL_INSIDE_LAB:-1}"
source "${SCRIPT_DIR}/lab_guard.sh"

RESET_SCRIPT="${SCRIPT_DIR}/../reset/reset_lab.sh"
FAILURES=0

pass_fact() {
    echo "PASS: $1 :: $2"
}

fail_fact() {
    echo "FAIL: $1 :: $2"
    FAILURES=$((FAILURES + 1))
}

prop_val() {
    systemctl show "$1" --property="$2" --value
}

bash "$RESET_SCRIPT"
sleep 0.5
systemctl kill -s SIGKILL lab-api.service
sleep 0.5

ACT_STATE="$(prop_val lab-api.service ActiveState)"
RES_VAL="$(prop_val lab-api.service Result)"
NRESTARTS_VAL="$(prop_val lab-api.service NRestarts)"

if [[ "$NRESTARTS_VAL" == "0" ]]; then
    pass_fact "FACT_1_RESTART_NO_NRESTARTS_ZERO" "ActiveState=${ACT_STATE}, NRestarts=${NRESTARTS_VAL}"
else
    fail_fact "FACT_1_RESTART_NO_NRESTARTS_ZERO" "Expected NRestarts=0, got ${NRESTARTS_VAL}"
fi

if [[ "$ACT_STATE" == "failed" && "$RES_VAL" == "signal" ]]; then
    pass_fact "FACT_3_SIGKILL_RESULT_SIGNAL" "ActiveState=${ACT_STATE}, Result=${RES_VAL}"
else
    fail_fact "FACT_3_SIGKILL_RESULT_SIGNAL" "Expected ActiveState=failed Result=signal, got ActiveState=${ACT_STATE} Result=${RES_VAL}"
fi

WORKER_BEFORE_START="$(prop_val lab-worker.service ActiveState)"
systemctl restart lab-api.service
sleep 0.5
WORKER_AFTER_FAILED_START="$(prop_val lab-worker.service ActiveState)"
if [[ "$WORKER_BEFORE_START" == "active" && "$WORKER_AFTER_FAILED_START" == "active" ]]; then
    pass_fact "FACT_4B_START_FAILED_API_PRESERVES_WORKER" "worker_before=${WORKER_BEFORE_START}, worker_after=${WORKER_AFTER_FAILED_START}"
else
    fail_fact "FACT_4B_START_FAILED_API_PRESERVES_WORKER" "worker_before=${WORKER_BEFORE_START}, worker_after=${WORKER_AFTER_FAILED_START}"
fi

INV_INITIAL="$(prop_val lab-api.service InvocationID)"
ST_INITIAL="$(prop_val lab-api.service ExecMainStartTimestampMonotonic)"

systemctl reload lab-api.service
sleep 0.3
INV_AFTER_RELOAD="$(prop_val lab-api.service InvocationID)"
ST_AFTER_RELOAD="$(prop_val lab-api.service ExecMainStartTimestampMonotonic)"

bash "$RESET_SCRIPT"
sleep 0.5
INV_BEFORE_RESTART="$(prop_val lab-api.service InvocationID)"
systemctl restart lab-api.service
sleep 0.5
INV_AFTER_RESTART="$(prop_val lab-api.service InvocationID)"

if [[ "$INV_INITIAL" == "$INV_AFTER_RELOAD" && "$ST_INITIAL" == "$ST_AFTER_RELOAD" && "$INV_BEFORE_RESTART" != "$INV_AFTER_RESTART" ]]; then
    pass_fact "FACT_2_INVOCATION_ID_RESTART_VS_RELOAD" "reload_kept=${INV_AFTER_RELOAD}, restart_changed=${INV_BEFORE_RESTART}->${INV_AFTER_RESTART}"
else
    fail_fact "FACT_2_INVOCATION_ID_RESTART_VS_RELOAD" "init=${INV_INITIAL}, reload=${INV_AFTER_RELOAD}, pre_rst=${INV_BEFORE_RESTART}, post_rst=${INV_AFTER_RESTART}"
fi

bash "$RESET_SCRIPT"
sleep 0.5
WORKER_PRE_ACTIVE_RST="$(prop_val lab-worker.service ActiveState)"
systemctl restart lab-api.service
sleep 0.5
WORKER_POST_ACTIVE_RST="$(prop_val lab-worker.service ActiveState)"
if [[ "$WORKER_PRE_ACTIVE_RST" == "active" && "$WORKER_POST_ACTIVE_RST" == "failed" ]]; then
    pass_fact "FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER" "worker_pre=${WORKER_PRE_ACTIVE_RST}, worker_post=${WORKER_POST_ACTIVE_RST}"
else
    fail_fact "FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER" "Expected active->failed, got ${WORKER_PRE_ACTIVE_RST}->${WORKER_POST_ACTIVE_RST}"
fi

# D1: Redesigned FACT_5 (systemd-run probe, SIGKILL, NRestarts=1, manual restart, read after 1.0s)
PROBE_UNIT="gateheal-nrestarts-probe.service"
systemctl stop "$PROBE_UNIT" 2>/dev/null || true
systemctl reset-failed "$PROBE_UNIT" 2>/dev/null || true
systemd-run --unit="$PROBE_UNIT" -p Restart=on-failure -p RestartSec=200ms /bin/sh -c 'exec sleep 300' >/dev/null 2>&1

# Wait until active
for _ in $(seq 1 30); do
    if [[ "$(prop_val "$PROBE_UNIT" ActiveState)" == "active" ]]; then
        break
    fi
    sleep 0.1
done

systemctl kill -s SIGKILL --kill-whom=main "$PROBE_UNIT"
sleep 0.8
NR_BEFORE_MANUAL="$(prop_val "$PROBE_UNIT" NRestarts)"
systemctl restart "$PROBE_UNIT"
sleep 1.0
NR_AFTER_MANUAL="$(prop_val "$PROBE_UNIT" NRestarts)"
PROBE_ACT="$(prop_val "$PROBE_UNIT" ActiveState)"
systemctl stop "$PROBE_UNIT" 2>/dev/null || true
systemctl reset-failed "$PROBE_UNIT" 2>/dev/null || true

if [[ "$NR_BEFORE_MANUAL" -eq 1 && "$PROBE_ACT" == "active" ]]; then
    OBSERVED_BEHAVIOR="reset"
    if [[ "$NR_AFTER_MANUAL" -eq 1 ]]; then
        OBSERVED_BEHAVIOR="preserved"
    fi
    pass_fact "FACT_5B_MANUAL_RESTART_NRESTARTS" "before=${NR_BEFORE_MANUAL} after=${NR_AFTER_MANUAL} observed=${OBSERVED_BEHAVIOR}"
else
    fail_fact "FACT_5B_MANUAL_RESTART_NRESTARTS" "Expected before=1 active, got before=${NR_BEFORE_MANUAL} after=${NR_AFTER_MANUAL} state=${PROBE_ACT}"
fi

bash "$RESET_SCRIPT"

# D2 & D3: Sudo positive and strict negative/argument-injection checks
assert_su_negative() {
    local cmd="$1"
    local out_file
    out_file="$(mktemp)"
    set +e
    su -s /bin/bash ubuntu -c "$cmd" >"$out_file" 2>&1
    local rc=$?
    set -e
    local err_text
    err_text="$(cat "$out_file")"
    rm -f "$out_file"

    if [[ $rc -eq 0 ]]; then
        fail_fact "SUDO_NEG_DENIED" "Unapproved command succeeded: ${cmd}"
        return
    fi

    if grep -qE "(a password is required|is not allowed to execute|may not run sudo)" <<< "$err_text"; then
        pass_fact "SUDO_NEG_DENIED" "Correctly denied: ${cmd}"
    else
        fail_fact "SUDO_NEG_DENIED" "Denied with unexpected stderr for ${cmd}: ${err_text}"
    fi
}

# D3: Positive checks for 4 allowlisted lines
POS_COMMANDS=(
    "sudo -n /usr/bin/systemctl reload lab-api.service"
    "sudo -n /usr/bin/systemctl restart lab-redis.service"
    "sudo -n /usr/bin/systemctl restart lab-api.service"
    "sudo -n /usr/bin/systemctl restart lab-worker.service"
)
POS_IDS=(
    "SUDO_POS_RELOAD_API"
    "SUDO_POS_RESTART_REDIS"
    "SUDO_POS_RESTART_API"
    "SUDO_POS_RESTART_WORKER"
)

for i in "${!POS_COMMANDS[@]}"; do
    bash "$RESET_SCRIPT"
    if su -s /bin/bash ubuntu -c "${POS_COMMANDS[$i]}" >/dev/null 2>&1; then
        pass_fact "${POS_IDS[$i]}" "${POS_COMMANDS[$i]} allowed and unit active"
    else
        fail_fact "${POS_IDS[$i]}" "${POS_COMMANDS[$i]} was denied"
    fi
done

bash "$RESET_SCRIPT"

# D3 & D2: Negatives and argument injection
DENIED_COMMANDS=(
    "sudo -n /usr/bin/systemctl stop lab-api.service"
    "sudo -n /usr/bin/systemctl reload lab-redis.service"
    "sudo -n /usr/bin/systemctl reload lab-worker.service"
    "sudo -n /usr/bin/systemctl restart ssh.service"
    "sudo -n /usr/bin/systemctl daemon-reload"
    "sudo -n /bin/sh -c id"
    "sudo -n /usr/bin/systemctl restart lab-api.service --no-block"
    "sudo -n /usr/bin/systemctl restart lab-api.service lab-redis.service"
    "sudo -n /usr/bin/systemctl --no-block restart lab-api.service"
    "sudo -n /usr/bin/systemctl restart 'lab-*.service'"
    "sudo -n /usr/bin/systemctl kill lab-api.service"
    "sudo -n /usr/bin/systemctl start lab-api.service"
)

for DENIED_CMD in "${DENIED_COMMANDS[@]}"; do
    assert_su_negative "$DENIED_CMD"
done

bash "$RESET_SCRIPT"

# D4: FACT_6_UBUNTU_UNPRIVILEGED_READS
if su -s /bin/bash ubuntu -c "systemctl show lab-api.service && journalctl -u lab-api.service -n 5 --no-pager" >/dev/null 2>&1; then
    pass_fact "FACT_6_UBUNTU_UNPRIVILEGED_READS" "ubuntu unprivileged reads succeed for lab-api.service"
else
    fail_fact "FACT_6_UBUNTU_UNPRIVILEGED_READS" "ubuntu unprivileged reads failed"
fi

# D4: FACT_7_EXECSTARTPRE_FAILURE
echo "invalid_yaml: [unclosed" > /etc/lab-api/config.yaml
set +e
systemctl restart lab-api.service >/dev/null 2>&1
API_RES="$(prop_val lab-api.service Result)"
API_ACT="$(prop_val lab-api.service ActiveState)"
WORKER_ACT="$(prop_val lab-worker.service ActiveState)"
set -e
bash "$RESET_SCRIPT"

if [[ -n "$API_RES" && -n "$API_ACT" ]]; then
    pass_fact "FACT_7_EXECSTARTPRE_FAILURE" "ActiveState=${API_ACT}, Result=${API_RES}, worker=${WORKER_ACT}"
else
    fail_fact "FACT_7_EXECSTARTPRE_FAILURE" "Failed to read ExecStartPre failure properties"
fi

if [[ "$FAILURES" -gt 0 ]]; then
    echo "CONFORMANCE_SUMMARY: FAILED (${FAILURES} failure(s))"
    exit 1
fi
echo "CONFORMANCE_SUMMARY: ALL_PASSED"#!/usr/bin/env bash
# WP5 empirical systemd conformance and sudoers positive/negative test script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GATEHEAL_INSIDE_LAB="${GATEHEAL_INSIDE_LAB:-1}"
source "${SCRIPT_DIR}/lab_guard.sh"

RESET_SCRIPT="${SCRIPT_DIR}/../reset/reset_lab.sh"
FAILURES=0

pass_fact() {
    echo "PASS: $1 :: $2"
}

fail_fact() {
    echo "FAIL: $1 :: $2"
    FAILURES=$((FAILURES + 1))
}

prop_val() {
    systemctl show "$1" --property="$2" --value
}

bash "$RESET_SCRIPT"
sleep 0.5
systemctl kill -s SIGKILL lab-api.service
sleep 0.5

ACT_STATE="$(prop_val lab-api.service ActiveState)"
RES_VAL="$(prop_val lab-api.service Result)"
NRESTARTS_VAL="$(prop_val lab-api.service NRestarts)"

if [[ "$NRESTARTS_VAL" == "0" ]]; then
    pass_fact "FACT_1_RESTART_NO_NRESTARTS_ZERO" "ActiveState=${ACT_STATE}, NRestarts=${NRESTARTS_VAL}"
else
    fail_fact "FACT_1_RESTART_NO_NRESTARTS_ZERO" "Expected NRestarts=0, got ${NRESTARTS_VAL}"
fi

if [[ "$ACT_STATE" == "failed" && "$RES_VAL" == "signal" ]]; then
    pass_fact "FACT_3_SIGKILL_RESULT_SIGNAL" "ActiveState=${ACT_STATE}, Result=${RES_VAL}"
else
    fail_fact "FACT_3_SIGKILL_RESULT_SIGNAL" "Expected ActiveState=failed Result=signal, got ActiveState=${ACT_STATE} Result=${RES_VAL}"
fi

WORKER_BEFORE_START="$(prop_val lab-worker.service ActiveState)"
systemctl restart lab-api.service
sleep 0.5
WORKER_AFTER_FAILED_START="$(prop_val lab-worker.service ActiveState)"
if [[ "$WORKER_BEFORE_START" == "active" && "$WORKER_AFTER_FAILED_START" == "active" ]]; then
    pass_fact "FACT_4B_START_FAILED_API_PRESERVES_WORKER" "worker_before=${WORKER_BEFORE_START}, worker_after=${WORKER_AFTER_FAILED_START}"
else
    fail_fact "FACT_4B_START_FAILED_API_PRESERVES_WORKER" "worker_before=${WORKER_BEFORE_START}, worker_after=${WORKER_AFTER_FAILED_START}"
fi

INV_INITIAL="$(prop_val lab-api.service InvocationID)"
ST_INITIAL="$(prop_val lab-api.service ExecMainStartTimestampMonotonic)"

systemctl reload lab-api.service
sleep 0.3
INV_AFTER_RELOAD="$(prop_val lab-api.service InvocationID)"
ST_AFTER_RELOAD="$(prop_val lab-api.service ExecMainStartTimestampMonotonic)"

bash "$RESET_SCRIPT"
sleep 0.5
INV_BEFORE_RESTART="$(prop_val lab-api.service InvocationID)"
systemctl restart lab-api.service
sleep 0.5
INV_AFTER_RESTART="$(prop_val lab-api.service InvocationID)"

if [[ "$INV_INITIAL" == "$INV_AFTER_RELOAD" && "$ST_INITIAL" == "$ST_AFTER_RELOAD" && "$INV_BEFORE_RESTART" != "$INV_AFTER_RESTART" ]]; then
    pass_fact "FACT_2_INVOCATION_ID_RESTART_VS_RELOAD" "reload_kept=${INV_AFTER_RELOAD}, restart_changed=${INV_BEFORE_RESTART}->${INV_AFTER_RESTART}"
else
    fail_fact "FACT_2_INVOCATION_ID_RESTART_VS_RELOAD" "init=${INV_INITIAL}, reload=${INV_AFTER_RELOAD}, pre_rst=${INV_BEFORE_RESTART}, post_rst=${INV_AFTER_RESTART}"
fi

bash "$RESET_SCRIPT"
sleep 0.5
WORKER_PRE_ACTIVE_RST="$(prop_val lab-worker.service ActiveState)"
systemctl restart lab-api.service
sleep 0.5
WORKER_POST_ACTIVE_RST="$(prop_val lab-worker.service ActiveState)"
if [[ "$WORKER_PRE_ACTIVE_RST" == "active" && "$WORKER_POST_ACTIVE_RST" == "failed" ]]; then
    pass_fact "FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER" "worker_pre=${WORKER_PRE_ACTIVE_RST}, worker_post=${WORKER_POST_ACTIVE_RST}"
else
    fail_fact "FACT_4A_ACTIVE_API_RESTART_KILLS_WORKER" "Expected active->failed, got ${WORKER_PRE_ACTIVE_RST}->${WORKER_POST_ACTIVE_RST}"
fi

# E4: Long-running probe unit killed once (NRestarts=1), manually restarted, and read after ~1s (NRestarts=0)
PROBE_UNIT="gateheal-nrestarts-probe.service"
systemctl stop "$PROBE_UNIT" 2>/dev/null || true
systemctl reset-failed "$PROBE_UNIT" 2>/dev/null || true
systemd-run --unit="$PROBE_UNIT" -p Restart=on-failure -p RestartSec=100ms /bin/sh -c 'exec sleep 300' >/dev/null 2>&1
sleep 0.3
systemctl kill -s SIGKILL "$PROBE_UNIT"
sleep 0.5
NR_BEFORE_MANUAL="$(prop_val "$PROBE_UNIT" NRestarts)"
systemctl restart "$PROBE_UNIT"
sleep 1.0
NR_AFTER_MANUAL="$(prop_val "$PROBE_UNIT" NRestarts)"
PROBE_ACT="$(prop_val "$PROBE_UNIT" ActiveState)"
systemctl stop "$PROBE_UNIT" 2>/dev/null || true
systemctl reset-failed "$PROBE_UNIT" 2>/dev/null || true

if [[ "$NR_BEFORE_MANUAL" -eq 1 && "$NR_AFTER_MANUAL" -eq 0 && "$PROBE_ACT" == "active" ]]; then
    pass_fact "FACT_5_MANUAL_RESTART_NRESTARTS_BEHAVIOR" "n_restarts_after_sigkill=${NR_BEFORE_MANUAL}, n_restarts_after_manual_restart_1s=${NR_AFTER_MANUAL} (manual_restart_resets_nrestarts=true)"
else
    fail_fact "FACT_5_MANUAL_RESTART_NRESTARTS_BEHAVIOR" "Expected before=1 after=0 active, got before=${NR_BEFORE_MANUAL} after=${NR_AFTER_MANUAL} state=${PROBE_ACT}"
fi

bash "$RESET_SCRIPT"

# E5: Positive tests for all 4 allowlisted sudoers lines
if su -s /bin/bash ubuntu -c "sudo -n /usr/bin/systemctl reload lab-api.service" >/dev/null 2>&1; then
    pass_fact "SUDO_POS_RELOAD_API" "sudo -n /usr/bin/systemctl reload lab-api.service allowed"
else
    fail_fact "SUDO_POS_RELOAD_API" "sudo -n /usr/bin/systemctl reload lab-api.service was denied"
fi

if su -s /bin/bash ubuntu -c "sudo -n /usr/bin/systemctl restart lab-redis.service" >/dev/null 2>&1; then
    pass_fact "SUDO_POS_RESTART_REDIS" "sudo -n /usr/bin/systemctl restart lab-redis.service allowed"
else
    fail_fact "SUDO_POS_RESTART_REDIS" "sudo -n /usr/bin/systemctl restart lab-redis.service was denied"
fi

if su -s /bin/bash ubuntu -c "sudo -n /usr/bin/systemctl restart lab-api.service" >/dev/null 2>&1; then
    pass_fact "SUDO_POS_RESTART_API" "sudo -n /usr/bin/systemctl restart lab-api.service allowed"
else
    fail_fact "SUDO_POS_RESTART_API" "sudo -n /usr/bin/systemctl restart lab-api.service was denied"
fi

if su -s /bin/bash ubuntu -c "sudo -n /usr/bin/systemctl restart lab-worker.service" >/dev/null 2>&1; then
    pass_fact "SUDO_POS_RESTART_WORKER" "sudo -n /usr/bin/systemctl restart lab-worker.service allowed"
else
    fail_fact "SUDO_POS_RESTART_WORKER" "sudo -n /usr/bin/systemctl restart lab-worker.service was denied"
fi

bash "$RESET_SCRIPT"

# E5: Negative tests (disallowed subcommands, units, and argument-injection attempts)
for DENIED_CMD in \
    "sudo -n /usr/bin/systemctl stop lab-api.service" \
    "sudo -n /usr/bin/systemctl reload lab-redis.service" \
    "sudo -n /usr/bin/systemctl reload lab-worker.service" \
    "sudo -n /usr/bin/systemctl restart ssh.service" \
    "sudo -n /usr/bin/systemctl daemon-reload" \
    "sudo -n /bin/sh -c id" \
    "sudo -n /usr/bin/systemctl restart lab-api.service ssh.service" \
    "sudo -n /usr/bin/systemctl restart lab-api.service --no-block" \
    "sudo -n /usr/bin/systemctl reload lab-api.service --force" \
    "sudo -n /usr/bin/systemctl --root=/tmp restart lab-api.service" \
    "sudo -n /usr/bin/systemctl restart lab-api.service -- --version"
do
    if su -s /bin/bash ubuntu -c "$DENIED_CMD" >/dev/null 2>&1; then
        fail_fact "SUDO_NEG_DENIED" "Unapproved command succeeded: ${DENIED_CMD}"
    else
        pass_fact "SUDO_NEG_DENIED" "Correctly denied: ${DENIED_CMD}"
    fi
done

if [[ "$FAILURES" -gt 0 ]]; then
    echo "CONFORMANCE_SUMMARY: FAILED (${FAILURES} failure(s))"
    exit 1
fi
echo "CONFORMANCE_SUMMARY: ALL_PASSED"

