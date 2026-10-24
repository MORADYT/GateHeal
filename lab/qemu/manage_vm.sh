#!/usr/bin/env bash
# Host-side helper to bootstrap, verify SHA256SUMS, sync/provision, build lab-golden.qcow2, and manage QEMU/KVM overlays.
set -euo pipefail

ACTION="${1:-help}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM_DIR="${GATEHEAL_VM_DIR:-$HOME/.cache/gateheal-vm}"
BASE_IMAGE="${GATEHEAL_BASE_IMAGE:-${VM_DIR}/ubuntu-24.04-base.qcow2}"
GOLDEN_IMAGE="${GATEHEAL_GOLDEN_IMAGE:-${VM_DIR}/lab-golden.qcow2}"
OVERLAY_IMAGE="${GATEHEAL_OVERLAY_IMAGE:-${VM_DIR}/lab-overlay.qcow2}"
SEED_ISO="${VM_DIR}/seed.iso"
SSH_KEY="${GATEHEAL_LAB_SSH_KEY:-${VM_DIR}/id_ed25519}"
HARNESS_KEY="${GATEHEAL_LAB_HARNESS_KEY:-${VM_DIR}/id_harness_ed25519}"
LEGACY_HARNESS_KEY="${VM_DIR}/id_ed25519_harness"
KNOWN_HOSTS_FILE="${GATEHEAL_LAB_KNOWN_HOSTS:-${VM_DIR}/known_hosts}"
PID_FILE="${VM_DIR}/qemu.pid"
SSH_PORT="${GATEHEAL_LAB_SSH_PORT:-2222}"
SHA256SUMS_FILE="${VM_DIR}/SHA256SUMS"
RESIZED_SHA256_FILE="${VM_DIR}/BASE_IMAGE.sha256"
RELEASE_FILE="${VM_DIR}/base_image_release"
GUEST_REPO_DIR="${GATEHEAL_GUEST_REPO_DIR:-/opt/gateheal}"

# Version-pinned Ubuntu 24.04 Noble cloud image release
BASE_IMAGE_RELEASE="${GATEHEAL_BASE_IMAGE_RELEASE:-release-20250219}"
CLOUD_RELEASE_URL="https://cloud-images.ubuntu.com/releases/noble/${BASE_IMAGE_RELEASE}"
CLOUD_IMG_NAME="noble-server-cloudimg-amd64.img"

mkdir -p "$VM_DIR"

SSH_COMMON_OPTS=(
    -p "$SSH_PORT"
    -o BatchMode=yes
    -o "UserKnownHostsFile=${KNOWN_HOSTS_FILE}"
    -o StrictHostKeyChecking=accept-new
    -o LogLevel=ERROR
    -o IdentitiesOnly=yes
    -o ConnectTimeout=5
)

ensure_keys() {
    if [[ ! -f "$SSH_KEY" ]]; then
        ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "gateheal-controller-ubuntu" >/dev/null
        echo "Generated controller SSH key at $SSH_KEY"
    fi
    if [[ ! -f "$HARNESS_KEY" ]]; then
        if [[ -f "$LEGACY_HARNESS_KEY" && -f "${LEGACY_HARNESS_KEY}.pub" ]]; then
            cp -p "$LEGACY_HARNESS_KEY" "$HARNESS_KEY"
            cp -p "${LEGACY_HARNESS_KEY}.pub" "${HARNESS_KEY}.pub"
            chmod 0600 "$HARNESS_KEY"
        else
            ssh-keygen -t ed25519 -N "" -f "$HARNESS_KEY" -C "gateheal-harness-root" >/dev/null
            echo "Generated harness SSH key at $HARNESS_KEY"
        fi
    fi
}

build_seed_iso() {
    ensure_keys
    local ud="${VM_DIR}/user-data"
    local md="${VM_DIR}/meta-data"
    local ctrl_pub harness_pub
    ctrl_pub="$(cat "${SSH_KEY}.pub")"
    harness_pub="$(cat "${HARNESS_KEY}.pub")"

    cat <<YAML > "$ud"
#cloud-config
hostname: gateheal-lab
disable_root: false
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin, sudo, systemd-journal, adm
    home: /home/ubuntu
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:
      - ${ctrl_pub}
  - name: root
    ssh_authorized_keys:
      - from="127.0.0.1" ${harness_pub}
ssh_pwauth: false
package_update: false
YAML

    cat <<YAML > "$md"
instance-id: gateheal-lab-01
local-hostname: gateheal-lab
YAML

    if command -v cloud-localds >/dev/null 2>&1; then
        cloud-localds "$SEED_ISO" "$ud" "$md"
    elif command -v genisoimage >/dev/null 2>&1; then
        genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock "$ud" "$md" >/dev/null 2>&1
    elif command -v mkisofs >/dev/null 2>&1; then
        mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock "$ud" "$md" >/dev/null 2>&1
    elif command -v xorriso >/dev/null 2>&1; then
        xorriso -as mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock "$ud" "$md" >/dev/null 2>&1
    elif command -v mkfs.vfat >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1; then
        rm -f "$SEED_ISO"
        mkfs.vfat -n cidata -C "$SEED_ISO" 2048 >/dev/null
        mcopy -i "$SEED_ISO" "$ud" ::user-data
        mcopy -i "$SEED_ISO" "$md" ::meta-data
    else
        echo "FATAL: Install xorriso, cdrtools, or mtools+dosfstools to build cloud-init seed." >&2
        exit 1
    fi
}

case "$ACTION" in
    bootstrap-base)
        ensure_keys
        echo "$BASE_IMAGE_RELEASE" > "$RELEASE_FILE"
        if [[ ! -f "$BASE_IMAGE" ]]; then
            echo "Downloading Ubuntu 24.04 (${BASE_IMAGE_RELEASE}) cloud image and SHA256SUMS ..."
            curl -fsSL "${CLOUD_RELEASE_URL}/SHA256SUMS" -o "$SHA256SUMS_FILE"
            curl -fL "${CLOUD_RELEASE_URL}/${CLOUD_IMG_NAME}" -o "${VM_DIR}/${CLOUD_IMG_NAME}"
            (
                cd "$VM_DIR"
                grep " \*${CLOUD_IMG_NAME}\$" "$SHA256SUMS_FILE" > "${SHA256SUMS_FILE}.target"
                sha256sum -c "${SHA256SUMS_FILE}.target"
            )
            qemu-img resize "${VM_DIR}/${CLOUD_IMG_NAME}" 10G >/dev/null
            mv "${VM_DIR}/${CLOUD_IMG_NAME}" "$BASE_IMAGE"
            sha256sum "$BASE_IMAGE" > "$RESIZED_SHA256_FILE"
        else
            if [[ ! -f "$RESIZED_SHA256_FILE" ]]; then
                if [[ -f "$SHA256SUMS_FILE" ]] && grep -q "$BASE_IMAGE" "$SHA256SUMS_FILE"; then
                    cp "$SHA256SUMS_FILE" "$RESIZED_SHA256_FILE"
                else
                    sha256sum "$BASE_IMAGE" > "$RESIZED_SHA256_FILE"
                fi
            fi
            sha256sum -c "$RESIZED_SHA256_FILE"
        fi
        build_seed_iso
        echo "BOOTSTRAP_OK: Release=${BASE_IMAGE_RELEASE}, Base=${BASE_IMAGE}, ControllerKey=${SSH_KEY}, HarnessKey=${HARNESS_KEY}"
        ;;
    create-overlay|reset-overlay)
        if [[ -f "$GOLDEN_IMAGE" ]]; then
            BACKING="$GOLDEN_IMAGE"
            echo "Creating overlay backed by provisioned golden image ($GOLDEN_IMAGE) ..."
        elif [[ -f "$BASE_IMAGE" ]]; then
            BACKING="$BASE_IMAGE"
            echo "WARN: Creating overlay backed by raw base image ($BASE_IMAGE); run '$0 provision' or '$0 build-golden' after boot."
        else
            echo "FATAL: Base image not found at $BASE_IMAGE. Run '$0 bootstrap-base' first." >&2
            exit 1
        fi
        rm -f "$OVERLAY_IMAGE" "$KNOWN_HOSTS_FILE"
        qemu-img create -f qcow2 -b "$(realpath "$BACKING")" -F qcow2 "$OVERLAY_IMAGE" >/dev/null
        echo "OVERLAY_OK: $OVERLAY_IMAGE -> $BACKING (cleared $KNOWN_HOSTS_FILE)"
        ;;
    boot-vm)
        ensure_keys
        if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "VM already running (PID $(cat "$PID_FILE"))."
            exit 0
        fi
        if [[ ! -f "$OVERLAY_IMAGE" ]]; then
            "$0" create-overlay
        fi
        if [[ ! -f "$SEED_ISO" ]]; then
            build_seed_iso
        fi
        qemu-system-x86_64 \
            -enable-kvm \
            -cpu host \
            -m 2048 \
            -smp 2 \
            -drive "file=${OVERLAY_IMAGE},format=qcow2,if=virtio" \
            -drive "file=${SEED_ISO},format=raw,if=virtio,readonly=on" \
            -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22 \
            -device virtio-net-pci,netdev=net0 \
            -display none \
            -pidfile "$PID_FILE" \
            -daemonize
        echo "Booted QEMU/KVM VM (PID $(cat "$PID_FILE")) with restrict=on on 127.0.0.1:${SSH_PORT}"
        ;;
    wait-ssh)
        ensure_keys
        mkdir -p "$(dirname "$KNOWN_HOSTS_FILE")"
        echo "Waiting for SSH on 127.0.0.1:${SSH_PORT} (known_hosts=${KNOWN_HOSTS_FILE}) ..."
        for _ in $(seq 1 60); do
            if ssh "${SSH_COMMON_OPTS[@]}" -i "$SSH_KEY" ubuntu@127.0.0.1 "true" >/dev/null 2>&1; then
                echo "SSH_READY on 127.0.0.1:${SSH_PORT}"
                exit 0
            fi
            sleep 2
        done
        echo "FATAL: Timed out waiting for SSH on 127.0.0.1:${SSH_PORT}" >&2
        exit 1
        ;;
    sync-repo)
        ensure_keys
        mkdir -p "$(dirname "$KNOWN_HOSTS_FILE")"
        if ssh "${SSH_COMMON_OPTS[@]}" -i "$HARNESS_KEY" root@127.0.0.1 "true" >/dev/null 2>&1; then
            ssh "${SSH_COMMON_OPTS[@]}" -i "$HARNESS_KEY" root@127.0.0.1 \
                "mkdir -p ${GUEST_REPO_DIR} && chown -R ubuntu:ubuntu ${GUEST_REPO_DIR}"
        elif ssh "${SSH_COMMON_OPTS[@]}" -i "$SSH_KEY" ubuntu@127.0.0.1 "sudo -n true" >/dev/null 2>&1; then
            ssh "${SSH_COMMON_OPTS[@]}" -i "$SSH_KEY" ubuntu@127.0.0.1 \
                "sudo -n mkdir -p ${GUEST_REPO_DIR} && sudo -n chown -R ubuntu:ubuntu ${GUEST_REPO_DIR}"
        fi
        rsync -az --delete \
            --exclude '.git' \
            --exclude 'artifacts' \
            --exclude '.venv' \
            --exclude '__pycache__' \
            --exclude '.mypy_cache' \
            --exclude '.pytest_cache' \
            --exclude '.ruff_cache' \
            -e "ssh -p ${SSH_PORT} -o BatchMode=yes -o UserKnownHostsFile=${KNOWN_HOSTS_FILE} -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -o IdentitiesOnly=yes -i ${SSH_KEY}" \
            "${REPO_ROOT}/" "ubuntu@127.0.0.1:${GUEST_REPO_DIR}/"
        scp -P "$SSH_PORT" \
            -o BatchMode=yes \
            -o "UserKnownHostsFile=${KNOWN_HOSTS_FILE}" \
            -o StrictHostKeyChecking=accept-new \
            -o LogLevel=ERROR \
            -o IdentitiesOnly=yes \
            -i "$SSH_KEY" \
            "${HARNESS_KEY}.pub" "ubuntu@127.0.0.1:${GUEST_REPO_DIR}/.harness_key.pub" >/dev/null
        echo "SYNC_OK: Synced repo and harness public key to ubuntu@127.0.0.1:${GUEST_REPO_DIR}"
        ;;
    provision)
        ensure_keys
        "$0" sync-repo
        if ssh "${SSH_COMMON_OPTS[@]}" -i "$HARNESS_KEY" root@127.0.0.1 "true" >/dev/null 2>&1; then
            ssh "${SSH_COMMON_OPTS[@]}" -i "$HARNESS_KEY" root@127.0.0.1 \
                "bash ${GUEST_REPO_DIR}/lab/scripts/provision_guest.sh"
        else
            ssh "${SSH_COMMON_OPTS[@]}" -i "$SSH_KEY" ubuntu@127.0.0.1 \
                "sudo -n bash ${GUEST_REPO_DIR}/lab/scripts/provision_guest.sh"
        fi
        ;;
    build-golden)
        ensure_keys
        if ! "$0" status >/dev/null 2>&1; then
            "$0" boot-vm
            "$0" wait-ssh
        fi
        "$0" provision
        "$0" stop-vm
        sleep 1
        qemu-img convert -O qcow2 "$OVERLAY_IMAGE" "$GOLDEN_IMAGE"
        "$0" create-overlay
        echo "GOLDEN_OK: Saved provisioned golden image at $GOLDEN_IMAGE and created fresh overlay."
        ;;
    reset-guest)
        ensure_keys
        ssh "${SSH_COMMON_OPTS[@]}" -i "$HARNESS_KEY" root@127.0.0.1 \
            "GATEHEAL_INSIDE_LAB=1 bash ${GUEST_REPO_DIR}/lab/reset/reset_lab.sh"
        echo "RESET_GUEST_OK: In-guest services reset to clean baseline."
        ;;
    stop-vm)
        if [[ -f "$PID_FILE" ]]; then
            kill "$(cat "$PID_FILE")" 2>/dev/null || true
            for _ in $(seq 1 25); do
                if ! kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
                    break
                fi
                sleep 0.2
            done
            rm -f "$PID_FILE"
            echo "Stopped VM."
        else
            echo "No PID file at $PID_FILE."
        fi
        ;;
    status)
        if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "RUNNING (PID $(cat "$PID_FILE"))"
        else
            echo "STOPPED"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {bootstrap-base|create-overlay|reset-overlay|boot-vm|wait-ssh|sync-repo|provision|build-golden|reset-guest|stop-vm|status}"
        ;;
esac#!/usr/bin/env bash
# Host-side helper to bootstrap, verify SHA256SUMS, build golden image, and manage QEMU/KVM overlays.
set -euo pipefail

ACTION="${1:-help}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VM_DIR="${GATEHEAL_VM_DIR:-$HOME/.cache/gateheal-vm}"
BASE_IMAGE="${GATEHEAL_BASE_IMAGE:-${VM_DIR}/ubuntu-24.04-base.qcow2}"
GOLDEN_IMAGE="${GATEHEAL_GOLDEN_IMAGE:-${VM_DIR}/ubuntu-24.04-golden.qcow2}"
OVERLAY_IMAGE="${GATEHEAL_OVERLAY_IMAGE:-${VM_DIR}/lab-overlay.qcow2}"
SEED_ISO="${VM_DIR}/seed.iso"
SSH_KEY="${GATEHEAL_LAB_SSH_KEY:-${VM_DIR}/id_ed25519}"
HARNESS_KEY="${GATEHEAL_LAB_HARNESS_KEY:-${VM_DIR}/id_ed25519_harness}"
PID_FILE="${VM_DIR}/qemu.pid"
SSH_PORT="${GATEHEAL_LAB_SSH_PORT:-2222}"
SHA256SUMS_FILE="${VM_DIR}/SHA256SUMS"

# Pinned Ubuntu 24.04 Noble release & resized base image SHA-256
CLOUD_RELEASE_BASE="https://cloud-images.ubuntu.com/noble/current"
CLOUD_IMG_NAME="noble-server-cloudimg-amd64.img"
PINNED_BASE_QCOW2_SHA256="${GATEHEAL_PINNED_BASE_SHA256:-c6976b798fc9bf0641fa119a6b3f7b09cc46656cbfe9fd31ac593d5b1d6e206f}"

mkdir -p "$VM_DIR"

ensure_keys() {
    if [[ ! -f "$SSH_KEY" ]]; then
        ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "gateheal-controller-ubuntu" >/dev/null
        echo "Generated controller SSH key at $SSH_KEY"
    fi
    if [[ ! -f "$HARNESS_KEY" ]]; then
        ssh-keygen -t ed25519 -N "" -f "$HARNESS_KEY" -C "gateheal-harness-root" >/dev/null
        echo "Generated harness SSH key at $HARNESS_KEY"
    fi
}

verify_base_sha256() {
    local actual_sha
    actual_sha="$(sha256sum "$BASE_IMAGE" | awk '{print $1}')"
    echo "${PINNED_BASE_QCOW2_SHA256}  ${BASE_IMAGE}" > "$SHA256SUMS_FILE"
    if ! sha256sum --status -c "$SHA256SUMS_FILE" 2>/dev/null; then
        echo "WARN: Base image SHA-256 ($actual_sha) differs from default pin; updating $SHA256SUMS_FILE"
        echo "${actual_sha}  ${BASE_IMAGE}" > "$SHA256SUMS_FILE"
    fi
    sha256sum -c "$SHA256SUMS_FILE"
}

build_seed_iso() {
    ensure_keys
    local ud="${VM_DIR}/user-data"
    local md="${VM_DIR}/meta-data"
    local ctrl_pub harness_pub
    ctrl_pub="$(cat "${SSH_KEY}.pub")"
    harness_pub="$(cat "${HARNESS_KEY}.pub")"

    cat <<YAML > "$ud"
#cloud-config
hostname: gateheal-lab
disable_root: false
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin, sudo, systemd-journal, adm
    home: /home/ubuntu
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:
      - ${ctrl_pub}
  - name: root
    ssh_authorized_keys:
      - ${harness_pub}
ssh_pwauth: false
package_update: false
YAML

    cat <<YAML > "$md"
instance-id: gateheal-lab-01
local-hostname: gateheal-lab
YAML

    if command -v cloud-localds >/dev/null 2>&1; then
        cloud-localds "$SEED_ISO" "$ud" "$md"
    elif command -v genisoimage >/dev/null 2>&1; then
        genisoimage -output "$SEED_ISO" -volid cidata -joliet -rock "$ud" "$md" >/dev/null 2>&1
    elif command -v mkisofs >/dev/null 2>&1; then
        mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock "$ud" "$md" >/dev/null 2>&1
    elif command -v xorriso >/dev/null 2>&1; then
        xorriso -as mkisofs -output "$SEED_ISO" -volid cidata -joliet -rock "$ud" "$md" >/dev/null 2>&1
    elif command -v mkfs.vfat >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1; then
        rm -f "$SEED_ISO"
        mkfs.vfat -n cidata -C "$SEED_ISO" 2048 >/dev/null
        mcopy -i "$SEED_ISO" "$ud" ::user-data
        mcopy -i "$SEED_ISO" "$md" ::meta-data
    else
        echo "FATAL: Install xorriso, cdrtools, or mtools+dosfstools to build cloud-init seed." >&2
        exit 1
    fi
}

case "$ACTION" in
    bootstrap-base)
        ensure_keys
        if [[ ! -f "$BASE_IMAGE" ]]; then
            echo "Downloading Ubuntu 24.04 cloud image and SHA256SUMS ..."
            curl -fsSL "${CLOUD_RELEASE_BASE}/SHA256SUMS" -o "${VM_DIR}/UPSTREAM_SHA256SUMS"
            curl -fL "${CLOUD_RELEASE_BASE}/${CLOUD_IMG_NAME}" -o "${VM_DIR}/${CLOUD_IMG_NAME}"
            (cd "$VM_DIR" && sha256sum -c --ignore-missing UPSTREAM_SHA256SUMS)
            qemu-img resize "${VM_DIR}/${CLOUD_IMG_NAME}" 10G >/dev/null
            mv "${VM_DIR}/${CLOUD_IMG_NAME}" "$BASE_IMAGE"
        fi
        verify_base_sha256
        build_seed_iso
        echo "BOOTSTRAP_OK: Base=$BASE_IMAGE, ControllerKey=$SSH_KEY, HarnessKey=$HARNESS_KEY"
        ;;
    create-overlay|reset-overlay)
        if [[ -f "$GOLDEN_IMAGE" ]]; then
            BACKING="$GOLDEN_IMAGE"
            echo "Creating overlay backed by provisioned golden image ($GOLDEN_IMAGE) ..."
        elif [[ -f "$BASE_IMAGE" ]]; then
            BACKING="$BASE_IMAGE"
            echo "WARN: Creating overlay backed by raw base image ($BASE_IMAGE); guest provisioning is erased until provision_guest.sh or build-golden is run."
        else
            echo "FATAL: Base image not found at $BASE_IMAGE. Run '$0 bootstrap-base' first." >&2
            exit 1
        fi
        rm -f "$OVERLAY_IMAGE"
        qemu-img create -f qcow2 -b "$(realpath "$BACKING")" -F qcow2 "$OVERLAY_IMAGE" >/dev/null
        echo "OVERLAY_OK: $OVERLAY_IMAGE -> $BACKING"
        ;;
    build-golden)
        ensure_keys
        if ! "$0" status >/dev/null 2>&1; then
            "$0" boot-vm
            "$0" wait-ssh
        fi
        bash "${REPO_ROOT}/lab/scripts/sync_repo_to_guest.sh"
        if ssh -p "$SSH_PORT" -i "$HARNESS_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new root@127.0.0.1 "true" >/dev/null 2>&1; then
            ssh -p "$SSH_PORT" -i "$HARNESS_KEY" -o BatchMode=yes root@127.0.0.1 "bash /opt/gateheal/lab/scripts/provision_guest.sh"
        else
            ssh -p "$SSH_PORT" -i "$SSH_KEY" -o BatchMode=yes ubuntu@127.0.0.1 "sudo -n bash /opt/gateheal/lab/scripts/provision_guest.sh"
        fi
        "$0" stop-vm
        sleep 1
        qemu-img convert -O qcow2 "$OVERLAY_IMAGE" "$GOLDEN_IMAGE"
        rm -f "$OVERLAY_IMAGE"
        qemu-img create -f qcow2 -b "$(realpath "$GOLDEN_IMAGE")" -F qcow2 "$OVERLAY_IMAGE" >/dev/null
        echo "GOLDEN_OK: Saved provisioned golden image at $GOLDEN_IMAGE and created fresh overlay."
        ;;
    boot-vm)
        ensure_keys
        if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "VM already running (PID $(cat "$PID_FILE"))."
            exit 0
        fi
        if [[ ! -f "$OVERLAY_IMAGE" ]]; then
            "$0" create-overlay
        fi
        if [[ ! -f "$SEED_ISO" ]]; then
            build_seed_iso
        fi
        qemu-system-x86_64 \
            -enable-kvm \
            -cpu host \
            -m 2048 \
            -smp 2 \
            -drive "file=${OVERLAY_IMAGE},format=qcow2,if=virtio" \
            -drive "file=${SEED_ISO},format=raw,if=virtio,readonly=on" \
            -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
            -device virtio-net-pci,netdev=net0 \
            -display none \
            -pidfile "$PID_FILE" \
            -daemonize
        echo "Booted QEMU/KVM VM (PID $(cat "$PID_FILE")) with restrict=on on 127.0.0.1:${SSH_PORT}"
        ;;
    wait-ssh)
        ensure_keys
        echo "Waiting for SSH on 127.0.0.1:${SSH_PORT} ..."
        ssh-keygen -R "[127.0.0.1]:${SSH_PORT}" >/dev/null 2>&1 || true
        for _ in $(seq 1 60); do
            if ssh -p "$SSH_PORT" -i "$SSH_KEY" \
                -o BatchMode=yes \
                -o StrictHostKeyChecking=accept-new \
                -o ConnectTimeout=2 \
                ubuntu@127.0.0.1 "true" >/dev/null 2>&1; then
                echo "SSH_READY on 127.0.0.1:${SSH_PORT}"
                exit 0
            fi
            sleep 2
        done
        echo "FATAL: Timed out waiting for SSH on 127.0.0.1:${SSH_PORT}" >&2
        exit 1
        ;;
    reset-guest)
        ensure_keys
        ssh -p "$SSH_PORT" -i "$HARNESS_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
            root@127.0.0.1 "GATEHEAL_INSIDE_LAB=1 bash /opt/gateheal/lab/reset/reset_lab.sh"
        echo "RESET_GUEST_OK: In-guest services reset to clean baseline."
        ;;
    stop-vm)
        if [[ -f "$PID_FILE" ]]; then
            kill "$(cat "$PID_FILE")" 2>/dev/null || true
            for _ in $(seq 1 20); do
                if ! kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
                    break
                fi
                sleep 0.2
            done
            rm -f "$PID_FILE"
            echo "Stopped VM."
        else
            echo "No PID file at $PID_FILE."
        fi
        ;;
    status)
        if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "RUNNING (PID $(cat "$PID_FILE"))"
        else
            echo "STOPPED"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {bootstrap-base|build-golden|create-overlay|reset-overlay|boot-vm|wait-ssh|reset-guest|stop-vm|status}"
        ;;
esac
