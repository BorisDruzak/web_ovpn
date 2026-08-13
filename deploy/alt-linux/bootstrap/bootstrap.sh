#!/bin/bash

set -Eeuo pipefail

if [[ $(id -u) -ne 0 ]]; then
    echo "Run as root" >&2
    exit 6
fi

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

exec > >(tee -a /var/log/alt-bootstrap.log) 2>&1

DEPLOY_HOST="${ALT_DEPLOY_HOST:-192.168.100.17}"
DEPLOY_URL="http://${DEPLOY_HOST}:8087"
REGISTER_HELPER_URL="${DEPLOY_URL}/bootstrap/alt-bootstrap-register"
REGISTER_HELPER_TARGET="/usr/local/sbin/alt-bootstrap-register"
ANSIBLE_AUTHORIZED_KEY_SHA256="${ALT_ANSIBLE_AUTHORIZED_KEY_SHA256:-SHA256:60+ctiToYXkwE+H5LfV2hD/MZqRFiato7Q1RcQRlTmM}"

ANSIBLE_USER="ansible"
LOCAL_ADMIN="osn-admin"

MARKER="/var/lib/alt-bootstrap-completed"
REGISTER_MARKER="/var/lib/alt-bootstrap-registered"
STATE_DIR="/var/lib/alt-bootstrap"
SELF_TARGET="/usr/local/sbin/alt-bootstrap"
RETRY_SERVICE="/etc/systemd/system/alt-bootstrap-register-retry.service"
RETRY_TIMER="/etc/systemd/system/alt-bootstrap-register-retry.timer"

write_state() {
    install -d -o root -g root -m 0700 "${STATE_DIR}"
    printf '%s\n' "$1" > "${STATE_DIR}/state"
    chmod 0600 "${STATE_DIR}/state"
}

install_deferred_registration_retry() {
    local temporary
    if [[ "$0" != "${SELF_TARGET}" ]]; then
        install -o root -g root -m 0700 "$0" "${SELF_TARGET}"
    fi
    temporary=$(mktemp)
    cat > "${temporary}" <<'UNIT'
[Unit]
Description=Retry ALT bootstrap registration
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/alt-bootstrap
UNIT
    install -o root -g root -m 0644 "${temporary}" "${RETRY_SERVICE}"
    cat > "${temporary}" <<'UNIT'
[Unit]
Description=Schedule ALT bootstrap registration retry
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true
[Install]
WantedBy=timers.target
UNIT
    install -o root -g root -m 0644 "${temporary}" "${RETRY_TIMER}"
    rm -f "${temporary}"
    systemctl daemon-reload
    systemctl enable --now alt-bootstrap-register-retry.timer
}

network_ready() {
    ip route show default | grep -q . \
        && ip -4 -o addr show scope global | grep -q .
}

recover_existing_networkmanager_profile() {
    local profile
    command -v nmcli >/dev/null 2>&1 || return 1
    nmcli networking on || true
    while IFS= read -r profile; do
        [[ -z "${profile}" ]] && continue
        nmcli connection up id "${profile}" || true
        network_ready && return 0
    done < <(nmcli -t -f NAME connection show --active)
    return 1
}

require_network() {
    network_ready && return 0
    echo "Default route or IPv4 is unavailable; reactivating existing NetworkManager profile"
    recover_existing_networkmanager_profile || true
    if ! network_ready; then
        echo "ERROR: default route or IPv4 is unavailable after safe recovery" >&2
        return 1
    fi
}

validate_alt_workstation() {
    local release

    release=$(cat /etc/altlinux-release 2>/dev/null || true)
    if [[ ! "${release}" =~ ^ALT\ Workstation\ K\ 11\. ]]; then
        echo "ERROR: unsupported operating system: ${release:-unknown}" >&2
        return 1
    fi
}

install_authorized_key() {
    local temporary
    local key_count
    local actual_fingerprint

    temporary=$(mktemp)

    if ! curl \
        --fail \
        --silent \
        --show-error \
        --connect-timeout 5 \
        --max-time 15 \
        "${DEPLOY_URL}/bootstrap/ansible_authorized_keys" \
        -o "${temporary}"; then
        rm -f "${temporary}"
        return 1
    fi

    key_count=$(awk 'NF && $1 !~ /^#/ { count += 1 } END { print count + 0 }' "${temporary}")
    actual_fingerprint=$(ssh-keygen -lf "${temporary}" -E sha256 | awk 'NR == 1 { print $2 }')

    if [[ "${key_count}" -ne 1 ]] \
        || [[ -z "${actual_fingerprint}" ]] \
        || [[ "${actual_fingerprint}" != "${ANSIBLE_AUTHORIZED_KEY_SHA256}" ]]; then
        echo "ERROR: controller authorized key fingerprint mismatch" >&2
        rm -f "${temporary}"
        return 1
    fi

    install \
        -o "${ANSIBLE_USER}" \
        -g "${ANSIBLE_USER}" \
        -m 0600 \
        "${temporary}" \
        "/home/${ANSIBLE_USER}/.ssh/authorized_keys"

    rm -f "${temporary}"
}

install_registration_helper() {
    local temporary
    temporary=$(mktemp)

    if ! curl \
        --fail \
        --silent \
        --show-error \
        --connect-timeout 5 \
        --max-time 15 \
        "${REGISTER_HELPER_URL}" \
        -o "${temporary}"; then
        rm -f "${temporary}"
        return 1
    fi

    if [[ ! -s "${temporary}" ]] \
        || ! bash -n "${temporary}"; then
        rm -f "${temporary}"
        return 1
    fi

    if ! install \
        -o root \
        -g root \
        -m 0755 \
        "${temporary}" \
        "${REGISTER_HELPER_TARGET}"; then
        rm -f "${temporary}"
        return 1
    fi

    rm -f "${temporary}"
}

register_machine() {
    echo "Registering machine on deployment server..."

    for attempt in $(seq 1 20); do
        if ! install_registration_helper; then
            echo "Registration attempt ${attempt}: helper installation failed"
            sleep 3
            continue
        fi

        if "${REGISTER_HELPER_TARGET}"; then
            touch "${REGISTER_MARKER}"
            echo "Machine registration completed"
            return 0
        fi

        echo "Registration attempt ${attempt} failed"
        sleep 3
    done

    echo "ERROR: machine registration failed"
    return 1
}

echo "=== Bootstrap started: $(date) ==="

validate_alt_workstation

if ! id "${LOCAL_ADMIN}" >/dev/null 2>&1; then
    echo "ERROR: required local administrator ${LOCAL_ADMIN} is missing" >&2
    exit 1
fi

usermod -aG wheel "${LOCAL_ADMIN}"

require_network

if [[ -f "${MARKER}" ]]; then
    echo "Bootstrap marker exists; reconciling technical access before registration"
fi

echo "Installing bootstrap dependencies..."

apt-get update

apt-get install -y \
    python3 \
    openssh-server \
    sudo \
    curl

echo "Creating Ansible user..."

if ! id "${ANSIBLE_USER}" >/dev/null 2>&1; then
    useradd \
        -m \
        -s /bin/bash \
        "${ANSIBLE_USER}"
fi

usermod -aG wheel "${ANSIBLE_USER}"

install \
    -d \
    -o "${ANSIBLE_USER}" \
    -g "${ANSIBLE_USER}" \
    -m 0700 \
    "/home/${ANSIBLE_USER}/.ssh"

if ! install_authorized_key; then
    install_deferred_registration_retry
    write_state "controller_unavailable"
    echo "Controller is unavailable; technical registration retry is scheduled" >&2
    exit 0
fi

temporary_sudoers=$(mktemp /etc/sudoers.d/.90-ansible.XXXXXXXX)
printf '%s ALL=(ALL:ALL) NOPASSWD: ALL\n' "${ANSIBLE_USER}" > "${temporary_sudoers}"
chmod 0440 "${temporary_sudoers}"
visudo -cf "${temporary_sudoers}"
install -o root -g root -m 0440 \
    "${temporary_sudoers}" \
    "/etc/sudoers.d/90-${ANSIBLE_USER}"
rm -f "${temporary_sudoers}"

if ! runuser -u "${ANSIBLE_USER}" -- sudo -n true; then
    echo "ERROR: ansible passwordless sudo validation failed" >&2
    exit 1
fi

systemctl enable --now sshd

# Base bootstrap is complete before registration, so a repeated run retries
# registration only instead of reinstalling packages.
touch "${MARKER}"

if register_machine; then
    systemctl disable --now alt-bootstrap-register-retry.timer || true
    write_state "registered"
else
    install_deferred_registration_retry
    write_state "registration_deferred"
fi

echo "=== Bootstrap completed: $(date) ==="
