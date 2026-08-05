#!/bin/bash

set -Eeuo pipefail

if [[ $(id -u) -ne 0 ]]; then
    echo "Run as root" >&2
    exit 6
fi

exec > >(tee -a /var/log/alt-bootstrap.log) 2>&1

DEPLOY_HOST="${ALT_DEPLOY_HOST:-192.168.100.17}"
DEPLOY_URL="http://${DEPLOY_HOST}:8087"
REGISTER_HELPER_URL="${DEPLOY_URL}/bootstrap/alt-bootstrap-register"
REGISTER_HELPER_TARGET="/usr/local/sbin/alt-bootstrap-register"
ANSIBLE_AUTHORIZED_KEY_SHA256="${ALT_ANSIBLE_AUTHORIZED_KEY_SHA256:-SHA256:60+ctiToYXkwE+H5LfV2hD/MZqRFiato7Q1RcQRlTmM}"

ANSIBLE_USER="ansible"

MARKER="/var/lib/alt-bootstrap-completed"
REGISTER_MARKER="/var/lib/alt-bootstrap-registered"

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

if ! ip route show default | grep -q .; then
    echo "ERROR: default route is unavailable" >&2
    exit 1
fi

if ! ip -4 -o addr show scope global | grep -q .; then
    echo "ERROR: IPv4 address is unavailable" >&2
    exit 1
fi

if [[ -f "${MARKER}" ]]; then
    echo "Bootstrap already completed"

    if [[ ! -f "${REGISTER_MARKER}" ]]; then
        register_machine
    else
        echo "Machine already registered"
    fi

    exit 0
fi

echo "Waiting for deployment server..."

NETWORK_READY=0

for attempt in $(seq 1 60); do
    if timeout 2 \
        bash -c "</dev/tcp/${DEPLOY_HOST}/8087" \
        2>/dev/null; then

        NETWORK_READY=1
        break
    fi

    sleep 2
done

if [[ "${NETWORK_READY}" -ne 1 ]]; then
    echo "ERROR: deployment server is unavailable"
    exit 1
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

install_authorized_key

cat > "/etc/sudoers.d/90-${ANSIBLE_USER}" <<SUDOEOF
${ANSIBLE_USER} ALL=(ALL:ALL) NOPASSWD: ALL
SUDOEOF

chmod 0440 \
    "/etc/sudoers.d/90-${ANSIBLE_USER}"

visudo -cf \
    "/etc/sudoers.d/90-${ANSIBLE_USER}"

if ! sudo -n -u "${ANSIBLE_USER}" true; then
    echo "ERROR: ansible passwordless sudo validation failed" >&2
    exit 1
fi

systemctl enable --now sshd

# Base bootstrap is complete before registration, so a repeated run retries
# registration only instead of reinstalling packages.
touch "${MARKER}"

register_machine

echo "=== Bootstrap completed: $(date) ==="
