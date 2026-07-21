#!/bin/bash

set -Eeuo pipefail

exec > >(tee -a /var/log/alt-bootstrap.log) 2>&1

DEPLOY_HOST="192.168.100.17"
DEPLOY_URL="http://${DEPLOY_HOST}:8087"
REGISTER_HELPER_URL="${DEPLOY_URL}/bootstrap/alt-bootstrap-register"
REGISTER_HELPER_TARGET="/usr/local/sbin/alt-bootstrap-register"

ANSIBLE_USER="ansible"

MARKER="/var/lib/alt-bootstrap-completed"
REGISTER_MARKER="/var/lib/alt-bootstrap-registered"

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

curl \
    --fail \
    --silent \
    --show-error \
    "${DEPLOY_URL}/bootstrap/ansible_authorized_keys" \
    -o "/home/${ANSIBLE_USER}/.ssh/authorized_keys"

chown \
    "${ANSIBLE_USER}:${ANSIBLE_USER}" \
    "/home/${ANSIBLE_USER}/.ssh/authorized_keys"

chmod 0600 \
    "/home/${ANSIBLE_USER}/.ssh/authorized_keys"

cat > "/etc/sudoers.d/90-${ANSIBLE_USER}" <<SUDOEOF
${ANSIBLE_USER} ALL=(ALL:ALL) NOPASSWD: ALL
SUDOEOF

chmod 0440 \
    "/etc/sudoers.d/90-${ANSIBLE_USER}"

visudo -cf \
    "/etc/sudoers.d/90-${ANSIBLE_USER}"

systemctl enable --now sshd

# Base bootstrap is complete before registration, so a repeated run retries
# registration only instead of reinstalling packages.
touch "${MARKER}"

register_machine

echo "=== Bootstrap completed: $(date) ==="
