#!/bin/bash
set -Eeuo pipefail

REQUIRED_COMMANDS=(
    python3
    ansible-playbook
    ansible-vault
    systemd-run
    install
    cp
    ssh
    ssh-keyscan
    mkpasswd
)

for command_name in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Missing required command: ${command_name}" >&2
        exit 1
    fi
done

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
fi

REPO_ROOT=$(
    cd "$(dirname "${BASH_SOURCE[0]}")/../.."
    pwd
)
ALT_ROOT="${REPO_ROOT}/deploy/alt-linux"

if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
    PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
else
    PYTHON_BIN=python3
fi

command -v ansible-playbook >/dev/null 2>&1 || {
    echo "ansible-playbook is not installed" >&2
    exit 1
}

id altserver >/dev/null 2>&1 || {
    echo "User altserver does not exist" >&2
    exit 1
}

echo "Installing ALT deployment control package"

install -d -o root -g root -m 0755 \
    /opt/alt-deploy-control

rm -rf /opt/alt-deploy-control/alt_deploy

cp -a \
    "${ALT_ROOT}/control/alt_deploy" \
    /opt/alt-deploy-control/alt_deploy

chown -R root:root /opt/alt-deploy-control
find /opt/alt-deploy-control -type d -exec chmod 0755 {} +
find /opt/alt-deploy-control -type f -exec chmod 0644 {} +

install -o root -g root -m 0755 \
    "${ALT_ROOT}/control/workstationctl" \
    /usr/local/sbin/workstationctl

install -d -o root -g root -m 0755 \
    /usr/local/libexec

install -o root -g root -m 0755 \
    "${ALT_ROOT}/control/alt-provision-worker" \
    /usr/local/libexec/alt-provision-worker

echo "Preparing private controller state"

install -d -o altserver -g altserver -m 0700 \
    /var/lib/alt-deploy \
    /var/lib/alt-deploy/jobs \
    /var/lib/alt-deploy/assignments \
    /srv/alt-deploy/registration

echo "Installing Ansible project"

install -d -o altserver -g altserver -m 0750 \
    /home/altserver/ansible \
    /home/altserver/ansible/playbooks \
    /home/altserver/ansible/roles \
    /home/altserver/ansible/group_vars

install -o altserver -g altserver -m 0644 \
    "${ALT_ROOT}/ansible/ansible.cfg" \
    /home/altserver/ansible/ansible.cfg

install -o altserver -g altserver -m 0644 \
    "${ALT_ROOT}/ansible/group_vars/all.yml" \
    /home/altserver/ansible/group_vars/all.yml

cp -a "${ALT_ROOT}/ansible/playbooks/." /home/altserver/ansible/playbooks/

cp -a "${ALT_ROOT}/ansible/roles/." /home/altserver/ansible/roles/

chown -R altserver:altserver \
    /home/altserver/ansible/playbooks \
    /home/altserver/ansible/roles

find /home/altserver/ansible/playbooks \
    /home/altserver/ansible/roles \
    -type d -exec chmod 0750 {} +

find /home/altserver/ansible/playbooks \
    /home/altserver/ansible/roles \
    -type f -exec chmod 0640 {} +

echo "Installing pending-registration processor"

install -d -o root -g root -m 0755 \
    /opt/alt-deploy-api

install -o root -g root -m 0755 \
    "${ALT_ROOT}/api/process_pending.py" \
    /opt/alt-deploy-api/process_pending.py

echo "Running verification"

python3 -m py_compile \
    /opt/alt-deploy-control/alt_deploy/*.py \
    /opt/alt-deploy-api/process_pending.py

bash -n "${ALT_ROOT}/install-control-plane.sh"
bash -n "${ALT_ROOT}/bootstrap/bootstrap.sh"

cd "${REPO_ROOT}"
"${PYTHON_BIN}" -m pytest -q tests/alt_linux

sudo -u altserver env \
    ANSIBLE_CONFIG=/home/altserver/ansible/ansible.cfg \
    ansible-playbook --syntax-check \
    /home/altserver/ansible/playbooks/01-preflight.yml

sudo -u altserver env \
    ANSIBLE_CONFIG=/home/altserver/ansible/ansible.cfg \
    ansible-playbook --syntax-check \
    /home/altserver/ansible/playbooks/02-provision-account.yml

echo "Restarting pending processor path unit"

systemctl restart alt-deploy-process.path

echo "ALT deployment control plane installed successfully"
