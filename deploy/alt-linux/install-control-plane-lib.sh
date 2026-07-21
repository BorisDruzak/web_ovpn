#!/bin/bash

install_destination() {
    local root_prefix=$1
    local absolute_path=$2
    printf '%s%s' "${root_prefix}" "${absolute_path}"
}

require_command() {
    local command_name=$1
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Missing required command: ${command_name}" >&2
        return 1
    fi
}

require_regular_nonempty() {
    local path=$1
    if [[ ! -f "${path}" || -L "${path}" || ! -s "${path}" ]]; then
        echo "Unsafe or missing required runtime file: ${path}" >&2
        return 1
    fi
}

require_directory() {
    local path=$1
    if [[ ! -d "${path}" || -L "${path}" ]]; then
        echo "Unsafe or missing required directory: ${path}" >&2
        return 1
    fi
}

installer_python() {
    if [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
        printf '%s' "${REPO_ROOT}/.venv/bin/python"
    else
        printf '%s' python3
    fi
}

validate_source_layout() {
    require_directory "${ALT_ROOT}/control/alt_deploy"
    require_directory "${ALT_ROOT}/ansible/playbooks"
    require_directory "${ALT_ROOT}/ansible/roles"

    local required_files=(
        "${ALT_ROOT}/control/workstationctl"
        "${ALT_ROOT}/control/alt-provision-worker"
        "${ALT_ROOT}/control/alt-job-stage"
        "${ALT_ROOT}/api/register_api.py"
        "${ALT_ROOT}/api/process_pending.py"
        "${ALT_ROOT}/systemd/alt-deploy-http.service"
        "${ALT_ROOT}/systemd/alt-deploy-register.service"
        "${ALT_ROOT}/systemd/alt-deploy-process.path"
        "${ALT_ROOT}/systemd/alt-deploy-process.service"
        "${ALT_ROOT}/ansible/ansible.cfg"
        "${ALT_ROOT}/ansible/group_vars/all.yml"
        "${ALT_ROOT}/ansible/playbooks/01-preflight.yml"
        "${ALT_ROOT}/ansible/playbooks/02-provision-account.yml"
        "${ALT_ROOT}/bootstrap/bootstrap.sh"
        "${ALT_ROOT}/install-control-plane.sh"
        "${ALT_ROOT}/install-control-plane-lib.sh"
    )

    local required_file
    for required_file in "${required_files[@]}"; do
        require_regular_nonempty "${required_file}"
    done
}

run_source_cli() {
    local root_prefix=$1
    shift
    local python_bin
    python_bin=$(installer_python)

    sudo -u altserver env \
        PYTHONPATH="${ALT_ROOT}/control" \
        ALT_DEPLOY_REGISTRATION_ROOT="$(install_destination "${root_prefix}" /srv/alt-deploy/registration)" \
        ALT_DEPLOY_STATE_ROOT="$(install_destination "${root_prefix}" /var/lib/alt-deploy)" \
        ALT_DEPLOY_ANSIBLE_PROJECT="$(install_destination "${root_prefix}" /home/altserver/ansible)" \
        ALT_DEPLOY_KNOWN_HOSTS="$(install_destination "${root_prefix}" /home/altserver/.ssh/known_hosts_autoinstall)" \
        ALT_DEPLOY_PRIVATE_KEY="$(install_destination "${root_prefix}" /home/altserver/.ssh/id_ed25519)" \
        "${python_bin}" -m alt_deploy.cli --json "$@"
}

validate_active_jobs() {
    local root_prefix=$1
    local jobs_json
    local active_count

    if ! jobs_json=$(run_source_cli "${root_prefix}" jobs active); then
        echo "Unable to validate active provision jobs" >&2
        return 1
    fi

    if ! active_count=$(
        printf '%s' "${jobs_json}" | python3 -c '
import json
import sys
payload = json.load(sys.stdin)
count = payload.get("count")
jobs = payload.get("active_jobs")
if type(count) is not int or count < 0 or not isinstance(jobs, list):
    raise SystemExit(1)
if len(jobs) != count:
    raise SystemExit(1)
print(count)
'
    ); then
        echo "Active provision job response is invalid" >&2
        return 1
    fi

    if (( active_count != 0 )); then
        echo "Active provision jobs block controller installation" >&2
        return 1
    fi
}

validate_vault_and_permissions() {
    local root_prefix=$1

    if ! run_source_cli "${root_prefix}" vault check >/dev/null; then
        echo "Vault health check blocks controller installation" >&2
        return 1
    fi

    if ! run_source_cli "${root_prefix}" controller permissions >/dev/null; then
        echo "Controller permission check blocks installation" >&2
        return 1
    fi
}

validate_external_prerequisites() {
    local root_prefix=$1
    local private_key
    private_key=$(install_destination \
        "${root_prefix}" \
        /home/altserver/.ssh/id_ed25519)

    local required_files=(
        "${private_key}"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/bootstrap/ansible_authorized_keys)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata/autoinstall.scm)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata/vm-profile.scm)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata/pkg-groups.tar)"
        "$(install_destination "${root_prefix}" /srv/alt-deploy/metadata/install-scripts.tar)"
    )

    local required_file
    for required_file in "${required_files[@]}"; do
        require_regular_nonempty "${required_file}"
    done

    local key_metadata
    key_metadata=$(stat -c '%a %U %G' "${private_key}") || {
        echo "Unable to inspect SSH private key" >&2
        return 1
    }
    if [[ "${key_metadata}" != "600 altserver altserver" ]]; then
        echo "SSH private key ownership or mode is unsafe" >&2
        return 1
    fi
}

require_pending_empty() {
    local root_prefix=$1
    local pending_dir
    pending_dir=$(install_destination \
        "${root_prefix}" \
        /srv/alt-deploy/registration/pending)

    if [[ ! -d "${pending_dir}" ]]; then
        return 0
    fi

    local pending_records
    shopt -s nullglob
    pending_records=("${pending_dir}"/*.json)
    shopt -u nullglob

    if (( ${#pending_records[@]} != 0 )); then
        echo "Pending workstation registrations block controller installation" >&2
        return 1
    fi
}

run_repository_verification() {
    local python_bin
    python_bin=$(installer_python)

    python3 -m py_compile \
        "${ALT_ROOT}/control/alt_deploy"/*.py \
        "${ALT_ROOT}/api/register_api.py" \
        "${ALT_ROOT}/api/process_pending.py" \
        "${ALT_ROOT}/control/alt-job-stage"

    bash -n "${ALT_ROOT}/install-control-plane.sh"
    bash -n "${ALT_ROOT}/install-control-plane-lib.sh"
    bash -n "${ALT_ROOT}/bootstrap/bootstrap.sh"

    (
        cd "${REPO_ROOT}"
        "${python_bin}" -m pytest -q tests/alt_linux
    )
}

install_control_plane_prechecks() {
    local root_prefix=$1
    local required_commands=(
        python3
        ansible-playbook
        ansible-vault
        systemd-run
        systemctl
        sudo
        install
        cp
        ssh
        ssh-keyscan
        mkpasswd
        stat
        id
        bash
    )

    local command_name
    for command_name in "${required_commands[@]}"; do
        require_command "${command_name}"
    done

    if ! id altserver >/dev/null 2>&1; then
        echo "User altserver does not exist" >&2
        return 1
    fi

    validate_source_layout
    run_repository_verification
    validate_active_jobs "${root_prefix}"
    validate_vault_and_permissions "${root_prefix}"
    validate_external_prerequisites "${root_prefix}"
    require_pending_empty "${root_prefix}"

    if systemctl is-active --quiet alt-deploy-process.service; then
        echo "Pending-registration processor is active" >&2
        return 1
    fi
}

install_control_plane_main() {
    local root_prefix=$1
    install_control_plane_prechecks "${root_prefix}"
    echo "ALT deployment control plane prechecks passed"
}
