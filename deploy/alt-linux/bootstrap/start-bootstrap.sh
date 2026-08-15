#!/bin/bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        if sudo -v; then
            exec sudo -- bash "$0"
        fi
        echo "sudo is unavailable for the current user; falling back to su." >&2
    fi

    if command -v su >/dev/null 2>&1; then
        quoted_launcher=$(printf '%q' "$0")
        echo "requesting the root password through su." >&2
        exec su -c "exec bash ${quoted_launcher}"
    fi

    echo "Run this launcher as root; neither sudo nor su is available." >&2
    exit 1
fi

DEPLOY_HOST=${ALT_DEPLOY_HOST:-192.168.100.17}
DEPLOY_URL="http://${DEPLOY_HOST}:8087"
BOOTSTRAP_URL="${DEPLOY_URL}/bootstrap/bootstrap.sh"
HOSTNAME_RE='^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$'
ASSIGNED_DOMAIN_USER_RE='^[a-z0-9][a-z0-9._-]{0,62}(@sosnadmin\.local)?$'

normalize_value() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | xargs
}

confirm_hostname() {
    local candidate=$1 answer
    read -r -p "Apply hostname ${candidate}? [y/N]: " answer
    [[ ${answer,,} == y ]]
}

current_hostname_raw=$(hostnamectl --static 2>/dev/null || true)
current_hostname=$(normalize_value "${current_hostname_raw}")
confirmed_hostname=''

if [[ "${current_hostname}" =~ ${HOSTNAME_RE} ]]; then
    echo "Current hostname: ${current_hostname}"
    if ! confirm_hostname "${current_hostname}"; then
        echo "Hostname confirmation was cancelled." >&2
        exit 1
    fi
    confirmed_hostname=${current_hostname}
else
    echo "Current hostname does not match the workstation naming scheme." >&2
    echo "Hostname must match: alt-a1-pc3" >&2
    while :; do
        read -r -p "Final hostname: " candidate_hostname
        candidate_hostname=$(normalize_value "${candidate_hostname}")
        if [[ ! "${candidate_hostname}" =~ ${HOSTNAME_RE} ]]; then
            echo "Hostname must match: alt-a1-pc3" >&2
            continue
        fi
        if ! confirm_hostname "${candidate_hostname}"; then
            echo "Hostname confirmation was cancelled." >&2
            exit 1
        fi
        confirmed_hostname=${candidate_hostname}
        break
    done
fi

if [[ "${current_hostname_raw}" != "${confirmed_hostname}" ]]; then
    hostnamectl set-hostname "${confirmed_hostname}"
fi

hostname_after=$(hostnamectl --static 2>/dev/null || true)
if [[ "${hostname_after}" != "${confirmed_hostname}" ]]; then
    echo "Hostname read-back verification failed." >&2
    exit 1
fi
export ALT_FINAL_HOSTNAME="${confirmed_hostname}"

assigned_domain_user=${ALT_ASSIGNED_DOMAIN_USER:-}
if [[ -z "${assigned_domain_user}" ]]; then
    read -r -p "AD user (login or UPN): " assigned_domain_user
fi

assigned_domain_user=$(normalize_value "${assigned_domain_user}")
if [[ ! "${assigned_domain_user}" =~ ${ASSIGNED_DOMAIN_USER_RE} ]]; then
    echo "AD user must be a valid sosnadmin.local login or UPN." >&2
    exit 1
fi
if [[ "${assigned_domain_user}" != *@* ]]; then
    assigned_domain_user="${assigned_domain_user}@sosnadmin.local"
fi
export ALT_ASSIGNED_DOMAIN_USER="${assigned_domain_user}"

temporary_dir=$(mktemp -d -t alt-bootstrap.XXXXXXXX)
chmod 0700 "${temporary_dir}"
bootstrap_path="${temporary_dir}/bootstrap.sh"

cleanup() {
    rm -rf -- "${temporary_dir}"
}
trap cleanup EXIT

curl --noproxy '*' -fsS \
    --connect-timeout 5 \
    --max-time 30 \
    "${BOOTSTRAP_URL}" \
    -o "${bootstrap_path}"

if [[ ! -s "${bootstrap_path}" ]]; then
    echo "Downloaded bootstrap is empty." >&2
    exit 1
fi

bash -n "${bootstrap_path}"
exec bash "${bootstrap_path}"
