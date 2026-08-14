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
ASSIGNED_DOMAIN_USER_RE='^[a-z0-9][a-z0-9._-]{0,62}(@sosnadmin\\.local)?$'

assigned_domain_user=${ALT_ASSIGNED_DOMAIN_USER:-}
if [[ -z "${assigned_domain_user}" ]]; then
    read -r -p "AD user (login or UPN): " assigned_domain_user
fi

assigned_domain_user=$(printf '%s' "${assigned_domain_user}" | tr '[:upper:]' '[:lower:]' | xargs)
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
