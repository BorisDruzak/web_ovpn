#!/usr/bin/env bash
# Collect a complete Yandex Browser profile without preserving SSH passwords.
set -Eeuo pipefail
umask 077

storage_root=${YANDEX_MIGRATION_ROOT:-/var/lib/alt-deploy/migrations/yandex}
known_hosts=${YANDEX_MIGRATION_KNOWN_HOSTS:-/home/altserver/.ssh/known_hosts_yandex_migration}
runtime_dir=
control_path=
remote=

usage() {
    echo "Usage: $0 --host HOST --user USER" >&2
}

valid_host() {
    [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]]
}

valid_user() {
    [[ $1 =~ ^[A-Za-z0-9._@-]{1,128}$ ]]
}

cleanup() {
    if [[ -n ${remote} && -n ${control_path} ]]; then
        ssh -o "ControlPath=${control_path}" -O exit "${remote}" >/dev/null 2>&1 || true
    fi
    [[ -n ${runtime_dir} ]] && rm -rf -- "${runtime_dir}"
}
trap cleanup EXIT

host=
source_user=
while (( $# > 0 )); do
    case $1 in
        --host) host=${2:-}; shift 2 ;;
        --user) source_user=${2:-}; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done

if [[ -z ${host} ]]; then read -r -p 'Source host or IP: ' host; fi
if [[ -z ${source_user} ]]; then read -r -p 'Source user: ' source_user; fi
valid_host "${host}" || { echo 'Invalid source host.' >&2; exit 2; }
valid_user "${source_user}" || { echo 'Invalid source user.' >&2; exit 2; }

command -v ssh >/dev/null || { echo 'ssh is required.' >&2; exit 1; }
command -v tar >/dev/null || { echo 'tar is required.' >&2; exit 1; }
command -v zstd >/dev/null || { echo 'zstd is required.' >&2; exit 1; }
command -v sha256sum >/dev/null || { echo 'sha256sum is required.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is required.' >&2; exit 1; }

install -d -m 0700 "${storage_root}"
install -d -m 0700 "$(dirname "${known_hosts}")"
touch "${known_hosts}"
chmod 0600 "${known_hosts}"
runtime_dir=$(mktemp -d "${TMPDIR:-/tmp}/yandex-profile.XXXXXX")
control_path="${runtime_dir}/control"
remote="${source_user}@${host}"
ssh_options=(
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="${known_hosts}"
    -o ControlMaster=auto
    -o ControlPersist=600
    -o ControlPath="${control_path}"
)

echo "Connecting to ${remote}. SSH may ask for the source password once."
ssh "${ssh_options[@]}" -MNf "${remote}"

home=$(ssh "${ssh_options[@]}" "${remote}" 'printf %s "$HOME"')
[[ ${home} == /home/* && ${home} != */..* ]] || { echo 'Source home is unsafe.' >&2; exit 1; }
ssh "${ssh_options[@]}" "${remote}" 'test -d "$HOME/.config/yandex-browser"' || {
    echo 'Yandex Browser profile is absent on source.' >&2
    exit 1
}

while ssh "${ssh_options[@]}" "${remote}" \
    'pgrep -u "$(id -u)" -f "(^|/)(yandex-browser|yandex_browser)( |$)" >/dev/null'; do
    echo 'Browser is still running. Close it normally to continue (Ctrl-C cancels).'
    sleep 2
done

migration_id="migration-$(python3 -c 'import uuid; print(uuid.uuid4())')"
staging=$(mktemp -d "${storage_root}/.incoming.XXXXXX")
final_dir="${storage_root}/${migration_id}"
trap '[[ -n ${staging:-} && -d ${staging} ]] && rm -rf -- "${staging}"; cleanup' EXIT

echo 'Copying the complete Yandex Browser profile. This can take several minutes.'
# The profile is intentionally complete; only Chromium runtime socket/lock files are excluded.
# The remote command deliberately executes: tar -C "$home/.config" ...
ssh "${ssh_options[@]}" "${remote}" \
    "tar -C \"$home/.config\" --exclude='yandex-browser/SingletonLock' --exclude='yandex-browser/SingletonSocket' --exclude='yandex-browser/SingletonCookie' -cf - yandex-browser" \
    | zstd -T0 -q -o "${staging}/profile.tar.zst"

sha256sum "${staging}/profile.tar.zst" > "${staging}/SHA256SUMS"
(cd "${staging}" && sha256sum -c SHA256SUMS >/dev/null)
source_version=$(ssh "${ssh_options[@]}" "${remote}" 'rpm -q --qf "%{EVR}" yandex-browser-stable 2>/dev/null || true')
SOURCE_HOST="${host}" SOURCE_USER="${source_user}" SOURCE_HOME="${home}" \
SOURCE_VERSION="${source_version}" MIGRATION_ID="${migration_id}" python3 - <<'PY' > "${staging}/manifest.json"
import json
import os
from datetime import datetime, timezone

print(json.dumps({
    "schema_version": 1,
    "migration_id": os.environ["MIGRATION_ID"],
    "source": {
        "host": os.environ["SOURCE_HOST"],
        "user": os.environ["SOURCE_USER"],
        "home": os.environ["SOURCE_HOME"],
        "yandex_browser_version": os.environ["SOURCE_VERSION"],
    },
    "profile": "yandex-browser",
    "created_at": datetime.now(timezone.utc).isoformat(),
}, ensure_ascii=False, indent=2))
PY
touch "${staging}/READY"
chmod 0600 "${staging}/profile.tar.zst" "${staging}/SHA256SUMS" "${staging}/manifest.json" "${staging}/READY"
mv -- "${staging}" "${final_dir}"
staging=

echo "Migration is ready: ${migration_id}"
echo "Stored at: ${final_dir}"
