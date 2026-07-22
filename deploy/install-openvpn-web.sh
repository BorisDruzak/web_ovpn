#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${SUDO_PASSWORD:-}" ]]; then
  echo "SUDO_PASSWORD is required" >&2
  exit 2
fi

sudo_cmd() {
  printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' "$@"
}

validate_netctl_directory() {
  local path="$1" expected_metadata="$2" legacy_metadata="${3:-}" resolved metadata
  if sudo_cmd test -L "$path" || ! sudo_cmd test -d "$path"; then
    echo "unsafe netctl directory: $path" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$path")"
  metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$path")"
  if [[ "$resolved" != "$path" ]] || {
    [[ "$metadata" != "$expected_metadata" ]] &&
    { [[ -z "$legacy_metadata" ]] || [[ "$metadata" != "$legacy_metadata" ]]; }
  }; then
    echo "unexpected netctl directory metadata: $path" >&2
    exit 2
  fi
  validated_netctl_metadata="$metadata"
}

SRC="${SRC:-/tmp/openvpn-web-src}"
APP="${APP:-/opt/openvpn-web}"

if [[ ! -d "$SRC/app" ]]; then
  echo "missing source: $SRC" >&2
  exit 2
fi

if ! id openvpn-web >/dev/null 2>&1; then
  sudo_cmd useradd --system --home "$APP" --shell /usr/sbin/nologin openvpn-web
fi
sudo_cmd groupadd --system openvpn-web >/dev/null 2>&1 || true
sudo_cmd usermod -aG openvpn-web openvpn-web
sudo_cmd groupadd --system netctl >/dev/null 2>&1 || true
if ! id netctl >/dev/null 2>&1; then
  sudo_cmd useradd --system --home /var/lib/netctl --shell /usr/sbin/nologin --gid netctl netctl
fi

if ! sudo_cmd test -e /var/lib/netctl && ! sudo_cmd test -L /var/lib/netctl; then
  sudo_cmd install -d -m 0750 -o netctl -g netctl /var/lib/netctl
else
  validate_netctl_directory /var/lib/netctl netctl:netctl:750
fi
if ! sudo_cmd test -e /etc/netctl && ! sudo_cmd test -L /etc/netctl && \
   ! sudo_cmd test -e /etc/netctl/sources.d && ! sudo_cmd test -L /etc/netctl/sources.d; then
  sudo_cmd install -d -m 0750 -o root -g netctl /etc/netctl /etc/netctl/sources.d
else
  if ! sudo_cmd test -e /etc/netctl && ! sudo_cmd test -L /etc/netctl; then
    sudo_cmd install -d -m 0750 -o root -g netctl /etc/netctl
  fi
  validate_netctl_directory /etc/netctl root:netctl:750 root:root:755
  netctl_config_metadata="$validated_netctl_metadata"
  if ! sudo_cmd test -e /etc/netctl/sources.d && ! sudo_cmd test -L /etc/netctl/sources.d; then
    sudo_cmd install -d -m 0750 -o root -g netctl /etc/netctl/sources.d
  fi
  validate_netctl_directory /etc/netctl/sources.d root:netctl:750 root:root:755
  netctl_sources_metadata="$validated_netctl_metadata"

  if [[ "$netctl_config_metadata" == root:root:755 ]]; then
    sudo_cmd chown root:netctl /etc/netctl
    sudo_cmd chmod 0750 /etc/netctl
  fi
  if [[ "$netctl_sources_metadata" == root:root:755 ]]; then
    sudo_cmd chown root:netctl /etc/netctl/sources.d
    sudo_cmd chmod 0750 /etc/netctl/sources.d
  fi
  validate_netctl_directory /etc/netctl root:netctl:750
  validate_netctl_directory /etc/netctl/sources.d root:netctl:750
fi

sudo_cmd mkdir -p "$APP" /etc/openvpn-web /etc/openvpn
if ! sudo_cmd test -e /var/lib/openvpn-web; then
  sudo_cmd install -d -m 0755 -o openvpn-web -g openvpn-web /var/lib/openvpn-web
elif sudo_cmd test -L /var/lib/openvpn-web || ! sudo_cmd test -d /var/lib/openvpn-web; then
  echo "refusing unsafe /var/lib/openvpn-web metadata" >&2
  exit 2
else
  state_dir_metadata="$(sudo_cmd stat -c '%U:%G:%a' -- /var/lib/openvpn-web)"
  case "$state_dir_metadata" in
    openvpn-web:openvpn-web:755|root:openvpn-web:1770) ;;
    *)
      echo "refusing unsafe /var/lib/openvpn-web metadata" >&2
      exit 2
      ;;
  esac
fi
sudo_cmd chown -R openvpn-web:openvpn-web "$APP"
sudo_cmd rm -rf \
  "$APP/app" \
  "$APP/netctl" \
  "$APP/tests" \
  "$APP/deploy" \
  "$APP/README.md" \
  "$APP/requirements.txt" \
  "$APP/.env.example" \
  "$APP/AGENTS.md"
sudo_cmd cp -a "$SRC/." "$APP/"
sudo_cmd rm -rf "$APP/.git" "$APP/.pytest_cache"
sudo_cmd chown -R openvpn-web:openvpn-web "$APP"
# netctl-collect.service runs as the separate netctl user and must be able
# to read the application root for Python module discovery, without opening
# it to unrelated local users.
sudo_cmd chown openvpn-web:netctl "$APP"
sudo_cmd chmod 0750 "$APP"

sudo_cmd install -m 0755 "$SRC/deploy/vpnctl" /usr/local/sbin/vpnctl
sudo_cmd install -m 0755 "$SRC/deploy/vpn-policy.sh" /usr/local/sbin/vpn-policy.sh
sudo_cmd install -m 0755 "$SRC/deploy/netctl" /usr/local/sbin/netctl
sudo_cmd install -m 0755 "$SRC/deploy/generate-client-wrapper.sh" /usr/local/sbin/generate-client-wrapper
sudo_cmd mkdir -p /etc/openvpn/client-generator/output
sudo_cmd chgrp openvpn-web /etc/openvpn/client-generator/output
sudo_cmd chmod 0750 /etc/openvpn/client-generator/output
sudo_cmd find /etc/openvpn/client-generator/output -maxdepth 1 \
  \( -name '*.ovpn' -o -name '*-install-hosts-as-admin.bat' \) \
  -exec chgrp openvpn-web {} + \
  -exec chmod 0640 {} +
sudo_cmd find /etc/openvpn/server/ccd -maxdepth 1 -type f ! -name '*.backup.*' -exec chmod 0644 {} + 2>/dev/null || true
if [[ ! -f /etc/openvpn/vpnctl.env ]]; then
  sudo_cmd install -m 0640 -o root -g root "$SRC/deploy/vpnctl.env.sample" /etc/openvpn/vpnctl.env
fi

ENV_PATH=/etc/openvpn-web/openvpn-web.env
if [[ ! -f "$ENV_PATH" ]] || ! sudo_cmd grep -q '^DATABASE_URL=' "$ENV_PATH"; then
  if [[ -f "$ENV_PATH" ]]; then
    sudo_cmd cp "$ENV_PATH" "$ENV_PATH.backup.$(date +%F_%H-%M-%S)"
  fi
  SECRET="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"
  ADMIN_PASS="${ADMIN_PASSWORD:-}"
  if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(18))
PY
)"
  fi
  API_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  API_TOKEN_HASH="$(API_TOKEN="$API_TOKEN" python3 - <<'PY'
import hashlib
import os
print(hashlib.sha256(os.environ["API_TOKEN"].encode("utf-8")).hexdigest())
PY
)"
  TMP_ENV="$(sudo_cmd mktemp -p /etc/openvpn-web .openvpn-web.env.XXXXXX)"
  sudo_cmd tee "$TMP_ENV" >/dev/null <<ENV_FILE
DATABASE_URL=sqlite:////var/lib/openvpn-web/openvpn-web.sqlite
VPNCTL_PATH=/usr/local/sbin/vpnctl
VPNCTL_USE_SUDO=1
NETCTL_PATH=/usr/local/sbin/netctl
NETCTL_USE_SUDO=1
NETCTL_SUDO_USER=netctl
NETWORK_OBSERVER_ENABLED=1
APP_SECRET_KEY=$SECRET
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$ADMIN_PASS
OPENVPN_WEB_API_TOKEN_HASH=$API_TOKEN_HASH
OPENVPN_WEB_API_ACTOR=api:codex-local
OUT_DIR=/etc/openvpn/client-generator/output
SHARE_OUT_DIR=/mnt/antares_soft/vpn_config
ARCHIVE_DIR=/etc/openvpn/client-generator/archive
ROUTEROS_BACKUP_DIR=/var/backups/routeros
DOWNLOAD_TOKEN_TTL_MINUTES=15
ENV_FILE
  sudo_cmd install -m 0640 -o root -g openvpn-web "$TMP_ENV" "$ENV_PATH"
  sudo_cmd rm -f "$TMP_ENV"
else
  if ! sudo_cmd grep -q '^OPENVPN_WEB_API_TOKEN_HASH=' "$ENV_PATH"; then
    API_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
    API_TOKEN_HASH="$(API_TOKEN="$API_TOKEN" python3 - <<'PY'
import hashlib
import os
print(hashlib.sha256(os.environ["API_TOKEN"].encode("utf-8")).hexdigest())
PY
)"
    sudo_cmd cp "$ENV_PATH" "$ENV_PATH.backup.$(date +%F_%H-%M-%S)"
    TMP_ENV="$(sudo_cmd mktemp -p /etc/openvpn-web .openvpn-web.env.XXXXXX)"
    sudo_cmd sh -c 'cat "$1" > "$2"' sh "$ENV_PATH" "$TMP_ENV"
    sudo_cmd tee -a "$TMP_ENV" >/dev/null <<ENV_FILE
OPENVPN_WEB_API_TOKEN_HASH=$API_TOKEN_HASH
OPENVPN_WEB_API_ACTOR=api:codex-local
ENV_FILE
    sudo_cmd install -m 0640 -o root -g openvpn-web "$TMP_ENV" "$ENV_PATH"
    sudo_cmd rm -f "$TMP_ENV"
  fi
  TMP_ENV="$(sudo_cmd mktemp -p /etc/openvpn-web .openvpn-web.env.XXXXXX)"
  sudo_cmd sh -c 'cat "$1" > "$2"' sh "$ENV_PATH" "$TMP_ENV"
  changed_env=0
  for line in \
    'NETCTL_PATH=/usr/local/sbin/netctl' \
    'NETCTL_USE_SUDO=1' \
    'NETCTL_SUDO_USER=netctl' \
    'NETWORK_OBSERVER_ENABLED=1' \
    'ROUTEROS_BACKUP_DIR=/var/backups/routeros'; do
    key="${line%%=*}"
    if ! sudo_cmd grep -q "^${key}=" "$TMP_ENV"; then
      printf '%s\n' "$line" | sudo_cmd tee -a "$TMP_ENV" >/dev/null
      changed_env=1
    fi
  done
  if [[ "$changed_env" == "1" ]]; then
    sudo_cmd cp "$ENV_PATH" "$ENV_PATH.backup.$(date +%F_%H-%M-%S)"
    sudo_cmd install -m 0640 -o root -g openvpn-web "$TMP_ENV" "$ENV_PATH"
  fi
  sudo_cmd rm -f "$TMP_ENV"
fi

sudo_cmd install -m 0440 "$SRC/deploy/sudoers-openvpn-web" /etc/sudoers.d/openvpn-web
sudo_cmd visudo -cf /etc/sudoers.d/openvpn-web

# Keep locally approved topology out of the repository. A first install gets
# only the role-only sample; existing operator configuration, including a
# dangling symlink, is never replaced by this installer.
if ! sudo_cmd test -e /etc/openvpn-web/network-paths.json \
  && ! sudo_cmd test -L /etc/openvpn-web/network-paths.json; then
  sudo_cmd install -m 0640 -o root -g openvpn-web \
    "$SRC/deploy/network-paths.json.sample" /etc/openvpn-web/network-paths.json
fi
if ! sudo_cmd test -e /etc/openvpn-web/server-roles.json \
  && ! sudo_cmd test -L /etc/openvpn-web/server-roles.json; then
  sudo_cmd install -m 0640 -o root -g openvpn-web \
    "$SRC/deploy/server-roles.json.sample" /etc/openvpn-web/server-roles.json
fi

if [[ ! -x "$APP/.venv/bin/python" ]]; then
  sudo_cmd -u openvpn-web python3 -m venv "$APP/.venv"
fi
sudo_cmd -u openvpn-web "$APP/.venv/bin/python" -m pip install --upgrade pip
sudo_cmd -u openvpn-web "$APP/.venv/bin/pip" install -r "$APP/requirements.txt"

sudo_cmd install -m 0644 "$SRC/deploy/openvpn-web.service" /etc/systemd/system/openvpn-web.service
sudo_cmd install -m 0644 "$SRC/deploy/netctl-collect.service" /etc/systemd/system/netctl-collect.service
sudo_cmd install -m 0644 "$SRC/deploy/netctl-collect.timer" /etc/systemd/system/netctl-collect.timer
sudo_cmd install -m 0644 "$SRC/deploy/vpn-policy.service" /etc/systemd/system/vpn-policy.service
sudo_cmd install -m 0644 "$SRC/deploy/vpn-policy-reconcile.service" /etc/systemd/system/vpn-policy-reconcile.service
sudo_cmd install -m 0644 "$SRC/deploy/vpn-policy-reconcile.timer" /etc/systemd/system/vpn-policy-reconcile.timer
sudo_cmd install -m 0644 "$SRC/deploy/vpn-runtime-health.service" /etc/systemd/system/vpn-runtime-health.service
sudo_cmd install -m 0644 "$SRC/deploy/vpn-runtime-health.timer" /etc/systemd/system/vpn-runtime-health.timer
sudo_cmd systemctl daemon-reload
sudo_cmd systemctl enable openvpn-web.service
sudo_cmd systemctl enable vpn-policy.service
sudo_cmd systemctl enable --now vpn-policy-reconcile.timer
sudo_cmd systemctl enable --now vpn-runtime-health.timer
sudo_cmd systemctl restart openvpn-web.service
sudo_cmd systemctl --no-pager --full status openvpn-web.service | sed -n '1,25p'
printf '%s\n' 'OpenVPN Web Manager installed; credentials remain in the protected environment.'
