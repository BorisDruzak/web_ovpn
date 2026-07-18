#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${SUDO_PASSWORD:-}" ]]; then
  echo "SUDO_PASSWORD is required" >&2
  exit 2
fi

sudo_cmd() {
  printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' "$@"
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

sudo_cmd mkdir -p "$APP" /etc/openvpn-web /var/lib/openvpn-web /etc/openvpn
sudo_cmd chown -R openvpn-web:openvpn-web "$APP" /var/lib/openvpn-web
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

sudo_cmd install -m 0755 "$SRC/deploy/vpnctl" /usr/local/sbin/vpnctl
sudo_cmd install -m 0755 "$SRC/deploy/vpn-policy.sh" /usr/local/sbin/vpn-policy.sh
sudo_cmd install -m 0755 "$SRC/deploy/netctl" /usr/local/sbin/netctl
sudo_cmd install -m 0755 "$SRC/deploy/generate-client-wrapper.sh" /usr/local/sbin/generate-client-wrapper
sudo_cmd mkdir -p /etc/netctl/sources.d /var/lib/netctl
sudo_cmd chmod 0755 /etc/netctl /etc/netctl/sources.d
sudo_cmd chown -R netctl:netctl /var/lib/netctl
sudo_cmd chmod 0750 /var/lib/netctl
if [[ ! -f /etc/netctl/sources.d/mikrotik-main.yaml ]]; then
  TMP_SOURCE="$(mktemp)"
  cat > "$TMP_SOURCE" <<'SOURCE_FILE'
name: mikrotik-main
driver: mikrotik_api
host: 192.168.100.250
port: 8729
tls: true
verify_tls: false
username: netobserver
secret_ref: mikrotik-main
site: main
role: core-router
enabled: true
SOURCE_FILE
  sudo_cmd install -m 0644 -o root -g root "$TMP_SOURCE" /etc/netctl/sources.d/mikrotik-main.yaml
  rm -f "$TMP_SOURCE"
fi
if [[ ! -f /etc/netctl/sources.d/mikrotik-hex.yaml ]]; then
  TMP_SOURCE="$(mktemp)"
  cat > "$TMP_SOURCE" <<'SOURCE_FILE'
name: mikrotik-hex
driver: mikrotik_ssh
host: 192.168.99.1
port: 22
tls: false
verify_tls: false
username: asmr_admin
secret_ref: mikrotik-hex
site: m-arhiv
role: edge-router
ssh_identity_file: /var/lib/netctl/.ssh/m_arhiv_hex_rsa
ssh_connect_timeout: 12
enabled: true
SOURCE_FILE
  sudo_cmd install -m 0644 -o root -g root "$TMP_SOURCE" /etc/netctl/sources.d/mikrotik-hex.yaml
  rm -f "$TMP_SOURCE"
fi
if [[ ! -f /etc/netctl/secrets.env ]]; then
  TMP_SECRETS="$(mktemp)"
  cat > "$TMP_SECRETS" <<'SECRETS_FILE'
# Add the MikroTik read-only API password here:
# NETCTL_SECRET_MIKROTIK_MAIN_PASSWORD='strong-password'
SECRETS_FILE
  sudo_cmd install -m 0640 -o root -g netctl "$TMP_SECRETS" /etc/netctl/secrets.env
  rm -f "$TMP_SECRETS"
fi
sudo_cmd chown root:netctl /etc/netctl/secrets.env
sudo_cmd chmod 0640 /etc/netctl/secrets.env
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
  ADMIN_PASS="$(sed -n 's/^ADMIN_PASSWORD=//p' /tmp/openvpn-web-admin-password.txt 2>/dev/null | head -1)"
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
  TMP_ENV="$(mktemp)"
  cat > "$TMP_ENV" <<ENV_FILE
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
  rm -f "$TMP_ENV"
  printf 'ADMIN_PASSWORD=%s\n' "$ADMIN_PASS" > /tmp/openvpn-web-admin-password.txt
  printf 'OPENVPN_WEB_API_TOKEN=%s\n' "$API_TOKEN" > /tmp/openvpn-web-api-token.txt
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
    TMP_ENV="$(mktemp)"
    sudo_cmd cat "$ENV_PATH" > "$TMP_ENV"
    {
      printf 'OPENVPN_WEB_API_TOKEN_HASH=%s\n' "$API_TOKEN_HASH"
      printf 'OPENVPN_WEB_API_ACTOR=api:codex-local\n'
    } >> "$TMP_ENV"
    sudo_cmd install -m 0640 -o root -g openvpn-web "$TMP_ENV" "$ENV_PATH"
    rm -f "$TMP_ENV"
    printf 'OPENVPN_WEB_API_TOKEN=%s\n' "$API_TOKEN" > /tmp/openvpn-web-api-token.txt
  else
    printf 'API_TOKEN_EXISTS=1\n' > /tmp/openvpn-web-api-token.txt
  fi
  TMP_ENV="$(mktemp)"
  sudo_cmd cat "$ENV_PATH" > "$TMP_ENV"
  changed_env=0
  for line in \
    'NETCTL_PATH=/usr/local/sbin/netctl' \
    'NETCTL_USE_SUDO=1' \
    'NETCTL_SUDO_USER=netctl' \
    'NETWORK_OBSERVER_ENABLED=1' \
    'ROUTEROS_BACKUP_DIR=/var/backups/routeros'; do
    key="${line%%=*}"
    if ! grep -q "^${key}=" "$TMP_ENV"; then
      printf '%s\n' "$line" >> "$TMP_ENV"
      changed_env=1
    fi
  done
  if [[ "$changed_env" == "1" ]]; then
    sudo_cmd cp "$ENV_PATH" "$ENV_PATH.backup.$(date +%F_%H-%M-%S)"
    sudo_cmd install -m 0640 -o root -g openvpn-web "$TMP_ENV" "$ENV_PATH"
  fi
  rm -f "$TMP_ENV"
  sudo_cmd awk -F= '/^ADMIN_PASSWORD=/{print $0}' "$ENV_PATH" > /tmp/openvpn-web-admin-password.txt
fi

sudo_cmd install -m 0440 "$SRC/deploy/sudoers-openvpn-web" /etc/sudoers.d/openvpn-web
sudo_cmd visudo -cf /etc/sudoers.d/openvpn-web

cd "$APP"
if [[ ! -x .venv/bin/python ]]; then
  sudo_cmd -u openvpn-web python3 -m venv .venv
fi
sudo_cmd -u openvpn-web .venv/bin/python -m pip install --upgrade pip
sudo_cmd -u openvpn-web .venv/bin/pip install -r requirements.txt

sudo_cmd install -m 0644 "$SRC/deploy/openvpn-web.service" /etc/systemd/system/openvpn-web.service
sudo_cmd install -m 0644 "$SRC/deploy/netctl-collect.service" /etc/systemd/system/netctl-collect.service
sudo_cmd install -m 0644 "$SRC/deploy/netctl-collect.timer" /etc/systemd/system/netctl-collect.timer
sudo_cmd install -m 0644 "$SRC/deploy/vpn-policy.service" /etc/systemd/system/vpn-policy.service
sudo_cmd install -m 0644 "$SRC/deploy/vpn-runtime-health.service" /etc/systemd/system/vpn-runtime-health.service
sudo_cmd install -m 0644 "$SRC/deploy/vpn-runtime-health.timer" /etc/systemd/system/vpn-runtime-health.timer
sudo_cmd systemctl daemon-reload
sudo_cmd systemctl enable openvpn-web.service
sudo_cmd systemctl enable vpn-policy.service
sudo_cmd systemctl enable --now netctl-collect.timer
sudo_cmd systemctl enable --now vpn-runtime-health.timer
sudo_cmd systemctl restart openvpn-web.service
sudo_cmd systemctl --no-pager --full status openvpn-web.service | sed -n '1,25p'
cat /tmp/openvpn-web-admin-password.txt
