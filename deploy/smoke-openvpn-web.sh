#!/usr/bin/env bash
set -eu

if [[ -z "${SUDO_PASSWORD:-}" ]]; then
  echo "SUDO_PASSWORD is required" >&2
  exit 2
fi

echo "SERVICE=$(systemctl is-active openvpn-web.service)"
ss -ltnp 2>/dev/null | grep ':8088' || true

printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' -u openvpn-web sudo -n /usr/local/sbin/vpnctl --json profiles >/tmp/vpnctl_profiles.json
python3 -m json.tool /tmp/vpnctl_profiles.json >/tmp/vpnctl_profiles.pretty
head -20 /tmp/vpnctl_profiles.pretty

curl -s -c /tmp/openvpn-web.cookies http://127.0.0.1:8088/login >/tmp/openvpn-web-login.html
TOKEN="$(grep -oP 'name="csrf_token" value="\K[^"]+' /tmp/openvpn-web-login.html | head -1)"
PASS="$(printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' awk -F= '/^ADMIN_PASSWORD=/{print substr($0, 16)}' /etc/openvpn-web/openvpn-web.env)"

curl -s -i -b /tmp/openvpn-web.cookies -c /tmp/openvpn-web.cookies \
  -X POST \
  --data-urlencode username=admin \
  --data-urlencode "password=$PASS" \
  --data-urlencode "csrf_token=$TOKEN" \
  http://127.0.0.1:8088/login >/tmp/openvpn-web-login-response.txt
head -5 /tmp/openvpn-web-login-response.txt

curl -s -b /tmp/openvpn-web.cookies http://127.0.0.1:8088/ >/tmp/openvpn-web-dashboard.html
curl -s -b /tmp/openvpn-web.cookies http://127.0.0.1:8088/clients >/tmp/openvpn-web-clients.html

grep -E 'Панель состояния|OpenVPN|Клиенты' /tmp/openvpn-web-dashboard.html | head -5
grep -E 'Клиенты|Синхронизировать' /tmp/openvpn-web-clients.html | head -5
grep -q 'Панель состояния' /tmp/openvpn-web-dashboard.html
grep -q 'Клиенты' /tmp/openvpn-web-clients.html

echo "SMOKE_OK"
