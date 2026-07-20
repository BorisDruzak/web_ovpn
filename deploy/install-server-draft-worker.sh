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

for source_file in \
  "$SRC/deploy/server-draft-worker" \
  "$SRC/deploy/server-draft-worker.service" \
  "$SRC/deploy/server-draft-worker.path"; do
  if [[ ! -f "$source_file" ]]; then
    echo "missing draft-worker source: $source_file" >&2
    exit 2
  fi
done

for account in openvpn-web openvpm; do
  if ! id "$account" >/dev/null 2>&1; then
    echo "required account is missing: $account" >&2
    exit 2
  fi
done

if ! sudo_cmd test -f /etc/openvpn-web/server-observer.key || \
  sudo_cmd test -L /etc/openvpn-web/server-observer.key; then
  echo "server observer key must be an existing regular file" >&2
  exit 2
fi

sudo_cmd install -m 0755 "$SRC/deploy/server-draft-worker" /usr/local/sbin/server-draft-worker
sudo_cmd install -d -m 0770 -o openvpn-web -g openvpn-web /var/lib/openvpn-web/server-drafts/queue
sudo_cmd install -d -m 0770 -o openvpn-web -g openvpn-web /var/lib/openvpn-web/server-drafts/results
sudo_cmd install -d -m 0700 -o openvpm -g openvpm /var/lib/openvpn-web/server-drafts/private

TMP_OBSERVER_PUBLIC_KEY="$(mktemp)"
trap 'rm -f "$TMP_OBSERVER_PUBLIC_KEY"' EXIT
sudo_cmd ssh-keygen -y -f /etc/openvpn-web/server-observer.key > "$TMP_OBSERVER_PUBLIC_KEY"
sudo_cmd install -m 0644 -o root -g openvpn-web \
  "$TMP_OBSERVER_PUBLIC_KEY" /etc/openvpn-web/server-observer.pub

sudo_cmd install -m 0644 "$SRC/deploy/server-draft-worker.service" \
  /etc/systemd/system/server-draft-worker.service
sudo_cmd install -m 0644 "$SRC/deploy/server-draft-worker.path" \
  /etc/systemd/system/server-draft-worker.path
sudo_cmd systemctl daemon-reload
sudo_cmd systemctl enable --now server-draft-worker.path
