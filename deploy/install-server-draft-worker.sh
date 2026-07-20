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
DRAFT_PARENT="/var/lib/openvpn-web"
DRAFT_ROOT="$DRAFT_PARENT/server-drafts"
TMP_OBSERVER_PUBLIC_KEY=""

cleanup() {
  local exit_code=$?
  if [[ -n "$TMP_OBSERVER_PUBLIC_KEY" ]]; then
    rm -f "$TMP_OBSERVER_PUBLIC_KEY"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

validate_root_component() {
  local path="$1" expected_owner="$2" expected_group="$3" expected_mode="$4"
  local resolved metadata
  if sudo_cmd test -L "$path" || ! sudo_cmd test -d "$path"; then
    echo "unsafe draft namespace component: $path" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$path")"
  metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$path")"
  if [[ "$resolved" != "$path" ]] || \
    [[ "$metadata" != "$expected_owner:$expected_group:$expected_mode" ]]; then
    echo "unexpected draft namespace component metadata: $path" >&2
    exit 2
  fi
}

validate_draft_parent() {
  local path="$1" resolved metadata
  if sudo_cmd test -L "$path" || ! sudo_cmd test -d "$path"; then
    echo "unsafe draft parent: $path" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$path")"
  metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$path")"
  if [[ "$resolved" != "$path" ]]; then
    echo "draft parent resolves outside its canonical path: $path" >&2
    exit 2
  fi
  case "$metadata" in
    openvpn-web:openvpn-web:755|root:openvpn-web:1770) ;;
    *)
      echo "unexpected draft parent ownership or mode: $path" >&2
      exit 2
      ;;
  esac
}

validate_existing_draft_component() {
  local path="$1" resolved metadata
  if sudo_cmd test -L "$path"; then
    echo "refusing symlinked draft component: $path" >&2
    exit 2
  elif sudo_cmd test -e "$path"; then
    if ! sudo_cmd test -d "$path"; then
      echo "draft component is not a directory: $path" >&2
      exit 2
    fi
    resolved="$(sudo_cmd readlink -e -- "$path")"
    if [[ "$resolved" != "$path" ]] || \
      [[ "$resolved" != "$DRAFT_ROOT" && "$resolved" != "$DRAFT_ROOT/"* ]]; then
      echo "draft component resolves outside the draft root: $path" >&2
      exit 2
    fi
    metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$path")"
    case "$path" in
      "$DRAFT_ROOT")
        [[ "$metadata" == openvpn-web:openvpn-web:770 || "$metadata" == root:openvpn-web:750 ]]
        ;;
      "$DRAFT_ROOT/queue"|"$DRAFT_ROOT/results")
        [[ "$metadata" == openvpn-web:openvpn-web:770 ]]
        ;;
      "$DRAFT_ROOT/private")
        [[ "$metadata" == openvpm:openvpm:700 ]]
        ;;
      *)
        echo "unexpected draft component ownership or mode: $path" >&2
        exit 2
        ;;
    esac
  fi
}

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

validate_root_component /var root root 755
validate_root_component /var/lib root root 755
validate_draft_parent "$DRAFT_PARENT"
validate_existing_draft_component "$DRAFT_ROOT"
validate_existing_draft_component "$DRAFT_ROOT/queue"
validate_existing_draft_component "$DRAFT_ROOT/results"
validate_existing_draft_component "$DRAFT_ROOT/private"

draft_parent_metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$DRAFT_PARENT")"
if [[ "$draft_parent_metadata" == "openvpn-web:openvpn-web:755" ]]; then
  # Removing owner write locks the legacy web-owned parent before migration.
  # /var/lib is root-owned and already validated, so the parent cannot be
  # replaced while this ownership change is made.
  sudo_cmd chown root:openvpn-web "$DRAFT_PARENT"
  sudo_cmd chmod 1750 "$DRAFT_PARENT"
  draft_root_action=legacy_locked
else
  # Temporarily remove group write even from an already-hardened sticky parent.
  # This makes the following revalidation and action selection race-free.
  sudo_cmd chmod 1750 "$DRAFT_PARENT"
fi

# Recheck after the parent is locked. A web process that won a race before the
# lock can only make this invocation fail; it cannot redirect mkdir or chown.
validate_existing_draft_component "$DRAFT_ROOT"
validate_existing_draft_component "$DRAFT_ROOT/queue"
validate_existing_draft_component "$DRAFT_ROOT/results"
validate_existing_draft_component "$DRAFT_ROOT/private"

if [[ "$draft_parent_metadata" == "root:openvpn-web:1770" ]]; then
  if sudo_cmd test -d "$DRAFT_ROOT"; then
    draft_root_metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$DRAFT_ROOT")"
    if ! [[ "$draft_root_metadata" == "root:openvpn-web:750" ]]; then
      echo "hardened draft parent contains an untrusted draft root" >&2
      exit 2
    fi
    draft_root_action=existing_hardened
  else
    draft_root_action=create_exclusive
  fi
fi

case "$draft_root_action" in
  create_exclusive)
    # No -p: creation is exclusive and fails closed if a concurrent web
    # process creates any entry at the draft-root name first.
    sudo_cmd mkdir --mode=0750 -- "$DRAFT_ROOT"
    ;;
  existing_hardened)
    # Sticky-parent rules already prevent the web account from replacing this
    # root-owned entry between validation and use.
    ;;
  legacy_locked)
    if sudo_cmd test -d "$DRAFT_ROOT"; then
      sudo_cmd chown root:root "$DRAFT_ROOT"
      sudo_cmd chmod 0750 "$DRAFT_ROOT"
      validate_existing_draft_component "$DRAFT_ROOT/queue"
      validate_existing_draft_component "$DRAFT_ROOT/results"
      validate_existing_draft_component "$DRAFT_ROOT/private"
    else
      sudo_cmd mkdir --mode=0750 -- "$DRAFT_ROOT"
    fi
    ;;
esac
sudo_cmd chown root:openvpn-web "$DRAFT_ROOT"
sudo_cmd chmod 0750 "$DRAFT_ROOT"
sudo_cmd chown root:openvpn-web "$DRAFT_PARENT"
sudo_cmd chmod 1770 "$DRAFT_PARENT"
sudo_cmd install -d -m 0770 -o openvpn-web -g openvpn-web /var/lib/openvpn-web/server-drafts/queue
sudo_cmd install -d -m 0770 -o openvpn-web -g openvpn-web /var/lib/openvpn-web/server-drafts/results
sudo_cmd install -d -m 0700 -o openvpm -g openvpm /var/lib/openvpn-web/server-drafts/private

sudo_cmd install -m 0755 "$SRC/deploy/server-draft-worker" /usr/local/sbin/server-draft-worker
TMP_OBSERVER_PUBLIC_KEY="$(mktemp)"
sudo_cmd ssh-keygen -y -f /etc/openvpn-web/server-observer.key > "$TMP_OBSERVER_PUBLIC_KEY"
sudo_cmd install -m 0644 -o root -g openvpn-web \
  "$TMP_OBSERVER_PUBLIC_KEY" /etc/openvpn-web/server-observer.pub

sudo_cmd install -m 0644 "$SRC/deploy/server-draft-worker.service" \
  /etc/systemd/system/server-draft-worker.service
sudo_cmd install -m 0644 "$SRC/deploy/server-draft-worker.path" \
  /etc/systemd/system/server-draft-worker.path
sudo_cmd systemctl daemon-reload
sudo_cmd systemctl enable --now server-draft-worker.path
