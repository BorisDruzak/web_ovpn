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
WORKER_RUNTIME="/usr/local/lib/openvpn-web-server-draft-worker"
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

validate_python_runtime() {
  local interpreter=/usr/bin/python3 resolved metadata mode
  if [[ ! -e "$interpreter" ]]; then
    echo "required system Python interpreter is missing: $interpreter" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$interpreter")"
  metadata="$(sudo_cmd stat -Lc '%U:%G:%a' -- "$interpreter")"
  case "$resolved" in
    /usr/bin/python3|/usr/bin/python3.*) ;;
    *)
      echo "system Python resolves outside the root-owned runtime" >&2
      exit 2
      ;;
  esac
  IFS=: read -r runtime_owner runtime_group mode <<< "$metadata"
  if [[ "$runtime_owner:$runtime_group" != root:root ]] || \
    (( (8#$mode & 0022) != 0 )); then
    echo "system Python is writable outside root" >&2
    exit 2
  fi
}

validate_worker_runtime() {
  local path="$1" resolved unsafe_entry
  if ! sudo_cmd test -e "$path" && ! sudo_cmd test -L "$path"; then
    return
  fi
  if sudo_cmd test -L "$path" || ! sudo_cmd test -d "$path"; then
    echo "refusing unsafe draft-worker runtime path" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$path")"
  if [[ "$resolved" != "$path" ]]; then
    echo "draft-worker runtime resolves outside its canonical path" >&2
    exit 2
  fi
  unsafe_entry="$(sudo_cmd find "$path" \( -type l -o ! -user root -o ! -group root -o -perm /022 \) -print -quit)"
  if [[ -n "$unsafe_entry" ]]; then
    echo "draft-worker runtime is not root-owned and immutable" >&2
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
  "$SRC/deploy/server-draft-worker-main.py" \
  "$SRC/deploy/server-draft-worker.service" \
  "$SRC/deploy/server-draft-worker.path" \
  "$SRC/app/__init__.py" \
  "$SRC/app/server_draft_worker.py" \
  "$SRC/app/server_drafts.py"; do
  if [[ ! -f "$source_file" ]] || [[ -L "$source_file" ]]; then
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
validate_root_component /usr root root 755
validate_root_component /usr/bin root root 755
validate_root_component /usr/local root root 755
validate_root_component /usr/local/lib root root 755
validate_python_runtime
validate_worker_runtime "$WORKER_RUNTIME"
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

# This exact runtime is outside the generic web bundle. Its bootstrap, worker
# modules, interpreter, and standard-library dependencies are all root-owned;
# the web account can modify only the scoped queue and result directories.
sudo_cmd install -d -m 0755 -o root -g root "$WORKER_RUNTIME/app"
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/app/__init__.py" "$WORKER_RUNTIME/app/__init__.py"
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/app/server_draft_worker.py" "$WORKER_RUNTIME/app/server_draft_worker.py"
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/app/server_drafts.py" "$WORKER_RUNTIME/app/server_drafts.py"
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/deploy/server-draft-worker-main.py" "$WORKER_RUNTIME/worker_main.py"
validate_worker_runtime "$WORKER_RUNTIME"

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
