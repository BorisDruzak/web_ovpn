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
OBSERVER_RUNTIME="/usr/local/lib/openvpn-web-server-observer"
STAGED_RUNTIME="/usr/local/lib/.openvpn-web-server-observer.new.$$"
PREVIOUS_RUNTIME="/usr/local/lib/.openvpn-web-server-observer.previous.$$"
STATE_PARENT="/var/lib/openvpn-web"
STATE_DIR="$STATE_PARENT/server-observer"
runtime_swapped=0
prior_runtime=absent

cleanup() {
  local exit_code=$?
  sudo_cmd rm -rf -- "$STAGED_RUNTIME"
  if [[ "$exit_code" != 0 && "$runtime_swapped" == 1 ]]; then
    sudo_cmd rm -rf -- "$OBSERVER_RUNTIME"
    if [[ "$prior_runtime" == present ]]; then
      sudo_cmd mv -- "$PREVIOUS_RUNTIME" "$OBSERVER_RUNTIME"
    fi
  fi
  if [[ "$exit_code" == 0 ]]; then
    sudo_cmd rm -rf -- "$PREVIOUS_RUNTIME"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

validate_root_component() {
  local path="$1" expected_owner="$2" expected_group="$3" expected_mode="$4"
  local resolved metadata
  if sudo_cmd test -L "$path" || ! sudo_cmd test -d "$path"; then
    echo "unsafe observer runtime namespace component: $path" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$path")"
  metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$path")"
  if [[ "$resolved" != "$path" ]] || \
    [[ "$metadata" != "$expected_owner:$expected_group:$expected_mode" ]]; then
    echo "unexpected observer runtime namespace metadata: $path" >&2
    exit 2
  fi
}

validate_python_runtime() {
  local interpreter=/usr/bin/python3 resolved metadata owner group mode
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
  IFS=: read -r owner group mode <<< "$metadata"
  if [[ "$owner:$group" != root:root ]] || (( (8#$mode & 0022) != 0 )); then
    echo "system Python is writable outside root" >&2
    exit 2
  fi
}

validate_source_tree() {
  local resolved unsafe_entry
  if [[ "$SRC" != /* ]] || sudo_cmd test -L "$SRC" || ! sudo_cmd test -d "$SRC"; then
    echo "server-observer source root must be a canonical directory" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$SRC")"
  if [[ "$resolved" != "$SRC" ]]; then
    echo "server-observer source root is noncanonical" >&2
    exit 2
  fi
  unsafe_entry="$(sudo_cmd find "$SRC" -maxdepth 0 \( -perm /022 -o -user openvpn-web \) -print -quit)"
  if [[ -n "$unsafe_entry" ]]; then
    echo "server-observer source root is web-owned or mutable" >&2
    exit 2
  fi
  unsafe_entry="$(sudo_cmd find "$SRC/app" "$SRC/deploy" \( -type l -o -perm /022 -o -user openvpn-web \) -print -quit)"
  if [[ -n "$unsafe_entry" ]]; then
    echo "server-observer source tree is web-owned, mutable, or symlinked" >&2
    exit 2
  fi
}

validate_observer_runtime() {
  local path="$1" resolved unsafe_entry
  if ! sudo_cmd test -e "$path" && ! sudo_cmd test -L "$path"; then
    return
  fi
  if sudo_cmd test -L "$path" || ! sudo_cmd test -d "$path"; then
    echo "refusing unsafe server-observer runtime path" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$path")"
  if [[ "$resolved" != "$path" ]]; then
    echo "server-observer runtime resolves outside its canonical path" >&2
    exit 2
  fi
  unsafe_entry="$(sudo_cmd find "$path" \( -type l -o ! -user root -o ! -group root -o -perm /022 \) -print -quit)"
  if [[ -n "$unsafe_entry" ]]; then
    echo "server-observer runtime is not root-owned and immutable" >&2
    exit 2
  fi
}

validate_private_file() {
  local path="$1" expected_metadata resolved metadata
  case "$path" in
    /etc/openvpn-web/server-observer.json)
      expected_metadata=root:openvpn-web:640
      ;;
    /etc/openvpn-web/server-observer.key|/etc/openvpn-web/server-observer.known_hosts)
      expected_metadata=openvpm:openvpm:600
      ;;
    *)
      echo "unexpected observer private file: $path" >&2
      exit 2
      ;;
  esac
  if sudo_cmd test -L "$path" || ! sudo_cmd test -f "$path"; then
    echo "observer private file must be an existing regular file: $path" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$path")"
  metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$path")"
  if [[ "$resolved" != "$path" ]] || [[ "$metadata" != "$expected_metadata" ]]; then
    echo "observer private file has unsafe metadata: $path" >&2
    exit 2
  fi
}

validate_state_parent() {
  local resolved metadata
  if sudo_cmd test -L "$STATE_PARENT" || ! sudo_cmd test -d "$STATE_PARENT"; then
    echo "unsafe observer state parent" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$STATE_PARENT")"
  metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$STATE_PARENT")"
  if [[ "$resolved" != "$STATE_PARENT" ]]; then
    echo "observer state parent resolves outside its canonical path" >&2
    exit 2
  fi
  case "$metadata" in
    openvpn-web:openvpn-web:755|root:openvpn-web:1770) ;;
    *)
      echo "observer state parent has unsafe metadata" >&2
      exit 2
      ;;
  esac
}

validate_state_dir() {
  local resolved metadata
  if ! sudo_cmd test -e "$STATE_DIR" && ! sudo_cmd test -L "$STATE_DIR"; then
    return
  fi
  if sudo_cmd test -L "$STATE_DIR" || ! sudo_cmd test -d "$STATE_DIR"; then
    echo "unsafe observer state directory" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$STATE_DIR")"
  metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$STATE_DIR")"
  if [[ "$resolved" != "$STATE_DIR" ]] || [[ "$metadata" != openvpm:openvpn-web:750 ]]; then
    echo "observer state directory has unsafe metadata" >&2
    exit 2
  fi
}

wait_for_observer() {
  local attempts=0 load_state state jobs
  while (( attempts < 180 )); do
    load_state="$(sudo_cmd systemctl show -p LoadState --value server-observer.service 2>/dev/null || true)"
    if [[ -z "$load_state" || "$load_state" == not-found ]]; then
      return
    fi
    state="$(sudo_cmd systemctl show -p ActiveState --value server-observer.service)"
    jobs="$(sudo_cmd systemctl list-jobs --no-legend --no-pager 2>/dev/null || true)"
    if [[ "$state" == inactive && "$jobs" != *server-observer.service* ]]; then
      return
    fi
    if [[ "$state" == failed ]]; then
      echo "server-observer.service is failed; refusing deployment" >&2
      exit 2
    fi
    sleep 1
    ((attempts += 1))
  done
  echo "server-observer.service did not quiesce" >&2
  exit 2
}

for source_file in \
  "$SRC/deploy/server-observer" \
  "$SRC/deploy/server-observer-main.py" \
  "$SRC/deploy/server-observer.service" \
  "$SRC/deploy/server-observer.timer" \
  "$SRC/app/__init__.py" \
  "$SRC/app/server_observer.py" \
  "$SRC/app/server_observer_cli.py"; do
  if [[ ! -f "$source_file" ]] || [[ -L "$source_file" ]]; then
    echo "missing server-observer source: $source_file" >&2
    exit 2
  fi
done
validate_source_tree

for account in openvpn-web openvpm; do
  if ! id "$account" >/dev/null 2>&1; then
    echo "required account is missing: $account" >&2
    exit 2
  fi
done

validate_root_component /usr root root 755
validate_root_component /usr/bin root root 755
validate_root_component /usr/local root root 755
validate_root_component /usr/local/lib root root 755
validate_root_component /var root root 755
validate_root_component /var/lib root root 755
validate_python_runtime
validate_observer_runtime "$OBSERVER_RUNTIME"
validate_private_file /etc/openvpn-web/server-observer.json
validate_private_file /etc/openvpn-web/server-observer.key
validate_private_file /etc/openvpn-web/server-observer.known_hosts
validate_state_parent
validate_state_dir

timer_load_state="$(sudo_cmd systemctl show -p LoadState --value server-observer.timer 2>/dev/null || true)"
if [[ -n "$timer_load_state" && "$timer_load_state" != not-found ]]; then
  sudo_cmd systemctl stop server-observer.timer
fi
wait_for_observer

# Harden the shared state parent before creating or using the observer entry.
# Sticky-directory ownership prevents the web account from replacing the
# openvpm-owned observer directory after validation.
sudo_cmd chown root:openvpn-web "$STATE_PARENT"
sudo_cmd chmod 1770 "$STATE_PARENT"
validate_state_dir
sudo_cmd install -d -m 0750 -o openvpm -g openvpn-web "$STATE_DIR"

if sudo_cmd test -e "$STAGED_RUNTIME" || sudo_cmd test -L "$STAGED_RUNTIME" || \
  sudo_cmd test -e "$PREVIOUS_RUNTIME" || sudo_cmd test -L "$PREVIOUS_RUNTIME"; then
  echo "temporary server-observer runtime path already exists" >&2
  exit 2
fi
sudo_cmd install -d -m 0755 -o root -g root "$STAGED_RUNTIME/app"
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/app/__init__.py" "$STAGED_RUNTIME/app/__init__.py"
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/app/server_observer.py" "$STAGED_RUNTIME/app/server_observer.py"
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/app/server_observer_cli.py" "$STAGED_RUNTIME/app/server_observer_cli.py"
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/deploy/server-observer-main.py" "$STAGED_RUNTIME/observer_main.py"
validate_observer_runtime "$STAGED_RUNTIME"

if sudo_cmd test -d "$OBSERVER_RUNTIME"; then
  prior_runtime=present
  sudo_cmd mv -- "$OBSERVER_RUNTIME" "$PREVIOUS_RUNTIME"
fi
sudo_cmd mv -- "$STAGED_RUNTIME" "$OBSERVER_RUNTIME"
runtime_swapped=1
validate_observer_runtime "$OBSERVER_RUNTIME"

sudo_cmd install -m 0755 -o root -g root \
  "$SRC/deploy/server-observer" /usr/local/sbin/server-observer
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/deploy/server-observer.service" /etc/systemd/system/server-observer.service
sudo_cmd install -m 0644 -o root -g root \
  "$SRC/deploy/server-observer.timer" /etc/systemd/system/server-observer.timer
sudo_cmd systemctl daemon-reload
sudo_cmd systemctl enable --now server-observer.timer
