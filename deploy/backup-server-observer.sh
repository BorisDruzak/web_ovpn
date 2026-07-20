#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${SUDO_PASSWORD:-}" ]]; then
  echo "SUDO_PASSWORD is required" >&2
  exit 2
fi

sudo_cmd() {
  printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' "$@"
}

BACKUP_ROOT="${BACKUP_ROOT:-/root/openvpn-web-server-observer-backup-$(date -u +%Y%m%d%H%M%S)}"
rollback_manifest="$BACKUP_ROOT/rollback.assets"
timer_was_active=0
state_parent_locked=0
execution_boundary=unknown
TMP_MANIFEST="$(mktemp)"

validate_backup_root() {
  local path="$1" name resolved metadata
  name="$(basename -- "$path")"
  if ! [[ "$name" =~ ^openvpn-web-server-observer-backup-[0-9]{14}$ ]] || \
    [[ "$path" != "/root/$name" ]]; then
    echo "refusing invalid server-observer backup root" >&2
    exit 2
  fi
  if sudo_cmd test -L "$path" || ! sudo_cmd test -d "$path"; then
    echo "server-observer backup root is not a real directory" >&2
    exit 2
  fi
  resolved="$(sudo_cmd readlink -e -- "$path")"
  metadata="$(sudo_cmd stat -c '%u:%g:%a' -- "$path")"
  if [[ "$resolved" != "$path" ]] || [[ "$metadata" != 0:0:700 ]]; then
    echo "server-observer backup root has unsafe metadata" >&2
    exit 2
  fi
}

reject_nested_symlinks() {
  local path="$1" unsafe
  unsafe="$(sudo_cmd find "$path" -type l -print -quit)"
  if [[ -n "$unsafe" ]]; then
    echo "refusing symlinked server-observer backup source" >&2
    exit 2
  fi
}

validate_root_owned_asset() {
  local name="$1" kind="$2" path="$3" unsafe metadata
  if ! sudo_cmd test -e "$path" && ! sudo_cmd test -L "$path"; then
    return
  fi
  if sudo_cmd test -L "$path"; then
    echo "refusing symlinked server-observer asset: $name" >&2
    exit 2
  fi
  case "$kind" in
    file) sudo_cmd test -f "$path" ;;
    directory) sudo_cmd test -d "$path" ;;
    *) exit 2 ;;
  esac
  unsafe="$(sudo_cmd find "$path" \( -type l -o ! -user root -o ! -group root -o -perm /022 \) -print -quit)"
  if [[ -n "$unsafe" ]]; then
    echo "server-observer asset is not root-owned and immutable: $name" >&2
    exit 2
  fi
  metadata="$(sudo_cmd stat -c '%U:%G' -- "$path")"
  if [[ "$metadata" != root:root ]]; then
    echo "server-observer asset has unsafe ownership: $name" >&2
    exit 2
  fi
}

validate_state_namespace() {
  local component resolved metadata
  for component in /var /var/lib; do
    if sudo_cmd test -L "$component" || ! sudo_cmd test -d "$component"; then
      echo "unsafe observer state namespace: $component" >&2
      exit 2
    fi
    resolved="$(sudo_cmd readlink -e -- "$component")"
    metadata="$(sudo_cmd stat -c '%U:%G:%a' -- "$component")"
    if [[ "$resolved" != "$component" ]] || [[ "$metadata" != root:root:755 ]]; then
      echo "unsafe observer state namespace metadata: $component" >&2
      exit 2
    fi
  done
  if sudo_cmd test -L /var/lib/openvpn-web || ! sudo_cmd test -d /var/lib/openvpn-web; then
    echo "unsafe observer state parent" >&2
    exit 2
  fi
  if [[ "$(sudo_cmd readlink -e -- /var/lib/openvpn-web)" != /var/lib/openvpn-web ]]; then
    echo "observer state parent is noncanonical" >&2
    exit 2
  fi
  case "$(sudo_cmd stat -c '%U:%G:%a' -- /var/lib/openvpn-web)" in
    openvpn-web:openvpn-web:755|root:openvpn-web:1770) ;;
    *) echo "unsafe observer state parent metadata" >&2; exit 2 ;;
  esac
}

validate_execution_boundary() {
  local wrapper=/usr/local/sbin/server-observer
  local runtime=/usr/local/lib/openvpn-web-server-observer
  local service=/etc/systemd/system/server-observer.service
  local timer=/etc/systemd/system/server-observer.timer
  if ! sudo_cmd test -e "$wrapper" && ! sudo_cmd test -e "$runtime" && \
    ! sudo_cmd test -e "$service" && ! sudo_cmd test -e "$timer"; then
    execution_boundary=absent
    return
  fi
  if sudo_cmd test -f "$wrapper" && ! sudo_cmd test -e "$runtime" && \
    sudo_cmd test -f "$service" && sudo_cmd test -f "$timer" && \
    sudo_cmd grep -Fq '/opt/openvpn-web' "$wrapper" && \
    sudo_cmd grep -Fq 'BindReadOnlyPaths=/etc/openvpn-web/server-observer.key' "$service"; then
    execution_boundary=legacy-unsafe
    return
  fi
  if sudo_cmd test -f "$wrapper" && sudo_cmd test -d "$runtime" && \
    sudo_cmd test -f "$service" && sudo_cmd test -f "$timer" && \
    sudo_cmd grep -Fq 'exec /usr/bin/python3 -I /usr/local/lib/openvpn-web-server-observer/observer_main.py' "$wrapper" && \
    ! sudo_cmd grep -Fq '/opt/openvpn-web' "$wrapper" && \
    sudo_cmd grep -Fq 'ReadOnlyPaths=/usr/local/lib/openvpn-web-server-observer' "$service" && \
    sudo_cmd grep -Fq 'InaccessiblePaths=/opt/openvpn-web' "$service"; then
    execution_boundary=isolated
    return
  fi
  echo "refusing inconsistent or unsafe server-observer execution assets" >&2
  exit 2
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
      echo "server-observer.service failed while quiescing" >&2
      exit 2
    fi
    sleep 1
    ((attempts += 1))
  done
  echo "server-observer.service did not quiesce" >&2
  exit 2
}

restore_timer() {
  local exit_code=$?
  rm -f -- "$TMP_MANIFEST"
  if [[ "$state_parent_locked" == 1 ]]; then
    if ! sudo_cmd tar --acls --xattrs --selinux --numeric-owner --same-owner --same-permissions \
      -xpf "$BACKUP_ROOT/server-observer-state-parent.tar" -C /var/lib; then
      exit_code=1
    fi
  fi
  if [[ "$timer_was_active" == 1 && "$execution_boundary" == isolated ]]; then
    if ! sudo_cmd systemctl start server-observer.timer; then
      exit_code=1
    fi
  fi
  exit "$exit_code"
}
trap restore_timer EXIT

backup_asset() {
  local name="$1" kind="$2" source="$3"
  if sudo_cmd test -L "$source"; then
    echo "refusing symlinked server-observer asset: $source" >&2
    exit 2
  fi
  if sudo_cmd test -e "$source"; then
    case "$kind" in
      file) sudo_cmd test -f "$source" ;;
      directory)
        sudo_cmd test -d "$source"
        reject_nested_symlinks "$source"
        ;;
      *) exit 2 ;;
    esac
    sudo_cmd cp -a -- "$source" "$BACKUP_ROOT/$name"
    printf '%s %s present\n' "$name" "$kind" >> "$TMP_MANIFEST"
  else
    printf '%s %s absent\n' "$name" "$kind" >> "$TMP_MANIFEST"
  fi
}

sudo_cmd mkdir --mode=0700 -- "$BACKUP_ROOT"
validate_backup_root "$BACKUP_ROOT"
validate_state_namespace
validate_root_owned_asset server-observer file /usr/local/sbin/server-observer
validate_root_owned_asset server-observer-runtime directory /usr/local/lib/openvpn-web-server-observer
validate_root_owned_asset server-observer.service file /etc/systemd/system/server-observer.service
validate_root_owned_asset server-observer.timer file /etc/systemd/system/server-observer.timer
validate_execution_boundary

service_state="$(sudo_cmd systemctl show -p ActiveState --value server-observer.service 2>/dev/null || true)"
if [[ "$service_state" == failed ]]; then
  echo "server-observer.service is failed; refusing backup" >&2
  exit 2
fi
timer_load_state="$(sudo_cmd systemctl show -p LoadState --value server-observer.timer 2>/dev/null || true)"
if [[ -z "$timer_load_state" || "$timer_load_state" == not-found ]]; then
  timer_enabled=not-found
  timer_active=unknown
else
  timer_enabled="$(sudo_cmd systemctl is-enabled server-observer.timer 2>/dev/null || true)"
  timer_active="$(sudo_cmd systemctl is-active server-observer.timer 2>/dev/null || true)"
fi
if [[ "$timer_active" == active ]]; then
  timer_was_active=1
fi
if [[ -n "$timer_load_state" && "$timer_load_state" != not-found ]]; then
  sudo_cmd systemctl stop server-observer.timer
fi
wait_for_observer

printf 'timer-enabled %s\ntimer-active %s\nexecution-boundary %s\n' \
  "$timer_enabled" "$timer_active" "$execution_boundary" >> "$TMP_MANIFEST"
backup_asset server-observer file /usr/local/sbin/server-observer
backup_asset server-observer-runtime directory /usr/local/lib/openvpn-web-server-observer
backup_asset server-observer.service file /etc/systemd/system/server-observer.service
backup_asset server-observer.timer file /etc/systemd/system/server-observer.timer
sudo_cmd tar --acls --xattrs --selinux --numeric-owner -cpf \
  "$BACKUP_ROOT/server-observer-state-parent.tar" --no-recursion \
  -C /var/lib openvpn-web
printf 'server-observer-state-parent metadata present\n' >> "$TMP_MANIFEST"
sudo_cmd chown root:openvpn-web /var/lib/openvpn-web
sudo_cmd chmod 1750 /var/lib/openvpn-web
state_parent_locked=1
if sudo_cmd test -e /var/lib/openvpn-web/server-observer; then
  if sudo_cmd test -L /var/lib/openvpn-web/server-observer || \
    ! sudo_cmd test -d /var/lib/openvpn-web/server-observer || \
    [[ "$(sudo_cmd stat -c '%U:%G:%a' -- /var/lib/openvpn-web/server-observer)" != openvpm:openvpn-web:750 ]]; then
    echo "observer state changed while locking its parent" >&2
    exit 2
  fi
fi
backup_asset server-observer-state directory /var/lib/openvpn-web/server-observer
sudo_cmd install -m 0600 -o root -g root "$TMP_MANIFEST" "$rollback_manifest"

printf 'Server-observer rollback backup: %s\n' "$BACKUP_ROOT"
