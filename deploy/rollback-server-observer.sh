#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${SUDO_PASSWORD:-}" ]] || [[ -z "${BACKUP_ROOT:-}" ]]; then
  echo "SUDO_PASSWORD and BACKUP_ROOT are required" >&2
  exit 2
fi

sudo_cmd() {
  printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' "$@"
}

rollback_manifest="$BACKUP_ROOT/rollback.assets"

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
  if sudo_cmd test -L "$rollback_manifest" || ! sudo_cmd test -f "$rollback_manifest" || \
    [[ "$(sudo_cmd stat -c '%u:%g:%a' -- "$rollback_manifest")" != 0:0:600 ]]; then
    echo "server-observer rollback manifest is unsafe" >&2
    exit 2
  fi
}

reject_nested_symlinks() {
  local path="$1" unsafe
  unsafe="$(sudo_cmd find "$path" -type l -print -quit)"
  if [[ -n "$unsafe" ]]; then
    echo "refusing symlinked server-observer rollback source" >&2
    exit 2
  fi
}

validate_manifest_asset() {
  local name="$1" kind="$2" state count source="$BACKUP_ROOT/$name"
  count="$(sudo_cmd awk -v name="$name" -v kind="$kind" '$1 == name && $2 == kind && ($3 == "present" || $3 == "absent") {count++} END {print count + 0}' "$rollback_manifest")"
  if [[ "$count" != 1 ]]; then
    echo "rollback manifest has invalid asset state: $name" >&2
    exit 2
  fi
  state="$(sudo_cmd awk -v name="$name" -v kind="$kind" '$1 == name && $2 == kind {print $3}' "$rollback_manifest")"
  if [[ "$state" == present ]]; then
    if [[ "$kind" == metadata ]]; then
      source="$source.tar"
    fi
    if sudo_cmd test -L "$source"; then
      echo "rollback source is symlinked: $source" >&2
      exit 2
    fi
    case "$kind" in
      file) sudo_cmd test -f "$source" ;;
      directory)
        sudo_cmd test -d "$source"
        reject_nested_symlinks "$source"
        ;;
      metadata) sudo_cmd test -f "$source" ;;
      *) exit 2 ;;
    esac
  elif sudo_cmd test -e "$source" || sudo_cmd test -L "$source"; then
    echo "rollback source exists although prior asset was absent: $source" >&2
    exit 2
  fi
}

validate_parent_archive() {
  local path="$1" entries
  if sudo_cmd test -L "$path" || ! sudo_cmd test -f "$path" || \
    [[ "$(sudo_cmd stat -c '%U:%G' -- "$path")" != root:root ]]; then
    echo "observer state-parent archive is unsafe" >&2
    exit 2
  fi
  entries="$(sudo_cmd tar -tf "$path")"
  if [[ "$entries" != openvpn-web/ ]]; then
    echo "observer state-parent archive has unexpected entries" >&2
    exit 2
  fi
}

manifest_value() {
  local key="$1" count
  count="$(sudo_cmd awk -v key="$key" '$1 == key {count++} END {print count + 0}' "$rollback_manifest")"
  if [[ "$count" != 1 ]]; then
    echo "rollback manifest has invalid unit state: $key" >&2
    exit 2
  fi
  sudo_cmd awk -v key="$key" '$1 == key {print $2}' "$rollback_manifest"
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
      sudo_cmd systemctl reset-failed server-observer.service
      return
    fi
    sleep 1
    ((attempts += 1))
  done
  echo "server-observer.service did not quiesce" >&2
  exit 2
}

stop_observer() {
  sudo_cmd systemctl stop server-observer.timer || true
  wait_for_observer
}

asset_state() {
  local name="$1" kind="$2"
  sudo_cmd awk -v name="$name" -v kind="$kind" '$1 == name && $2 == kind {print $3}' "$rollback_manifest"
}

restore_asset() {
  local name="$1" kind="$2" destination="$3" state
  state="$(asset_state "$name" "$kind")"
  case "$kind" in
    file) sudo_cmd rm -f -- "$destination" ;;
    directory) sudo_cmd rm -rf -- "$destination" ;;
    *) exit 2 ;;
  esac
  if [[ "$state" == present ]]; then
    sudo_cmd cp -a -- "$BACKUP_ROOT/$name" "$destination"
  fi
}

validate_backup_root "$BACKUP_ROOT"
validate_manifest_asset server-observer file
validate_manifest_asset server-observer-runtime directory
validate_manifest_asset server-observer.service file
validate_manifest_asset server-observer.timer file
validate_manifest_asset server-observer-state directory
validate_manifest_asset server-observer-state-parent metadata
validate_parent_archive "$BACKUP_ROOT/server-observer-state-parent.tar"
if [[ "$(asset_state server-observer-runtime directory)" == present ]]; then
  reject_nested_symlinks "$BACKUP_ROOT/server-observer-runtime"
fi
timer_enabled="$(manifest_value timer-enabled)"
timer_active="$(manifest_value timer-active)"
boundary_state="$(manifest_value execution-boundary)"
case "$timer_enabled" in enabled|disabled|static|indirect|not-found) ;; *) exit 2 ;; esac
case "$timer_active" in active|inactive|failed|unknown) ;; *) exit 2 ;; esac
case "$boundary_state" in isolated|legacy-unsafe|absent) ;; *) exit 2 ;; esac

for component in /usr /usr/local /usr/local/lib /var /var/lib; do
  if sudo_cmd test -L "$component" || ! sudo_cmd test -d "$component" || \
    [[ "$(sudo_cmd readlink -e -- "$component")" != "$component" ]] || \
    [[ "$(sudo_cmd stat -c '%U:%G:%a' -- "$component")" != root:root:755 ]]; then
    echo "unsafe rollback namespace component: $component" >&2
    exit 2
  fi
done
if sudo_cmd test -L /var/lib/openvpn-web || ! sudo_cmd test -d /var/lib/openvpn-web; then
  echo "unsafe observer state parent" >&2
  exit 2
fi
case "$(sudo_cmd stat -c '%U:%G:%a' -- /var/lib/openvpn-web)" in
  openvpn-web:openvpn-web:755|root:openvpn-web:1770) ;;
  *) echo "unsafe observer state parent metadata" >&2; exit 2 ;;
esac

stop_observer
sudo_cmd chown root:openvpn-web /var/lib/openvpn-web
sudo_cmd chmod 1770 /var/lib/openvpn-web
restore_asset server-observer-state directory /var/lib/openvpn-web/server-observer
sudo_cmd tar --acls --xattrs --selinux --numeric-owner --same-owner --same-permissions \
  -xpf "$BACKUP_ROOT/server-observer-state-parent.tar" -C /var/lib

case "$boundary_state" in
  isolated)
    restore_asset server-observer file /usr/local/sbin/server-observer
    restore_asset server-observer-runtime directory /usr/local/lib/openvpn-web-server-observer
    restore_asset server-observer.service file /etc/systemd/system/server-observer.service
    restore_asset server-observer.timer file /etc/systemd/system/server-observer.timer
    sudo_cmd systemctl daemon-reload
    if [[ "$timer_enabled" == enabled ]]; then
      sudo_cmd systemctl enable server-observer.timer
    else
      sudo_cmd systemctl disable server-observer.timer || true
    fi
    if [[ "$timer_active" == active ]]; then
      sudo_cmd systemctl start server-observer.timer
    else
      sudo_cmd systemctl stop server-observer.timer || true
    fi
    ;;
  legacy-unsafe|absent)
    sudo_cmd systemctl disable server-observer.timer || true
    sudo_cmd rm -f -- /usr/local/sbin/server-observer
    sudo_cmd rm -rf -- /usr/local/lib/openvpn-web-server-observer
    sudo_cmd rm -f -- /etc/systemd/system/server-observer.service
    sudo_cmd rm -f -- /etc/systemd/system/server-observer.timer
    sudo_cmd systemctl daemon-reload
    ;;
esac
