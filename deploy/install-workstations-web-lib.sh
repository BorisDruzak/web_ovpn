#!/usr/bin/env bash
# Sourced by the existing installer; APP, ENV_PATH and sudo_cmd are inherited.
workstations_quiesce() {
  local unit load_state active_state
  for unit in workstations-reconcile.timer workstations-reconcile.service; do
    load_state="$(sudo_cmd systemctl show --property=LoadState --value "$unit")" || {
      [[ "$load_state" == not-found ]] || return 1
    }
    case "$load_state" in
      not-found|loaded|masked) ;;
      *) return 1 ;;
    esac
    active_state="$(sudo_cmd systemctl show --property=ActiveState --value "$unit")" || {
      [[ "$load_state" == not-found && "$active_state" == inactive ]] || return 1
    }
    case "$active_state" in
      inactive|failed|active|activating|deactivating|reloading|refreshing) ;;
      *) return 1 ;;
    esac
    if [[ "$unit" == *.timer && "$load_state" != not-found ]]; then
      sudo_cmd systemctl disable --now "$unit" || return
    fi
    if [[ "$load_state" != not-found || ( "$active_state" != inactive && "$active_state" != failed ) ]]; then
      sudo_cmd systemctl stop "$unit" || return
    fi
    active_state="$(sudo_cmd systemctl show --property=ActiveState --value "$unit")" || {
      [[ "$load_state" == not-found && "$active_state" == inactive ]] || return 1
    }
    case "$active_state" in inactive|failed) ;; *) return 1 ;; esac
  done
}

workstations_gate() {
  workstations_quiesce || return
  sudo_cmd systemd-analyze verify /etc/systemd/system/workstations-reconcile.service \
    /etc/systemd/system/workstations-reconcile.timer || return
  if sudo_cmd -u openvpn-web "$APP/.venv/bin/python" "$APP/deploy/workstations_deployment.py" \
    --app-dir "$APP" --env-file "$ENV_PATH" --initialize-schema; then
    sudo_cmd systemctl enable --now workstations-reconcile.timer
  else
    local readiness_status=$?
    if [[ "$readiness_status" -eq 77 ]]; then
      printf '%s\n' 'Workstation integration is not configured; reconciliation timer remains disabled'
    else
      printf '%s\n' 'Workstation readiness failed; reconciliation timer remains disabled' >&2
      return "$readiness_status"
    fi
  fi
}
