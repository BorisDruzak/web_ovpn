#!/bin/bash

ALT_INSTALL_CMDLINE_FILE=${ALT_INSTALL_CMDLINE_FILE:-/proc/cmdline}
ALT_INSTALL_EXECUTION_CONTROLLER_CONFIG=${ALT_INSTALL_EXECUTION_CONTROLLER_CONFIG:-/usr/share/alt-install/execution-controller-url}
ALT_INSTALL_EXECUTION_CONTROLLER=${ALT_INSTALL_EXECUTION_CONTROLLER:-https://192.168.100.17:18092}
ALT_INSTALL_EXECUTION_CA=${ALT_INSTALL_EXECUTION_CA:-/usr/share/alt-install/execution-ca.pem}
ALT_INSTALL_HELPER=${ALT_INSTALL_HELPER:-/usr/libexec/alt-install-helper}
ALT_INSTALL_PUBLIC_KEY=${ALT_INSTALL_PUBLIC_KEY:-/usr/share/alt-install/public-key.json}
ALT_INSTALL_RELAY_START_DELAY=${ALT_INSTALL_RELAY_START_DELAY:-0.2}

cmdline_value() {
    local wanted="$1" token
    while IFS= read -r token; do
        case "$token" in
            "$wanted"=*)
                printf '%s\n' "${token#*=}"
                return 0
                ;;
        esac
    done < <(tr '[:space:]' '\n' < "$ALT_INSTALL_CMDLINE_FILE")
    return 1
}

config_load() {
    local configured_controller embedded_controller
    local -a controller_lines=()

    [[ "$(cmdline_value sosnadmin.mode)" == agent-v2 ]] || return 1
    [[ -f "$ALT_INSTALL_EXECUTION_CONTROLLER_CONFIG" &&
        ! -L "$ALT_INSTALL_EXECUTION_CONTROLLER_CONFIG" ]] || return 1
    mapfile -t controller_lines < "$ALT_INSTALL_EXECUTION_CONTROLLER_CONFIG"
    ((${#controller_lines[@]} == 1)) || return 1
    embedded_controller=${controller_lines[0]}
    [[ "$embedded_controller" == https://192.168.100.17:18092 ]] ||
        return 1
    configured_controller=$(cmdline_value sosnadmin.controller) || true
    if [[ -n "$configured_controller" ]]; then
        [[ "$configured_controller" == "$embedded_controller" ]] ||
            return 1
    fi
    [[ "$ALT_INSTALL_EXECUTION_CONTROLLER" == "$embedded_controller" ]] ||
        return 1
    [[ -f "$ALT_INSTALL_EXECUTION_CA" &&
        ! -L "$ALT_INSTALL_EXECUTION_CA" ]] || return 1
    [[ -f "$ALT_INSTALL_PUBLIC_KEY" &&
        ! -L "$ALT_INSTALL_PUBLIC_KEY" ]] || return 1
    export ALT_INSTALL_EXECUTION_CONTROLLER
}
