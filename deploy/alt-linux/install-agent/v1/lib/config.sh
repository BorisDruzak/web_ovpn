#!/bin/bash

ALT_INSTALL_CMDLINE_FILE=${ALT_INSTALL_CMDLINE_FILE:-/proc/cmdline}
ALT_INSTALL_CONTROLLER_CONFIG=${ALT_INSTALL_CONTROLLER_CONFIG:-/usr/share/alt-install/controller-url}
ALT_INSTALL_HELPER=${ALT_INSTALL_HELPER:-/usr/libexec/alt-install-helper}
ALT_INSTALL_PUBLIC_KEY=${ALT_INSTALL_PUBLIC_KEY:-/usr/share/alt-install/public-key.json}
ALT_INSTALL_SOURCE_ISO=${ALT_INSTALL_SOURCE_ISO:-/usr/share/alt-install/source_iso.json}
ALT_INSTALL_BUILD_ID=${ALT_INSTALL_BUILD_ID:-/usr/share/alt-install/build-id}
ALT_INSTALL_AGENT_VERSION=${ALT_INSTALL_AGENT_VERSION:-1.0.0}

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
    local configured_controller= embedded_controller=
    local -a controller_lines=()
    ALT_INSTALL_MODE=$(cmdline_value sosnadmin.mode) || return 1
    [[ "$ALT_INSTALL_MODE" == 'agent-v1' ]] || return 1
    [[ -f "$ALT_INSTALL_CONTROLLER_CONFIG" && ! -L "$ALT_INSTALL_CONTROLLER_CONFIG" ]] || return 1
    mapfile -t controller_lines < "$ALT_INSTALL_CONTROLLER_CONFIG"
    ((${#controller_lines[@]} == 1)) || return 1
    embedded_controller=${controller_lines[0]}
    case "$embedded_controller" in
        http://192.168.100.17:18089|http://192.168.100.17:18090) ;;
        *) return 1 ;;
    esac
    configured_controller=$(cmdline_value sosnadmin.controller) || true
    if [[ -z "$configured_controller" ]]; then
        ALT_INSTALL_CONTROLLER=$embedded_controller
    else
        [[ "$configured_controller" == "$embedded_controller" ]] ||
            return 1
        ALT_INSTALL_CONTROLLER=$configured_controller
    fi
    [[ "$ALT_INSTALL_CONTROLLER" == http://* ]] || return 1
    export ALT_INSTALL_MODE ALT_INSTALL_CONTROLLER
}
