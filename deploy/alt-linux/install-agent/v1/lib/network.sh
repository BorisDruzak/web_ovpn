#!/bin/bash

ALT_INSTALL_SLEEP=${ALT_INSTALL_SLEEP:-sleep}
ALT_INSTALL_SYS_CLASS_NET=${ALT_INSTALL_SYS_CLASS_NET:-/sys/class/net}
ALT_INSTALL_DHCP_HOOK=${ALT_INSTALL_DHCP_HOOK:-/usr/libexec/alt-install-agent-lib/lib/dhcp-hook.sh}

network_request_dhcp_once() {
    local interface interface_path
    command -v udhcpc >/dev/null 2>&1 || return 0
    for interface_path in "$ALT_INSTALL_SYS_CLASS_NET"/*; do
        [[ -d "$interface_path" ]] || continue
        interface=${interface_path##*/}
        [[ "$interface" != lo ]] || continue
        ip link set dev "$interface" up >/dev/null 2>&1 || continue
        udhcpc -n -q -T 3 -t 3 -i "$interface" -s "$ALT_INSTALL_DHCP_HOOK" \
            >/dev/null 2>&1 || true
    done
}

network_prepare() {
    local attempt
    for ((attempt = 1; attempt <= 6; attempt++)); do
        network_request_dhcp_once
        if ip -4 route get 192.168.100.17 >/dev/null 2>&1; then
            return 0
        fi
        ((attempt == 6)) || "$ALT_INSTALL_SLEEP" "$attempt"
    done
    printf '%s\n' 'ALT_INSTALL_ERROR network_unavailable' >&2
    return 1
}
