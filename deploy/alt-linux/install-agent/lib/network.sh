#!/bin/bash

dhcp_configure() {
    local interface="$1"

    udhcpc -n -q -T 3 -t 3 -i "$interface" -s "$AGENT_ROOT/lib/dhcp-hook.sh" \
        >/dev/null 2>&1 || true
}

request_dhcp() {
    local interface

    command -v udhcpc >/dev/null 2>&1 || return 0
    for interface_path in /sys/class/net/*; do
        interface=${interface_path##*/}
        [[ "$interface" == lo || -d "$interface_path" ]] || continue
        ip link set dev "$interface" up >/dev/null 2>&1 || continue
        dhcp_configure "$interface"
        ip -4 route get 192.168.100.17 >/dev/null 2>&1 && return 0
    done
}

wait_for_controller_route() {
    local attempt=0

    request_dhcp || true
    while (( attempt < 60 )); do
        if ip -4 route get 192.168.100.17 >/dev/null 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    return 1
}
