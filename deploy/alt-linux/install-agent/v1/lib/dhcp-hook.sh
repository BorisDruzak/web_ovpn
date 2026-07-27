#!/bin/bash
set -eu

mask_to_prefix() {
    local octet prefix=0
    local -a octets

    IFS=. read -r -a octets <<<"${1:-255.255.255.0}"
    for octet in "${octets[@]}"; do
        case "$octet" in
            255) prefix=$((prefix + 8)) ;;
            254) prefix=$((prefix + 7)) ;;
            252) prefix=$((prefix + 6)) ;;
            248) prefix=$((prefix + 5)) ;;
            240) prefix=$((prefix + 4)) ;;
            224) prefix=$((prefix + 3)) ;;
            192) prefix=$((prefix + 2)) ;;
            128) prefix=$((prefix + 1)) ;;
            0) ;;
            *) exit 0 ;;
        esac
    done
    printf '%s\n' "$prefix"
}

case "${1:-}" in
    bound|renew)
        : "${interface:?missing DHCP interface}"
        : "${ip:?missing DHCP address}"
        prefix=$(mask_to_prefix "${mask:-255.255.255.0}")
        ip -4 addr replace "$ip/$prefix" dev "$interface"
        for gateway in ${router:-}; do
            ip -4 route replace default via "$gateway" dev "$interface"
        done
        ;;
esac
