#!/bin/bash

readonly INVENTORY_PROC_ROOT="${SOSNADMIN_PROC_ROOT:-/proc}"
readonly INVENTORY_SYS_ROOT="${SOSNADMIN_SYS_ROOT:-/sys}"
readonly max_interfaces=16
readonly max_disks=16

sanitize_json_string() {
    LC_ALL=C printf '%s' "${1:0:128}" | sed 's/[^A-Za-z0-9 ._:\/-]/_/g'
}

read_first_line() {
    local path="$1"
    [[ -r "$path" ]] || return 0
    IFS= read -r value < "$path" || true
    sanitize_json_string "${value:-}"
}

build_inventory() {
    local uuid manufacturer product memory boot_id boot_media
    uuid=$(read_first_line "$INVENTORY_SYS_ROOT/class/dmi/id/product_uuid")
    manufacturer=$(read_first_line "$INVENTORY_SYS_ROOT/class/dmi/id/sys_vendor")
    product=$(read_first_line "$INVENTORY_SYS_ROOT/class/dmi/id/product_name")
    memory=$(awk '/MemTotal:/ {print $2; exit}' "$INVENTORY_PROC_ROOT/meminfo" 2>/dev/null || true)
    boot_id=$(read_first_line "$INVENTORY_PROC_ROOT/sys/kernel/random/boot_id")
    boot_media=$(findmnt -n -o SOURCE,FSTYPE,OPTIONS /image 2>/dev/null || true)
    boot_media=$(sanitize_json_string "$boot_media")
    printf '{"machine":{"uuid":"%s","manufacturer":"%s","product_name":"%s","memory_kib":"%s","boot_id":"%s"},"boot_media":"%s","limits":{"interfaces":%s,"disks":%s}}\n' \
        "$uuid" "$manufacturer" "$product" "$(sanitize_json_string "$memory")" "$boot_id" "$boot_media" "$max_interfaces" "$max_disks"
}
