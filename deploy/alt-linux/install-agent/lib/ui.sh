#!/bin/bash

ui_show_state() {
    local state="$1"
    local message="SOSNADMIN ALT INSTALLATION — SAFE SPIKE\nStatus: $state\nALTERATOR HAS NOT BEEN STARTED.\nNO DISK CHANGES ARE ALLOWED IN THIS SPIKE."
    if command -v dialog >/dev/null 2>&1 && [[ -t 1 ]]; then
        dialog --clear --msgbox "$message" 10 72 || true
    else
        printf '%b\n' "$message" >/dev/tty 2>/dev/null || printf '%b\n' "$message"
    fi
}
