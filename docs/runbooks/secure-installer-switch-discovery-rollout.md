# Secure installer and disabled switch discovery rollout

Use this procedure only in an approved maintenance window. It rotates the web
administrator credential and verifies switch identity with read-only system
SNMP requests. It does not restart OpenVPN or WireGuard, run SNMP SET, enable
a source, enable netctl-collect.timer, or invoke the Netctl collection command.

## Preconditions and rollback set

Keep the timer disabled before every step.

    test "$(systemctl is-enabled netctl-collect.timer)" = disabled
    test "$(systemctl is-active netctl-collect.timer)" = inactive

Create the database copy on the data volume and protected configuration copy on
the system volume. Validate database integrity and archive hashes before
changing the web environment. The database target is
/var/lib/netctl/backups; environment archives are under /var/backups/netctl.

## Protected credential rotation

Supply the new password only through the approved operator secret channel. Do
not put it in a shell command, history, source file, ticket, terminal output,
or this runbook. The operator updates only
/etc/openvpn-web/openvpn-web.env, preserves root:openvpn-web 0640, and
restarts only the web service.

    sudoedit /etc/openvpn-web/openvpn-web.env
    sudo chown root:openvpn-web /etc/openvpn-web/openvpn-web.env
    sudo chmod 0640 /etc/openvpn-web/openvpn-web.env
    sudo rm -f /tmp/openvpn-web-admin-password.txt /tmp/openvpn-web-api-token.txt
    sudo systemctl restart openvpn-web.service
    test "$(systemctl is-active openvpn-web.service)" = active
    test "$(systemctl is-active openvpn-server@server.service)" = active
    curl -fsS -o /dev/null http://127.0.0.1:8088/login

## Protected SNMP community

Add a supplied community only through sudoedit to /etc/netctl/secrets.env.
Never place it in source YAML, shell history, output, this runbook, or Git.
After the edit, validate only file metadata:

    sudo chown root:netctl /etc/netctl/secrets.env
    sudo chmod 0640 /etc/netctl/secrets.env
    sudo -u netctl test -r /etc/netctl/secrets.env

## Disabled source guard

Set source_name to the approved source name without printing its inspect
payload. The helper rejects a missing source, a non-SNMP source, or any value
other than the JSON boolean false for enabled.

    source_name='replace-with-approved-source-name'
    assert_disabled_snmp_source() {
      inspection="$(sudo -u netctl /usr/local/sbin/netctl --json sources inspect "$source_name")" || return 1
      printf '%s' "$inspection" | sudo /opt/openvpn-web/.venv/bin/python -c '
    import json, sys
    source = json.load(sys.stdin).get("source")
    if not isinstance(source, dict):
        raise SystemExit(1)
    if source.get("name") != sys.argv[1]:
        raise SystemExit(1)
    if source.get("driver") != "snmp_switch":
        raise SystemExit(1)
    if source.get("enabled") is not False:
        raise SystemExit(1)
    ' "$source_name"
    }

    test "$(systemctl is-enabled netctl-collect.timer)" = disabled
    test "$(systemctl is-active netctl-collect.timer)" = inactive
    assert_disabled_snmp_source
    sudo -u netctl /usr/local/sbin/netctl --json sources discover "$source_name"
    assert_disabled_snmp_source
    test "$(systemctl is-enabled netctl-collect.timer)" = disabled
    test "$(systemctl is-active netctl-collect.timer)" = inactive

The discovery result may be known or requires_profile. Record only the source
name, status, profile decision and final disabled state. Do not record
credentials, endpoint details, raw SNMP rows, or switch inventory.
