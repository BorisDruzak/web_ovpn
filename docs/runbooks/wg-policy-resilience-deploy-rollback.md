# WG policy-routing: deploy, verify and roll back

## Scope and safety boundary

This runbook installs the self-healing lifecycle for the existing VLAN50
policy route through `wg0`. It owns only table `123`, rule priority `1000` with
mark `0x1`, and the `VPN_POLICY_MARK` / `VPN_POLICY_NAT` iptables-nft chains.
The reconciler uses the same `/run/lock/vpn-policy.lock` flock as the normal
policy service, so it cannot race a controlled policy-service start or stop.

Do not use this procedure to change OpenVPN profiles, MSS/MTU, OPNsense,
MikroTik or WireGuard peer configuration. In particular, `Table = off` remains
required in `/etc/wireguard/wg0.conf`.

`vpn-policy.service` deliberately uses `Wants=` (not `Requires=` or
`BindsTo=`) for `wg-quick@wg0.service`. This lets it install the marked,
`unreachable default` route even if WireGuard is temporarily unavailable at
boot (for example while endpoint DNS is unavailable). `PartOf=` still makes a
controlled WG restart rerun the policy reconciler; once `wg0` exists, it
replaces the unreachable route with `default dev wg0` and reinstates NAT.

## Deploy without restarting tunnels

Run from the repository checkout copied to `openvpm`; the deploy account must
have sudo access. This installer restarts `openvpn-web.service`, but does not
restart `openvpn-server@server.service` or `wg-quick@wg0.service`.

```bash
stamp="$(date +%Y%m%d-%H%M%S)"
sudo install -d -m 0700 "/root/wg-policy-backup-$stamp"
sudo cp -a /usr/local/sbin/vpn-policy.sh \
  /etc/systemd/system/vpn-policy.service \
  /etc/systemd/system/vpn-policy-reconcile.service \
  /etc/systemd/system/vpn-policy-reconcile.timer \
  /etc/systemd/system/vpn-runtime-health.service \
  /etc/systemd/system/vpn-runtime-health.timer \
  "/root/wg-policy-backup-$stamp/" 2>/dev/null || true
SUDO_PASSWORD='*** supplied securely ***' ./deploy/install-openvpn-web.sh
```

The installer places the assets, reloads systemd, enables `vpn-policy.service`
for the next boot, and starts both one-minute timers. The
`vpn-policy-reconcile.timer` is probe-first: it writes only when the active or
fail-closed policy has drifted. `vpn-runtime-health.timer` is alarm-only and
writes nothing. Neither timer starts, stops, restarts, or reconfigures `wg0`;
a failed peer remains fail-closed until an operator or normal service lifecycle
restores the interface.

## Post-deploy status and explicit repair verification

Wait for one timer run, then run the checks below. All commands except
`systemctl start vpn-policy-reconcile.service` are read-only. That command is
an explicit scoped repair: it first probes the policy and changes only the
managed PBR/NAT objects when it finds drift. It never starts, stops, or restarts
WireGuard or OpenVPN.

```bash
sudo systemctl status vpn-policy-reconcile.timer vpn-runtime-health.timer --no-pager
sudo systemctl start vpn-policy-reconcile.service
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
curl -fsS -H "Authorization: Bearer $OPENVPN_WEB_API_TOKEN" http://127.0.0.1:8088/api/v1/runtime-health
sudo systemctl status wg-quick@wg0.service vpn-policy.service --no-pager
sudo ip rule show
sudo ip route show table 123
sudo journalctl -u vpn-policy-reconcile.service -u vpn-runtime-health.service -n 20 --no-pager
```

Expected results: exactly the marked policy rule points to table 123, that
table has `default dev wg0`, both managed chains are present, no rule mentions
table `51820`, and `runtime-health --strict` exits 0. The command reports
handshake age and byte counters but never prints WireGuard key material.

The Bearer endpoint returns a normal health payload even when its `overall`
field is `error`; this permits an integration to see the failed component. Do
not put its Bearer token in browser code. The authenticated
`/network/dashboard` card uses the session-only `/network/runtime-health`
endpoint instead; an unauthenticated browser request gets HTTP 303 to
`/login`. The card redacts key-like values, addresses, endpoint names, and
ports from runtime warning/error messages before inserting text into the DOM.

## Optional operator-directed WG recovery verification

Use an approved maintenance window only when an operator intentionally needs
to restart WireGuard. Keep an OpenVPN client session and an independent console
path available first. This is not a reconciler action: the reconciler itself
never starts or restarts WireGuard.

```bash
sudo systemctl restart wg-quick@wg0.service
sudo systemctl status vpn-policy.service --no-pager
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
sudo /usr/local/sbin/vpnctl --json management test
```

`vpn-policy.service` must return active and rebuild the named mark/NAT chains
after the WG restart. If strict health fails, leave OpenVPN untouched and roll
back the policy assets.

## Rollback

Replace `BACKUP_DIR` with the timestamped directory created before deployment.
This restores the policy assets captured by that version's backup; it does not
modify peer keys, OpenVPN configuration, router settings, or the WireGuard
service lifecycle. The commands intentionally do not restart
`wg-quick@wg0.service`. A backup made before the reconciler existed must not
enable the new reconciler again.

```bash
BACKUP_DIR=/root/wg-policy-backup-YYYYMMDD-HHMMSS
sudo install -m 0755 "$BACKUP_DIR/vpn-policy.sh" /usr/local/sbin/vpn-policy.sh
sudo install -m 0644 "$BACKUP_DIR/vpn-policy.service" /etc/systemd/system/vpn-policy.service
sudo install -m 0644 "$BACKUP_DIR/vpn-runtime-health.service" /etc/systemd/system/vpn-runtime-health.service
sudo install -m 0644 "$BACKUP_DIR/vpn-runtime-health.timer" /etc/systemd/system/vpn-runtime-health.timer

if sudo test -f "$BACKUP_DIR/vpn-policy-reconcile.service" \
  && sudo test -f "$BACKUP_DIR/vpn-policy-reconcile.timer"; then
  sudo install -m 0644 "$BACKUP_DIR/vpn-policy-reconcile.service" /etc/systemd/system/vpn-policy-reconcile.service
  sudo install -m 0644 "$BACKUP_DIR/vpn-policy-reconcile.timer" /etc/systemd/system/vpn-policy-reconcile.timer
  restore_reconciler=1
else
  sudo systemctl disable --now vpn-policy-reconcile.timer || true
  sudo rm -f /etc/systemd/system/vpn-policy-reconcile.service /etc/systemd/system/vpn-policy-reconcile.timer
  restore_reconciler=0
fi

sudo systemctl daemon-reload
sudo systemctl start vpn-policy.service
if [[ "$restore_reconciler" == "1" ]]; then
  sudo systemctl enable --now vpn-policy-reconcile.timer
fi
sudo systemctl enable --now vpn-runtime-health.timer
sudo systemctl status vpn-runtime-health.timer --no-pager
if [[ "$restore_reconciler" == "1" ]]; then
  sudo systemctl status vpn-policy-reconcile.timer --no-pager
fi
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
```

If only one of the two reconciler backup files is present, treat it as an
incomplete pre-feature backup: leave the reconciler disabled and remove both
new unit files as shown above. Do not restart WireGuard as part of rollback or
cleanup.
