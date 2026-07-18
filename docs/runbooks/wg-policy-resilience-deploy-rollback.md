# WG policy-routing: deploy, verify and roll back

## Scope and safety boundary

This runbook installs the self-healing lifecycle for the existing VLAN50
policy route through `wg0`. It owns only table `123`, rule priority `1000` with
mark `0x1`, and the `VPN_POLICY_MARK` / `VPN_POLICY_NAT` iptables-nft chains.

Do not use this procedure to change OpenVPN profiles, MSS/MTU, OPNsense,
MikroTik or WireGuard peer configuration. In particular, `Table = off` remains
required in `/etc/wireguard/wg0.conf`.

## Deploy without restarting tunnels

Run from the repository checkout copied to `openvpm`; the deploy account must
have sudo access. This installer restarts `openvpn-web.service`, but does not
restart `openvpn-server@server.service` or `wg-quick@wg0.service`.

```bash
stamp="$(date +%Y%m%d-%H%M%S)"
sudo install -d -m 0700 "/root/wg-policy-backup-$stamp"
sudo cp -a /usr/local/sbin/vpn-policy.sh \
  /etc/systemd/system/vpn-policy.service \
  /etc/systemd/system/vpn-runtime-health.service \
  /etc/systemd/system/vpn-runtime-health.timer \
  "/root/wg-policy-backup-$stamp/" 2>/dev/null || true
SUDO_PASSWORD='*** supplied securely ***' ./deploy/install-openvpn-web.sh
```

The installer places the assets, reloads systemd, enables `vpn-policy.service`
for the next boot and starts the one-minute health timer. It intentionally does
not restart `wg0`; use the maintenance-window check below to prove the new
lifecycle behavior.

## Non-mutating acceptance checks

Wait for one timer run, then run:

```bash
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
sudo systemctl status wg-quick@wg0.service vpn-policy.service vpn-runtime-health.timer
sudo ip rule show
sudo ip route show table 123
sudo journalctl -u vpn-runtime-health.service -n 20 --no-pager
```

Expected results: exactly the marked policy rule points to table 123, that
table has `default dev wg0`, both managed chains are present, no rule mentions
table `51820`, and `runtime-health --strict` exits 0. The command reports
handshake age and byte counters but never prints WireGuard key material.

## Controlled restart verification

Use an approved maintenance window. Keep an OpenVPN client session and an
independent console path available before restarting WireGuard.

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
This restores only the four WG-policy assets; it does not modify peer keys,
OpenVPN configuration or router settings.

```bash
BACKUP_DIR=/root/wg-policy-backup-YYYYMMDD-HHMMSS
sudo install -m 0755 "$BACKUP_DIR/vpn-policy.sh" /usr/local/sbin/vpn-policy.sh
sudo install -m 0644 "$BACKUP_DIR/vpn-policy.service" /etc/systemd/system/vpn-policy.service
sudo install -m 0644 "$BACKUP_DIR/vpn-runtime-health.service" /etc/systemd/system/vpn-runtime-health.service
sudo install -m 0644 "$BACKUP_DIR/vpn-runtime-health.timer" /etc/systemd/system/vpn-runtime-health.timer
sudo systemctl daemon-reload
sudo systemctl restart wg-quick@wg0.service
sudo systemctl start vpn-policy.service
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
```

If a pre-existing installation did not yet have one of these files, its backup
will be absent; remove only that newly installed asset after confirming the
exact path, then reload systemd and rerun the acceptance checks.
