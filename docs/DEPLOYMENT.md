# Deployment Runbook

This project is deployed as a FastAPI service on the OpenVPN host. The current production host is `openvpm@192.168.100.30`, reachable from the operator workstation as:

```bash
ssh ui-vpn-deploy
```

## Repository Layout

- `app/` - FastAPI web UI, API routes, templates, static assets, auth, audit and sync helpers.
- `deploy/vpnctl` - privileged OpenVPN control CLI. The web service calls it with `--json`.
- `deploy/install-openvpn-web.sh` - installer used to copy the app to `/opt/openvpn-web`, install systemd units and configure env files.
- `mcp/openvpn_mcp_server.py` - local stdio MCP server that calls the HTTP API.
- `tests/` - smoke, API, MCP and `vpnctl` regression tests.

## First-Time GitHub Publish

The repository can be published over SSH:

```bash
git remote add origin git@github.com:BorisDruzak/web_ovpn.git
git branch -M main
git add .
git commit -m "Initial OpenVPN web manager"
git push -u origin main
```

Before committing, verify that `.gitignore` excludes local virtual environments, caches, generated `.ovpn` files, tokens, passwords and private key material.

## Local Verification

From the project root:

```bash
python -m pytest -q
```

On the Windows Codex workstation the bundled Python runtime can be used if system Python is not configured:

```powershell
& 'C:\Users\admin-2\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q
```

## Deploy To OpenVPN Host

Package and copy the local source tree:

```powershell
tar --exclude='.git' --exclude='.pytest_cache' --exclude='__pycache__' -czf "$env:TEMP\openvpn-web-src.tgz" -C "C:\Users\admin-2\Documents\ui_vpn" .
scp "$env:TEMP\openvpn-web-src.tgz" ui-vpn-deploy:/tmp/openvpn-web-src.tgz
```

Install on the host:

```bash
ssh ui-vpn-deploy "rm -rf /tmp/openvpn-web-src && mkdir -p /tmp/openvpn-web-src && tar -xzf /tmp/openvpn-web-src.tgz -C /tmp/openvpn-web-src && cd /tmp/openvpn-web-src && SUDO_PASSWORD='<sudo-password>' bash deploy/install-openvpn-web.sh"
```

Do not commit or publish the sudo password. For interactive deployment, enter it only in the shell command or through the operator's secret store.

## Remote Verification

After deployment:

```bash
ssh ui-vpn-deploy "cd /opt/openvpn-web && .venv/bin/python -m pytest -q"
ssh ui-vpn-deploy "systemctl is-active openvpn-web && systemctl is-active openvpn-server@server"
ssh ui-vpn-deploy "systemctl is-active netctl-collect.timer"
```

Useful live checks:

```bash
ssh ui-vpn-deploy "journalctl -u openvpn-web -n 100 --no-pager"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json status"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json logs -n 50"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json sources list"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json dashboard"
```

## SSH Server Draft Checks

The Test servers page verifies an existing SSH target from the gateway; it does
not enroll the target as a Network Observer collector. The observer private key
remains gateway-only and is never downloaded, displayed, copied, or stored with
the draft.

For each target:

1. Download or copy the displayed observer public key from `/network/server-drafts`.
2. Install that public key in the target account's `~/.ssh/authorized_keys`.
3. Create a server draft with the target name, host, SSH user, and port; the worker scans the target host key.
4. Compare the displayed host-key fingerprint with a trusted, out-of-band source, then confirm the fingerprint in the page.
5. Wait for the worker to complete the pinned SSH check, then read its fixed SSH result in the draft list.

Drafts only request these scan, confirmation, and pinned-check actions. They do
not add collector targets, change the target's host key, or expose host keys or
private storage beyond the fixed check result.

## SSH Server Draft Worker Handoff and Rollback

This is a deliberately narrow handoff for the SSH server-draft worker. It must
not be used to change Network Observer collection or OpenVPN. In particular,
do **not** restart OpenVPN, and do **not** create, edit, remove, test, or
otherwise modify any collector configuration, `/etc/netctl`, or
`netctl-collect` unit.

Run it only on an existing OpenVPN web deployment that already has the
`openvpn-web` and `openvpm` accounts plus the regular
`/etc/openvpn-web/server-observer.key` file. The scoped installer verifies
those prerequisites and refuses to create or modify them.

Before running the installer, make a timestamped backup containing **only**
the draft-worker systemd units and the draft state directory:

```bash
BACKUP_ROOT="/root/openvpn-web-server-drafts-backup-$(date -u +%Y%m%d%H%M%S)"
sudo install -d -m 0700 "$BACKUP_ROOT"
sudo cp -a \
  /etc/systemd/system/server-draft-worker.service \
  /etc/systemd/system/server-draft-worker.path \
  /var/lib/openvpn-web/server-drafts \
  "$BACKUP_ROOT/"
printf 'Draft-worker rollback backup: %s\n' "$BACKUP_ROOT"
```

Copy the reviewed source bundle to the host as described in [Deploy To OpenVPN
Host](#deploy-to-openvpn-host), then invoke only the dedicated draft-worker
installer from the extracted source directory:

```bash
cd /tmp/openvpn-web-src
SUDO_PASSWORD='<sudo-password>' bash deploy/install-server-draft-worker.sh
```

That installer installs only `/usr/local/sbin/server-draft-worker`, the two
`server-draft-worker` unit files, the three `server-drafts` directories, and
the derived observer public key. It reloads systemd and enables only
`server-draft-worker.path`; it does not alter the application bundle, collector
configuration or timers, OpenVPN, or any unrelated service. Do not enable or
start `server-draft-worker.service` directly. The path unit starts the worker
only when a public queue entry changes. Verify that boundary and the public-key
access required by the web application:

```bash
sudo systemctl is-enabled server-draft-worker.path
sudo systemctl is-active server-draft-worker.path
sudo systemctl status server-draft-worker.path --no-pager
sudo stat -c '%U:%G %a %n' /etc/openvpn-web/server-observer.pub
sudo -u openvpn-web test -r /etc/openvpn-web/server-observer.pub
```

The public key must be readable through the `openvpn-web` group (the installer
sets it to `root:openvpn-web` with mode `0644`). Do not run a target SSH test
as part of this deployment rehearsal. A target interaction begins only after
an operator has intentionally created a draft in `/network/server-drafts` and
completed the documented fingerprint-confirmation workflow.

### Rollback

If this handoff must be rolled back, first set `BACKUP_ROOT` to the exact path
printed by the backup command above. The validation below rejects a guessed,
unrelated, or symlinked backup root and verifies every restore source before
stopping services, replacing units, or deleting draft state:

```bash
BACKUP_ROOT='/root/openvpn-web-server-drafts-backup-20260720120000'
case "$BACKUP_ROOT" in
  /root/openvpn-web-server-drafts-backup-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
  *) echo 'refusing an unvalidated draft-worker backup root' >&2; exit 2 ;;
esac
BACKUP_ROOT="$(sudo readlink -f -- "$BACKUP_ROOT")"
case "$BACKUP_ROOT" in
  /root/openvpn-web-server-drafts-backup-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
  *) echo 'refusing a resolved backup root outside the draft-worker backup namespace' >&2; exit 2 ;;
esac
if ! sudo test -d "$BACKUP_ROOT" || sudo test -L "$BACKUP_ROOT" || \
  ! sudo test -f "$BACKUP_ROOT/server-draft-worker.service" || \
  sudo test -L "$BACKUP_ROOT/server-draft-worker.service" || \
  ! sudo test -f "$BACKUP_ROOT/server-draft-worker.path" || \
  sudo test -L "$BACKUP_ROOT/server-draft-worker.path" || \
  ! sudo test -d "$BACKUP_ROOT/server-drafts" || \
  sudo test -L "$BACKUP_ROOT/server-drafts"; then
  echo 'draft-worker rollback backup is incomplete or unsafe' >&2
  exit 2
fi

sudo systemctl stop server-draft-worker.path
sudo systemctl disable server-draft-worker.path
sudo systemctl stop server-draft-worker.service
sudo install -m 0644 "$BACKUP_ROOT/server-draft-worker.service" /etc/systemd/system/server-draft-worker.service
sudo install -m 0644 "$BACKUP_ROOT/server-draft-worker.path" /etc/systemd/system/server-draft-worker.path
sudo rm -rf -- /var/lib/openvpn-web/server-drafts
sudo cp -a -- "$BACKUP_ROOT/server-drafts" /var/lib/openvpn-web/server-drafts
sudo systemctl daemon-reload
```

Do not disable or restart OpenVPN, and do not change collector configuration or
collector timers during rollback. This rollback intentionally leaves all
non-draft services and assets untouched.

## Network Observer Setup

The installer creates:

- `/usr/local/sbin/netctl`
- `/etc/netctl/sources.d/mikrotik-main.yaml`
- `/etc/netctl/sources.d/mikrotik-hex.yaml`
- `/etc/netctl/secrets.env`
- `/var/lib/netctl/netctl.sqlite`
- `netctl-collect.service`
- `netctl-collect.timer`
- Linux service user `netctl`; automatic collection runs as this user, not root.

Before the first real collection, configure a read-only RouterOS API user and put its password into `/etc/netctl/secrets.env`:

```bash
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S install -m 0640 -o root -g netctl /dev/null /etc/netctl/secrets.env"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S sh -c 'printf %s\\n \"NETCTL_SECRET_MIKROTIK_MAIN_PASSWORD='\"'\"'STRONG_PASSWORD'\"'\"'\" > /etc/netctl/secrets.env'"
```

For the remote m-arhiv hEX, `netctl` uses SSH because that router is RouterOS 6 and may not expose API to the OpenVPN host. The installer creates `/etc/netctl/sources.d/mikrotik-hex.yaml`; the required private key is `/var/lib/netctl/.ssh/m_arhiv_hex_rsa`, owned by `netctl` with mode `0600`.

Recommended RouterOS configuration:

```routeros
/user group add name=netobserver policy=read,api,test,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!romon
/user add name=netobserver group=netobserver password="STRONG_PASSWORD"
/ip service set api-ssl disabled=no address=192.168.100.30/32 port=8729
/ip service set api disabled=yes
```

Temporary non-TLS API fallback:

```routeros
/ip service set api disabled=no address=192.168.100.30/32 port=8728
```

Remote hEX SSH requirements:

```routeros
/ip service set ssh address=192.168.99.176/32,192.168.100.30/32
/user ssh-keys import user=asmr_admin public-key-file=netctl-openvpn-to-m-arhiv.pub
```

Verify:

```bash
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json sources test mikrotik-main"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json sources test mikrotik-hex"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json ipsec status"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json collect mikrotik-main"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json hosts list"
```

The web pages are:

- `/network/dashboard`
- `/network/hosts`
- `/network/sources`
- `/network/interfaces`
- `/network/routes`
- `/network/ipsec`
- `/network/backups`
- `/network/collect`

OpenVPN addressing and site-to-site checks:

```bash
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json server-config inspect"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json validate-network-plan"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json nat-status"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json site-routes list"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json preview test_router_s2s router_vipnet 192.168.50.201 --client-type router_site_to_site --remote-lan 192.168.51.0/24 --create-server-route"
```

Expected addressing:

- OpenVPN tunnel pool: `192.168.50.0/24`.
- OpenVPN server tunnel IP: `192.168.50.1`.
- User VPN-IP range: `192.168.50.2-199`.
- Router VPN-IP range: `192.168.50.200-249`.
- Remote LANs behind site-to-site routers: `192.168.51.0/24`, `192.168.52.0/24`.

The expected production design is routing without SNAT from OpenVPN to ViPNet. `nat-status` should report `mode=disabled_expected`; legacy `vipnet-openvpn-nat.service` and `VIPNET_OPENVPN_SNAT` should be inactive or absent.

`openvpn-server@server.service` starts OpenVPN with `--status /run/openvpn-server/status-server.log`; this command-line setting overrides any `status` directive in `server.conf`. Set `STATUS_LOG` to that runtime path so `vpnctl connected --source status-log` uses the live fallback file.

## WireGuard policy-routing health

The VLAN50 (`ens18.50`) egress policy is intentionally narrow: only mark `0x1`,
priority `1000`, table `123`, and the `VPN_POLICY_MARK` / `VPN_POLICY_NAT`
chains belong to `vpn-policy.service`. `wg0.conf` must retain `Table = off` so
WireGuard cannot install a global default route.

`vpn-policy-reconcile.timer` runs once per minute and repairs only drift in
those owned objects. It first probes the active state (when `wg0` exists) or
the fail-closed state (when it does not); a healthy state is not flushed or
rebuilt. The reconciler shares `/run/lock/vpn-policy.lock` with
`vpn-policy.service`, so a timer tick cannot race the normal policy-service
lifecycle. It never starts, restarts, stops, or reconfigures WireGuard or
OpenVPN. If a WG peer fails, VLAN50 remains fail-closed until an operator or
the normal WG service lifecycle brings `wg0` back.

`vpn-runtime-health.timer` is deliberately separate and alarm-only: it runs
`vpnctl --json runtime-health --strict` once per minute and records an error in
journald if OpenVPN management, `wg0`, the handshake, table 123 or its managed
chains disappear. It never changes routes, firewall rules, or services.

Use these post-deploy checks or an explicit scoped repair:

```bash
sudo systemctl status vpn-policy-reconcile.timer vpn-runtime-health.timer --no-pager
sudo systemctl start vpn-policy-reconcile.service
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
curl -fsS -H "Authorization: Bearer $OPENVPN_WEB_API_TOKEN" http://127.0.0.1:8088/api/v1/runtime-health
```

`systemctl start vpn-policy-reconcile.service` is the explicit repair command:
it only writes the managed PBR/NAT objects if its probe finds drift, and never
starts, stops, or restarts WireGuard or OpenVPN. The other commands shown are
read-only. The final command is the read-only Bearer integration endpoint. Browser users
do not use that token: an authenticated session can view the same sanitized
state in `/network/dashboard`, whose VPN Runtime card polls
`/network/runtime-health` every 30 seconds. An unauthenticated request to the
session endpoint redirects with HTTP 303 to `/login`. The card displays only
the health fields and redacts key-like values, endpoint names, IP addresses,
and ports from warning/error text before rendering it.

Use the acceptance and maintenance-window procedure in
[`wg-policy-resilience-deploy-rollback.md`](runbooks/wg-policy-resilience-deploy-rollback.md).

## Route Update Behavior

When client networks are changed from the web UI or API, the app writes CCD through `vpnctl`, runs auto sync, then calls `reconnect-client`. If the client is connected and OpenVPN management is available, the session is dropped so the client reconnects and receives fresh pushed routes. If the client is offline, the new CCD is applied at the next connection.

For `router_site_to_site` clients, `vpnctl` writes an `iroute` into the CCD and can add the matching server `route` only inside its managed block. Do not add remote LAN routes by hand outside the managed block; use `vpnctl --json site-routes add ...` and run `vpnctl --json validate-network-plan` before and after changes.

## Safety Rules

- Do not edit OpenVPN PKI, CRL, CCD, `.ovpn`, iptables or systemd directly from the web app.
- Use `vpnctl --json` for all privileged OpenVPN changes.
- Do not expose a delete-client API or MCP tool. Disable clients instead.
- Require `confirm_client` and `reason` for client-impacting API/MCP actions.
- Keep bearer tokens, password files, generated configs and private keys out of git.
