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
WireGuard cannot install a global default route. `vpn-runtime-health.timer`
runs `vpnctl --json runtime-health --strict` once per minute and records an
error in journald if OpenVPN management, `wg0`, the handshake, table 123 or its
managed chains disappear. It never changes routes, firewall rules or services.

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
