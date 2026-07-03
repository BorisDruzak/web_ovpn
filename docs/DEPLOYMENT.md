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
```

Useful live checks:

```bash
ssh ui-vpn-deploy "journalctl -u openvpn-web -n 100 --no-pager"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json status"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json logs -n 50"
```

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

## Route Update Behavior

When client networks are changed from the web UI or API, the app writes CCD through `vpnctl`, runs auto sync, then calls `reconnect-client`. If the client is connected and OpenVPN management is available, the session is dropped so the client reconnects and receives fresh pushed routes. If the client is offline, the new CCD is applied at the next connection.

For `router_site_to_site` clients, `vpnctl` writes an `iroute` into the CCD and can add the matching server `route` only inside its managed block. Do not add remote LAN routes by hand outside the managed block; use `vpnctl --json site-routes add ...` and run `vpnctl --json validate-network-plan` before and after changes.

## Safety Rules

- Do not edit OpenVPN PKI, CRL, CCD, `.ovpn`, iptables or systemd directly from the web app.
- Use `vpnctl --json` for all privileged OpenVPN changes.
- Do not expose a delete-client API or MCP tool. Disable clients instead.
- Require `confirm_client` and `reason` for client-impacting API/MCP actions.
- Keep bearer tokens, password files, generated configs and private keys out of git.
