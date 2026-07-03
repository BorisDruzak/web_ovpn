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

## Route Update Behavior

When client networks are changed from the web UI or API, the app writes CCD through `vpnctl`, runs auto sync, then calls `reconnect-client`. If the client is connected and OpenVPN management is available, the session is dropped so the client reconnects and receives fresh pushed routes. If the client is offline, the new CCD is applied at the next connection.

## Safety Rules

- Do not edit OpenVPN PKI, CRL, CCD, `.ovpn`, iptables or systemd directly from the web app.
- Use `vpnctl --json` for all privileged OpenVPN changes.
- Do not expose a delete-client API or MCP tool. Disable clients instead.
- Require `confirm_client` and `reason` for client-impacting API/MCP actions.
- Keep bearer tokens, password files, generated configs and private keys out of git.
