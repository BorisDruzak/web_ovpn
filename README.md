# OpenVPN Web Manager

FastAPI/Jinja2 web UI for managing OpenVPN profiles through `vpnctl`, plus a read-only Network Observer backend through `netctl`.

Deployment runbook: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Security Model

- The web app does not edit OpenVPN PKI, CRL, CCD, `.ovpn`, iptables, RouterOS, or systemd directly.
- Privileged OpenVPN actions go through `vpnctl --json ...`.
- Network inventory actions go through `netctl --json ...`.
- `app/vpnctl_client.py` and `app/netctl_client.py` use `subprocess.run([...], shell=False)`.
- API uses a bearer token; `/etc/openvpn-web/openvpn-web.env` stores only `OPENVPN_WEB_API_TOKEN_HASH`.
- Dangerous client actions require POST, CSRF, and explicit confirmation.
- Client delete is intentionally not exposed; disable is the supported destructive action.
- Network Observer is read-only for MikroTik in the MVP.
- Network Observer secrets are kept outside SQLite in `/etc/netctl/secrets.env`.

## Install

```bash
sudo apt-get update
sudo apt-get install -y python3-venv
sudo useradd --system --home /opt/openvpn-web --shell /usr/sbin/nologin openvpn-web
sudo mkdir -p /opt/openvpn-web /etc/openvpn-web /var/lib/openvpn-web
sudo chown -R openvpn-web:openvpn-web /opt/openvpn-web /var/lib/openvpn-web
```

Copy the project to `/opt/openvpn-web`, then:

```bash
cd /opt/openvpn-web
sudo -u openvpn-web python3 -m venv .venv
sudo -u openvpn-web .venv/bin/pip install -r requirements.txt
sudo install -m 0440 deploy/sudoers-openvpn-web /etc/sudoers.d/openvpn-web
sudo visudo -cf /etc/sudoers.d/openvpn-web
sudo install -m 0644 deploy/openvpn-web.service /etc/systemd/system/openvpn-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-web.service
```

The installer script `deploy/install-openvpn-web.sh` performs the production install, including `vpnctl`, `netctl`, env defaults, and systemd units.

## Environment

Example `/etc/openvpn-web/openvpn-web.env`:

```env
DATABASE_URL=sqlite:////var/lib/openvpn-web/openvpn-web.sqlite
VPNCTL_PATH=/usr/local/sbin/vpnctl
VPNCTL_USE_SUDO=1
NETCTL_PATH=/usr/local/sbin/netctl
NETCTL_USE_SUDO=1
NETCTL_SUDO_USER=netctl
NETWORK_OBSERVER_ENABLED=1
APP_SECRET_KEY=<long-random-secret>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<initial-admin-password>
OPENVPN_WEB_API_TOKEN_HASH=<sha256-hex-of-token>
OPENVPN_WEB_API_ACTOR=api:codex-local
OUT_DIR=/etc/openvpn/client-generator/output
SHARE_OUT_DIR=/mnt/antares_soft/vpn_config
ARCHIVE_DIR=/etc/openvpn/client-generator/archive
ROUTEROS_BACKUP_DIR=/var/backups/routeros
DOWNLOAD_TOKEN_TTL_MINUTES=15
```

## OpenVPN Management

Recommended setup is through `vpnctl`:

```bash
sudo vpnctl --json server-config apply \
  --status-interval 10 \
  --status-version 2 \
  --enable-management \
  --management-socket /run/openvpn/server.sock \
  --management-client-group openvpn-web \
  --management-log-cache 300 \
  --restart

sudo vpnctl --json management test
sudo vpnctl --json connected --source auto
```

When a client network/template changes, the web UI runs sync and then `reconnect-client` so connected clients receive fresh pushed routes on reconnect.

## Network Observer

Network Observer adds a second read-only backend:

```bash
sudo /usr/local/sbin/netctl --json sources list
sudo /usr/local/sbin/netctl --json sources test mikrotik-main
sudo /usr/local/sbin/netctl --json sources test mikrotik-hex
sudo /usr/local/sbin/netctl --json collect mikrotik-main
sudo /usr/local/sbin/netctl --json hosts list
sudo /usr/local/sbin/netctl --json dashboard
sudo /usr/local/sbin/netctl --json ipsec status
```

Main files:

- `/usr/local/sbin/netctl` - CLI wrapper.
- `/etc/netctl/sources.d/mikrotik-main.yaml` - central MikroTik source metadata without password.
- `/etc/netctl/sources.d/mikrotik-hex.yaml` - m-arhiv hEX source metadata, using the `netctl` SSH key.
- `/etc/netctl/secrets.env` - root-owned secrets file readable by the `netctl` group.
- `/var/lib/netctl/netctl.sqlite` - SQLite snapshots owned by the `netctl` service user.
- `netctl-collect.timer` - automatic collection every 5 minutes as the `netctl` user.

Default source:

```yaml
name: mikrotik-main
driver: mikrotik_api
host: 192.168.100.250
port: 8729
tls: true
verify_tls: false
username: netobserver
secret_ref: mikrotik-main
site: main
role: core-router
enabled: true
```

Remote hEX source:

```yaml
name: mikrotik-hex
driver: mikrotik_ssh
host: 192.168.99.1
port: 22
tls: false
verify_tls: false
username: asmr_admin
secret_ref: mikrotik-hex
site: m-arhiv
role: edge-router
ssh_identity_file: /var/lib/netctl/.ssh/m_arhiv_hex_rsa
ssh_connect_timeout: 12
enabled: true
```

`mikrotik_ssh` is read-only and exists for RouterOS 6 devices where API access is not available. It uses legacy SSH algorithms required by RouterOS 6 and does not collect `installed-sa` keys from the remote side.

Secrets file:

```bash
sudo install -m 0640 -o root -g netctl /dev/null /etc/netctl/secrets.env
sudoedit /etc/netctl/secrets.env
```

```env
NETCTL_SECRET_MIKROTIK_MAIN_PASSWORD='strong-password'
```

Recommended MikroTik setup:

- Use RouterOS API-SSL on `8729`.
- Restrict API/API-SSL service by source address to the OpenVPN/Web server IP.
- Use dedicated read-only user `netobserver`.
- Use a strong password.
- Do not expose API to WAN.
- SSH is only fallback/debug.
- SNMP can be added later for metrics.

Remote hEX SSH requirements:

- `/ip service ssh` on the hEX must allow `192.168.100.30/32`.
- The public key for `/var/lib/netctl/.ssh/m_arhiv_hex_rsa` must be imported for the RouterOS user configured in `mikrotik-hex.yaml`.
- The web IPsec page checks both policy directions: central LAN/telephony to `192.168.99.0/24`, and `192.168.99.0/24` back to central LAN/telephony.

RouterOS commands:

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

Web pages:

- `/network/dashboard`
- `/network/hosts`
- `/network/sources`
- `/network/interfaces`
- `/network/routes`
- `/network/ipsec`
- `/network/backups`
- `/network/collect`

HTTP API endpoints are under `/api/v1/network/...`.

## Local Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=sqlite:///./openvpn-web.sqlite
export VPNCTL_PATH=/path/to/vpnctl
export VPNCTL_USE_SUDO=0
export NETCTL_PATH=/path/to/netctl
export NETCTL_USE_SUDO=0
export APP_SECRET_KEY=dev-secret
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=admin-pass
uvicorn app.main:app --reload
```

## Tests

```bash
pytest
```

## API And MCP

Main HTTP API prefix: `/api/v1`.

```bash
curl -H "Authorization: Bearer $OPENVPN_WEB_API_TOKEN" \
  http://192.168.100.30:8088/api/v1/status

curl -H "Authorization: Bearer $OPENVPN_WEB_API_TOKEN" \
  http://192.168.100.30:8088/api/v1/network/hosts
```

The local Codex plugin `openvpn-control` uses the MCP server in `mcp/openvpn_mcp_server.py`.
