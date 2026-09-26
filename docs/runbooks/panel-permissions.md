# Panel capabilities and production sessions

This is configuration guidance, not an executed deployment.

Active non-administrator accounts retain read access. New accounts default to
non-administrator. Existing administrator/network-administrator flags and password
hashes are preserved by the repeatable `web_users.permissions_json` migration.
Bootstrap creates a missing administrator only; it never resets an existing user.

An existing administrator can assign individual capabilities at `/admin/users`.
The form requires the existing session and CSRF token. Capability assignment and
its audit entry commit together. It cannot change administrator flags or passwords.
Observers and ordinary editors cannot assign permissions, even by a direct POST.

Inventory write, delete/restore and export are separate capabilities. VPN changes
and sensitive downloads are separate from read access. Downloads require a download
capability and token ownership (administrators can consume another user's token).
Token consumption uses an atomic conditional update, preventing double use.

The legacy service token keeps its prior basic inventory/read/VPN operations by
default, but gains neither inventory delete/restore, exports nor network management.
`OPENVPN_WEB_API_PERMISSIONS` explicitly overrides its comma-separated capabilities.
An empty value grants no protected route. Network-control endpoints retain their
additional scoped credentials and trusted-HTTPS gate; these permissions do not
replace that boundary.

Set `APP_ENV=production` and configure a randomly generated `APP_SECRET_KEY` of at
least 32 characters through the deployment's protected environment/secret storage.
Startup rejects the development default and short keys in production. Production
cookies always use Secure, HttpOnly and SameSite=Lax, independently of request
headers. Development is explicit through `APP_ENV=development` (the local default).

Serve production through HTTPS; restrict the backend to the trusted reverse proxy
and configure uvicorn's allowed forwarded-proxy addresses narrowly. Do not trust
forwarded headers from arbitrary clients. Secure cookies will intentionally not
authenticate plain HTTP requests. Existing HTTP-only deployments need HTTPS before
enabling production mode. No deployed proxy, VPN or network configuration was changed.

The shipped systemd unit now explicitly pins `--proxy-headers
--forwarded-allow-ips 127.0.0.1`, matching nginx's loopback upstream. It does not
inherit a wildcard `FORWARDED_ALLOW_IPS`. Direct service/API listener addresses
remain compatible; non-loopback peers cannot replace their identity or scheme by
supplying forwarded headers. Protect direct backend access in the target environment.
The example nginx listener is HTTP development/bootstrap configuration, not a TLS
production configuration. Do not switch an existing HTTP-only installation to
APP_ENV=production until HTTPS is configured and verified. Local template edits
have not changed the deployed service or proxy.
