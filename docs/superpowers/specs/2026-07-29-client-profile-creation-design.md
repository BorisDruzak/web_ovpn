# Client profile creation design

## Goal

Make the web-panel form at `/clients/new` reliably create and download OpenVPN
client profiles. Operators can add one or more custom IPv4 CIDRs while creating
a client. Each custom CIDR is validated, registered in the shared network
catalogue, and assigned to that client.

## Scope

- Do not pass `--comment` to `vpnctl generate` when the optional comment field
  is blank.
- Keep the comment optional in the UI.
- Add a `Custom routes` field to the new-client form. It accepts comma- or
  newline-separated IPv4 CIDRs.
- Validate and normalize every submitted CIDR before any mutation. Duplicate
  entries are collapsed.
- For every submitted CIDR, call the existing catalogue operation to create or
  update it with a fixed `custom-route` tag and a descriptive audit-safe
  comment.
- Generate the requested OVPN profile, then apply the selected profile routes
  plus the submitted custom CIDRs through the existing client-networks command.
- Preserve the profile's DNS setting when applying routes. A user can opt in to
  DNS/DOMAIN from the form; a DNS-enabled selected profile remains DNS-enabled.
- Report the generated OVPN path and download control exactly as today.

## Client type behaviour

For `user` and `router_nat`, the creation form shows client name, profile,
optional comment, optional VPN IP, DNS/DOMAIN, and custom routes. It hides
`Remote LAN CIDR` and `Create route in server.conf`.

For `router_site_to_site`, it also shows `Remote LAN CIDR` and `Create route in
server.conf`. The remote LAN is the subnet behind the remote router; it is not
a client access route and must remain subject to the current server-side
overlap and pool validation.

## Order of operations and failure handling

1. Validate form values and render a preview without mutations.
2. On Generate, validate/normalize custom CIDRs.
3. Register missing custom CIDRs in the shared catalogue.
4. Generate the OVPN profile.
5. Apply the combined route set and DNS choice to the new client.
6. Sync the registry and offer the OVPN download.

If validation or catalogue registration fails, generation does not start. If
generation succeeds but the route-application step fails, show a clear error
that the OVPN exists but its requested access was not fully applied; retain the
audit trail and do not claim success. Existing client-route application also
handles a disconnect/reconnect notice without forcing a disconnect.

## Safety boundary

Custom routes are catalogue entries, not raw CCD text. CIDRs must be IPv4
networks and are processed only through the existing validated `vpnctl`
commands. No OpenVPN server restart, router, DNS, DHCP, firewall, or other
network-device configuration is changed.

## Verification

- Unit/route tests prove an empty comment omits `--comment`.
- Route tests prove custom CIDRs are normalized, deduplicated, registered, and
  applied to the generated client.
- Tests cover an invalid CIDR and a catalogue failure with no profile
  generation.
- Tests cover the selected DNS option, and browser-level checks confirm the
  site-to-site-only fields are hidden for ordinary users.
