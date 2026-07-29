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

## Access-mode exclusivity

The creation form offers exactly one of two access modes:

- **Network template:** choose one existing template. The template alone
  supplies the client's routes and DNS policy.
- **Custom networks:** enter any number of comma- or newline-separated IPv4
  CIDRs and choose DNS/DOMAIN explicitly. No template routes are retained.

The custom-network mode registers missing CIDRs in the shared catalogue before
the client is created. Existing and repeated CIDRs are normalized and used once
only. A client can therefore never receive a duplicated route from mixing a
template with a manually entered CIDR.

## Bulk user creation

The form has a `Bulk creation` switch for creating a group of ordinary user
clients. Bulk clients always share one selected template or one custom-network
set; they do not accept router types, a static VPN IP, remote LAN, or a server
route.

Operators supply client names through either or both of:

- a newline/comma-separated name list in the form;
- a CSV upload with a required `client_name` header. Legacy `profile` and
  `vpn_ip` columns are rejected when populated, because the web bulk flow has
  one common profile and dynamic user addressing.

The combined inputs are normalized, de-duplicated, and validated before any
certificate or profile is created. Five unique names produce exactly five OVPN
profiles. Existing active client names, invalid names, duplicate names after
normalization, and an empty combined input stop the whole request before the
first profile is generated.

The CLI gains a batch-generation command that is the single creation engine for
the web form and the legacy `generate-all.sh` entry point. It preflights the
complete name list, generates the valid batch sequentially, returns per-client
results, and does not silently overwrite an existing profile. The web layer
applies the common access policy to every generated client, synchronizes the
registry, and creates a private ZIP download containing only the successfully
generated OVPN files. A partial generation is reported per client and is never
presented as a complete batch.

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
- Tests cover pasted names and CSV upload, input de-duplication, empty input,
  existing-name preflight rejection, five names producing five profiles,
  common template/custom-network enforcement, and ZIP contents.
