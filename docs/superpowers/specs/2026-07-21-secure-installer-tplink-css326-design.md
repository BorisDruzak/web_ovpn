# Secure installer, TP-Link and CSS326 safe onboarding design

## Goal

Remove the OpenVPN web installer path that writes or prints administrator and
API credentials, rotate the web administrator password through the protected
server environment, accept one precisely identified TP-Link JetStream switch,
and stage one CSS326 switch as a disabled read-only SNMP source.

## Scope and safety boundary

- Do not store or print administrator passwords, API tokens, SNMP communities,
  endpoints, or raw SNMP responses in Git, logs, tests, or UI output.
- The password rotation changes only `/etc/openvpn-web/openvpn-web.env` and
  restarts only `openvpn-web.service`.  It does not restart OpenVPN, WireGuard,
  or collection services.
- All SNMP sources remain `enabled: false`; `netctl-collect.timer` remains
  disabled and inactive.
- Discovery is limited to the five system identity OIDs.  It does not call FDB,
  VLAN, interface, bridge, LLDP, port, or collection routines.
- SNMP SET and device configuration changes are out of scope.

## Installer credential handling

The installer will no longer create `/tmp/openvpn-web-admin-password.txt` or
`/tmp/openvpn-web-api-token.txt`, read either file, or print an administrator
password at completion.  Existing protected environment values are read only
through privileged commands when preservation is necessary.  A first-time
installation may generate credentials directly into the protected environment;
the installer prints only a generic completion message.

The production rotation uses an operator-provided password through a protected
server-side operation.  The value is never passed to source control, command
history, or Codex output.  After the protected environment is atomically
updated, `openvpn-web.service` is restarted and the login endpoint is smoke
checked.  Old temporary credential files are removed only after the new
protected configuration is in place.

## Exact TP-Link identity

`TplinkProfile.matches()` gains one narrow branch that accepts exactly both:

- `sysObjectID` `1.3.6.1.4.1.11863.5.29`;
- `sysDescr` `JetStream 48-Port Gigabit Smart Switch with 4 SFP Slots`.

The existing `T1600G-*` matcher remains unchanged.  A generic `JetStream`
pattern or an OID-prefix match is forbidden.  Tests cover the exact positive
case and a mismatch of either scalar.  Production validation invokes only
`sources discover tplink-ito-15` with the existing disabled source.

## CSS326 staging and discovery

The supplied community is placed only in `/etc/netctl/secrets.env` with mode
`0640`, owner `root`, group `netctl`, under a new dedicated secret reference.
The CSS326 source is created by `netctl` as `enabled: false` and is never
enabled in this change.

The existing CSS326 profile means the expected production discovery result is
`known/css326`, not `requires_profile`.  This validates the safe onboarding
gate but does not exercise the unknown-fingerprint branch.  A later unknown
device with no matching profile is needed for that branch.

## Verification and rollback

Before every production mutation, make a verified rollback copy of the web
environment, application state and Netctl database on the data volume.  Verify
the timer and selected source are disabled before and after each discovery.
Run focused installer, profile, discovery-store, CLI and web tests locally,
then the same relevant tests on the Linux host.  Stop on any failure; restore
the protected environment and application from the rollback set before
restarting the web service.  Do not run `collect`.
