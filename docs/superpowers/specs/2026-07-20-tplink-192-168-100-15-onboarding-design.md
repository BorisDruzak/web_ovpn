# TP-Link T1600G-52TS (`192.168.100.15`) safe onboarding design

## Scope

Onboard one TP-Link T1600G-52TS as a `snmp_switch` source on the OpenVPN host.
The source is created disabled.  The work never performs SNMP SET, changes the
switch configuration, enables the collection timer, or enables another SNMP
source.

## Data and secret boundary

- The source name is stable and identifies this one switch.
- Its address is stored only in the production source YAML.
- The SNMPv2c community is copied from the operator-provided inventory only to
  `/etc/netctl/secrets.env`, referenced by a valid `secret_ref`, and never
  echoed, committed, or included in diagnostics.
- The profile hint is `tplink`; the collector must still validate the detected
  profile and all required capability groups.

## Rollout sequence

1. Confirm the collector timer is inactive and disabled, then back up the new
   source YAML before any temporary edit.
2. Create the root-owned source YAML as disabled through `sudo netctl`, with
   `snmp_version: 2c` and the TP-Link profile hint; verify `root:netctl 0640`
   ownership and read access.  The `netctl` service account must not receive
   write access to the source directory.
3. Run `netctl sources test` as `netctl`.  This issues only SNMP GET/WALK and
   must identify the TP-Link profile with successful required groups.
4. Keep the source disabled after the test.  A later, separately approved
   manual-collection gate will test FDB persistence and failure preservation.

## Acceptance and rollback

Acceptance is a successful read-only source test, a disabled source, an
inactive/disabled collector timer, and no change to OpenVPN, WireGuard or switch
configuration.  A failed source test leaves the source disabled; the source
YAML can be removed or restored from its local backup without touching the
secret file or device.
