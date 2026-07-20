# TP-Link JetStream profile identity design

## Goal

Extend the existing read-only TP-Link collector so that the observed JetStream
48-port switch is accepted by the TP-Link profile without broadening detection
to unrelated TP-Link devices.

## Evidence

The disabled production source was reachable through read-only SNMP system
probes.  Its system identity is:

- `sysObjectID`: `1.3.6.1.4.1.11863.5.29`
- `sysDescr`: `JetStream 48-Port Gigabit Smart Switch with 4 SFP Slots`

The current matcher accepts only descriptions containing `T1600G-*`; it rejects
this identity before any interface or FDB parsing.

## Design

`TplinkProfile.matches()` will add one exact JetStream identity branch.  That
branch returns true only when both the exact object ID and the exact observed
description match.  The existing `T1600G-*` description matcher remains
unchanged.  No generic `JetStream` pattern, OID prefix, SNMP write, or source
configuration change is introduced.

## Tests and rollout

Add a unit test proving that the exact JetStream identity selects
`TplinkProfile`, while an identity with either a different object ID or a
different description does not select it under the `tplink` hint.  Run the
focused profile tests and the full test suite.  Deploy the code while the
source and collection timer remain disabled, then repeat `sources test` as
`netctl`.  This continues to be GET/WALK only; manual FDB collection requires
a separate approval.
