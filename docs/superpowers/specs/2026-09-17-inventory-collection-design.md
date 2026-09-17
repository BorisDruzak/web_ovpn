# Inventory collection reliability and device forms

## Goal

Make inventory lookup reliable during short availability-projection gaps, use
bounded active collection where it is useful, and show only identifiers that
belong to the device being edited.

## Confirmed behaviour

- The collector keeps one shared collection lock.  A scheduled availability
  pass must not race a reconcile pass; every successful availability pass
  republishes the host snapshot before releasing that lock.
- Inventory lookup first uses current hosts and, for an exact identifier, can
  use a recently observed host from the same snapshot source while availability
  is temporarily stale.  It never accepts a fuzzy or old result.
- Nmap remains a single-host, fixed-profile, no-NSE fallback for every device
  type.  It is bounded so that a filtered printer cannot hold the mobile form
  indefinitely.  Its output supplies only evidence it actually discovers.
- Printer discovery additionally uses read-only SNMP GET requests.  The
  community is resolved only from the protected runtime secret store; it is
  never committed, returned or logged.  SNMPv1 and SNMPv2c are supported.
- PCs, printers, phones and Other retain IP/MAC/hostname fields.  Monitors and
  UPS devices do not show those network-only fields.  Existing common fields
  remain available, and serial/select-field changes are out of scope.
- Invalid cross-type detail rows are repaired idempotently: the wrong detail
  row is removed and the asset receives its own empty details row.

## Non-goals

- No SNMP SET, printer reconfiguration, subnet scanning, secret persistence in
  source, removal of serial numbers, or schema redesign.
