# SNMP Compatible Fallbacks Design

## Goal

Make switch collection resilient to standards-adjacent SNMP agents without
binding behaviour to an address, device name, or firmware version.

## Scope

The collector will preserve usable data when an agent provides equivalent
standard tables or compatible numeric representations:

- When the Q-BRIDGE FDB table is empty, probe the legacy BRIDGE FDB table.
  Use the legacy rows only when its address, port, and status tables are all
  internally valid and contain rows. Retain an empty Q-BRIDGE result when the
  legacy tables are also empty. Do not turn a failed or malformed legacy probe
  into invented FDB data.
- Treat IF-MIB extension-table failures, including `ifHighSpeed`, as optional.
  Core IF-MIB and bridge-port mapping remain required before port or FDB data
  is accepted.
- Accept `integer`, `unsigned32`, and `gauge32` only for specifically
  designated numeric SNMP fields, after each field's existing range checks.
  This covers equivalent agent encodings while keeping MAC, bitmap, OID index,
  status, and unrelated numeric validation strict.

## Architecture

The FDB collector owns evidence-based fallback selection. It first queries
Q-BRIDGE as today. An empty Q-BRIDGE result triggers a legacy FDB probe for
every switch profile; a complete non-empty legacy result becomes the FDB
snapshot. A malformed, partial, timed-out, or unauthorized legacy probe is
recorded as capability evidence but cannot replace a valid empty Q-BRIDGE
result.

Interface collection separates required core IF-MIB capabilities from optional
IFX capabilities. Optional failures remain visible in the snapshot capability
list but cannot erase otherwise valid interface, bridge, or FDB results.

A focused helper validates accepted SNMP integral representations. Callers
declare the allowed representations and retain their current minimum and
maximum checks. The helper is used only for `dot1qVlanFdbId` and PVID in this
change.

## Error Handling

- Q-BRIDGE rows still take precedence whenever present.
- Legacy fallback requires all three legacy tables to have successful outcomes
  and to pass the existing join and port-resolution checks.
- Empty legacy tables are a valid empty result, not an error.
- Optional IFX failures remain observable as capabilities and do not change
  the collection status by themselves.
- Incompatible types and out-of-range values remain parse errors.

## Testing

Unit tests will cover:

- non-empty legacy fallback after an empty Q-BRIDGE result;
- empty Q-BRIDGE plus empty legacy tables;
- malformed legacy data that is not accepted as a fallback;
- an IFX timeout that does not invalidate a valid FDB;
- `Gauge32` acceptance for VLAN FDB ID and PVID with range checks still
  enforced.

Tests use synthetic sanitized SNMP varbinds. No production addresses,
communities, MAC addresses, or device names are committed.

## Deployment and Verification

Deploy only after local targeted tests pass. Re-test the affected disabled
sources manually, then run one controlled collection cycle. Keep the periodic
collector disabled if an unrelated enabled source still makes `collect all`
exit non-zero.
