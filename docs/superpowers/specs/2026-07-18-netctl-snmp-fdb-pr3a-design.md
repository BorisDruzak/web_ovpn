# Netctl SNMP/FDB PR 3A Design

## Goal

Implement the first, non-production phase of multi-vendor switch observation: a read-only SNMPv2c collector core and a DGS vertical slice. It must provide normalized ports and Q-BRIDGE FDB state without exposing communities or modifying a device.

## Scope

PR 3A contains only migration 5, secret-safe SNMP source configuration, the `snmp_switch` driver, numeric-OID transport and outcome classes, DGS parsing/profile support, transactional FDB current state and events, and read-only CLI queries. All live SNMP sources remain disabled.

It does not include SNR, TP-Link, CSS326, SNMPv3, counters/findings, automatic identity binding, raw capture, device writes, a web UI, or a production community.

## Design

`netctl/snmp` owns protocol transport, normalized value objects, OID parsing and vendor profiles. `netctl/drivers/snmp_switch.py` adapts the normalized snapshot to the existing driver interface. `switch_store.py` persists switch-only data and compares a fully successful FDB collection with prior `current_switch_fdb` rows in one transaction.

The transport returns an explicit outcome for every capability: successful rows, confirmed empty, unsupported object, timeout, explicit authentication/view failure, or parse error. Only a confirmed successful FDB result replaces current state; any other FDB outcome preserves it and emits no false disappearance event. Q-BRIDGE FID remains distinct from VID unless the DGS fixture-proven profile rule maps it.

SNMP requests use only GET/WALK operations and numeric OIDs. The source references a secret name; `load_secrets()` resolves the community from the protected process environment at run time. Community values are rejected from YAML and are absent from public source, records, logs, errors and test data.

## Safety and verification

All unit and parser tests use sanitized fixtures and an injected transport; no test contacts a switch. Migration 5 runs inside the existing migration savepoint and preserves immutable migrations 1–4. Initial acceptance requires idempotent DGS events, one exact MAC-move event, failure preservation of current FDB, source isolation, and a secret scan.

Production DGS pilot is explicitly outside this PR. It requires a separate approval, an SQLite backup, the community placed only in `/etc/netctl/secrets.env`, disabled-source testing, two manual collections, and rollback evidence.

## Success criteria

- `python -m pytest` passes with new focused SNMP tests.
- No source, fixture, database row, response, log or exception contains a community value.
- A failed or unsupported FDB read leaves `current_switch_fdb` unchanged.
- A confirmed empty FDB read clears current state intentionally.
- No implementation path can issue SNMP SET or device configuration commands.
