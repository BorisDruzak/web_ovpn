# Switch STP and Identity Persistence Design

## Goal

Persist normalized STP current state and explicit configured switch identity without allowing optional SNMP failures or observations to create implicit runtime-asset bindings.

## Design

Migration 7 adds `current_switch_stp_state`, keyed by `source_id`. Its columns contain the normalized STP values already produced by the collector: protocol, root bridge MAC, root port key, root path cost, topology change count and observation time.

The existing successful-FDB transaction replaces STP state only when every STP capability (`stp_protocol`, `stp_topology_changes`, `stp_designated_root`, `stp_root_cost`, `stp_root_port`) is `success_with_rows` or `success_empty`. A confirmed empty group clears the row. Unsupported, timeout, auth/view failure, protocol failure and parse error preserve the prior STP row. Optional STP never blocks FDB, port, VLAN or LLDP persistence.

`switch_devices` already has `runtime_asset_id`, `intent_context_id` and `intent_stable_id`. `_upsert_device()` writes them only from the normalized source fields. `runtime_asset_id` is used only when it is a valid existing asset ID; identity is not discovered, inferred, inserted, confirmed or merged from SNMP observations. Empty configured identity clears the corresponding optional stored value.

Read-only CLI/query output gains paginated `switches stp`, with source filtering and bounded pagination. Existing status output may show the STP row count but no raw SNMP payloads or secrets.

## Safety and Tests

- Migration 7 is additive; migrations 1–6 stay immutable.
- Tests cover STP success replacement, confirmed-empty clearing, each failed outcome preserving prior state, and continued successful FDB persistence.
- Tests cover explicit identity upsert, explicit clearing, invalid/missing asset rejection, and absence of automatic asset binding.
- CLI reads use the existing read-only connection and assert no database mutation.
- Fixtures are sanitized and no test contacts a live switch.
