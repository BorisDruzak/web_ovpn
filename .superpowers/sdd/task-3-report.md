# Task 3 report: normalized switch interfaces and FDB

## Outcome

Implemented the offline PR3A generic SNMP normalization core. The change adds frozen normalized system, port, resolution, FDB and snapshot dataclasses; explicit JSON-compatible serialization; strict numeric-OID system/interface/bridge parsers; generic port/FID profile behavior; Q-BRIDGE and legacy FDB parsers; and an injected asynchronous snapshot collector.

No source was enabled and no live network operation, community value, secret resolution, vendor-specific DGS rule, persistence, migration, CLI, device write or deployment was added.

## TDD evidence

- Initial RED: `python -m pytest tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py -q`
  - Result: `20 failed in 0.70s`.
  - Failures were the expected missing normalized modules/dataclasses (`system`, `interfaces`, `fdb`, `profiles`, `collector`, `SwitchSystem`, `SwitchPort`, and `SwitchSnapshot`).
- Initial GREEN after the minimal implementation:
  - Result: `20 passed in 0.43s`.
- Expanded outcome/security coverage:
  - Result: `25 passed in 0.48s`.
  - Added explicit coverage for legacy unsupported/timeout/auth/parse outcomes after Q-BRIDGE fallback, malformed Q-BRIDGE collection without legacy fallback, and secret/topology-bearing source fields omitted from serialized snapshots.
- A self-review refactor briefly produced an awaited async generator. The focused collector tests caught all affected paths; the refactor was corrected before final verification.

## Contract summary

- `SwitchSystem`, `SwitchPort`, `PortResolution`, `SwitchFdbEntry`, `SwitchCounterSample`, and `SwitchSnapshot` are frozen dataclasses.
- Every normalized record has an explicit `to_dict()` implementation. Snapshot capability serialization includes only stable outcome/error metadata; raw varbind rows and arbitrary capability details are not serialized.
- `parse_system()` accepts only typed Task 2 varbind values for known numeric scalar OIDs.
- `parse_interfaces()` joins ifTable/ifXTable by `ifIndex`, rejects conflicting rows, uses `ifHighSpeed` when `ifSpeed` is absent/zero/saturated, and normalizes six-octet MACs to uppercase colon notation.
- `parse_bridge_port_map()` rejects conflicting bridge-port mappings and multiple bridge ports resolving to the same ifIndex.
- `GenericProfile` resolves FDB ports only through `dot1dBasePortIfIndex` and uses the `mapped_only` FID policy.
- `parse_qbridge_fdb()` decodes the index as FID plus six MAC octets, joins status by that same index, maps a FID to a VID only when exactly one explicit `dot1qVlanFdbId` row proves it, and never duplicates an entry across multiple VIDs.
- `parse_legacy_fdb()` joins address/port/status by the six-octet MAC index and emits `legacy:unknown` with null FID/VID.
- `collect_switch_snapshot()` prefers Q-BRIDGE. `SUCCESS_EMPTY` is a confirmed empty result. Legacy is queried only after `UNSUPPORTED_NO_SUCH_OBJECT`; timeout, auth/view failure, transport parse failure, and normalized-row parse failure do not trigger fallback and remain non-replacing outcomes.

## Safety review

- All requests in the collector use imported numeric OID tuples and only the injected Task 2 `get()`/`walk()` boundary.
- Tests use synthetic MAC/port/FID data and the RFC 5737 documentation address `192.0.2.99`; no production topology is present.
- The serialization test proves source host and `secret_ref` fields are absent from snapshots, and capability `details`/raw rows are not exposed.
- A targeted scan found no private-address topology or community text in the new parser/profile/collector production and test files.

## Final verification

- `python -m pytest tests/test_netctl_snmp_config.py tests/test_netctl_snmp_transport.py tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py -q`
  - Result: `108 passed in 0.92s`.
- `python -m compileall -q netctl`: exit 0.
- `ruff check netctl/snmp tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py`: all checks passed.
- `git diff --check`: exit 0.
- Targeted private-topology/community scan of new Task 3 code/tests: no matches.

Pytest emitted only the repository's pre-existing `pytest-asyncio` deprecation warning about `asyncio_default_fixture_loop_scope` being unset.

## Review follow-up fixes

- Corrected Q-BRIDGE companion-table handling: only `dot1qVlanFdbId` may be explicitly unsupported as an optional mapping. An unsupported status table now remains `UNSUPPORTED_NO_SUCH_OBJECT`, is non-replacing, and never triggers legacy fallback.
- Replaced generic integer-like acceptance with field-specific ASN.1 validation and bounds. System uptime requires `time_ticks`; ifIndex, bridge mappings, FDB ports and status require `integer`; interface speeds require `gauge32`; and VLAN FDB IDs require `unsigned32`. Enumerated interface/FDB statuses are range-checked.
- Bridge-port mappings are now rejected when any mapped ifIndex is absent from the parsed interface table, including collections whose FDB is empty.
- `dot1qVlanFdbId` now requires the complete TimeMark plus VLAN numeric OID suffix; the formerly accepted one-component suffix is rejected.
- Added six direct review regressions plus domain-boundary coverage. Focused parser/profile verification after the fixes reports `33 passed`; the final combined Task 1/2/3 suite reports `116 passed in 1.01s`.
