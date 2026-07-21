# Compatible SNMP Fallbacks — Implementation Plan

> **For implementation:** execute this plan through `superpowers:subagent-driven-development`.

**Goal:** Preserve valid switch state from standards-adjacent SNMP agents without device-specific exceptions.

**Architecture:** Keep Q-BRIDGE as the preferred FDB source. When it returns a valid empty table, collect and validate legacy BRIDGE FDB evidence before selecting non-empty legacy rows. Keep IF-MIB core mandatory, make IFX observations optional, and permit compatible integral representations only in declared VLAN/FDB fields.

**Tech stack:** Python 3, pytest, existing `netctl.snmp` collector and parser modules.

## Global constraints

- Do not add device, address, firmware, community, MAC, or secret-specific behaviour.
- A non-empty Q-BRIDGE table always takes precedence over legacy FDB data.
- Legacy fallback is allowed only when address, port, and status walks all succeed, join cleanly using existing validation, and yield non-empty entries.
- A failed, partial, malformed, or empty legacy probe must not create FDB entries or turn a valid empty Q-BRIDGE result into an error.
- Core IF-MIB and bridge-port mapping remain mandatory. IFX failures must remain capability evidence but may not erase valid interfaces or FDB data.
- Only `dot1qVlanFdbId` and PVID may accept `integer`, `unsigned32`, or `gauge32`; retain each existing range check and all other type checks.
- Tests use synthetic, sanitized SNMP varbinds only.

## Task 1: Select legacy FDB after a valid empty Q-BRIDGE result

**Files:**
- Modify: `netctl/snmp/collector.py`
- Test: `tests/test_netctl_snmp_profiles.py`

1. Write failing collector tests for a valid empty Q-BRIDGE result with: (a) complete non-empty legacy rows, (b) complete empty legacy rows, and (c) malformed or partial legacy rows.
2. Extract or extend the existing legacy FDB collection path so it can be run after `SUCCESS_EMPTY` Q-BRIDGE evidence, without changing the precedence for non-empty Q-BRIDGE rows or existing unsupported-Q-BRIDGE fallback.
3. Select legacy entries only when the three legacy walks succeed, the existing parser accepts their joined rows, and parsed entries are non-empty. Otherwise retain the empty Q-BRIDGE result while preserving all capabilities.
4. Run `pytest -q tests/test_netctl_snmp_profiles.py`.
5. Commit the task with a focused message and write the implementation report specified by the SDD workflow.

## Task 2: Keep IFX optional and accept compatible integral encodings

**Files:**
- Modify: `netctl/snmp/collector.py`
- Modify: `netctl/snmp/fdb.py`
- Modify: `netctl/snmp/vlan.py`
- Test: `tests/test_netctl_snmp_profiles.py`
- Test: `tests/test_netctl_snmp_parsers.py`

1. Write failing tests proving an IFX `ifHighSpeed` timeout does not discard a valid core IF-MIB, bridge, and FDB snapshot, while the failed capability remains reported.
2. Make IFX collection results optional for required-failure selection; do not weaken required core IF-MIB or bridge-port checks.
3. Write failing parser tests for `gauge32` `dot1qVlanFdbId` and PVID inputs, plus out-of-range rejection.
4. Add a narrow integral-type helper or equivalent callers that accept exactly `integer`, `unsigned32`, and `gauge32` for those two fields only. Preserve all existing range checks.
5. Run `pytest -q tests/test_netctl_snmp_parsers.py tests/test_netctl_snmp_profiles.py`.
6. Commit the task with a focused message and write the implementation report specified by the SDD workflow.

## Task 3: Document operator verification and perform integrated regression tests

**Files:**
- Modify: `docs/runbooks/` (add a focused compatibility-verification runbook)
- Test: `tests/test_netctl_snmp_parsers.py`
- Test: `tests/test_netctl_snmp_profiles.py`
- Test: `tests/test_netctl_snmp_transport.py`
- Test: `tests/test_netctl_switch_cli.py`
- Test: `tests/test_netctl_switch_discovery_store.py`

1. Add a sanitized runbook describing the evidence hierarchy, expected capability warnings, and safe verification sequence: individual source test, manual collection inspection, then one controlled all-source cycle with the recurring timer disabled.
2. Do not document live addresses, communities, credentials, or operational device inventory.
3. Run the complete targeted regression command from the task tests.
4. Commit the documentation task and write the implementation report specified by the SDD workflow.

## Final verification and deployment

1. Run the targeted local suite from Task 3 and inspect `git diff --check`.
2. Obtain a whole-branch subagent code review and resolve all Critical or Important findings.
3. Merge the verified branch to `main`, push it, and deploy the exact commit with an explicit installer source path.
4. Immediately leave `netctl-collect.timer` disabled. Test affected sources individually; inspect their snapshot/capability/FDB outcomes before changing a source enablement flag.
5. Run one controlled all-source collection only if individual tests succeed. If an unrelated source fails, leave the timer disabled and report the independent failure.
