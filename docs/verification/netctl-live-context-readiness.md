# Netctl live runtime identity and context readiness

This is the sanitized production-readiness record for the runtime identity
closure (migrations `2`, `3`, and `4`) and active-context classification. It records
aggregate outcomes only. Raw host inventories, MAC and IP values, source
configuration, credentials, database rows, and protected backup artifacts are
intentionally not committed.

Verified: 2026-07-18

## Release, schema, and context provenance

| Item | Verified value |
| --- | --- |
| Deployed `web_ovpn` release | `58575134b85e6fe50fdccd7cb98b97d55d32eec5` |
| Canonical `network_configuration` context commit | `6795a43b7e179870361944d280cc15f6b169395c` |
| Imported active context revision | `1` |
| Active context head | present and singular |
| SQLite migration ledger | `1, 2, 3, 4` |
| SQLite integrity check | `ok` |
| Context classifier fallback | `false` |

The release contains the reviewed runtime rollout followed by the relation and
date-scalar compatibility fixes. The active context is the canonical commit
above; classification is derived from that imported revision, rather than from
Python CIDR constants.

## Test evidence

The reviewed release passed the targeted live-context/runtime identity suite:

```text
48 passed
```

Its complete Python regression suite passed:

```text
211 passed, 1 skipped
```

These tests include migration-3 interface guards and conflict preservation,
live writer transaction rollback, legacy observer compatibility, active-context
classification, retirement, invalid category rejection, and fallback handling.

## Retained production collection evidence

Two independent successful `mikrotik-main` collection cycles were retained:

| UTC completion | Source | Classifier fallback | Reported runtime counters (CLI order) |
| --- | --- | --- | --- |
| `2026-07-18T14:04:11Z` | `mikrotik-main` | `false` | `200 / 233 / 49 / 46277` |
| `2026-07-18T14:05:18Z` | `mikrotik-main` | `false` | `200 / 233 / 50 / 46277` |

The observed outcomes were:

- the same observed MAC continued to resolve to one runtime asset;
- a source IP removed between observations became historical rather than
  deleting its history or creating a new permanent identity;
- no interface referenced a different runtime asset;
- legacy observer commands remained operational alongside the live writer.

At approximately `2026-07-18T14:04Z`, `mikrotik-hex` timed out. Its failed
run did not change the prior current runtime state. This is retained evidence
of the writer's all-or-nothing failure boundary, not evidence of a successful
source collection.

## Current runtime health and findings

The post-cycle runtime status reported:

| Measure | Value |
| --- | ---: |
| Runtime assets | 1,027 |
| Runtime interfaces | 1,027 |
| Current IP observations | 233 |
| Current hostname observations | 50 |
| Acknowledged historical-identity findings | 46,271 |
| Open MAC-identity-collision findings | 5 |
| Open IP-only findings | 1 |

Acknowledgement is a reviewed provenance classification for the historical
identity findings, not automatic remediation or deletion. The five
MAC-collision and one IP-only finding remain open and visible for operator
review; none is silently promoted to a permanent identity and no asset merge
or alias execution was performed. The acknowledged historical findings remain
accessible through the read-only findings query.

## Service boundary and readiness decision

- `openvpn-web.service`: active
- `netctl-collect.timer`: active
- OpenVPN service: remained active with five connected clients during the
  runtime/context verification

The release, database, active context, collection behavior, and service state
meet the readiness conditions for the subsequent SNMP/FDB phase. This record
does **not** authorize router, switch, or other network-device writes.

Tracking-issue closure is an administrative GitHub action performed after this
evidence is merged; the evidence itself is intentionally version controlled
here.
