# Runtime asset identity production verification

This is a sanitized closure record for runtime-asset-identity migration 2.
It records verified outcomes only; raw database rows, host inventories,
credentials, tokens, and private keys remain outside Git in the protected
deployment backup.

## Release and rollback evidence

- deployed release commit: `7427e08f0ce7bdb3957cf407d2d9db1e8c0e36a9`
- deployment backup directory: `/var/backups/netctl/runtime-asset-identity-20260718T092445Z`
- rollback manifest and SHA256SUMS: retained in the protected backup directory
- migration-report review acknowledgement: retained in the protected backup directory
- rollback required: `false`

Approved-release SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `netctl/migrations.py` | `fbf68b5a0b693978770d8c4cba7a3867e3f207f7dc790dbaf6667479c49c9b09` |
| `netctl/runtime_assets.py` | `adef3ba7b2a02bddf2796e871beca15d967b2b76b1230f681ad0ccb96b7dbe5d` |
| `tests/test_netctl_runtime_assets.py` | `3738e69438c9caefb223a7324b87d11f566d1809b2f219d3d200ba966ae2816e` |

## Database verification

- SQLite integrity check: `ok`
- schema migration ledger: `1, 2`
- migration 2 ledger count: `1`
- legacy table-count diff before versus after migration: `empty`
- runtime connection pragmas: `foreign_keys=1`, `journal_mode=wal`, `busy_timeout=5000`

The retained legacy table counts were equal before and after migration:

| Legacy table | Count |
| --- | ---: |
| `network_sources` | 2 |
| `collection_runs` | 4,841 |
| `network_hosts` | 1,221 |
| `network_device_tags` | 0 |
| `host_observations` | 5,048,040 |
| `network_interfaces` | 21 |
| `network_routes` | 36 |
| `dhcp_leases` | 73 |
| `arp_entries` | 887 |
| `bridge_hosts` | 171 |
| `network_neighbors` | 13 |
| `network_events` | 4,841 |
| context tables | 0 |

## Migration report disposition

| Migration-report field | Verified value |
| --- | ---: |
| legacy hosts | 1,221 |
| mapped legacy hosts | 1,221 |
| MAC-backed assets | 347 |
| provisional assets | 678 |
| asset interfaces | 1,025 |
| IP observations | 4,419,140 |
| hostname observations | 470,552 |
| tag bindings | 0 |
| unresolved legacy hosts | 0 |
| unresolved observations | 628,306 |
| unresolved tags | 0 |
| aggregation conflicts | 135 |

Migration-report structure passed: all legacy hosts were mapped and no
unresolved legacy hosts remained. The operator reviewed and explicitly
accepted preservation of all 628,441 reviewable records (628,306 unresolved
observations and 135 aggregation conflicts). These records were retained;
they were neither discarded nor changed. The acknowledgement artifact and
the detailed records remain in the protected backup directory and are not
committed to Git.

## Application verification

- focused regression: `84 passed`
- full regression: `171 passed, 1 skipped`
- legacy read commands: verified successfully against the deployed database
- `openvpn-web.service`: active
- `netctl-collect.timer`: active

The release did not require rollback. Runtime observations were preserved
through the migration; this migration does not update or delete observations
from a collection.
