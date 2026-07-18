# Netctl runtime live observations deployment and rollback

Use this runbook to deploy migration `3` and the runtime-observation writer.
It is additive: the legacy collector tables and commands remain the operational
compatibility surface. The target host does not provide the `sqlite3` CLI;
every database check below uses the deployed application virtual environment.
Do not run a collection while the database and code backup are being captured.
The OpenVPN service is out of scope and must stay running.

## 1. Quiesce the application and create backups

Record the release SHA. As root, mask and stop the application/collector units
before any backup or migration, then verify both conditions. Do not unmask or
start them until all checks in this runbook have passed.

```bash
set -euo pipefail
units=(openvpn-web.service netctl-collect.timer netctl-collect.service)
for unit in "${units[@]}"; do sudo systemctl mask --runtime "$unit"; done
for unit in "${units[@]}"; do sudo systemctl stop "$unit"; done
for unit in "${units[@]}"; do
  if sudo systemctl is-active --quiet "$unit"; then
    echo "unit is still active: $unit" >&2
    exit 1
  fi
  test "$(sudo readlink -f "/run/systemd/system/$unit")" = /dev/null
done

app_dir=/opt/openvpn-web
python_bin="$app_dir/.venv/bin/python"
db_path=/var/lib/netctl/netctl.sqlite
backup_dir=/var/backups/netctl/runtime-live-$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -o netctl -g netctl -m 0700 "$backup_dir"
sudo -u netctl "$python_bin" - "$db_path" "$backup_dir/netctl-before.sqlite" <<'PY'
import sqlite3
import sys
from pathlib import Path

source_path = Path(sys.argv[1]).resolve()
target_path = Path(sys.argv[2])
source = sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)
target = sqlite3.connect(target_path)
try:
    source.backup(target)
finally:
    target.close()
    source.close()
PY
sudo -u netctl "$python_bin" - "$db_path" <<'PY' | sudo tee "$backup_dir/integrity-before.txt"
import sqlite3
import sys
from pathlib import Path

path = Path(sys.argv[1]).resolve()
conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
try:
    print(conn.execute("PRAGMA integrity_check").fetchone()[0])
finally:
    conn.close()
PY
sudo test -s "$backup_dir/netctl-before.sqlite"
sudo tar -C /opt -czf "$backup_dir/openvpn-web-before.tgz" openvpn-web
sudo cp -a /usr/local/sbin/netctl "$backup_dir/netctl-wrapper-before"
```

Continue only when `integrity_check` is `ok`, the backup has a non-zero size,
and the release artefacts are recorded in the change record.

## 2. Apply migration once and verify its guards

Install the verified release while the units remain masked. Trigger normal
application startup once as the collector user; it owns schema migration. The
subsequent `runtime-assets` commands are read-only and do not synchronize
configured sources.

```bash
sudo -u netctl /usr/local/sbin/netctl --json dashboard \
  | sudo tee "$backup_dir/dashboard-migration-trigger.json"
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets status \
  | sudo tee "$backup_dir/runtime-status-after-migration.json"
```

Verify the ledger and both migration-3 interface guard triggers with the
deployed Python. The command exits nonzero unless each required version occurs
exactly once and both expected guards exist:

```bash
sudo -u netctl "$python_bin" - "$db_path" <<'PY' | sudo tee "$backup_dir/migration-3-verify.json"
import json
import sqlite3
import sys
from pathlib import Path

path = Path(sys.argv[1]).resolve()
conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
try:
    versions = conn.execute(
        "SELECT version, COUNT(*) FROM schema_migrations GROUP BY version ORDER BY version"
    ).fetchall()
    guards = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = ? AND name IN (?, ?) ORDER BY name",
        (
            "trigger",
            "ip_observations_interface_asset_insert_guard",
            "ip_observations_interface_asset_update_guard",
        ),
    ).fetchall()
finally:
    conn.close()

payload = {
    "schema_migrations": [{"version": version, "count": count} for version, count in versions],
    "guard_triggers": [name for (name,) in guards],
}
print(json.dumps(payload, sort_keys=True))
assert payload["schema_migrations"] == [
    {"version": 1, "count": 1},
    {"version": 2, "count": 1},
    {"version": 3, "count": 1},
]
assert payload["guard_triggers"] == [
    "ip_observations_interface_asset_insert_guard",
    "ip_observations_interface_asset_update_guard",
]
PY
```

The status output's `migration_only_current.total` must be zero:
migration-created IP and hostname observations are historical, not live state.

Review the migration-2 report summary in the status JSON. Review every
`historical_identity_conflict` backfill before acknowledging or resolving it:

```bash
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets findings --status open \
  | sudo tee "$backup_dir/runtime-open-findings.json"
```

## 3. Prove live writer behavior

While the timer remains masked, run one successful collection for a
non-production test source or during the approved collection window:

```bash
sudo -u netctl /usr/local/sbin/netctl --json collect <source> \
  | sudo tee "$backup_dir/collect-first.json"
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets status \
  | sudo tee "$backup_dir/runtime-status-after-first.json"
```

The first successful collection must create current runtime rows for observed
MAC-backed hosts. Repeat the exact collection. Asset, interface, IP, and
hostname totals must not duplicate. Then collect a controlled snapshot in
which one prior IP/hostname is absent; its `collector_host` observation must
be demoted (`is_current=0`) while the new snapshot remains current.

Induce or use an approved failed collection and compare the prior current
runtime rows. A failed collection must leave them unchanged; it must not
demote or create current runtime observations.

Inspect a known key and review all open findings:

```bash
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets inspect \
  --asset-key mac:AA:BB:CC:DD:EE:FF
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets findings --status open
```

Record the findings disposition in the change record. Do not silently delete
findings or historical observations.

## 4. Compatibility and service restoration

Confirm legacy commands while the units remain masked:

```bash
sudo -u netctl /usr/local/sbin/netctl --json dashboard
sudo -u netctl /usr/local/sbin/netctl --json hosts list
```

Only after all migration, writer, finding, and legacy checks have passed,
unmask and start the services:

```bash
for unit in "${units[@]}"; do sudo systemctl unmask --runtime "$unit"; done
sudo systemctl daemon-reload
sudo systemctl start openvpn-web.service netctl-collect.timer
sudo systemctl is-active --quiet openvpn-web.service
sudo systemctl is-active --quiet netctl-collect.timer
sudo systemctl --no-pager --full status openvpn-web.service netctl-collect.timer
```

The web service and collector timer must be active, and the OpenVPN service
must remain healthy. Preserve all JSON and Python-check outputs under
`$backup_dir`.

## 5. Rollback

Roll back for a failed integrity check, missing trigger, duplicate migration
ledger entry, incorrect live-state transition, unreviewed conflict, failed
legacy command, or unhealthy service. Stop the application/collector units,
restore the archived code and wrapper, then restore the SQLite backup as one
file (including no stale `-wal`/`-shm` sidecars):

```bash
for unit in "${units[@]}"; do sudo systemctl stop "$unit"; done
sudo rm -f "$db_path" "$db_path-wal" "$db_path-shm"
sudo cp "$backup_dir/netctl-before.sqlite" "$db_path"
sudo chown netctl:netctl "$db_path"
sudo tar -C /opt -xzf "$backup_dir/openvpn-web-before.tgz"
sudo install -m 0755 "$backup_dir/netctl-wrapper-before" /usr/local/sbin/netctl
sudo -u netctl /usr/local/sbin/netctl --json dashboard
```

Before restoring services, repeat the deployed-Python `PRAGMA integrity_check`
block from section 1, capture the restored schema ledger using the
deployed-Python block from section 2, and capture legacy dashboard output.
Only then unmask and start `openvpn-web.service` and `netctl-collect.timer` as
in section 4. Migration `3` is not removed in-place; the database backup is
the rollback boundary.
