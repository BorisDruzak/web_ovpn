# Netctl runtime live observations deployment and rollback

Use this runbook to deploy migration `3` and the runtime-observation writer.
It is additive: the legacy collector tables and commands remain the operational
compatibility surface. Do not run a collection while the database and code
backup are being captured.

## 1. Preflight and backups

Record the release SHA and stop only the web/collector services that open the
database. Preserve the VPN service. Set the paths for the deployment:

```bash
db_path=/var/lib/netctl/netctl.sqlite
backup_dir=/var/backups/netctl/runtime-live-$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$backup_dir"
sudo -u netctl sqlite3 "$db_path" ".backup '$backup_dir/netctl-before.sqlite'"
sudo sqlite3 "$db_path" 'PRAGMA integrity_check;' | sudo tee "$backup_dir/integrity-before.txt"
sudo tar -C /opt -czf "$backup_dir/openvpn-web-before.tgz" openvpn-web
sudo cp -a /usr/local/sbin/netctl "$backup_dir/netctl-wrapper-before"
```

Continue only when `integrity_check` is `ok`, the backup has a non-zero size,
and the release artefacts are recorded in the change record.

## 2. Apply migration once

Install the verified release, then trigger normal application startup once as
the collector user. Do not invoke migration functions directly.

```bash
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets status \
  | sudo tee "$backup_dir/runtime-status-after-startup.json"
sudo sqlite3 "$db_path" \
  'SELECT version, COUNT(*) AS count FROM schema_migrations GROUP BY version ORDER BY version;' \
  | sudo tee "$backup_dir/schema-migrations-after.txt"
```

The ledger must contain versions `1`, `2`, and `3`, each exactly once. Verify
both migration-3 interface guards exist:

```bash
sudo sqlite3 "$db_path" \
  "SELECT name FROM sqlite_master WHERE type='trigger' AND name IN
   ('ip_observations_interface_asset_insert_guard',
    'ip_observations_interface_asset_update_guard') ORDER BY name;"
```

Both names must be returned. The status output's `migration_only_current.total`
must be zero: migration-created IP and hostname observations are historical,
not live state.

Review the migration-2 report summary in the status JSON. Review every
`historical_identity_conflict` backfill before acknowledging or resolving it:

```bash
sudo -u netctl /usr/local/sbin/netctl --json runtime-assets findings --status open \
  | sudo tee "$backup_dir/runtime-open-findings.json"
```

## 3. Prove live writer behavior

Run one successful collection for a non-production test source or during the
approved collection window:

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

## 4. Compatibility and health

Confirm legacy commands still work, then restore the services and inspect
their status:

```bash
sudo -u netctl /usr/local/sbin/netctl --json dashboard
sudo -u netctl /usr/local/sbin/netctl --json hosts list
sudo systemctl unmask --runtime openvpn-web.service netctl-collect.timer netctl-collect.service
sudo systemctl start openvpn-web.service netctl-collect.timer
sudo systemctl --no-pager --full status openvpn-web.service netctl-collect.timer
```

The web service and collector timer must be active, and the VPN service must
remain healthy. Preserve all JSON and SQL outputs under `$backup_dir`.

## 5. Rollback

Roll back for a failed integrity check, missing trigger, duplicate migration
ledger entry, incorrect live-state transition, unreviewed conflict, failed
legacy command, or unhealthy service. Stop the application/collector units,
restore the archived code and wrapper, then restore the SQLite backup as one
file (including no stale `-wal`/`-shm` sidecars):

```bash
sudo systemctl stop openvpn-web.service netctl-collect.timer netctl-collect.service
sudo rm -f "$db_path" "$db_path-wal" "$db_path-shm"
sudo cp "$backup_dir/netctl-before.sqlite" "$db_path"
sudo chown netctl:netctl "$db_path"
sudo tar -C /opt -xzf "$backup_dir/openvpn-web-before.tgz"
sudo install -m 0755 "$backup_dir/netctl-wrapper-before" /usr/local/sbin/netctl
sudo -u netctl /usr/local/sbin/netctl --json dashboard
sudo systemctl start openvpn-web.service netctl-collect.timer
```

After rollback, capture `PRAGMA integrity_check`, the schema ledger, legacy
dashboard output, and service status. Migration `3` is not removed in-place;
the database backup is the rollback boundary.
