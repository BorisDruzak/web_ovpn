# Netctl runtime asset identity: backup, deployment, and rollback

Use this runbook only for the production deployment that introduces migration
version `2` (runtime asset identity). It is an additive migration of the
Network Observer database; existing observer tables and commands remain the
operational interface. Do not run a collection while capturing the comparison
counts or while the migration is being checked.

The commands use the normal production paths. If the configured database or
application path differs, substitute it consistently before starting and
record the changed paths in the manifest. Do not put passwords, API tokens,
private keys, source YAML, or other credentials in the manifest, shell history,
or deployment record.

## 1. Stop services and capture the rollback set

Run these commands in one privileged production shell. They stop the web
application, collector timer, and any in-flight collector before a SQLite
backup is taken. The `.backup` command is required: do not copy the live
database file with `cp` while WAL mode is in use.

```bash
sudo systemctl stop openvpn-web.service netctl-collect.timer netctl-collect.service
sudo systemctl is-active --quiet openvpn-web.service && exit 1 || true
sudo systemctl is-active --quiet netctl-collect.timer && exit 1 || true
sudo systemctl is-active --quiet netctl-collect.service && exit 1 || true

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/backups/netctl/runtime-asset-identity-$stamp"
db_path="/var/lib/netctl/netctl.sqlite"
app_path="/opt/openvpn-web"
wrapper_path="/usr/local/sbin/netctl"
sudo install -d -m 0750 "$backup_dir"

db_backup="$backup_dir/netctl-before-runtime-asset-identity.sqlite"
app_backup="$backup_dir/openvpn-web-before-runtime-asset-identity.tgz"
wrapper_backup="$backup_dir/netctl-before-runtime-asset-identity"
pre_migrations="$backup_dir/schema-migrations-before.txt"
pre_counts="$backup_dir/legacy-counts-before.txt"
manifest="$backup_dir/rollback.paths"

sudo sqlite3 "$db_path" ".backup '$db_backup'"
sudo sqlite3 "$db_backup" 'PRAGMA integrity_check;'
sudo tar -C /opt -czf "$app_backup" openvpn-web
sudo install -m 0755 "$wrapper_path" "$wrapper_backup"
sudo tar -tzf "$app_backup" >/dev/null
sudo test -x "$wrapper_backup"
sudo sha256sum "$db_backup" "$app_backup" "$wrapper_backup" | sudo tee "$backup_dir/SHA256SUMS" >/dev/null
```

Proceed only if `PRAGMA integrity_check` prints exactly `ok`, the archive list
completes, and the wrapper is executable. Capture the pre-migration ledger and
the legacy-table baseline from the backup, rather than from the live path:

```bash
sudo sqlite3 -header -column "$db_backup" \
  'SELECT version, applied_at FROM schema_migrations ORDER BY version;' | sudo tee "$pre_migrations" >/dev/null

sudo sqlite3 -header -column "$db_backup" <<'SQL' | sudo tee "$pre_counts" >/dev/null
SELECT 'network_sources' AS table_name, COUNT(*) AS row_count FROM network_sources
UNION ALL SELECT 'collection_runs', COUNT(*) FROM collection_runs
UNION ALL SELECT 'network_hosts', COUNT(*) FROM network_hosts
UNION ALL SELECT 'network_device_tags', COUNT(*) FROM network_device_tags
UNION ALL SELECT 'host_observations', COUNT(*) FROM host_observations
UNION ALL SELECT 'network_interfaces', COUNT(*) FROM network_interfaces
UNION ALL SELECT 'network_routes', COUNT(*) FROM network_routes
UNION ALL SELECT 'dhcp_leases', COUNT(*) FROM dhcp_leases
UNION ALL SELECT 'arp_entries', COUNT(*) FROM arp_entries
UNION ALL SELECT 'bridge_hosts', COUNT(*) FROM bridge_hosts
UNION ALL SELECT 'network_neighbors', COUNT(*) FROM network_neighbors
UNION ALL SELECT 'network_events', COUNT(*) FROM network_events
UNION ALL SELECT 'context_revisions', COUNT(*) FROM context_revisions
UNION ALL SELECT 'context_import_runs', COUNT(*) FROM context_import_runs
UNION ALL SELECT 'context_heads', COUNT(*) FROM context_heads
ORDER BY table_name;
SQL

{
  printf 'db_path=%s\n' "$db_path"
  printf 'app_path=%s\n' "$app_path"
  printf 'wrapper_path=%s\n' "$wrapper_path"
  printf 'db_backup=%s\n' "$db_backup"
  printf 'app_backup=%s\n' "$app_backup"
  printf 'wrapper_backup=%s\n' "$wrapper_backup"
  printf 'pre_migrations=%s\n' "$pre_migrations"
  printf 'pre_counts=%s\n' "$pre_counts"
} | sudo tee "$manifest" >/dev/null
sudo chmod 0640 "$manifest"
```

`schema_migrations` must already exist and its pre-deployment output must be
kept with the backup. If it does not exist, stop and investigate; this release
is intended to upgrade the existing migration-ledger database, not an unknown
schema.

## 2. Deploy without allowing collection

Use the documented source-package and installation procedure in
[`docs/DEPLOYMENT.md`](../DEPLOYMENT.md). Before executing its installer,
temporarily mask the collector service. The standard installer enables the
timer; the mask prevents a timer-triggered collection from changing the legacy
baseline before migration verification is complete.

```bash
sudo systemctl mask --runtime netctl-collect.service
sudo systemctl is-enabled netctl-collect.service
```

Stage the already-reviewed release archive and run the documented installer
using the operator's approved secret-entry method. Do not place a credential in
this runbook or in a pasted command. Immediately stop the web service that the
installer starts; leave the collector service masked.

```bash
# Follow docs/DEPLOYMENT.md to unpack the approved release in /tmp/openvpn-web-src
# and invoke deploy/install-openvpn-web.sh using the approved interactive secret method.
sudo systemctl stop openvpn-web.service netctl-collect.timer netctl-collect.service || true
sudo systemctl is-active --quiet openvpn-web.service && exit 1 || true
sudo systemctl is-active --quiet netctl-collect.timer && exit 1 || true
```

Trigger migration `2` once, explicitly and as the collector user. This command
opens the deployed database through the deployed wrapper; it is read-only with
respect to network devices and does not collect from any source.

```bash
sudo -u netctl /usr/local/sbin/netctl --json dashboard
```

The command must return JSON success. If it fails, do not retry with a
collection; start the rollback procedure below.

## 3. Verify migration and legacy compatibility

All checks below must pass before starting either service. Save their output in
the same backup directory for the deployment record.

```bash
# Use the exact directory printed in the deployment record from section 1.
manifest='/var/backups/netctl/runtime-asset-identity-REPLACE_WITH_STAMP/rollback.paths'
backup_dir="$(dirname "$manifest")"
db_path="$(sudo sed -n 's/^db_path=//p' "$manifest")"
test -n "$db_path"

sudo sqlite3 -header -column "$db_path" \
  'SELECT version, applied_at FROM schema_migrations ORDER BY version;' | sudo tee "$backup_dir/schema-migrations-after.txt" >/dev/null
sudo sqlite3 "$db_path" "SELECT CASE WHEN EXISTS (SELECT 1 FROM schema_migrations WHERE version = 2) THEN 'migration_2_present' ELSE 'migration_2_missing' END;"

sudo sqlite3 -header -column "$db_path" <<'SQL' | sudo tee "$backup_dir/legacy-counts-after.txt" >/dev/null
SELECT 'network_sources' AS table_name, COUNT(*) AS row_count FROM network_sources
UNION ALL SELECT 'collection_runs', COUNT(*) FROM collection_runs
UNION ALL SELECT 'network_hosts', COUNT(*) FROM network_hosts
UNION ALL SELECT 'network_device_tags', COUNT(*) FROM network_device_tags
UNION ALL SELECT 'host_observations', COUNT(*) FROM host_observations
UNION ALL SELECT 'network_interfaces', COUNT(*) FROM network_interfaces
UNION ALL SELECT 'network_routes', COUNT(*) FROM network_routes
UNION ALL SELECT 'dhcp_leases', COUNT(*) FROM dhcp_leases
UNION ALL SELECT 'arp_entries', COUNT(*) FROM arp_entries
UNION ALL SELECT 'bridge_hosts', COUNT(*) FROM bridge_hosts
UNION ALL SELECT 'network_neighbors', COUNT(*) FROM network_neighbors
UNION ALL SELECT 'network_events', COUNT(*) FROM network_events
UNION ALL SELECT 'context_revisions', COUNT(*) FROM context_revisions
UNION ALL SELECT 'context_import_runs', COUNT(*) FROM context_import_runs
UNION ALL SELECT 'context_heads', COUNT(*) FROM context_heads
ORDER BY table_name;
SQL
sudo diff -u "$backup_dir/legacy-counts-before.txt" "$backup_dir/legacy-counts-after.txt"
```

The post-deployment ledger must contain version `2` exactly once, and the
legacy count diff must be empty. Inspect the migration report: mapped legacy
hosts must equal legacy hosts, and all three unresolved/conflict JSON fields
must be `[]`. Treat any other value as a failed verification and roll back.

```bash
sudo sqlite3 -header -column "$db_path" <<'SQL' | sudo tee "$backup_dir/migration-report.txt" >/dev/null
SELECT migration_version, completed_at, legacy_host_count,
       mapped_legacy_host_count, mac_asset_count, provisional_asset_count,
       interface_count, ip_observation_count, hostname_observation_count,
       tag_binding_count, unresolved_legacy_host_ids_json,
       unresolved_observation_ids_json, unresolved_tag_records_json,
       aggregation_conflicts_json
FROM runtime_asset_migration_reports
WHERE migration_version = 2;
SQL

sudo sqlite3 -header -column "$db_path" <<'SQL' | sudo tee "$backup_dir/ip-indexes.txt" >/dev/null
WITH indexes AS (
  SELECT il.name, il.[unique] AS is_unique,
         group_concat(ii.name, ',') AS indexed_columns
  FROM pragma_index_list('ip_observations') AS il
  JOIN pragma_index_info(il.name) AS ii
  GROUP BY il.name, il.[unique]
)
SELECT name, is_unique, indexed_columns FROM indexes ORDER BY name;
SQL
sudo sqlite3 "$db_path" <<'SQL'
WITH indexes AS (
  SELECT il.name, il.[unique] AS is_unique,
         group_concat(ii.name, ',') AS indexed_columns
  FROM pragma_index_list('ip_observations') AS il
  JOIN pragma_index_info(il.name) AS ii
  GROUP BY il.name, il.[unique]
)
SELECT CASE WHEN EXISTS (
  SELECT 1 FROM indexes WHERE is_unique = 1 AND indexed_columns = 'ip'
) THEN 'unexpected_unique_runtime_ip_index' ELSE 'no_unique_runtime_ip_index' END;
SQL
```

The final index check must print `no_unique_runtime_ip_index`. The allowed
unique constraint is the composite observation identity
`(asset_id, ip, source_key, observation_source)`; an IP by itself must not be
unique.

Verify connection settings through the deployed application's `connect()`
function, because `foreign_keys` and `busy_timeout` are connection-local:

```bash
sudo -u netctl env PYTHONPATH=/opt/openvpn-web /opt/openvpn-web/.venv/bin/python - <<'PY' | sudo tee "$backup_dir/runtime-pragmas.txt" >/dev/null
from netctl.db import connect

conn = connect("sqlite:////var/lib/netctl/netctl.sqlite")
try:
    for pragma in ("foreign_keys", "journal_mode", "busy_timeout"):
        print(f"{pragma}={conn.execute(f'PRAGMA {pragma}').fetchone()[0]}")
finally:
    conn.close()
PY
sudo grep -Fx 'foreign_keys=1' "$backup_dir/runtime-pragmas.txt"
sudo grep -Fxi 'journal_mode=wal' "$backup_dir/runtime-pragmas.txt"
sudo grep -Fx 'busy_timeout=5000' "$backup_dir/runtime-pragmas.txt"
```

Finally, prove that the legacy observer read commands still work. These only
read the database; do not substitute `collect` or `sources test` in this
verification stage.

```bash
for command in \
  'sources list' \
  'dashboard' \
  'hosts list' \
  'tags list' \
  'interfaces list' \
  'routes list' \
  'dhcp-leases list' \
  'arp list' \
  'bridge-hosts list' \
  'observations list'; do
  sudo -u netctl /usr/local/sbin/netctl --json $command | sudo tee "$backup_dir/legacy-${command// /-}.json" >/dev/null
done
```

After every command succeeds, make the release live:

```bash
sudo systemctl unmask --runtime netctl-collect.service
sudo systemctl start openvpn-web.service netctl-collect.timer
sudo systemctl is-active openvpn-web.service netctl-collect.timer
```

Keep the complete backup directory until the agreed retention period has
passed. Record the release revision, backup directory, migration ledger output,
report output, and verification result in the deployment ticket.

## 4. Roll back safely

Roll back on a failed install, failed migration, any non-empty legacy count
diff, unexpected report data, incorrect PRAGMAs, or a failed legacy command.
First preserve the failed application and database for diagnosis. Then restore
the **old application tree and old wrapper before restoring the old database**;
the old database must never be started beneath the new code.

```bash
manifest='/var/backups/netctl/runtime-asset-identity-REPLACE_WITH_STAMP/rollback.paths'
db_path="$(sudo sed -n 's/^db_path=//p' "$manifest")"
app_path="$(sudo sed -n 's/^app_path=//p' "$manifest")"
wrapper_path="$(sudo sed -n 's/^wrapper_path=//p' "$manifest")"
db_backup="$(sudo sed -n 's/^db_backup=//p' "$manifest")"
app_backup="$(sudo sed -n 's/^app_backup=//p' "$manifest")"
wrapper_backup="$(sudo sed -n 's/^wrapper_backup=//p' "$manifest")"
test -n "$db_path" -a -n "$app_path" -a -n "$wrapper_path"
sudo test -f "$db_backup"
sudo test -f "$app_backup"
sudo test -x "$wrapper_backup"
sudo sha256sum -c "$(dirname "$manifest")/SHA256SUMS"

sudo systemctl stop openvpn-web.service netctl-collect.timer netctl-collect.service || true
sudo systemctl mask --runtime netctl-collect.service
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
failed_app="${app_path}.failed-runtime-asset-identity-$stamp"
failed_db="${db_path}.failed-runtime-asset-identity-$stamp"

sudo mv "$app_path" "$failed_app"
sudo tar -C "$(dirname "$app_path")" -xzf "$app_backup"
sudo install -m 0755 "$wrapper_backup" "$wrapper_path"

sudo mv "$db_path" "$failed_db"
sudo install -m 0640 -o netctl -g netctl "$db_backup" "$db_path"
sudo sqlite3 "$db_path" 'PRAGMA integrity_check;'
```

Only continue if the restored database prints exactly `ok`. The old application
tree and wrapper are now in place before any command opens the old database.
Complete rollback verification and restore service operation:

```bash
sudo -u netctl /usr/local/sbin/netctl --json dashboard
sudo -u netctl /usr/local/sbin/netctl --json hosts list
sudo systemctl unmask --runtime netctl-collect.service
sudo systemctl start openvpn-web.service netctl-collect.timer
sudo systemctl is-active openvpn-web.service netctl-collect.timer
```

Record `failed_app`, `failed_db`, and the failed verification output with the
rollback. Do not delete those diagnostic artifacts until the failure has been
investigated.
