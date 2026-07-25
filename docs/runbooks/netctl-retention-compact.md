# Netctl 30-day retention and controlled SQLite compaction

Use this procedure only for a planned, one-time compaction of the Network
Observer database. The daily `netctl-retention.timer` normally removes history
older than 30 days without running `VACUUM`. This runbook permits exactly one
manual `VACUUM` after a verified backup and successful retention cleanup.

The procedure changes only the local SQLite database and systemd unit state.
It does not write to switches, routers, OpenVPN, DNS, DHCP, firewall rules, or
any other network device. The final collection reads configured sources; it
does not modify them.

Run it from a privileged shell on the deployed Linux host. If the database is
configured somewhere other than `/var/lib/netctl/netctl.sqlite`, replace both
the database and lock paths consistently before starting.

## 1. Capture and stop the scheduled work

Choose a maintenance window. Record each timer's enabled and active state,
then disable and stop all collection, reconciliation, and retention timers.
Keep the state file for restoration and rollback.

```bash
set -euo pipefail
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir=/var/backups/netctl
timer_state="$backup_dir/retention-compact-$stamp.timers.tsv"
sudo install -d -m 0750 -o root -g root "$backup_dir"
for timer in netctl-collect.timer netctl-reconcile.timer netctl-retention.timer; do
  printf '%s\t%s\t%s\n' "$timer" \
    "$(systemctl is-enabled "$timer" 2>/dev/null || true)" \
    "$(systemctl is-active "$timer" 2>/dev/null || true)"
done | sudo tee "$timer_state" >/dev/null
sudo chmod 0640 "$timer_state"
sudo systemctl disable --now netctl-collect.timer netctl-reconcile.timer netctl-retention.timer
sudo systemctl stop netctl-collect.service netctl-reconcile.service netctl-retention.service
```

Wait for `CollectLock` to disappear. Do not delete the lock file: an existing
lock may represent a collector that has not yet exited safely.

```bash
db=/var/lib/netctl/netctl.sqlite
lock=/var/lib/netctl/netctl.lock
until sudo test ! -e "$lock"; do
  printf '%s waiting for CollectLock %s\n' "$(date -u +%FT%TZ)" "$lock"
  sleep 2
done
```

## 2. Back up and validate before changing history

Create a SQLite-consistent backup and record its checksum and integrity
result. Stop the web service before any maintenance so it cannot open the
database during cleanup or compaction.

```bash
db_backup="$backup_dir/netctl-before-retention-compact-$stamp.sqlite"
sha_file="$db_backup.sha256"
sudo systemctl stop openvpn-web.service
sudo sqlite3 "$db" ".backup '$db_backup'"
sudo chown root:root "$db_backup"
sudo chmod 0640 "$db_backup"
sudo sha256sum "$db_backup" | sudo tee "$sha_file" >/dev/null
sudo sqlite3 "$db_backup" 'PRAGMA integrity_check;'
sudo sha256sum -c "$sha_file"
```

Proceed only if the integrity check returns `ok` and the checksum verifies.

## 3. Run and verify normal 30-day retention

Save the dry-run and apply JSON results. Compare the `delete` values from the
preview with `deleted` values from the apply result, record their aggregate
counts, and stop if either command fails. Both commands use `CollectLock` and
the apply command checks foreign keys and database integrity atomically.

```bash
preview="$backup_dir/retention-preview-$stamp.json"
applied="$backup_dir/retention-apply-$stamp.json"
sudo /usr/local/sbin/netctl --json retention cleanup --days 30 | sudo tee "$preview"
sudo /usr/local/sbin/netctl --json retention cleanup --days 30 --apply | sudo tee "$applied"
sudo sqlite3 "$db" 'PRAGMA foreign_key_check; PRAGMA integrity_check;'
sudo python3 - "$preview" "$applied" <<'PY'
import json
import sys

preview, applied = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:])
print("preview delete:", preview["delete"])
print("applied deleted:", applied["deleted"])
print("total deleted:", applied["total_deleted"])
PY
```

`PRAGMA foreign_key_check` must print no rows and `PRAGMA integrity_check`
must print `ok`. Preserve the two JSON files with the backup.

## 4. Check space and compact once

`VACUUM` rewrites the entire database and can require space comparable to the
current database size plus the rewritten copy. Measure free space while the
web service and all Netctl services remain stopped; proceed only if available
bytes are at least twice the current database size. Then run one controlled
`VACUUM`—the daily timer must never do this.

```bash
db_bytes="$(sudo stat -c %s "$db")"
free_bytes="$(df -PB1 "$db" | awk 'NR == 2 {print $4}')"
printf 'database_bytes=%s free_bytes=%s required_free_bytes=%s\n' \
  "$db_bytes" "$free_bytes" "$((db_bytes * 2))"
test "$free_bytes" -ge "$((db_bytes * 2))"
sudo sqlite3 "$db" 'VACUUM; PRAGMA integrity_check;'
```

Stop immediately unless the final integrity result is `ok`.

## 5. Restart, validate context, and restore the prior timer states

Start the web service, execute one read-only source collection and reconciliation,
then check the device-card context. Restore exactly the saved timer enablement
and active states; do not force all timers on.

```bash
sudo systemctl start openvpn-web.service
sudo /usr/local/sbin/netctl --json collect all --reconcile
sudo /usr/local/sbin/netctl --json hosts list --q '<known-hostname-or-ip>'
sudo sqlite3 "$db" 'PRAGMA integrity_check;'

while IFS=$'\t' read -r timer enabled active; do
  case "$enabled" in
    enabled|enabled-runtime) sudo systemctl enable "$timer" ;;
    *) sudo systemctl disable "$timer" ;;
  esac
  case "$active" in
    active) sudo systemctl start "$timer" ;;
    *) sudo systemctl stop "$timer" ;;
  esac
done < "$timer_state"

systemctl is-active openvpn-web.service
cat "$timer_state"
```

Open the web card for the known hostname or IP and confirm its confirmed
switch/port context, freshness, and alternatives are present. Investigate a
failed collection or missing context before considering maintenance complete.

## 6. Roll back from the verified backup

Use rollback if cleanup, compaction, collection, or context validation fails.
Stop every database user, retain the failed database for diagnosis, restore the
verified backup, verify it, restart the web service, and restore the original
timer states from the saved file.

```bash
sudo systemctl stop openvpn-web.service netctl-collect.service netctl-reconcile.service netctl-retention.service
sudo systemctl disable --now netctl-collect.timer netctl-reconcile.timer netctl-retention.timer
failed_db="$db.failed-$stamp"
sudo mv "$db" "$failed_db"
sudo install -m 0640 -o netctl -g netctl "$db_backup" "$db"
sudo sha256sum -c "$sha_file"
sudo sqlite3 "$db" 'PRAGMA foreign_key_check; PRAGMA integrity_check;'
sudo systemctl start openvpn-web.service

while IFS=$'\t' read -r timer enabled active; do
  case "$enabled" in enabled|enabled-runtime) sudo systemctl enable "$timer" ;; *) sudo systemctl disable "$timer" ;; esac
  case "$active" in active) sudo systemctl start "$timer" ;; *) sudo systemctl stop "$timer" ;; esac
done < "$timer_state"
```

Do not resume normal operation unless the restored database has no foreign-key
rows, returns `ok` from `PRAGMA integrity_check`, and the saved timer states
have been restored.
