# Netctl host-availability rollout and rollback

Use this runbook for the host-availability release. The normal collection
service remains the primary path: it runs availability only after a successful
collection. `netctl-availability.timer` is a boot/recovery path only. Its
fixed command, `netctl --json availability collect`, reads approved context and
current collection state, records availability evidence, and does not change
network-device configuration.

Use the deployed database path unless the deployment configuration explicitly
uses another database URL. Do not place credentials, topology exports, or
unapproved scan output in the deployment record.

## Rollout

1. Stop collection and availability timers before making the backup. Do not
   run a manually constructed probe command or change RouterOS, OpenVPN, DNS,
   DHCP, switch, or firewall configuration during this rollout.

   ```bash
   sudo systemctl stop netctl-collect.timer netctl-availability.timer
   ```

2. Take an SQLite online backup and hash it. Preserve the backup path and
   SHA-256 digest with the change record.

   ```bash
   sudo install -d -m 0750 /var/backups/netctl
   stamp="$(date -u +%Y%m%dT%H%M%SZ)"
   backup="/var/backups/netctl/netctl-before-host-availability-$stamp.sqlite"
   sudo sqlite3 /var/lib/netctl/netctl.sqlite ".backup '$backup'"
   sudo sqlite3 "$backup" 'PRAGMA integrity_check;'
   sudo sha256sum "$backup"
   ```

   Continue only if the backup integrity check returns `ok`.

3. Deploy the approved application release by the normal deployment process.
   Do not enable the recovery timer until the installed systemd verifier has
   passed. The installer performs this verification before `enable --now`.

4. Verify the migration ledger through version 15 and database integrity.

   ```bash
   sudo sqlite3 /var/lib/netctl/netctl.sqlite \
     'SELECT group_concat(version, ",") FROM (SELECT version FROM schema_migrations ORDER BY version);'
   sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
   ```

   The ledger must be `1,2,3,4,5,6,7,8,9,10,11,12,13,14,15`, with no duplicate
   versions, and integrity must be `ok`.

5. Validate and import the approved canonical context. Use the approved YAML,
   schema, and release provenance from the change record; do not substitute a
   locally edited context.

   ```bash
   context_path='/approved/path/network-context.yaml'
   schema_path='/approved/path/network-context.schema.json'
   git_sha='<approved-release-sha>'
   sudo /usr/local/sbin/netctl --json context validate --path "$context_path" --schema "$schema_path"
   sudo /usr/local/sbin/netctl --json context import --path "$context_path" --schema "$schema_path" --git-sha "$git_sha"
   ```

6. Start normal collection, then run one availability cycle. The direct cycle
   is permitted only through the fixed netctl command and fails closed if the
   imported context or source health is invalid.

   ```bash
   sudo systemctl start netctl-collect.timer
   sudo /usr/local/sbin/netctl --json collect all --reconcile
   sudo /usr/local/sbin/netctl --json availability collect
   ```

7. For `192.168.99.0/24`, export the current availability-status counts and
   compare the count with a separately authorized active scan. Record only the
   approved comparison result, not raw scan output. Confirm that an ARP entry
   with an empty MAC is not presented as `online`; it may not be used as active
   or passive positive evidence.

8. Enable the collection and availability timers after the checks above are
   accepted.

   ```bash
   sudo systemctl enable --now netctl-collect.timer
   sudo systemctl enable --now netctl-availability.timer
   sudo systemctl is-active netctl-collect.timer netctl-availability.timer
   ```

## Rollback

Roll back if the verifier, migration ledger, integrity check, approved-context
import, availability cycle, or comparison fails.

1. Stop the collection and availability timers. Preserve the failed database
   unchanged for diagnosis before restoring anything.

   ```bash
   sudo systemctl stop netctl-collect.timer netctl-availability.timer
   stamp="$(date -u +%Y%m%dT%H%M%SZ)"
   failed_db="/var/lib/netctl/netctl.failed-host-availability-$stamp.sqlite"
   sudo mv /var/lib/netctl/netctl.sqlite "$failed_db"
   ```

2. Verify the recorded SHA-256 digest of the backup, restore the verified
   database and the previous application release, and restore ownership.

   ```bash
   backup='/var/backups/netctl/netctl-before-host-availability-<timestamp>.sqlite'
   sha256sum --check /path/to/recorded-backup.sha256
   sudo install -m 0640 -o netctl -g netctl "$backup" /var/lib/netctl/netctl.sqlite
   # Restore the previous approved application release by the normal release procedure.
   ```

3. Run `PRAGMA integrity_check` on the restored database. Only after it
   returns `ok`, start the prior application services and the prior collection
   timer. Leave the availability timer stopped unless it was part of the
   previously approved release.

   ```bash
   sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
   sudo systemctl start openvpn-web.service netctl-collect.timer
   ```

Record the failed-database path, backup digest verification, integrity result,
and restored release identifier. This rollback changes local application and
database state only; it does not modify production network configuration.
