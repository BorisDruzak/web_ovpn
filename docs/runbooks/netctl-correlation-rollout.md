# Netctl correlation rollout and rollback

Use this runbook to enable the local topology and attachment reconciliation
timer. Reconciliation reads the collected SQLite state only; it does not
contact network devices or alter their configuration.

## Backup and deploy

Keep the reconcile timer disabled until the database backup, integrity check,
and one manual reconciliation have all succeeded.

```bash
sudo systemctl disable --now netctl-reconcile.timer
sudo install -d -m 0750 /var/backups/netctl
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
db_backup="/var/backups/netctl/netctl-before-correlation-$stamp.sqlite"
app_backup="/var/backups/netctl/openvpn-web-before-correlation-$stamp.tgz"
sudo sqlite3 /var/lib/netctl/netctl.sqlite ".backup '$db_backup'"
sudo tar -C /opt -czf "$app_backup" openvpn-web
sudo sqlite3 "$db_backup" 'PRAGMA integrity_check;'
sudo sha256sum "$db_backup" "$app_backup"
```

Proceed only when the integrity check returns `ok`. Deploy the application
tree, then validate the migration and current state before enabling the timer:

```bash
sudo /usr/local/sbin/netctl --json topology status
sudo /usr/local/sbin/netctl --json topology reconcile
sudo /usr/local/sbin/netctl --json attachments reconcile
sudo /usr/local/sbin/netctl --json topology status
sudo /usr/local/sbin/netctl --json attachments status
sudo systemctl enable --now netctl-reconcile.timer
sudo systemctl is-active netctl-reconcile.timer
```

Inspect only aggregate counts and finding status in the deployment record; do
not copy endpoint evidence, MAC addresses, or secrets into tickets.

## Rollback

Disable reconciliation first. Restore the application tree compatible with the
backup before replacing the database, then verify SQLite integrity.

```bash
sudo systemctl disable --now netctl-reconcile.timer
sudo systemctl stop netctl-reconcile.service
sudo tar -C /opt -xzf "$app_backup"
sudo install -m 0640 -o netctl -g netctl "$db_backup" /var/lib/netctl/netctl.sqlite
sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
```

Do not re-enable the timer unless the restored database returns `ok` and the
compatible application deployment has been verified.
