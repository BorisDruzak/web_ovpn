# Netctl context import: backup, deployment, and rollback

Use this runbook when deploying the netctl context-import migration to the
production Network Observer database. It protects the existing SQLite database
and provides a tested path back to the pre-deployment state.

The deployed database is normally `/var/lib/netctl/netctl.sqlite`. If the
deployment configuration supplies another `--db` URL, use that configured
database path consistently instead; do not assume the default path applies.

## Pre-upgrade backup

1. Stop collection so no collector process changes the database while it is
   being backed up.
2. Create an SQLite online backup, retain the timestamped filename printed by
   the shell, and verify both integrity and its checksum.

```bash
sudo systemctl stop netctl-collect.timer netctl-collect.service
sudo install -d -m 0750 /var/backups/netctl
backup="/var/backups/netctl/netctl-before-context-import-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
sudo sqlite3 /var/lib/netctl/netctl.sqlite ".backup '$backup'"
sudo sqlite3 "$backup" 'PRAGMA integrity_check;'
sudo sha256sum "$backup"
```

Proceed only when `PRAGMA integrity_check` returns `ok`. Preserve the recorded
timestamped backup filename and checksum for the deployment and any rollback.

## Deploy and verify

Run the migration and normal startup according to the deployment procedure.
Then, using known-good context input for this environment, perform all of the
following checks:

```bash
sudo /usr/local/sbin/netctl --json context status
context_path='/path/to/known-good-context.yaml'
schema_path='/path/to/network-context.schema.json'
git_sha='<deployed-git-sha>'
context_id='<known-context-id>'
sudo /usr/local/sbin/netctl --json context diff --path "$context_path" --schema "$schema_path"
sudo /usr/local/sbin/netctl --json context import --path "$context_path" --schema "$schema_path" --git-sha "$git_sha"
sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM context_heads WHERE context_id = '$context_id';"
```

The `context_heads` query must return exactly `1` for the imported context.
Record the successful import run ID and the deployed Git SHA in the deployment
ticket or deployment log. Keep the verified backup until the change has passed
the agreed operational retention period.

## Rollback

Roll back if the migration fails or any post-deployment verification fails.
This preserves the failed database for diagnosis before restoring the verified
backup.

```bash
sudo systemctl stop netctl-collect.timer netctl-collect.service
failed="/var/lib/netctl/netctl.failed-$(date -u +%Y%m%dT%H%M%SZ).sqlite"
sudo mv /var/lib/netctl/netctl.sqlite "$failed"
sudo install -m 0640 -o netctl -g netctl "$backup" /var/lib/netctl/netctl.sqlite
sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
sudo systemctl start netctl-collect.timer
sudo /usr/local/sbin/netctl --json context status
```

Do not restart collection unless the restored database returns `ok` from
`PRAGMA integrity_check`. After startup, confirm that `context status` succeeds
and record the failed-database diagnostic filename alongside the rollback in the
deployment ticket or log.
