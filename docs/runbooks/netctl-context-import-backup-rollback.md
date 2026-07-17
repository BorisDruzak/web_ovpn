# Netctl context import: backup, deployment, and rollback

Use this runbook when deploying the netctl context-import migration to the
production Network Observer database. It protects the existing SQLite database
and provides a tested path back to the pre-deployment state.

The deployed database is normally `/var/lib/netctl/netctl.sqlite`. If the
deployment configuration supplies another `--db` URL, use that configured
database path consistently instead; do not assume the default path applies.

## Pre-upgrade backup

1. Stop the web application and collection so neither code nor database state
   changes while the rollback set is being captured.
2. Back up the SQLite database, the deployed application tree, and the
   `/usr/local/sbin/netctl` wrapper. Record their absolute paths in the fixed
   manifest file shown below so rollback works from a fresh shell.
3. Verify the database integrity, archives, and checksums.

```bash
sudo systemctl stop openvpn-web.service netctl-collect.timer netctl-collect.service
sudo install -d -m 0750 /var/backups/netctl
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
db_backup="/var/backups/netctl/netctl-before-context-import-$stamp.sqlite"
app_backup="/var/backups/netctl/openvpn-web-before-context-import-$stamp.tgz"
netctl_backup="/var/backups/netctl/netctl-before-context-import-$stamp"
rollback_manifest='/var/backups/netctl/context-import-rollback.paths'
sudo sqlite3 /var/lib/netctl/netctl.sqlite ".backup '$db_backup'"
sudo tar -C /opt -czf "$app_backup" openvpn-web
sudo install -m 0755 /usr/local/sbin/netctl "$netctl_backup"
{
  printf 'db_backup=%s\n' "$db_backup"
  printf 'app_backup=%s\n' "$app_backup"
  printf 'netctl_backup=%s\n' "$netctl_backup"
} | sudo tee "$rollback_manifest" >/dev/null
sudo chmod 0640 "$rollback_manifest"
sudo sqlite3 "$db_backup" 'PRAGMA integrity_check;'
sudo tar -tzf "$app_backup" >/dev/null
sudo test -x "$netctl_backup"
sudo sha256sum "$db_backup" "$app_backup" "$netctl_backup"
```

Proceed only when `PRAGMA integrity_check` returns `ok`. Preserve the recorded
checksums and `/var/backups/netctl/context-import-rollback.paths` for the
deployment and any rollback. Keep the old application archive and wrapper with
the database backup: restoring only the pre-migration database under the new
application is not a valid rollback.

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
This preserves the failed application and database for diagnosis, restores the
compatible pre-upgrade application and `netctl` wrapper, and only then restores
the verified database. The fixed manifest path makes these commands reusable
from a fresh shell.

```bash
rollback_manifest='/var/backups/netctl/context-import-rollback.paths'
db_backup="$(sudo sed -n 's/^db_backup=//p' "$rollback_manifest")"
app_backup="$(sudo sed -n 's/^app_backup=//p' "$rollback_manifest")"
netctl_backup="$(sudo sed -n 's/^netctl_backup=//p' "$rollback_manifest")"
test -n "$db_backup" && test -n "$app_backup" && test -n "$netctl_backup"
sudo test -f "$db_backup"
sudo test -f "$app_backup"
sudo test -x "$netctl_backup"

sudo systemctl stop openvpn-web.service netctl-collect.timer netctl-collect.service
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
failed_app="/opt/openvpn-web.failed-$stamp"
failed_db="/var/lib/netctl/netctl.failed-$stamp.sqlite"
sudo mv /opt/openvpn-web "$failed_app"
sudo tar -C /opt -xzf "$app_backup"
sudo install -m 0755 "$netctl_backup" /usr/local/sbin/netctl
sudo mv /var/lib/netctl/netctl.sqlite "$failed_db"
sudo install -m 0640 -o netctl -g netctl "$db_backup" /var/lib/netctl/netctl.sqlite
sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
sudo systemctl start openvpn-web.service netctl-collect.timer
sudo systemctl is-active openvpn-web.service netctl-collect.timer
sudo /usr/local/sbin/netctl --json context status
```

Do not start the web application or collection timer unless the restored
database returns `ok` from `PRAGMA integrity_check`. The previous application
tree and `netctl` wrapper must already be active before either service starts or
any status command runs. After startup, confirm that both units are active and
that `context status` succeeds. Record the failed application and database
diagnostic paths alongside the rollback in the deployment ticket or log.
