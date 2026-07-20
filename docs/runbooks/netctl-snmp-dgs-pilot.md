# Netctl DGS SNMP pilot gate

This runbook defines the gate for a later, separately approved production DGS
pilot. PR 3A does **not** execute this procedure, deploy code, contact a switch,
create or enable a live source, or change a device. Every SNMP operation in the
future pilot is read-only GET/WALK; SNMP SET and switch configuration are out of
scope.

Use deployment-approved values for the source name, management address and
metadata. Do not copy network topology into this repository. Stop at any failed
gate and roll back before restarting normal collection.

## Preconditions

- The exact reviewed release commit and dependency lock are available on the
  deployment host.
- A change window and explicit approval for the DGS read-only pilot exist.
- The operator has confirmed adequate free space for a database and application
  rollback set.
- The collection timer remains disabled and stopped for the entire migration
  and manual pilot. The installer does not add a live SNMP source, but it does
  run `systemctl enable --now netctl-collect.timer`; the post-deploy gate below
  must therefore disable and stop it again before any source is staged.
- The automated preservation tests pass before production access:

```bash
python -m pytest \
  tests/test_netctl_switch_store.py::test_identical_success_retains_first_seen_and_emits_no_event \
  tests/test_netctl_switch_store.py::test_failed_fdb_preserves_all_current_rows_and_emits_no_disappeared \
  tests/test_netctl_switch_cli.py::test_collect_all_isolates_failed_snmp_source_from_other_sources -q
```

## 1. Freeze and capture a rollback set

Stop the application and collector before copying any state. Keep the manifest
and checksums with the change record. Adjust the application path only when the
deployed service definition proves it is different.

```bash
timer_enabled_before="$(systemctl is-enabled netctl-collect.timer 2>/dev/null || true)"
timer_active_before="$(systemctl is-active netctl-collect.timer 2>/dev/null || true)"
case "$timer_enabled_before" in enabled|disabled) ;; *) exit 1 ;; esac
case "$timer_active_before" in active|inactive) ;; *) exit 1 ;; esac
sudo systemctl stop openvpn-web.service netctl-collect.service
sudo systemctl disable --now netctl-collect.timer
sudo install -d -m 0750 /var/backups/netctl
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
db_backup="/var/backups/netctl/netctl-before-snmp-dgs-$stamp.sqlite"
app_backup="/var/backups/netctl/openvpn-web-before-snmp-dgs-$stamp.tgz"
wrapper_backup="/var/backups/netctl/netctl-before-snmp-dgs-$stamp"
sources_backup="/var/backups/netctl/sources-before-snmp-dgs-$stamp.tgz"
secrets_backup="/var/backups/netctl/secrets-before-snmp-dgs-$stamp.env"
manifest='/var/backups/netctl/snmp-dgs-rollback.paths'
checksums='/var/backups/netctl/snmp-dgs-rollback.sha256'
sudo sqlite3 /var/lib/netctl/netctl.sqlite ".backup '$db_backup'"
sudo sqlite3 "$db_backup" 'PRAGMA integrity_check;'
sudo tar -C /opt -czf "$app_backup" openvpn-web
sudo install -m 0755 /usr/local/sbin/netctl "$wrapper_backup"
sudo tar -C /etc/netctl -czf "$sources_backup" sources.d
sudo install -m 0600 /etc/netctl/secrets.env "$secrets_backup"
{
  printf 'db_backup=%s\n' "$db_backup"
  printf 'app_backup=%s\n' "$app_backup"
  printf 'wrapper_backup=%s\n' "$wrapper_backup"
  printf 'sources_backup=%s\n' "$sources_backup"
  printf 'secrets_backup=%s\n' "$secrets_backup"
  printf 'checksums=%s\n' "$checksums"
  printf 'timer_enabled_before=%s\n' "$timer_enabled_before"
  printf 'timer_active_before=%s\n' "$timer_active_before"
} | sudo tee "$manifest" >/dev/null
sudo sha256sum "$db_backup" "$app_backup" "$wrapper_backup" \
  "$sources_backup" "$secrets_backup" | sudo tee "$checksums" >/dev/null
sudo chmod 0640 "$manifest" "$checksums"
sudo tar -tzf "$app_backup" >/dev/null
sudo tar -tzf "$sources_backup" >/dev/null
sudo test -s "$secrets_backup"
test "$(sudo awk 'END { print NR }' "$checksums")" = 5
sudo sha256sum -c "$checksums" >/dev/null
```

`PRAGMA integrity_check` must return exactly `ok`. Do not continue if the
database backup, application archive, wrapper copy, source archive, protected
secret backup, path manifest, or the five-entry protected checksum manifest
cannot be verified. Checksum verification reads the backup files but never
prints their contents or secret values.

## 2. Deploy with every SNMP source disabled

Deploy the reviewed release by the normal application procedure. The installer
enables and starts `netctl-collect.timer`, so immediately disable and stop it
again before running any `netctl` command. Export `RELEASE_SHA` from the
approved release manifest (the deployed application tree intentionally has no
`.git` directory), compare the deployed file checksums with that manifest, and
verify the pinned SNMP dependency from the deployed virtual environment. Then
run a non-collection command to apply migrations and verify the complete
ledger.

```bash
sudo systemctl disable --now netctl-collect.timer
sudo systemctl stop netctl-collect.service
test "$(systemctl is-active netctl-collect.timer)" = inactive
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
test -n "$RELEASE_SHA"
printf 'approved_release_commit=%s\n' "$RELEASE_SHA"
sudo sha256sum /opt/openvpn-web/netctl/cli.py /opt/openvpn-web/requirements.txt \
  /usr/local/sbin/netctl
test "$(/opt/openvpn-web/.venv/bin/python -c \
  "import importlib.metadata as m; print(m.version('pysnmp'))")" = '7.1.27'
sudo -u netctl /usr/local/sbin/netctl --json sources list
sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT group_concat(version, ',') FROM (SELECT version FROM schema_migrations ORDER BY version);"
sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
enabled_snmp_before_stage="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM network_sources WHERE driver='snmp_switch' AND enabled<>0;")"
test "$enabled_snmp_before_stage" = 0
```

The required results are the reviewed PySNMP version, migration ledger
`1,2,3,4,5,6,7,8`, integrity `ok`, and zero enabled SNMP sources. A different ledger,
integrity result, dependency version, or enabled-source count blocks the pilot.

## 2a. Safe unknown-fingerprint discovery gate

This gate is for a source that is already staged with `enabled: false`. It is
observational only and does not authorize collection. Keep the collection timer
inactive and disabled before and after both commands:

```bash
disabled_source='replace-with-approved-disabled-source-name'
assert_disabled_snmp_source() {
  local inspection
  inspection="$(sudo -u netctl /usr/local/sbin/netctl --json sources inspect "$disabled_source")" || {
    printf '%s\n' 'disabled SNMP source inspection failed' >&2
    return 1
  }
  printf '%s' "$inspection" | /opt/openvpn-web/.venv/bin/python -c '
import json
import sys

expected_name = sys.argv[1]
try:
    payload = json.load(sys.stdin)
    source = payload.get("source")
except (AttributeError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(source, dict):
    raise SystemExit(1)
if source.get("name") != expected_name:
    raise SystemExit(1)
if source.get("driver") != "snmp_switch":
    raise SystemExit(1)
if source.get("enabled") is not False:
    raise SystemExit(1)
' "$disabled_source" || {
    printf '%s\n' 'named source is missing, not an SNMP switch, or enabled' >&2
    return 1
  }
}
test "$(systemctl is-active netctl-collect.timer)" = inactive
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
assert_disabled_snmp_source
sudo -u netctl /usr/local/sbin/netctl --json sources discover "$disabled_source"
sudo -u netctl /usr/local/sbin/netctl --json switches unknown-fingerprints
assert_disabled_snmp_source
test "$(systemctl is-active netctl-collect.timer)" = inactive
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
```

`sources discover` performs only the bounded system-identity probe needed to
classify a switch. It must not invoke FDB, VLAN, interface, bridge, port, or
other full-collection queries. The command may record a sanitized
`requires_profile` fingerprint for review, but neither command enables the
source or timer and neither writes FDB/current-switch state. A known profile is
still not permission to run `collect`; stop on any command failure and preserve
the source as disabled.

The helper consumes the sanitized `sources inspect` JSON without printing it
and fails closed unless the named source exists, reports driver
`snmp_switch`, and has the JSON boolean `enabled: false` before and after the
discovery commands. It does not display the source endpoint or any secret.

Record only the source name, discovery classification, profile decision,
sanitized system identity, capability outcomes, timestamp, and final
timer/source disabled state. Do not record a community, endpoint secret, raw
SNMP response, or FDB inventory.

## 3. Stage a disabled source and protected secret

Create the source through the CLI. The command always writes `enabled: false`.
The values below are documentation placeholders and must be replaced only from
the approved deployment record.

```bash
pilot_source='replace-with-approved-source-name'
pilot_host='replace-with-approved-management-address'
pilot_secret_ref='switch_dgs_pilot_snmp'
test "$(systemctl is-active netctl-collect.timer)" = inactive
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
sudo /usr/local/sbin/netctl --json sources add-snmp-switch \
  "$pilot_source" --host "$pilot_host" --secret-ref "$pilot_secret_ref" \
  --profile-hint dgs
sudo -u netctl /usr/local/sbin/netctl --json sources inspect "$pilot_source"
enabled_snmp_after_stage="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM network_sources WHERE driver='snmp_switch' AND enabled<>0;")"
test "$enabled_snmp_after_stage" = 0
```

The environment variable name derived from this documentation placeholder is
`NETCTL_SECRET_SWITCH_DGS_PILOT_SNMP_COMMUNITY`. Enter its value with
`sudoedit /etc/netctl/secrets.env`; never pass it as a command argument, print
it, echo it, grep it, copy it into the source YAML, or retain it in terminal
history. Verify only ownership and mode:

```bash
sudo chown root:netctl /etc/netctl/secrets.env
sudo chmod 0640 /etc/netctl/secrets.env
sudo stat -c '%U:%G %a' /etc/netctl/secrets.env
sudo -u netctl test -r /etc/netctl/secrets.env
```

The expected metadata is `root:netctl 640`. Inspect the source response and
file only for non-secret metadata, and confirm it remains disabled. Then run the
read-only source test while the timer is still stopped:

```bash
sudo -u netctl /usr/local/sbin/netctl --json sources test "$pilot_source"
```

The detected profile must be DGS and required capabilities must succeed. A
timeout, authentication/view failure, generic profile, or parse error blocks
manual collection. Do not weaken validation or expose secret material to
diagnose a failure.

## 4. Two controlled manual collections

Only after all preceding gates pass, use `sudoedit` to make a rollback copy of
the one pilot source YAML and temporarily change its `enabled` field to `true`.
Do not enable any other SNMP source. Synchronize and verify that exactly one
SNMP source is enabled while the timer remains stopped.

```bash
pilot_yaml="/etc/netctl/sources.d/$pilot_source.yaml"
pilot_yaml_backup="/var/backups/netctl/$pilot_source-before-manual-$stamp.yaml"
test "$(systemctl is-active netctl-collect.timer)" = inactive
test "$(systemctl is-enabled netctl-collect.timer)" = disabled
sudo install -m 0640 -o root -g netctl "$pilot_yaml" "$pilot_yaml_backup"
sudoedit "$pilot_yaml"
sudo -u netctl /usr/local/sbin/netctl --json sources list
enabled_snmp_before_manual="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM network_sources WHERE driver='snmp_switch' AND enabled<>0;")"
test "$enabled_snmp_before_manual" = 1
sudo -u netctl /usr/local/sbin/netctl --json collect "$pilot_source"
sudo -u netctl /usr/local/sbin/netctl --json switches status
sudo -u netctl /usr/local/sbin/netctl --json switches capabilities \
  --source "$pilot_source" --limit 100
```

Record the first run ID, aggregate port/FDB counts and capability outcomes. A
live FDB count is observational and must not be compared with the synthetic
fixture count.

Capture a digest and event count without printing the FDB inventory, then run
the second manual collection:

```bash
fdb_digest_before="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT vlan_key,mac,port_key,status FROM current_switch_fdb WHERE source_id=(SELECT id FROM network_sources WHERE name='$pilot_source') ORDER BY vlan_key,mac;" \
  | sha256sum | cut -d' ' -f1)"
events_before="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM switch_fdb_events WHERE source_id=(SELECT id FROM network_sources WHERE name='$pilot_source');")"
sudo -u netctl /usr/local/sbin/netctl --json collect "$pilot_source"
fdb_digest_after="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT vlan_key,mac,port_key,status FROM current_switch_fdb WHERE source_id=(SELECT id FROM network_sources WHERE name='$pilot_source') ORDER BY vlan_key,mac;" \
  | sha256sum | cut -d' ' -f1)"
events_after="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM switch_fdb_events WHERE source_id=(SELECT id FROM network_sources WHERE name='$pilot_source');")"
test "$fdb_digest_before" = "$fdb_digest_after"
test "$events_before" = "$events_after"
```

The second run passes the idempotence gate only when the digest is unchanged
and it emits zero new events. Genuine network churn is not a collector defect,
but it does not prove idempotence; wait for a stable window and repeat the pair.

## 5. Prove failure preservation

With the timer still stopped, record the successful current-state digest and
event count. Use `sudoedit` to temporarily replace only this source's
`secret_ref` with an approved nonexistent reference, leaving the actual secret
file untouched. The expected manual collection failure must be secret-safe.

```bash
preserved_digest="$fdb_digest_after"
preserved_events="$events_after"
enabled_snmp_before_failure="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM network_sources WHERE driver='snmp_switch' AND enabled<>0;")"
test "$enabled_snmp_before_failure" = 1
sudoedit "$pilot_yaml"
if sudo -u netctl /usr/local/sbin/netctl --json collect "$pilot_source"; then
  echo 'expected the synthetic missing-secret collection to fail' >&2
  exit 1
fi
failed_digest="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT vlan_key,mac,port_key,status FROM current_switch_fdb WHERE source_id=(SELECT id FROM network_sources WHERE name='$pilot_source') ORDER BY vlan_key,mac;" \
  | sha256sum | cut -d' ' -f1)"
failed_events="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM switch_fdb_events WHERE source_id=(SELECT id FROM network_sources WHERE name='$pilot_source');")"
test "$preserved_digest" = "$failed_digest"
test "$preserved_events" = "$failed_events"
sudo install -m 0640 -o root -g netctl "$pilot_yaml_backup" "$pilot_yaml"
sudo -u netctl /usr/local/sbin/netctl --json sources list
```

The failed run must have a fixed sanitized error, leave every current FDB row
unchanged, and emit no `disappeared` event. Restoration from the protected YAML
copy also restores `enabled: false`. Verify zero enabled SNMP sources before
starting any service:

```bash
enabled_snmp_after_restore="$(sudo sqlite3 /var/lib/netctl/netctl.sqlite \
  "SELECT COUNT(*) FROM network_sources WHERE driver='snmp_switch' AND enabled<>0;")"
test "$enabled_snmp_after_restore" = 0
sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
sudo systemctl start openvpn-web.service
case "$timer_enabled_before" in enabled) sudo systemctl enable netctl-collect.timer ;; disabled) sudo systemctl disable netctl-collect.timer ;; esac
case "$timer_active_before" in active) sudo systemctl start netctl-collect.timer ;; inactive) sudo systemctl stop netctl-collect.timer ;; esac
test "$(systemctl is-enabled netctl-collect.timer)" = "$timer_enabled_before"
test "$(systemctl is-active netctl-collect.timer)" = "$timer_active_before"
test "$(systemctl is-active openvpn-web.service)" = active
```

This readiness gate ends with the source disabled. Enabling scheduled DGS
collection requires another explicit approval and is outside PR 3A.

## Evidence and rollback

Retain only sanitized evidence: release commit, backup checksums, migration
ledger, integrity results, protected-file metadata, run IDs, aggregate counts,
capability outcomes, current-state digests, event-count deltas, failure-
preservation result, and final disabled-source count. Do not retain the secret,
raw FDB inventory, command history containing a secret, or a raw SNMP capture.

Roll back on any failed gate. Keep all services stopped, restore the matching
application tree and wrapper before the database, verify the restored database,
and only then restart normal service:

```bash
manifest='/var/backups/netctl/snmp-dgs-rollback.paths'
db_backup="$(sudo sed -n 's/^db_backup=//p' "$manifest")"
app_backup="$(sudo sed -n 's/^app_backup=//p' "$manifest")"
wrapper_backup="$(sudo sed -n 's/^wrapper_backup=//p' "$manifest")"
sources_backup="$(sudo sed -n 's/^sources_backup=//p' "$manifest")"
secrets_backup="$(sudo sed -n 's/^secrets_backup=//p' "$manifest")"
checksums="$(sudo sed -n 's/^checksums=//p' "$manifest")"
timer_enabled_before="$(sudo sed -n 's/^timer_enabled_before=//p' "$manifest")"
timer_active_before="$(sudo sed -n 's/^timer_active_before=//p' "$manifest")"
test -n "$db_backup" && test -n "$app_backup" && test -n "$wrapper_backup"
test -n "$sources_backup" && test -n "$secrets_backup"
test -n "$checksums"
case "$timer_enabled_before" in enabled|disabled) ;; *) exit 1 ;; esac
case "$timer_active_before" in active|inactive) ;; *) exit 1 ;; esac
sudo test -f "$db_backup"
sudo test -f "$app_backup"
sudo test -x "$wrapper_backup"
sudo test -f "$sources_backup"
sudo test -s "$secrets_backup"
sudo test -s "$checksums"
test "$(sudo awk 'END { print NR }' "$checksums")" = 5
sudo sha256sum -c "$checksums" >/dev/null || exit 1
sudo systemctl stop openvpn-web.service netctl-collect.timer netctl-collect.service
rollback_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
sudo test ! -e "/opt/openvpn-web.failed-$rollback_stamp"
sudo test ! -e "/etc/netctl/sources.d.failed-$rollback_stamp"
sudo test ! -e "/var/lib/netctl/netctl.failed-$rollback_stamp.sqlite"
sudo mv /opt/openvpn-web "/opt/openvpn-web.failed-$rollback_stamp"
sudo tar -C /opt -xzf "$app_backup"
sudo install -m 0755 "$wrapper_backup" /usr/local/sbin/netctl
sudo mv /etc/netctl/sources.d "/etc/netctl/sources.d.failed-$rollback_stamp"
sudo tar -C /etc/netctl -xzf "$sources_backup"
sudo install -m 0640 -o root -g netctl "$secrets_backup" \
  /etc/netctl/secrets.env
sudo mv /var/lib/netctl/netctl.sqlite \
  "/var/lib/netctl/netctl.failed-$rollback_stamp.sqlite"
sudo install -m 0640 -o netctl -g netctl "$db_backup" \
  /var/lib/netctl/netctl.sqlite
sudo sqlite3 /var/lib/netctl/netctl.sqlite 'PRAGMA integrity_check;'
sudo systemctl start openvpn-web.service
case "$timer_enabled_before" in enabled) sudo systemctl enable netctl-collect.timer ;; disabled) sudo systemctl disable netctl-collect.timer ;; esac
case "$timer_active_before" in active) sudo systemctl start netctl-collect.timer ;; inactive) sudo systemctl stop netctl-collect.timer ;; esac
test "$(systemctl is-enabled netctl-collect.timer)" = "$timer_enabled_before"
test "$(systemctl is-active netctl-collect.timer)" = "$timer_active_before"
test "$(systemctl is-active openvpn-web.service)" = active
```

Do not start rollback or restart services unless the protected checksum
manifest validates all five backup artifacts. Do not restart services unless
the restored database returns `ok` and the restored application and wrapper
match the backup manifest. Checksum verification must remain silent except for
its exit status; never print or inspect the protected secret backup contents.
