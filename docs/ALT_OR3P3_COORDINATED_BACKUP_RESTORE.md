# ALT OR-3P3 Coordinated Backup and Restore

## 1. Scope and same-controller recovery assumption

OR-3P3 is the rollback boundary for changes to the ALT workstation provisioning
control plane on controller `192.168.100.17`.

The recovery model is a coordinated rollback on the same controller. It assumes
that the controller disk and these controller-local secret identities remain
present and readable:

- the encrypted Ansible Vault file;
- the Ansible Vault password file;
- the controller SSH private key;
- `/var/lib/alt-deploy-backup/fingerprint.key`.

Secret contents are never copied into a backup bundle. OR-3P3 is not bare-metal
recovery after complete controller loss and it does not restore workstations.
Restore is always all-component: runtime, systemd units, Ansible project,
controller state, registration state and deployment assets are one compatible
generation.

## 2. Immutable workstation warning

Do not contact, modify, reinstall, re-register or reprovision the accepted
reference workstation `192.168.101.111` while installing, creating, verifying,
rehearsing or restoring an OR-3P3 backup.

Repository verification and all backup-tool operations are controller-local.
The next destructive acceptance target must be a new disposable and unassigned
machine or VM.

## 3. Install the dedicated backup utility

Run from the repository checkout on the controller:

```bash
cd /path/to/web_ovpn
sudo bash deploy/alt-linux/install-backup-tool.sh
```

The public installer accepts no arguments. It installs only the independent
backup utility, its Python package, the fail-closed systemd guard and private
backup state. It does not stop or replace the provisioning control plane.
Existing bundles, the fingerprint key, rollout state and the operation log are
preserved.

Confirm the installed entry points without displaying secret material:

```bash
sudo test -x /usr/local/sbin/alt-deploy-backup
sudo test -f /etc/systemd/system/alt-deploy-guard.service
sudo systemctl daemon-reload
```

## 4. Safe preflight before backup creation

Stop creating provisioning jobs and review controller-local readiness:

```bash
sudo -u altserver workstationctl --json jobs active
sudo -u altserver workstationctl --json controller readiness
sudo systemctl is-active alt-deploy-process.service || true
sudo find /srv/alt-deploy/registration/pending \
  -maxdepth 1 -type f -name '*.json' -printf '.' | wc -c
sudo df -h \
  /var/backups/alt-deploy \
  /var/lib/alt-deploy \
  /home/altserver \
  /srv/alt-deploy \
  /etc/systemd/system \
  /opt
```

Required conditions are:

- no `queued` or `running` provisioning job;
- no active `alt-provision-*.service` unit;
- no pending registration JSON record;
- `alt-deploy-process.service` is not running;
- Vault, controller permissions, source paths and secret identities are valid;
- sufficient free space exists.

`alt-deploy-backup create` repeats these checks before service mutation, records
the current managed-unit state, stops only the maintenance units, acquires the
controller lifecycle lock, repeats the checks and then captures the six
components. A preflight failure does not stop services.

## 5. Create, verify and rehearse the rollback generation

Create one coordinated backup and retain its exact JSON response:

```bash
BACKUP_JSON=$(sudo /usr/local/sbin/alt-deploy-backup create)
printf '%s\n' "${BACKUP_JSON}"
```

Extract and validate the exact backup ID without selecting the newest backup:

```bash
BACKUP_ID=$(
  printf '%s\n' "${BACKUP_JSON}" | python3 -c '
import json
import re
import sys
payload = json.load(sys.stdin)
backup_id = payload.get("backup_id")
if payload.get("status") != "ok" or payload.get("result") != "backup_created":
    raise SystemExit(1)
if not isinstance(backup_id, str) or not re.fullmatch(
    r"backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", backup_id
):
    raise SystemExit(1)
print(backup_id)
'
)
printf 'Rollback backup: %s\n' "${BACKUP_ID}"
```

Write fresh verification evidence and perform the isolated restore rehearsal:

```bash
sudo /usr/local/sbin/alt-deploy-backup verify "${BACKUP_ID}"
sudo /usr/local/sbin/alt-deploy-backup rehearse "${BACKUP_ID}"
sudo /usr/local/sbin/alt-deploy-backup list
```

A successful rehearsal extracts only beneath
`/var/tmp/alt-deploy-restore-test/<backup-id>/`, runs independent structural,
Python, shell, systemd, Ansible and state checks, scans for prohibited secret
material, writes `rehearsal.json` and removes the successful rehearsal tree.
It does not replace production runtime or state.

Do not run `verify` again after a successful rehearsal merely as a status
check. Public `verify` writes a new `verification.json`; rehearsal evidence is
bound to the exact verification-record bytes. The control-plane installer uses
the internal read-only eligibility path and does not rewrite evidence.

## 6. Preserve the exact successful backup ID

Record all of the following in the controlled rollout record:

```text
backup ID
manifest SHA-256 returned by create/verify/rehearse
UTC creation time
operator identity
repository commit to be installed
controller hostname
```

Do not infer the rollback generation from directory order, timestamps or the
output of `list`. OR-3P4 must receive the exact ID captured above.

A convenient root-readable record can be created without copying secret data:

```bash
printf '%s\n' "${BACKUP_ID}" | sudo tee \
  /var/lib/alt-deploy-backup/approved-rollback-id >/dev/null
sudo chown root:root /var/lib/alt-deploy-backup/approved-rollback-id
sudo chmod 0600 /var/lib/alt-deploy-backup/approved-rollback-id
```

This operator note is not backup eligibility evidence. Eligibility continues to
come from the bundle, `verification.json`, `rehearsal.json`, current bytes and
current secret identities.

## 7. Interpret verification and rehearsal evidence without opening archives

Use the public list command for a bounded summary:

```bash
sudo /usr/local/sbin/alt-deploy-backup list
```

For the selected bundle, inspect only safe evidence fields:

```bash
sudo python3 - "${BACKUP_ID}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

backup_id = sys.argv[1]
root = pathlib.Path("/var/backups/alt-deploy") / backup_id
verification_raw = (root / "verification.json").read_bytes()
verification = json.loads(verification_raw)
rehearsal = json.loads((root / "rehearsal.json").read_bytes())
hex64 = re.compile(r"[0-9a-f]{64}")

assert verification["status"] == "ok"
assert verification["backup_id"] == backup_id
assert hex64.fullmatch(verification["manifest_sha256"])
assert len(verification["component_hashes"]) == 6
assert rehearsal["status"] == "ok"
assert rehearsal["backup_id"] == backup_id
assert rehearsal["manifest_sha256"] == verification["manifest_sha256"]
assert rehearsal["verification_sha256"] == hashlib.sha256(
    verification_raw
).hexdigest()

print(json.dumps({
    "backup_id": backup_id,
    "manifest_sha256": verification["manifest_sha256"],
    "verification_check_count": len(verification["passed_checks"]),
    "rehearsal_check_count": len(rehearsal["passed_checks"]),
    "evidence_binding": "ok",
}, sort_keys=True))
PY
```

Do not print `secret_identities`, archive member contents, registration bodies,
job logs, Vault data or private-key data.

## 8. Run OR-3P4 with the exact rollback ID

Only after create, verify and rehearsal have all succeeded on the live
controller, run:

```bash
cd /path/to/web_ovpn
sudo bash deploy/alt-linux/install-control-plane.sh \
  --rollback-backup-id "${BACKUP_ID}"
```

The public installer rejects a missing value, duplicate flag, unknown flag,
positional argument and malformed ID before loading mutation functions. Before
any runtime mutation it invokes exactly one read-only eligibility command
against the already installed backup utility. It does not select a backup
implicitly and it does not rewrite verification or rehearsal evidence.

The installer then creates a durable rollout marker, enters maintenance,
installs the control-plane generation, grants a short-lived activation permit,
runs controller readiness and removes rollout state only after readiness
succeeds. A failed rollout leaves the guard blocking normal service startup and
directs the operator to restore the selected backup.

## 9. Emergency full restore

Restore the complete selected generation with:

```bash
sudo /usr/local/sbin/alt-deploy-backup restore "${BACKUP_ID}"
```

Expected behavior:

1. current verification and rehearsal eligibility are checked read-only;
2. quiescence and free-space checks run before service mutation;
3. the current service state and a complete pre-restore generation are saved;
4. maintenance units are stopped and a restore permit authorizes only the
   matching transaction;
5. all six components are staged and replaced as one coordinated generation;
6. Python, shell, systemd, Ansible, state, secret and loopback checks run;
7. the journal reaches `committed` before guard state is cleared;
8. failed post-replacement health triggers automatic reversal and proof.

Do not use a component-selection option; none is supported. Do not manually
start ALT control-plane units while a rollout marker or non-terminal restore
journal exists.

## 10. Respond to `restore_manual_recovery_required`

When the command returns `restore_manual_recovery_required`:

1. retain the complete JSON error response and its `restore_id`;
2. leave `alt-deploy-http.service`, `alt-deploy-register.service` and
   `alt-deploy-process.path` stopped;
3. do not edit or delete the restore journal, rollout marker, permits, rollback
   siblings or pre-restore generation;
4. inspect only bounded metadata and the audit trail;
5. retry the durable recovery command once after correcting an external cause:

```bash
RESTORE_ID=restore-YYYYMMDDTHHMMSSZ-xxxxxxxx
sudo /usr/local/sbin/alt-deploy-backup recover "${RESTORE_ID}"
```

Relevant protected evidence is located at:

```text
/var/backups/alt-deploy/.restore-transactions/<restore-id>/journal.json
/var/backups/alt-deploy/pre-restore-*/<restore-id>/
/var/log/alt-deploy-backup.log
/var/lib/alt-deploy-backup/rollout.json
/run/alt-deploy-backup/restore.permit
```

If `recover` still returns `restore_manual_recovery_required`, do not bypass
`alt-deploy-guard.service` and do not start the controller manually. Preserve
the controller in maintenance, copy the bounded journal and command error to
the incident record, and perform a reviewed manual recovery from the recorded
pre-restore generation.

## 11. Safe deletion

Review current status first:

```bash
sudo /usr/local/sbin/alt-deploy-backup list
```

Delete only an explicitly selected normal published backup:

```bash
sudo /usr/local/sbin/alt-deploy-backup delete "${BACKUP_ID}"
```

Deletion validates the exact ID, direct-child containment, owner, group, mode,
filesystem boundary and active restore references. It does not require the
bundle to be intact, so a corrupted but safely contained bundle remains
deletable. There is no bulk delete and no automatic retention.

Do not delete the approved rollback bundle until OR-3P4 acceptance is complete,
the rollback window is explicitly closed and no transaction references it.

## 12. Paths and permissions

Production ownership and mode contract:

| Path | Owner | Mode | Purpose |
| --- | --- | ---: | --- |
| `/usr/local/sbin/alt-deploy-backup` | `root:root` | `0750` | root-only CLI |
| `/opt/alt-deploy-backup` | `root:root` | `0750` | independent package root |
| `/opt/alt-deploy-backup/alt_deploy_backup/*.py` | `root:root` | `0640` | backup implementation |
| `/var/lib/alt-deploy-backup` | `root:root` | `0700` | private utility state |
| `/var/lib/alt-deploy-backup/fingerprint.key` | `root:root` | `0600` | local identity key |
| `/var/lib/alt-deploy-backup/rollout.json` | `root:root` | `0600` | durable rollout marker when present |
| `/var/backups/alt-deploy` | `root:root` | `0700` | bundles and restore transactions |
| `/var/backups/alt-deploy/<backup-id>` | `root:root` | `0700` | one published generation |
| bundle files and evidence JSON | `root:root` | `0600` | archives, manifest and evidence |
| `/var/tmp/alt-deploy-restore-test` | `root:root` | `0700` | isolated rehearsal root |
| `/run/alt-deploy-backup` | `root:root` | `0700` | ephemeral guard permits |
| rollout and restore permits | `root:root` | `0600` | exact temporary authorization |
| `/var/log/alt-deploy-backup.log` | `root:root` | `0600` | bounded JSONL audit |
| `/etc/systemd/system/alt-deploy-guard.service` | `root:root` | `0644` | fail-closed service gate |

Bundle top-level contents are exactly:

```text
manifest.json
runtime.tar.zst
systemd.tar.zst
ansible.tar.zst
controller-state.tar.zst
registration-state.tar.zst
deployment-assets.tar.zst
verification.json        # after verify
rehearsal.json           # after rehearse
```

No other normal top-level object is permitted.

## 13. Live-operation boundary before OR-3P4

Repository implementation and CI do not complete the operational gate. On
controller `192.168.100.17`, the operational gate is complete only after:

```text
install-backup-tool
create
verify
rehearse
capture and approve the exact backup ID
```

A real production-path restore is deliberately **not executed before OR-3P4**.
The mandatory pre-rollout proof is the isolated rehearsal. The full restore
command is reserved for an unsuccessful guarded rollout or an explicitly
approved recovery exercise on an appropriate disposable controller clone.
