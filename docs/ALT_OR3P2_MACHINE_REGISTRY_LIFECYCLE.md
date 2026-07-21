# ALT OR-3P2 Machine Registry Lifecycle

## Status and safety gate

OR-3P2 adds repository-side machine registration archival and register-only re-registration.

It is **not installed on the live controller**. Do not run the updated installer on `192.168.100.17` until OR-3P3 backup/restore has been completed and verified.

The accepted reference workstation `192.168.101.111` is immutable. Do not use it for removal, re-registration, destructive testing, or the next acceptance cycle. The next target must be a new disposable and unassigned VM or workstation.

## Active and archived state

Active registration records remain under:

```text
/srv/alt-deploy/registration/pending
/srv/alt-deploy/registration/ready
/srv/alt-deploy/registration/failed
```

Protected archives are stored only under:

```text
/var/lib/alt-deploy/machine-archives
/var/lib/alt-deploy/machine-archives/.transactions
```

Expected ownership and modes:

```text
/var/lib/alt-deploy                         altserver:altserver 0700
/var/lib/alt-deploy/workstationctl.lock     altserver:altserver 0600
/var/lib/alt-deploy/machine-archives        altserver:altserver 0700
.../.transactions                           altserver:altserver 0700
archive directories                         altserver:altserver 0700
archive JSON and copied records              altserver:altserver 0600
```

Archive state is not stored under the static HTTP root.

## Preview removal

Preview is read-only. It performs no reservation and creates no archive identifier:

```bash
sudo -u altserver workstationctl --json \
  machines remove preview <machine-uuid>
```

Example result:

```json
{
  "status": "ok",
  "preview": {
    "machine_uuid": "<uuid>",
    "machine_key": "<key>",
    "source_states": ["pending", "failed"],
    "record_count": 2,
    "assignment_present": false,
    "active_job": null,
    "action": "archive_registration_records"
  }
}
```

Preview can become stale immediately. Apply repeats every authoritative check while holding the shared lifecycle lock.

## Apply removal

Apply requires root and a non-empty audit reason:

```bash
sudo workstationctl --json \
  machines remove apply <machine-uuid> \
  --reason "Переустановка тестовой машины"
```

The reason is trimmed, limited to 500 Unicode code points and must not contain control characters.

Apply archives every matching active registration record for the physical machine from `pending`, `ready` and `failed`. It does not delete or modify job history, job logs, assignments, Vault data, SSH identity, known hosts or ISO-derived metadata.

Successful result:

```json
{
  "status": "ok",
  "archive": {
    "result": "archived",
    "archive_id": "archive-...",
    "machine_uuid": "<uuid>",
    "machine_key": "<key>",
    "source_states": ["ready"]
  }
}
```

Repeating apply after completion is idempotent:

```json
{
  "status": "ok",
  "archive": {
    "result": "already_archived",
    "archive_id": "archive-...",
    "machine_uuid": "<uuid>",
    "machine_key": "<key>",
    "source_states": ["ready"]
  }
}
```

No empty audit record or new archive ID is created for the repeat.

## Blocking outcomes

### Assigned machine

An active assignment blocks preview, apply and registration:

```text
error.code = machine_assigned
```

OR-3P2 does not implement assignment release or reassignment.

### Active provisioning job

A job in `queued` or `running` blocks preview, apply and registration:

```text
error.code = machine_busy
```

Only these job fields may be returned:

```text
job_id
state
stage
```

Provision request data, employee data, logs, results and Ansible output are not returned.

### Invalid registration state

Malformed JSON, an unsafe symlink or object type, conflicting identity or invalid generation fails closed before active state is changed:

```text
machine_record_invalid
machine_record_unsafe
machine_identity_conflict
```

### Invalid archive state

Malformed transaction, manifest, commit marker, ownership/type boundary or hash relationship fails closed:

```text
machine_archive_invalid
```

## Logical transaction and recovery

Active registrations and protected archives can be on different filesystems. OR-3P2 therefore uses a journaled logical transaction rather than claiming cross-filesystem rename atomicity.

Phases:

```text
prepared
copied
committed
cleaned
aborted
```

Before commit, source registration records remain active and byte-identical.

After durable `commit.json` creation, only the exact archived registration generations are considered archived. If cleanup is incomplete, active registry reads hide those exact generations and the registration API rejects a new registration with:

```text
error.code = machine_archive_cleanup_required
```

The response exposes only the existing `archive_id`.

To resume cleanup, rerun the same apply operation:

```bash
sudo workstationctl --json \
  machines remove apply <machine-uuid> \
  --reason "Переустановка тестовой машины"
```

The command resumes the committed transaction using the same archive ID. It never deletes a newer registration generation that has appeared at a reused source path. If cleanup remains blocked, preserve the transaction and investigate the conflicting path; do not manually delete the archive evidence.

## Registration generations

Every newly accepted registration receives a controller-generated identifier:

```text
reg-<32 lowercase hexadecimal characters>
```

Legacy records without `registration_id` use an exact-byte identity:

```text
legacy-sha256:<SHA-256>
```

A committed archive hides only the exact recorded generations. A later registration of the same physical machine gets a new `registration_id` and remains visible.

## Register-only command on a workstation

Newly bootstrapped workstations receive:

```text
/usr/local/sbin/alt-bootstrap-register
```

Run locally on the workstation:

```bash
sudo alt-bootstrap-register
```

The command collects the default-interface MAC address, hostname and DMI UUID when available, then sends one bounded registration request.

It performs none of the following:

```text
package installation or update
creation or modification of the ansible user
SSH key, authorized_keys or sshd changes
sudoers changes
preflight or provisioning
bootstrap marker deletion or rewrite
```

Successful API outcomes are:

```text
HTTP 201 status=registered
HTTP 200 status=already_registered
```

Lifecycle conflicts and malformed/network responses return a non-zero exit code.

Existing workstations are not modified by merging OR-3P2. Distribution of the helper to already deployed machines is a separate controlled rollout after OR-3P3.

## Registration API outcomes

New or previously archived physical machine:

```text
HTTP 201
status=registered
registration_id=reg-...
```

Consistent active unassigned machine:

```text
HTTP 200
status=already_registered
```

The existing record is not overwritten and its timestamp is unchanged.

Assigned, busy or cleanup-required machine:

```text
HTTP 409
machine_assigned | machine_busy | machine_archive_cleanup_required
```

Unexpected storage failures return a safe HTTP 500 response without paths, tracebacks or raw exceptions.

## Pending processor race protection

The pending processor captures the exact registration generation before SSH and Ansible work. Long-running target work occurs outside `workstationctl.lock`.

Immediately before writing `ready` or `failed`, the processor acquires the lock and verifies that:

- the source still exists;
- the source is still the same generation;
- that generation is not committed in an archive.

A stale result is discarded. It cannot recreate `ready` or `failed` after archive commit and cannot overwrite a newer generation.

## No restore in OR-3P2

OR-3P2 has no `machines restore` command. Archived evidence is immutable.

Return to the active registry only through a new registration:

```bash
sudo alt-bootstrap-register
```

Assignment release/reassignment remains a separate future operation.

## Controller installation boundary

The OR-3P1 installer is extended to publish the helper, install updated APIs and lifecycle modules, create protected archive roots and lifecycle lock, update systemd sandbox access and include the helper in local readiness.

It preserves existing archives byte-for-byte and does not recursively chmod, chown, copy or delete archive contents.

Do not execute the installer on `192.168.100.17` until OR-3P3 is complete.

## Next operational sequence

```text
1. Merge OR-3P2 after explicit approval.
2. Design, implement and verify OR-3P3 backup/restore.
3. Back up and validate restore for controller 192.168.100.17.
4. Install the control-plane update in a controlled maintenance window.
5. Run controller readiness locally.
6. Use a new disposable, unassigned VM or workstation.
7. Validate preview, archive apply and local register-only re-registration.
8. Do not use 192.168.101.111.
```
