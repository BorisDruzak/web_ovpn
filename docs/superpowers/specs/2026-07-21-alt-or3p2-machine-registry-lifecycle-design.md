# ALT OR-3P2 Machine Registry Lifecycle Design

**Status:** approved for planning  
**Date:** 2026-07-21  
**Base:** `main` at `6eeaf514bda322ba73188ce625005e73d869dfcf`

## Goal

Add a safe lifecycle for removing a workstation from the active registration registry and registering the same physical workstation again without rerunning the full bootstrap.

OR-3P2 provides:

- read-only removal preview;
- audited archival instead of destructive deletion;
- fail-closed blocking for assignments, active provision jobs, malformed records, and unsafe filesystem objects;
- recovery from interruption before or after archive commit;
- a register-only command on the workstation;
- shared admission rules for CLI, registration API, and pending-record processing;
- registration-generation identity so an old archive never hides a legitimate new registration.

The work is repository-only. Installation on controller `192.168.100.17` remains blocked until OR-3P3 backup/restore is approved and executed. Reference workstation `192.168.101.111` must not be contacted or modified.

## Approved decisions

The accepted product and safety decisions are:

1. Re-registration is initiated locally on the workstation with `sudo alt-bootstrap-register`.
2. A removal operation archives every active registration record for the selected machine from `pending`, `ready`, and `failed`.
3. Registration API rejects assigned machines with HTTP `409` and `machine_assigned`.
4. Active provision jobs block preview, archive apply, and re-registration with `machine_busy`.
5. Archive apply requires a non-empty `--reason` and records operator audit fields.
6. Repeating removal after completion returns `already_archived` with the original archive ID.
7. Preview is read-only and does not issue a mandatory token.
8. OR-3P2 has no restore command; re-entry into the active registry occurs only through a new registration.
9. Malformed, conflicting, symlinked, or otherwise unsafe records fail closed before active state is changed.
10. The implementation uses a dedicated `MachineArchiveService` and shared lifecycle guards rather than embedding filesystem mutation in the CLI.
11. Assigned machines cannot be archived. Assignment release/reassignment is a separate future operation.

## Scope

OR-3P2 must:

- add `machines remove preview` and `machines remove apply` CLI contracts;
- require root only for `apply`;
- archive active registration records under protected controller state;
- preserve archived record bytes exactly;
- create immutable archive evidence with hashes and operator audit fields;
- distinguish registration generations using `registration_id`;
- handle existing records without `registration_id` through a deterministic fingerprint;
- hide only committed archived generations from the active registry;
- allow a new generation of the same machine after successful archive cleanup;
- prevent pending processing from recreating `ready` or `failed` state for an archived generation;
- reject registration of assigned or busy machines;
- return `already_registered` without replacing an active healthy record;
- install and serve the register-only workstation helper;
- keep existing jobs, logs, assignments, SSH identity, and Vault data unchanged;
- provide complete synthetic crash, race, permission, and preservation tests.

Non-goals:

- assignment release or reassignment;
- deletion or archival of assignment records;
- deletion or archival of job history and logs;
- restoring an archived registration record;
- renaming an assigned machine or employee;
- contacting a workstation from the archive command;
- automatic controller rollout;
- modifying the accepted reference workstation;
- solving the separate static HTTP root-exposure hardening item;
- transactional rollback for the full control-plane installer.

## Current state and constraints

The active registration registry is split across:

```text
/srv/alt-deploy/registration/pending
/srv/alt-deploy/registration/ready
/srv/alt-deploy/registration/failed
```

`MachineRepository` selects the newest record for each machine key and overlays assignment and active-job information during reads. Assignments and jobs are separate protected state under `/var/lib/alt-deploy`.

The current registration API writes directly to `pending/<machine_key>.json`. The current bootstrap contains an internal registration function and uses `/var/lib/alt-bootstrap-registered` to avoid repeating registration during a full bootstrap rerun.

The active registry and protected state can be on different filesystems. OR-3P2 therefore must not claim that a cross-root `rename()` is physically atomic. It implements a journaled logical transaction with a durable commit marker and generation-aware active view.

## Public CLI contracts

### Removal preview

```bash
sudo -u altserver workstationctl --json \
  machines remove preview <machine-identifier>
```

`<machine-identifier>` accepts the normalized machine UUID or machine key, matching the existing repository lookup behavior.

Success:

```json
{
  "status": "ok",
  "preview": {
    "machine_uuid": "...",
    "machine_key": "...",
    "source_states": ["pending", "failed"],
    "record_count": 2,
    "assignment_present": false,
    "active_job": null,
    "action": "archive_registration_records"
  }
}
```

Preview:

- performs no filesystem mutation;
- validates every candidate record and archive state;
- fails when the machine is assigned or has an active job;
- fails closed on malformed jobs, assignments, registration records, archive records, or unsafe paths;
- does not create an archive ID or reservation token;
- may become stale immediately after it returns, so apply repeats every check under the exclusive lock.

### Removal apply

```bash
sudo workstationctl --json \
  machines remove apply <machine-identifier> \
  --reason "Переустановка тестовой машины"
```

Apply requires effective UID `0`.

The reason:

- is required after trimming surrounding whitespace;
- must contain at least one non-whitespace character;
- must not contain Unicode control characters;
- is limited to 500 Unicode code points;
- is stored as audit data and never interpreted as a command or path.

Success:

```json
{
  "status": "ok",
  "archive": {
    "result": "archived",
    "archive_id": "archive-20260721T120000Z-1a2b3c4d",
    "machine_uuid": "...",
    "machine_key": "...",
    "source_states": ["ready"]
  }
}
```

Idempotent repeat after a completed archive:

```json
{
  "status": "ok",
  "archive": {
    "result": "already_archived",
    "archive_id": "archive-20260721T120000Z-1a2b3c4d",
    "machine_uuid": "...",
    "machine_key": "...",
    "source_states": ["ready"]
  }
}
```

A repeat against a committed but incompletely cleaned transaction resumes cleanup and returns the original archive ID.

## Identity and registration generations

### Machine identity

The canonical physical identity remains:

```text
machine_key = normalized DMI UUID when present
machine_key = normalized MAC without colons when DMI UUID is absent
```

A registration record contains both `machine_key` and `uuid`. `uuid` may be empty for legacy or non-DMI hardware. All values are normalized before comparison.

### Registration generation

Every newly accepted registration receives:

```text
registration_id = reg-<32 lowercase hexadecimal characters>
```

The value is generated by the controller using a cryptographically secure random source. The client does not choose it.

A generation identity is:

```text
registration_id, when present and valid
legacy-sha256:<SHA-256 of exact record bytes>, otherwise
```

The archive commit records generation identities, not only machine UUIDs. This ensures:

- stale files from an archived generation remain hidden;
- a newly registered generation of the same physical machine is visible;
- a pending processor result can be rejected if its exact generation was archived;
- legacy records remain supportable without rewriting their bytes.

Invalid or duplicate `registration_id` values fail closed.

## Architecture

### `MachineArchiveService`

Responsibilities:

- discover all active registration records for one machine;
- perform preview validation;
- enforce assignment and active-job blockers;
- create and advance archive transactions;
- copy and verify exact record bytes;
- commit the archive logically;
- remove active source files after commit;
- resume cleanup for a committed transaction;
- return an existing completed archive idempotently.

It is the only component allowed to archive registration records.

### `MachineLifecycleGuard`

Responsibilities:

- normalize machine identifiers;
- inspect assignments through `AssignmentRepository`;
- inspect active jobs through `JobRepository` and canonical `ACTIVE_STATES`;
- discover active registration generations;
- inspect completed and in-progress archive state;
- answer whether a generation is active, committed, or blocked;
- produce safe structured lifecycle errors.

It is used by archive preview/apply, registration admission, active registry reads, and pending-record finalization.

### `RegistrationAdmissionService`

Responsibilities:

- validate lifecycle eligibility for `/register`;
- reject assigned, busy, cleanup-required, malformed, or conflicting state;
- return `already_registered` for an existing consistent active machine;
- allocate a new `registration_id` only when creating a new generation;
- write the pending record atomically under the shared lock.

### `MachineArchiveRepository`

A focused persistence component may be introduced under the service boundary to:

- enumerate transaction and completed archive directories;
- validate archive object types and permissions;
- read/write transaction state and immutable manifests;
- find a committed archive by machine and generation;
- generate archive IDs;
- enforce no-follow regular-file access.

This component contains filesystem mechanics but no product policy.

### Existing components

`MachineRepository` remains the active read model. It gains generation-aware filtering but does not perform archival.

`register_api.py` becomes an HTTP adapter over `RegistrationAdmissionService`.

`process_pending.py` keeps long-running network and Ansible work outside the global lock, then uses `MachineLifecycleGuard` before each final state mutation.

## Protected archive layout

`Settings` gains:

```text
machine_archives_dir = <state_root>/machine-archives
archive_transactions_dir = <state_root>/machine-archives/.transactions
```

Default layout:

```text
/var/lib/alt-deploy/machine-archives/
├── .transactions/
│   └── archive-20260721T120000Z-1a2b3c4d/
│       ├── transaction.json
│       ├── manifest.json
│       ├── commit.json          # present only after logical commit
│       └── records/
│           ├── pending.json
│           ├── ready.json
│           └── failed.json
└── archive-20260721T120000Z-1a2b3c4d/
    ├── transaction.json         # final phase: cleaned
    ├── manifest.json            # immutable after creation
    ├── commit.json              # immutable commit marker
    └── records/
        └── ...
```

Rules:

- archive root and transaction root: `altserver:altserver`, mode `0700`;
- archive directories: `0700`;
- JSON and record files: `0600`;
- no archive state is stored under `/srv/alt-deploy`;
- no symlink, FIFO, socket, block device, character device, or unexpected directory is accepted where a regular file is expected;
- source record bytes are copied without JSON reserialization;
- temporary files are created in the destination directory and atomically renamed there;
- durable writes use file flush/fsync and directory fsync where supported;
- an unsupported fsync operation may be handled explicitly, but silent durability downgrade is not allowed in apply.

## Candidate discovery and validation

Candidate discovery combines:

1. exact filenames matching the normalized identifier in `pending`, `ready`, and `failed`;
2. valid regular JSON records whose normalized `machine_key` or `uuid` matches the identifier.

This allows lookup by UUID or machine key and catches duplicated state files with matching identity.

Before mutation, every candidate must:

- be a non-symlink regular file;
- be readable through no-follow semantics;
- contain a JSON object;
- have non-empty `machine_key` and resolved machine UUID/machine key identity;
- match the selected physical machine;
- have a valid state consistent with its parent directory;
- have either a valid unique `registration_id` or a calculable legacy fingerprint;
- not conflict with another candidate on UUID, machine key, MAC, or physical identity.

If an exact candidate filename exists but is malformed or unsafe, apply fails closed even if its contents cannot be parsed.

An arbitrary malformed file with an unrelated filename cannot be attributed to the selected machine and is outside that operation. General registry integrity auditing remains a separate concern.

## Blocking conditions

Preview and apply both fail when:

- `AssignmentRepository.get()` returns an assignment for the resolved identity;
- a canonical active job exists for the machine;
- job enumeration itself is malformed;
- an archive transaction is committed but cleanup is incomplete and cannot be safely resumed;
- registration identity is conflicting or unsafe;
- archive persistence state is malformed or unsafe.

### Assigned machine

Error:

```text
code: machine_assigned
exit code: 4
```

No registration or assignment file changes.

### Active provision job

Error:

```json
{
  "status": "error",
  "error": {
    "code": "machine_busy",
    "message": "Machine has an active provision job",
    "details": {
      "job_id": "job-...",
      "state": "queued",
      "stage": "created"
    }
  }
}
```

Only `job_id`, `state`, and `stage` are exposed. Request data, employee data, logs, results, and Ansible output are never included.

## Shared exclusive lock

Mutating lifecycle operations use the existing lock:

```text
/var/lib/alt-deploy/workstationctl.lock
```

The following actions must participate in this lock:

- archive apply and cleanup resume;
- registration admission and pending-file creation;
- final pending transition to `ready` or `failed`;
- provision preview/start, as already implemented.

Archive preview is read-only and does not hold the lock for its entire execution, but it must use safe no-follow reads. Apply repeats all preview checks after acquiring the lock.

No operation holds the global lock during SSH waits, `ssh-keyscan`, Ansible ping, preflight playbooks, or other long-running target work.

## Archive transaction state machine

Transaction IDs use:

```text
archive-<UTC YYYYMMDDTHHMMSSZ>-<8 lowercase hexadecimal characters>
```

`transaction.json` is the mutable journal and records one of:

```text
prepared
copied
committed
cleaned
aborted
```

`manifest.json` is finalized before commit and remains immutable. It contains a static `commit_phase: "committed"` field describing the archive contract, while the current cleanup phase remains only in `transaction.json`.

### Phase: `prepared`

Under the exclusive lock:

1. repeat all discovery and blocker checks;
2. allocate one archive ID;
3. create the transaction directory safely;
4. write transaction identity and planned source paths;
5. write no commit marker;
6. leave active registration files unchanged.

Failure before leaving `prepared` leaves the active registry unchanged. The transaction is removed if safe or marked `aborted` with a safe error class.

### Phase: `copied`

For every candidate:

1. open source with no-follow regular-file checks;
2. copy exact bytes into `records/<state>.json`;
3. record byte length and SHA-256;
4. fsync the destination file;
5. reopen and verify length and SHA-256;
6. write and fsync the immutable manifest.

Multiple candidates from the same state are not expected under canonical filenames. If they are discovered through conflicting filenames, the operation fails with `machine_identity_conflict` instead of inventing alternate archive names.

Until commit, source records remain active and untouched.

### Phase: `committed`

Commit is the durable creation of `commit.json` within the transaction directory after every archived record and manifest has been verified.

`commit.json` contains only:

```text
archive_id
machine_uuid
machine_key
registration_generations
committed_at
manifest_sha256
```

After `commit.json` is durable:

- the listed generations are logically archived;
- `MachineRepository` excludes only those generations;
- registration admission recognizes cleanup as incomplete;
- pending finalization cannot write a new active state for those generations;
- failure is recoverable by resuming cleanup with the same archive ID.

### Phase: `cleaned`

Under the lock:

1. revalidate each source path and generation;
2. unlink only files whose exact generation and byte hash match the committed manifest;
3. never unlink a newer registration generation;
4. fsync active registration directories where supported;
5. update `transaction.json` to `cleaned`;
6. atomically rename the transaction directory to the final archive directory within the archive filesystem.

If a source path now contains a different generation or hash, cleanup does not delete it. The command fails safely and retains the committed transaction for operator investigation.

## Logical atomicity and recovery

### Failure before commit

If failure occurs in `prepared` or `copied`:

- no active source record is removed;
- no generation is hidden;
- no completed archive is reported;
- the error is `machine_archive_failed`;
- an incomplete transaction is removed when safe or retained as `aborted` for diagnosis.

### Failure after commit

If failure occurs after durable `commit.json` but before full cleanup:

- committed generations remain hidden from the active registry;
- registration API returns `machine_archive_cleanup_required`;
- apply returns `machine_archive_cleanup_required` when automatic resume cannot complete;
- a repeat apply resumes the same transaction and never allocates another archive ID;
- the transaction contains enough hashes and paths to complete or safely refuse cleanup.

### Completed archive

When no active generation remains and a completed archive matches the machine:

- repeat apply returns `already_archived`;
- no empty audit record is created;
- no new archive ID is allocated;
- preview may report the latest archive as already archived instead of `machine_not_found`.

If the machine later obtains a new registration generation, that new active generation takes precedence over old completed archives. A later archive of the new generation creates a new archive ID.

## Archive manifest and audit

`manifest.json` contains:

```text
schema_version
archive_id
machine_uuid
machine_key
archived_at
reason
operator_uid
operator_username
source_states
registration_generations
record entries: source state, archive filename, byte size, SHA-256
commit_phase = committed
```

The operator is resolved as follows:

1. apply still requires effective UID `0`;
2. when valid `SUDO_UID` and `SUDO_USER` identify an existing local account and agree with the account database, record that invoking account;
3. otherwise record real UID/account when available;
4. fall back to effective UID/account only when no trustworthy invoking identity exists.

The archive never copies into its manifest:

- Ansible output;
- preflight output beyond what already exists in the exact archived registration record;
- provision requests;
- employee assignment contents;
- job status contents beyond the safe blocker response;
- job logs;
- Vault data;
- private or public SSH key material.

Archived source records are retained byte-for-byte and may already contain historical fields such as `ansible_output`; this is why archive permissions are private and the records are never returned by normal CLI output.

## Active registry behavior

`MachineRepository` continues to read only `pending`, `ready`, and `failed`, but it filters records whose exact generation appears in a durable committed archive or committed transaction.

Filtering rules:

- no commit marker: record remains active;
- committed matching generation: record is hidden;
- committed older generation plus new `registration_id`: new record remains active;
- malformed archive state: fail closed with a registry/archive error instead of silently showing or hiding records;
- legacy record: match by exact legacy fingerprint;
- archive identity keyed only by machine UUID without generation is forbidden.

`machines list` and `machines show` do not expose archive manifests or audit reasons in OR-3P2.

## Registration API admission

The API retains current network, payload-size, hostname, MAC, UUID, and JSON validation. Lifecycle admission occurs only after these checks.

### New or previously archived machine

HTTP `201`:

```json
{
  "status": "registered",
  "machine_key": "...",
  "registration_id": "reg-...",
  "ip": "192.168.101.x"
}
```

The pending record is created atomically under the shared lock.

### Consistent active unassigned machine

HTTP `200`:

```json
{
  "status": "already_registered",
  "machine_key": "...",
  "registration_id": "reg-...",
  "registration_state": "pending"
}
```

The existing record is not overwritten, its timestamp does not change, and pending processing is not retriggered by replacing the file.

For a legacy active record, `registration_id` may be omitted and a safe `legacy: true` flag may be returned.

### Assigned machine

HTTP `409` with `machine_assigned`. No pending file is created or replaced.

### Active provision job

HTTP `409` with `machine_busy` and only safe job fields.

### Committed cleanup incomplete

HTTP `409` with:

```json
{
  "status": "error",
  "error": {
    "code": "machine_archive_cleanup_required",
    "message": "Machine archive cleanup is incomplete",
    "details": {
      "archive_id": "archive-..."
    }
  }
}
```

### Invalid or conflicting controller state

Unsafe or malformed registration/archive state returns HTTP `409` with a stable lifecycle code where the request conflicts with controller state. Unexpected I/O failures return HTTP `500` with a safe generic storage error and no path contents, traceback, or raw exception.

## Register-only workstation command

Repository source:

```text
deploy/alt-linux/bootstrap/alt-bootstrap-register
```

Controller deployment target served by static bootstrap content:

```text
/srv/alt-deploy/bootstrap/alt-bootstrap-register
```

Workstation installation target:

```text
/usr/local/sbin/alt-bootstrap-register
```

The controller installer does not treat the helper as a controller-side operational command. It publishes the source under the bootstrap tree. The workstation bootstrap downloads it, verifies that the response is a non-empty regular script, installs it as root mode `0755`, and invokes it for initial registration.

Usage on a workstation:

```bash
sudo alt-bootstrap-register
```

The helper:

1. requires root;
2. determines the default-route interface;
3. reads hostname, interface MAC, and DMI product UUID when available;
4. constructs JSON safely without shell-string injection;
5. POSTs to the configured registration endpoint with bounded timeouts;
6. prints the safe API response;
7. exits `0` for `registered` and `already_registered`;
8. exits non-zero for lifecycle conflict, invalid response, or network failure.

The helper does not:

- run `apt-get`;
- create or modify the `ansible` user;
- change SSH keys, `authorized_keys`, or `sshd`;
- change sudoers;
- remove or rewrite bootstrap markers;
- run preflight or provisioning;
- contact any endpoint other than the configured registration API.

### Bootstrap integration

`bootstrap.sh` installs the helper before first registration and replaces its internal `register_machine()` implementation with a call to the installed helper.

The full bootstrap keeps its existing completion behavior:

1. install base dependencies and configure the Ansible account;
2. write `/var/lib/alt-bootstrap-completed`;
3. call `alt-bootstrap-register`;
4. write `/var/lib/alt-bootstrap-registered` only after a successful `registered` or `already_registered` response.

A manual call to `alt-bootstrap-register` ignores the registration marker and always asks the controller for current admission state.

Workstations installed after OR-3P2 receive the helper automatically. Existing workstations are not contacted or modified by repository implementation. Any later helper distribution to existing machines must be an explicit rollout action after OR-3P3.

## Pending processor race protection

`process_pending.py` must not hold the global lock during SSH wait, key scan, Ansible ping, or preflight.

Required flow:

1. load the pending record and capture its generation identity;
2. perform target work without the global lock;
3. immediately before writing `ready`, acquire the shared lock;
4. verify the same generation is still active and not committed;
5. write/move the result only if that check passes;
6. immediately before writing `failed`, perform the same locked generation check;
7. if the generation is committed, discard the result and remove only a still-matching stale pending source when the archive cleanup contract permits it;
8. never recreate `ready` or `failed` for a committed generation.

Ordering is safe in both directions:

- processor finalizes first, then archive discovers and archives the resulting state;
- archive commits first, then processor observes the committed generation and suppresses finalization.

A newly registered generation is never suppressed merely because an older generation of the same machine was archived.

## Installer changes

The OR-3P1 control-plane installer is extended to:

- install the new Python lifecycle/archive modules;
- install updated `register_api.py` and `process_pending.py`;
- publish `/srv/alt-deploy/bootstrap/alt-bootstrap-register`;
- publish the updated `bootstrap.sh`;
- create archive and transaction roots with correct private ownership/mode;
- preserve all existing archive directories and files byte-for-byte;
- never recursively chmod/chown archive contents merely to ensure parents;
- include the served helper in controller readiness/static asset checks;
- run `bash -n` on both bootstrap scripts;
- keep the OR-3P3 live-rollout gate.

Installer success does not imply that any existing workstation has received the helper.

## Permissions and safety

Expected private controller state:

```text
/var/lib/alt-deploy                              0700 altserver:altserver
/var/lib/alt-deploy/machine-archives             0700 altserver:altserver
/var/lib/alt-deploy/machine-archives/.transactions 0700 altserver:altserver
```

Apply runs as root but creates finalized state owned by `altserver:altserver` so normal read-only lifecycle commands and services can inspect it.

No archive operation follows symlinks. Source validation and cleanup use `lstat`, regular-file checks, `O_NOFOLLOW` when available, and post-open identity checks. A platform without an equivalent safe no-follow strategy must fail apply rather than silently weaken the contract.

Normal CLI and API responses never include archived record contents, hashes of secrets, filesystem exception text, raw subprocess output, or absolute paths beyond fixed public contract paths.

## Stable error contracts

Core CLI/service codes:

```text
machine_not_found
machine_assigned
machine_busy
machine_record_invalid
machine_record_unsafe
machine_identity_conflict
machine_archive_invalid
machine_archive_failed
machine_archive_cleanup_required
root_required
invalid_archive_reason
registration_storage_failed
```

Recommended exit codes:

```text
3  not found
4  invalid/conflicting state or request
6  root/permission/runtime mutation failure
```

HTTP mapping:

```text
400 invalid registration request syntax or fields
403 source network forbidden
409 lifecycle conflict or controller-state conflict
413 invalid payload size
500 unexpected storage/runtime failure
```

Every error uses the existing structured `ControlError` shape where applicable. `machine_busy` exposes only `job_id`, `state`, and `stage`. `machine_archive_cleanup_required` exposes only `archive_id`.

## Test strategy

Implementation follows TDD.

### Archive service and CLI

Tests must prove:

1. preview performs zero mutations;
2. preview and apply reject assigned machines;
3. preview and apply reject active jobs with safe fields only;
4. malformed job state fails closed;
5. one `ready` record archives successfully;
6. matching records across `pending`, `ready`, and `failed` are archived in one operation;
7. source record bytes are preserved exactly;
8. manifest sizes and SHA-256 values match archived bytes;
9. reason and operator audit fields follow the contract;
10. non-root apply fails before mutation;
11. invalid reason fails before mutation;
12. malformed JSON fails the whole operation;
13. symlink, FIFO, directory, or other unexpected type fails the whole operation;
14. identity conflicts across records fail the whole operation;
15. legacy records use deterministic fingerprints without source rewrite;
16. failure in `prepared` leaves the active registry unchanged;
17. failure in `copied` leaves the active registry unchanged;
18. failure after commit hides the exact old generation and reports cleanup required;
19. repeat apply resumes cleanup with the same archive ID;
20. completed repeat returns `already_archived` without creating new state;
21. cleanup never deletes a newer generation at a reused source path;
22. archive manifests and records use private modes and expected ownership in the sandbox model.

### Registration admission and API

Tests must prove:

1. accepted new registration gets a controller-generated `registration_id`;
2. active consistent machine returns `already_registered` without byte changes;
3. assigned machine returns HTTP `409 machine_assigned`;
4. busy machine returns HTTP `409 machine_busy` with safe fields only;
5. committed incomplete cleanup returns HTTP `409 machine_archive_cleanup_required`;
6. a new generation after completed archive is accepted and visible;
7. an old committed generation remains hidden;
8. malformed or unsafe active/archive state fails closed;
9. concurrent registration requests cannot create conflicting generations;
10. invalid payload/network validation remains compatible with existing behavior.

### Pending processor

Tests must prove:

1. processor finalization checks the captured generation under lock;
2. committed generation cannot produce `ready`;
3. committed generation cannot produce `failed`;
4. processor-first ordering remains archivable;
5. archive-first ordering suppresses stale finalization;
6. a new generation is not confused with an archived old generation;
7. long-running target work occurs outside the global lock.

### Helper, bootstrap, and installer

Tests must prove:

1. helper collects identity and sends the expected bounded request;
2. helper treats `registered` and `already_registered` as success;
3. helper returns non-zero for lifecycle conflicts and malformed responses;
4. helper never runs package, SSH, sudoers, or user-management commands;
5. bootstrap installs and invokes the helper in the approved order;
6. registration marker is written only after helper success;
7. controller installer publishes the helper and updated bootstrap;
8. installer preserves existing archives byte-for-byte;
9. installer readiness checks both served scripts;
10. no test contacts a real workstation, controller, or production secret.

### Final verification

At minimum:

```bash
python -m pytest -q tests/alt_linux
python -m pytest -q
python3 -m py_compile \
  deploy/alt-linux/control/alt_deploy/*.py \
  deploy/alt-linux/api/register_api.py \
  deploy/alt-linux/api/process_pending.py
bash -n deploy/alt-linux/install-control-plane.sh
bash -n deploy/alt-linux/bootstrap/bootstrap.sh
bash -n deploy/alt-linux/bootstrap/alt-bootstrap-register
git diff --check
```

Ansible syntax checks from OR-3P1 remain required because the installer and full ALT suite are touched.

## Documentation

Update:

```text
deploy/alt-linux/README.md
docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
docs/ALT_OR3P1_PILOT_ROLLOUT.md or a dedicated OR-3P2 operator runbook
```

Documentation must include:

- preview and apply examples;
- exact blockers and error codes;
- reason/audit behavior;
- no restore and no assignment release in OR-3P2;
- register-only helper behavior;
- distinction between old and new registration generations;
- cleanup-required recovery procedure;
- archive locations and permissions;
- explicit prohibition on using `192.168.101.111`;
- explicit OR-3P3 gate before controller installation.

## Operational boundary

During design, implementation, and CI:

- do not access controller `192.168.100.17`;
- do not access reference workstation `192.168.101.111`;
- do not use a production Vault password, private key, or active registration record;
- use temporary filesystems, fake commands, and synthetic identities only;
- do not merge without explicit user confirmation.

After merge, OR-3P2 still must not be installed on the live controller until OR-3P3 backup/restore has been completed. The next acceptance target remains a new disposable and unassigned VM or physical workstation.

## Acceptance

OR-3P2 is complete when:

- preview is read-only and apply is root-only;
- assigned and busy machines are blocked consistently across CLI and API;
- every active registration record for a machine is archived without source-byte mutation;
- committed archives survive interruption and incomplete cleanup is safely resumable;
- only exact archived generations are hidden;
- a new registration generation for the same machine is accepted after cleanup;
- pending processing cannot resurrect an archived generation;
- `alt-bootstrap-register` performs registration only;
- installer and bootstrap publish/install the helper correctly;
- archive state remains private and preserved;
- all focused, ALT, and full-repository tests pass;
- documentation preserves the OR-3P3 and reference-machine safety boundaries.
