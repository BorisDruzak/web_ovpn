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

1. Re-registration is initiated locally with `sudo alt-bootstrap-register`.
2. Removal archives every active registration record for the selected machine from `pending`, `ready`, and `failed`.
3. Registration API rejects assigned machines with HTTP `409 machine_assigned`.
4. Active provision jobs block preview, archive apply, and re-registration with `machine_busy`.
5. Archive apply requires a non-empty `--reason` and records operator audit fields.
6. Repeating removal after completion returns `already_archived` with the original archive ID.
7. Preview is read-only and does not issue a mandatory token.
8. OR-3P2 has no restore command; re-entry occurs only through a new registration.
9. Malformed, conflicting, symlinked, or otherwise unsafe records fail closed before active state changes.
10. A dedicated `MachineArchiveService` and shared lifecycle guards own the policy; CLI code does not move files directly.
11. Assigned machines cannot be archived. Assignment release/reassignment is separate future work.

## Scope

OR-3P2 must:

- add `machines remove preview` and `machines remove apply`;
- require root only for `apply`;
- archive active registration records under protected controller state;
- preserve archived record bytes exactly;
- create immutable archive evidence with hashes and operator audit fields;
- distinguish registration generations with `registration_id`;
- handle existing records without `registration_id` through deterministic fingerprints;
- hide only committed archived generations from the active registry;
- allow a new generation of the same machine after successful cleanup;
- prevent pending processing from recreating `ready` or `failed` for an archived generation;
- reject registration of assigned or busy machines;
- return `already_registered` without replacing an active consistent record;
- publish and install the register-only workstation helper;
- leave jobs, logs, assignments, SSH identity, and Vault data unchanged;
- provide synthetic crash, race, permission, and preservation tests.

Non-goals:

- assignment release or reassignment;
- deletion or archival of assignments, jobs, or logs;
- restoring an archived registration record;
- renaming an assigned machine or employee;
- contacting a workstation from the archive command;
- automatic controller rollout;
- modifying the accepted reference workstation;
- solving the separate static HTTP root-exposure hardening item;
- transactional rollback for the full control-plane installer.

## Current state and constraints

Active registration state is split across:

```text
/srv/alt-deploy/registration/pending
/srv/alt-deploy/registration/ready
/srv/alt-deploy/registration/failed
```

`MachineRepository` selects the newest record for each machine key and overlays assignment and active-job information during reads. Assignments and jobs are separate protected state under `/var/lib/alt-deploy`.

The registration API currently writes directly to `pending/<machine_key>.json`. The bootstrap contains an internal registration function and uses `/var/lib/alt-bootstrap-registered` only to avoid repeating registration during a full bootstrap rerun.

The active registry and protected state can be on different filesystems. OR-3P2 therefore implements a journaled logical transaction with a durable commit marker. It does not claim that a cross-root `rename()` is physically atomic.

## Public CLI contracts

### Removal preview

```bash
sudo -u altserver workstationctl --json \
  machines remove preview <machine-identifier>
```

`<machine-identifier>` accepts normalized UUID or machine key, consistent with existing repository lookup.

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
- validates every candidate record and relevant archive state;
- fails for assigned or busy machines;
- fails closed on malformed jobs, assignments, candidate records, archive records, or unsafe paths;
- creates no archive ID or reservation token;
- may become stale immediately, so apply repeats all checks under lock.

### Removal apply

```bash
sudo workstationctl --json \
  machines remove apply <machine-identifier> \
  --reason "Переустановка тестовой машины"
```

Apply requires effective UID `0`.

The reason:

- is required after trimming surrounding whitespace;
- contains at least one non-whitespace character;
- contains no Unicode control characters;
- is limited to 500 Unicode code points;
- is stored as audit text and never interpreted as a command or path.

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

Idempotent repeat:

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

A repeat against a committed but incompletely cleaned transaction resumes that transaction and retains its archive ID.

## Identity and registration generations

### Physical identity

```text
machine_key = normalized DMI UUID when present
machine_key = normalized MAC without colons when DMI UUID is absent
```

A record contains `machine_key` and `uuid`; `uuid` may be empty for legacy or non-DMI hardware. The resolved physical identifier is the normalized UUID when non-empty, otherwise the machine key.

### Registration generation

Every newly accepted registration receives:

```text
registration_id = reg-<32 lowercase hexadecimal characters>
```

The controller generates it with a cryptographically secure random source. The client cannot choose it.

Generation identity is:

```text
registration_id, when present and valid
legacy-sha256:<SHA-256 of exact record bytes>, otherwise
```

Archive commits identify exact generations, not only a machine UUID. Therefore:

- stale files from an archived generation remain hidden;
- a new generation of the same physical machine remains visible;
- a pending processor result can be rejected for its exact archived generation;
- legacy records remain supportable without byte changes.

Invalid or duplicate `registration_id` values fail closed.

## Architecture

### `MachineArchiveService`

The service:

- discovers all active records for one machine;
- performs preview validation;
- enforces assignment and job blockers;
- creates and advances archive transactions;
- copies and verifies exact bytes;
- commits the archive logically;
- removes matching active sources after commit;
- resumes committed cleanup;
- returns completed archives idempotently.

It is the only component allowed to archive registration records.

### `MachineLifecycleGuard`

The guard:

- normalizes machine identifiers;
- inspects assignments through `AssignmentRepository`;
- inspects active jobs through `JobRepository` and canonical `ACTIVE_STATES`;
- discovers active registration generations;
- inspects completed and in-progress archive state;
- answers whether a generation is active, committed, or blocked;
- emits safe structured lifecycle errors.

It is reused by archive preview/apply, registration admission, active registry reads, and pending finalization.

### `RegistrationAdmissionService`

The admission service:

- validates lifecycle eligibility for `/register`;
- rejects assigned, busy, cleanup-required, malformed, or conflicting state;
- returns `already_registered` for a consistent active machine;
- allocates `registration_id` only for a new generation;
- writes the pending record atomically under the shared lock.

### `MachineArchiveRepository`

This persistence component is required. It:

- enumerates transaction and completed archive directories;
- validates archive object types and permissions;
- reads/writes journals, manifests, and commit markers;
- finds committed archives by machine and generation;
- generates archive IDs;
- enforces no-follow regular-file access.

It contains filesystem mechanics but no product policy.

### Existing components

`MachineRepository` remains the active read model. It gains generation-aware filtering but performs no archival.

`register_api.py` becomes an HTTP adapter over `RegistrationAdmissionService`.

`process_pending.py` keeps long-running network and Ansible work outside the global lock, then uses the lifecycle guard before each final mutation.

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
    ├── manifest.json            # immutable
    ├── commit.json              # immutable
    └── records/
        └── ...
```

Rules:

- archive root, transaction root, and archive directories: `altserver:altserver`, mode `0700`;
- JSON and copied record files: mode `0600`;
- no archive state is stored under `/srv/alt-deploy`;
- symlink, FIFO, socket, device, and unexpected directory types are rejected;
- source bytes are copied without JSON reserialization;
- temporary files are created and renamed within their destination directory;
- durable writes use flush/fsync plus directory fsync where supported;
- apply must not silently downgrade durability if the platform cannot provide the required guarantees.

## Candidate discovery and validation

Candidate discovery combines:

1. exact filenames matching the normalized identifier in `pending`, `ready`, and `failed`;
2. valid regular JSON records whose normalized `machine_key` or `uuid` matches the identifier.

Before mutation, each candidate must:

- be a non-symlink regular file opened with no-follow semantics;
- contain a JSON object;
- have non-empty `machine_key` and a resolvable physical identity;
- match the selected physical machine;
- reside directly in one canonical state directory;
- have either a valid unique `registration_id` or a deterministic legacy fingerprint;
- not conflict with another candidate on UUID, machine key, MAC, or generation.

The directory defines `registration_state`. Payload `status` is a workflow status and is not required to equal the directory name; for example, a record in `ready` may legitimately have `status=awaiting_assignment`.

An exact candidate filename that is malformed or unsafe fails closed even when its contents cannot be parsed.

An arbitrary malformed file with an unrelated filename cannot be attributed to the selected machine. General registry-wide integrity auditing remains separate work.

## Blocking conditions

Preview and apply fail when:

- an assignment exists for the resolved identity;
- a canonical active job exists;
- job enumeration is malformed;
- committed cleanup is incomplete and cannot be resumed safely;
- registration identity is conflicting or unsafe;
- archive persistence state is malformed or unsafe.

Assigned error:

```text
code: machine_assigned
exit code: 4
```

Busy error exposes only safe fields:

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

No request data, employee data, logs, results, or Ansible output is returned.

## Shared exclusive lock

Mutating lifecycle operations use:

```text
/var/lib/alt-deploy/workstationctl.lock
```

The following participate in this lock:

- archive apply and cleanup resume;
- registration admission and pending-file creation;
- final pending transition to `ready` or `failed`;
- provision preview/start, as already implemented.

Archive preview is read-only and does not reserve state. Apply acquires the lock before its authoritative recheck and holds it continuously through `prepared`, copying, commit, source cleanup, and final archive rename. This prevents registration admission or processor finalization from replacing a source while its bytes are being archived.

No operation holds the lock during SSH waits, `ssh-keyscan`, Ansible ping, preflight, or other long-running target work.

## Archive transaction state machine

Archive IDs use:

```text
archive-<UTC YYYYMMDDTHHMMSSZ>-<8 lowercase hexadecimal characters>
```

`transaction.json` records:

```text
prepared
copied
committed
cleaned
aborted
```

`manifest.json` is written once after all source records have been copied and verified. It remains immutable. It contains static `commit_phase: "committed"`; the current mutable phase exists only in `transaction.json`.

### `prepared`

Under the exclusive lock:

1. repeat discovery and blockers;
2. allocate one archive ID;
3. create the transaction directory safely;
4. record transaction identity and planned sources;
5. create no commit marker;
6. leave active registration files unchanged.

Failure leaves the registry unchanged. A safely removable precommit transaction is removed; otherwise it is marked `aborted` with a safe error class. An aborted transaction hides no generation and does not count as an archive. A later apply may remove a valid abandoned precommit transaction and allocate a new ID, but it must fail on malformed or ambiguous transaction state.

### `copied`

Still under the same lock, for every candidate:

1. open the source with no-follow regular-file checks;
2. copy exact bytes to `records/<state>.json`;
3. fsync the copied file;
4. reopen and verify byte length and SHA-256.

After every record verifies:

5. write the complete immutable manifest once;
6. fsync the manifest and transaction directory;
7. set journal phase `copied`.

Multiple candidates from one state are not assigned alternate archive names. Such state is an identity conflict and fails before commit.

Until commit, source records remain active and untouched.

### `committed`

Commit is durable creation of `commit.json` after every archived record and the manifest have verified.

`commit.json` contains only:

```text
archive_id
machine_uuid
machine_key
registration_generations
committed_at
manifest_sha256
```

After it is durable:

- listed generations are logically archived;
- `MachineRepository` excludes only those generations;
- registration admission reports cleanup incomplete;
- pending finalization cannot write active state for those generations;
- recovery resumes with the same archive ID.

### `cleaned`

Under the same lock:

1. revalidate each source path and generation;
2. unlink only sources whose generation and byte hash match the committed manifest;
3. never unlink a newer generation;
4. fsync active registration directories where supported;
5. set transaction phase `cleaned`;
6. atomically rename the transaction directory to the final archive directory within the archive filesystem.

If a source path contains a different generation or hash, cleanup does not delete it. The committed transaction remains available for investigation and the command returns cleanup required.

## Logical atomicity and recovery

### Before commit

Failure in `prepared` or `copied` means:

- no active source is removed;
- no generation is hidden;
- no completed archive is reported;
- error code is `machine_archive_failed`;
- transaction is removed safely or retained as non-committed `aborted` evidence.

### After commit

Failure after durable commit but before cleanup means:

- committed generations stay hidden;
- registration returns `machine_archive_cleanup_required`;
- apply resumes automatically when safe;
- if automatic resume cannot complete, apply returns `machine_archive_cleanup_required`;
- repeat apply never allocates a second archive ID.

### Completed archive

When no active generation remains and a completed archive matches the identifier:

- repeat apply returns `already_archived`;
- no empty audit record is created;
- no new archive ID is allocated;
- preview reports the latest archive as already archived rather than `machine_not_found`.

A later new registration generation takes precedence over older completed archives. Archiving that new generation creates a new archive ID.

## Manifest and operator audit

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

Operator resolution:

1. apply requires effective UID `0`;
2. valid `SUDO_UID` and `SUDO_USER` are used only when both identify the same existing local account;
3. otherwise use real UID/account when available;
4. fall back to effective UID/account only when no trustworthy invoking identity exists.

The manifest does not copy:

- Ansible or preflight output;
- provision requests;
- employee assignment contents;
- job contents or logs;
- Vault data;
- SSH key material.

Archived source records remain exact and may already contain historical fields such as `ansible_output`. They are private and never returned by normal CLI output.

## Active registry behavior

`MachineRepository` continues reading `pending`, `ready`, and `failed`, but filters exact generations present in a durable commit marker in either `.transactions` or a final archive directory.

Rules:

- no commit marker: record remains active;
- matching committed generation: record is hidden;
- committed old generation plus new `registration_id`: new record remains active;
- malformed archive state: fail closed instead of guessing visibility;
- legacy record: match by exact legacy fingerprint;
- archive identity keyed only by machine UUID without generation is forbidden.

`machines list` and `machines show` expose no archive manifests or reasons in OR-3P2.

## Registration API admission

Existing network, payload-size, hostname, MAC, UUID, and JSON validation remains. Lifecycle admission runs afterwards under the shared lock.

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

A new pending record is written atomically.

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

The existing record is not overwritten, timestamps do not change, and pending processing is not retriggered by replacement. `registration_state` may be `pending`, `ready`, or `failed`. For a legacy active record, `registration_id` is omitted and `legacy: true` is returned.

### Assigned machine

HTTP `409 machine_assigned`; no pending file is created or replaced.

### Active provision job

HTTP `409 machine_busy` with only `job_id`, `state`, and `stage`.

### Committed cleanup incomplete

HTTP `409`:

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

Malformed or unsafe lifecycle state returns HTTP `409` with a stable lifecycle code. Unexpected I/O returns HTTP `500 registration_storage_failed` without raw exception text, traceback, or unsafe path disclosure.

## Register-only workstation command

Repository source:

```text
deploy/alt-linux/bootstrap/alt-bootstrap-register
```

Controller-served target:

```text
/srv/alt-deploy/bootstrap/alt-bootstrap-register
```

Workstation target:

```text
/usr/local/sbin/alt-bootstrap-register
```

The control-plane installer publishes the helper under the bootstrap tree; it is not a controller-side operator command. Workstation bootstrap downloads it, validates a non-empty regular script, installs it as root mode `0755`, and invokes it for initial registration.

Usage:

```bash
sudo alt-bootstrap-register
```

The helper:

1. requires root;
2. determines the default-route interface;
3. reads hostname, MAC, and DMI UUID when available;
4. constructs JSON safely;
5. POSTs to the configured registration API with bounded timeouts;
6. prints the safe API response;
7. exits `0` for `registered` and `already_registered`;
8. exits non-zero for conflicts, invalid responses, or network failure.

It does not:

- run package management;
- create or modify `ansible`;
- change SSH, authorized keys, or sshd;
- change sudoers;
- remove or rewrite bootstrap markers;
- run preflight or provisioning;
- contact any endpoint except the configured registration API.

### Bootstrap integration

`bootstrap.sh` installs the helper before registration and replaces its embedded registration implementation with the installed helper.

Order:

1. install base dependencies and configure Ansible account;
2. write `/var/lib/alt-bootstrap-completed`;
3. call `alt-bootstrap-register`;
4. write `/var/lib/alt-bootstrap-registered` only after `registered` or `already_registered`.

A manual helper call ignores the registration marker and always requests current admission state.

Newly installed workstations receive the helper automatically. Existing workstations are not contacted or modified by repository work. Later distribution to existing machines is an explicit post-OR-3P3 rollout action.

## Pending processor race protection

`process_pending.py` does not hold the global lock during SSH wait, key scan, Ansible ping, or preflight.

Flow:

1. load pending record and capture generation identity;
2. perform target work without the lock;
3. before writing `ready`, acquire the lock;
4. verify the same generation remains active and uncommitted;
5. write/move only if the check passes;
6. before writing `failed`, repeat the same locked check;
7. if committed, discard the result and remove only a still-matching stale pending source when archive cleanup permits;
8. never recreate `ready` or `failed` for a committed generation.

Safe orderings:

- processor finalizes first, then archive discovers the resulting state;
- archive commits first, then processor suppresses stale finalization.

A new generation is not suppressed because an older generation was archived.

## Installer changes

The OR-3P1 installer is extended to:

- install lifecycle/archive modules;
- install updated registration API and processor;
- publish `/srv/alt-deploy/bootstrap/alt-bootstrap-register`;
- publish updated `bootstrap.sh`;
- create archive roots with private ownership/mode;
- preserve all existing archives byte-for-byte;
- avoid recursive chmod/chown of existing archive content;
- include the helper in readiness/static asset checks;
- run `bash -n` on both bootstrap scripts;
- retain the OR-3P3 live-rollout gate.

Installer success does not mean an existing workstation received the helper.

## Permissions and safety

```text
/var/lib/alt-deploy                                0700 altserver:altserver
/var/lib/alt-deploy/machine-archives               0700 altserver:altserver
/var/lib/alt-deploy/machine-archives/.transactions 0700 altserver:altserver
```

Apply runs as root but finalized state is owned by `altserver:altserver` for service-side inspection.

No archive operation follows symlinks. Validation and cleanup use `lstat`, regular-file checks, `O_NOFOLLOW` when available, and post-open identity checks. A platform without an equivalent safe strategy must fail apply.

Responses never include archived contents, unsafe hashes, raw filesystem errors, subprocess output, or non-contract absolute paths.

## Stable errors

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

Exit codes:

```text
3  not found
4  invalid/conflicting state or request
6  root/permission/runtime mutation failure
```

HTTP mapping:

```text
400 invalid registration request
403 forbidden source network
409 lifecycle/controller-state conflict
413 invalid payload size
500 unexpected storage/runtime failure
```

Errors use existing structured `ControlError` where applicable. `machine_busy` exposes only `job_id`, `state`, `stage`; cleanup-required exposes only `archive_id`.

## Test strategy

Implementation follows TDD.

### Archive service and CLI

Tests prove:

1. preview performs zero mutations;
2. preview/apply reject assigned machines;
3. preview/apply reject active jobs with safe fields;
4. malformed job state fails closed;
5. one `ready` record archives;
6. matching records across all three states archive in one operation;
7. source bytes remain exact;
8. manifest sizes and hashes match;
9. reason/operator audit follows contract;
10. non-root apply fails before mutation;
11. invalid reason fails before mutation;
12. malformed JSON fails the whole operation;
13. unsafe object types fail the whole operation;
14. identity conflicts fail the whole operation;
15. legacy records use fingerprints without rewrite;
16. `prepared` failure leaves active state unchanged;
17. `copied` failure leaves active state unchanged;
18. post-commit failure hides only the old generation;
19. repeat apply resumes the same archive ID;
20. completed repeat returns `already_archived` without new state;
21. cleanup never deletes a newer generation at a reused path;
22. private modes/ownership are enforced in the sandbox model;
23. apply holds the lifecycle lock through copy, commit, and cleanup;
24. aborted precommit transactions do not hide or block valid state.

### Registration admission and API

Tests prove:

1. a new registration gets controller-generated `registration_id`;
2. an active consistent machine returns `already_registered` without byte changes;
3. assigned returns HTTP `409 machine_assigned`;
4. busy returns HTTP `409 machine_busy` safely;
5. incomplete cleanup returns HTTP `409 machine_archive_cleanup_required`;
6. a new generation after archive is accepted and visible;
7. old committed generation remains hidden;
8. malformed/unsafe lifecycle state fails closed;
9. concurrent requests cannot create conflicting generations;
10. existing payload/network validation remains compatible.

### Pending processor

Tests prove:

1. finalization checks captured generation under lock;
2. committed generation cannot produce `ready`;
3. committed generation cannot produce `failed`;
4. processor-first ordering remains archivable;
5. archive-first ordering suppresses stale finalization;
6. new generation is not confused with old archive;
7. long-running target work occurs outside the lock.

### Helper, bootstrap, and installer

Tests prove:

1. helper collects identity and sends bounded request;
2. helper treats `registered` and `already_registered` as success;
3. conflicts and malformed responses return non-zero;
4. helper performs no package/SSH/sudoers/user management;
5. bootstrap installs and invokes helper in order;
6. registration marker is written only after success;
7. installer publishes helper and bootstrap;
8. installer preserves archives byte-for-byte;
9. readiness checks both served scripts;
10. no test contacts a real workstation, controller, or production secret.

### Final verification

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

OR-3P1 Ansible syntax checks remain required because installer and ALT suite are touched.

## Documentation

Update:

```text
deploy/alt-linux/README.md
docs/ALT_WORKSTATION_PROVISIONING_CONTEXT.md
docs/ALT_WORKSTATION_PROVISIONING_NEXT_STEPS.md
dedicated OR-3P2 operator runbook
```

Document:

- preview/apply examples;
- blockers and error codes;
- reason/audit behavior;
- no restore and no assignment release;
- helper behavior;
- registration generations;
- cleanup-required recovery;
- archive locations and permissions;
- prohibition on `192.168.101.111`;
- OR-3P3 gate before controller installation.

## Operational boundary

During design, implementation, and CI:

- do not access controller `192.168.100.17`;
- do not access reference workstation `192.168.101.111`;
- do not use production Vault passwords, private keys, or active records;
- use temporary filesystems, fake commands, and synthetic identities;
- do not merge without explicit user confirmation.

After merge, OR-3P2 still must not be installed on the live controller until OR-3P3 is complete. The next acceptance target remains a new disposable and unassigned VM or physical workstation.

## Acceptance

OR-3P2 is complete when:

- preview is read-only and apply is root-only;
- assigned/busy blockers are consistent across CLI and API;
- every active record for a machine archives without byte mutation;
- committed archives survive interruption and cleanup resumes safely;
- only exact archived generations are hidden;
- a new generation of the same machine is accepted after cleanup;
- pending processing cannot resurrect an archived generation;
- `alt-bootstrap-register` performs registration only;
- installer/bootstrap publish and install the helper correctly;
- archive state remains private and preserved;
- focused, ALT, and full repository tests pass;
- documentation preserves OR-3P3 and reference-machine boundaries.
