# ALT OR-3P3 Coordinated Backup and Restore Design

**Date:** 2026-07-22  
**Status:** approved design, implementation not started  
**Target repository:** `BorisDruzak/web_ovpn`  
**Target controller:** `192.168.100.17`

## 1. Purpose

OR-3P3 provides a verified rollback boundary before OR-3P4 changes the live ALT workstation provisioning controller.

The selected recovery level is a coordinated rollback on the same controller after an unsuccessful OR-3P4 rollout. The design assumes that the controller disk, the active Ansible Vault material, the Vault password file, and the controller SSH private identity still exist and are readable.

OR-3P3 does not provide bare-metal disaster recovery after total controller loss. It does not export secret contents to another host. It does not perform a real restore before OR-3P4; it requires an isolated restore rehearsal.

The accepted reference workstation `192.168.101.111` remains immutable and must not be contacted or used during OR-3P3 development, verification, backup creation, or rehearsal.

## 2. Safety goals

The implementation must guarantee the following boundaries:

1. A backup is created only while provisioning jobs, pending registration processing, and registration writes are quiescent.
2. Runtime code and controller state are captured as one coordinated generation.
3. A restore always restores the complete bundle. Partial component restore is not supported.
4. Secret contents are never copied into the rollback bundle or printed in logs or command output.
5. A published bundle is checksummed, structurally validated, and restore-rehearsed before it can be selected for OR-3P4.
6. Rehearsal never writes to production runtime or state paths.
7. A restore failure either returns the complete pre-restore state or leaves maintenance services stopped with an explicit manual-recovery error.
8. Filesystem traversal, unsafe archive members, symlink escapes, hardlink escapes, devices, sockets, and FIFOs fail closed.
9. Existing bundles are never removed automatically.
10. The live controller is not modified by repository tests or CI.

## 3. Non-goals

OR-3P3 does not implement:

- remote or off-site backup replication;
- total-loss recovery of Vault, the Vault password, or the SSH private key;
- selective restore of one component;
- automatic retention or age-based deletion;
- automatic restore during installer failure;
- workstation-side backup or restore;
- assignment release, machine reassignment, or job deletion;
- a broad transactional release framework for future controller versions.

## 4. Operator interface

A separate root-only utility is installed at:

```text
/usr/local/sbin/alt-deploy-backup
```

It is independent of `workstationctl`, so an operator can use it when the provisioning control package is unhealthy.

Supported commands:

```bash
sudo alt-deploy-backup create
sudo alt-deploy-backup list
sudo alt-deploy-backup verify <backup-id>
sudo alt-deploy-backup rehearse <backup-id>
sudo alt-deploy-backup restore <backup-id>
sudo alt-deploy-backup delete <backup-id>
```

All commands require effective UID `0`. Each command emits exactly one public JSON object. Diagnostics that are not part of that object go to the protected operation log, not to stdout. Error responses expose a stable error code and safe details only.

The utility is installed as `root:root` mode `0750`. It must not import runtime modules from `/opt/alt-deploy-control`; its backup, verification, rehearsal, and restore logic must remain usable independently.

## 5. Storage layout

Published bundles are stored locally under:

```text
/var/backups/alt-deploy/<backup-id>/
```

The backup root and every bundle directory are `root:root` mode `0700`. Bundle files are `root:root` mode `0600`.

Backup identifiers use the exact form:

```text
backup-YYYYMMDDTHHMMSSZ-<8 lowercase hex>
```

Creation uses a private temporary directory:

```text
/var/backups/alt-deploy/.creating-<backup-id>/
```

A temporary directory is published only by an atomic rename after all component archives, the manifest, and the initial integrity verification succeed.

Restore rehearsal uses:

```text
/var/tmp/alt-deploy-restore-test/<backup-id>/
```

Restore transaction state and emergency rollback material remain under the backup root and outside all restored production paths:

```text
/var/backups/alt-deploy/.restore-transactions/<restore-id>/
/var/backups/alt-deploy/pre-restore-<timestamp>/
```

## 6. Bundle components

A published bundle contains:

```text
manifest.json
runtime.tar.zst
systemd.tar.zst
ansible.tar.zst
controller-state.tar.zst
registration-state.tar.zst
deployment-assets.tar.zst
```

After successful validation it may also contain:

```text
verification.json
rehearsal.json
```

No other top-level object is allowed.

### 6.1 Runtime component

`runtime.tar.zst` captures the presence or absence and, when present, the exact content and metadata of:

```text
/opt/alt-deploy-control
/opt/alt-deploy-api
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/usr/local/libexec/alt-job-stage
```

An absent path is a valid source state when it was absent before OR-3P4. The manifest records it as absent. Full restore removes a post-backup path when the corresponding source path was recorded as absent.

The backup utility itself is not restored as part of this component during the current OR-3P3/OR-3P4 cycle. OR-3P4 must use the same verified OR-3P3 utility version and must not replace `/usr/local/sbin/alt-deploy-backup` before its rollback gate is complete.

### 6.2 Systemd component

`systemd.tar.zst` captures the existing regular unit files matching the approved `alt-deploy-*` unit set under:

```text
/etc/systemd/system/
```

Enablement links are not archived. The manifest records `is-enabled`, `is-active`, and failed-state information for each managed unit, and restore reconstructs the service state through `systemctl` after `daemon-reload`.

The managed maintenance units are:

```text
alt-deploy-process.path
alt-deploy-register.service
alt-deploy-http.service
```

The oneshot processor is inspected but is not started as part of service-state restoration:

```text
alt-deploy-process.service
```

Transient `alt-provision-*.service` units are never stopped or archived. Their presence blocks backup and restore through the active-job gate.

### 6.3 Ansible component

`ansible.tar.zst` captures:

```text
/home/altserver/ansible
```

with this mandatory exclusion:

```text
/home/altserver/ansible/group_vars/vault.yml
```

The archive preserves regular files, directories, safe internal symlinks where explicitly permitted by the source policy, numeric ownership, modes, timestamps, ACLs, and supported extended attributes. A source symlink that resolves outside the allowed Ansible root fails closed.

Restore replaces the non-secret Ansible tree while preserving the active `vault.yml` in place. The staged restored tree receives the existing Vault file only after fingerprint verification and immediately before final installation.

### 6.4 Controller-state component

`controller-state.tar.zst` captures the complete existing tree:

```text
/var/lib/alt-deploy
```

This includes jobs, assignments, machine archives, archive transactions, controller locks stored under the tree, and other provisioning state owned by that root.

Runtime code and this state component form one compatibility generation. They cannot be restored independently.

### 6.5 Registration-state component

`registration-state.tar.zst` captures:

```text
/srv/alt-deploy/registration
```

including pending, ready, failed, and any approved archive-related registration state present under that root. Backup creation requires the pending queue to be empty, but ready and failed records remain part of the bundle.

### 6.6 Deployment-assets component

`deployment-assets.tar.zst` captures both:

```text
/srv/alt-deploy/bootstrap
/srv/alt-deploy/metadata
```

This includes `ansible_authorized_keys`, autoinstall metadata, VM profile metadata, package-group archives, installation-script archives, bootstrap scripts, and the register-only helper when present.

The authorized key is public key material and is intentionally included. No SSH private key is included.

## 7. Manifest contract

`manifest.json` is UTF-8 JSON with a trailing newline and a strict schema. Unknown schema versions fail closed.

The manifest contains:

- schema version and utility version;
- backup ID, creation time in UTC, controller hostname, and machine ID when available;
- source controller operating-system metadata;
- installed repository or package commit identity when it can be determined safely;
- one record per component with filename, byte size, SHA-256, archive format, allowed roots, and source path presence;
- numeric UID/GID, owner/group names, modes, ACL/xattr capability flags, and required path metadata;
- the exact managed systemd unit state observed before maintenance;
- preflight results;
- safe secret identity records;
- the ordered component set required for full restore.

The manifest does not contain file contents, registration payloads, job logs, Ansible variable values, passwords, password hashes, private keys, or decrypted Vault material.

## 8. Secret identity verification

These secret paths are never archived:

```text
/home/altserver/ansible/group_vars/vault.yml
/home/altserver/.ansible-vault-pass
/home/altserver/.ssh/id_ed25519
```

The manifest records path, numeric owner/group, names, mode, size, and a safe identity value.

Identity mechanisms are:

- `vault.yml`: SHA-256 of the encrypted Vault file plus Vault-header validation;
- SSH private key: public-key fingerprint derived with `ssh-keygen`, never a hash of private-key bytes;
- `.ansible-vault-pass`: HMAC-SHA-256 using a controller-local root-only fingerprint key that is not stored in the bundle.

The fingerprint key is created once under a dedicated root-only state path outside all restored roots. The same-controller recovery model requires that key to remain available. The raw Vault password and a plain unsalted hash of it are never stored.

Before backup publication, verify, rehearsal, and restore, all secret files must:

- be regular files opened with no-follow semantics;
- have the approved owner/group and mode;
- remain stable across safe open and read;
- match the expected Vault, password-file, or SSH-key format;
- match the bundle identity during verify, rehearsal, and restore.

A mismatch blocks restore until the operator resolves it manually.

## 9. Global operation lock

Every command takes an exclusive root-owned lock:

```text
/run/lock/alt-deploy-backup.lock
```

The lock file and its parent must pass no-follow, owner, type, and mode checks. Concurrent create, verify, rehearse, restore, or delete operations fail with `backup_lock_busy`.

The common controller lifecycle lock remains authoritative for provisioning and registration state checks. The backup utility must not hold that lifecycle lock during long archive compression. It uses a maintenance service stop plus before-and-after generation checks to establish quiescence.

## 10. Backup creation lifecycle

`create` follows this sequence.

### 10.1 Preflight before service mutation

The utility verifies:

- effective UID is `0`;
- required commands are available: `python3`, GNU `tar`, `zstd`, `sha256sum`, `systemctl`, `systemd-analyze`, `ansible-playbook`, `ssh-keygen`;
- the `altserver` account exists with the expected UID/GID relationship;
- source roots are safely inspectable;
- there are no queued or running provision jobs;
- `registration/pending` contains no registration JSON record;
- `alt-deploy-process.service` is inactive;
- no transient `alt-provision-*.service` is active;
- secret files pass identity, ownership, mode, and format checks;
- sufficient free space exists for the estimated bundle and temporary data;
- the backup root and lock paths are safe.

No service is stopped if preflight fails.

### 10.2 Maintenance window

The utility records the exact enabled, active, inactive, and failed state of each managed unit. It then stops, in dependency-safe order:

```text
alt-deploy-process.path
alt-deploy-register.service
alt-deploy-http.service
```

Failure to stop a required unit aborts creation before archive work starts.

After stop completion, the utility repeats the active-job, transient-unit, pending-registration, source-generation, and secret checks. Any change aborts the snapshot.

### 10.3 Component creation

Each component is written into `.creating-<backup-id>` using a temporary filename, then fsynced and renamed within the temporary bundle directory.

Archive creation must:

- use relative member names rooted in an explicit component namespace;
- avoid shell-expanded untrusted paths;
- never dereference a symlink outside an allowed source root;
- reject devices, sockets, and FIFOs;
- preserve supported metadata needed for same-controller restore;
- exclude all defined secret paths;
- fail if a file changes while it is being captured;
- fsync each archive and the containing directory.

The manifest is generated only after all component archives are complete. SHA-256 and byte size are computed from the final archive bytes.

### 10.4 Publication and service recovery

The utility performs the same structural and integrity checks used by `verify` against the temporary bundle. It then atomically renames the directory to `<backup-id>` and fsyncs the backup root.

On the normal success path, services are returned to their exact recorded enabled and active states only after the bundle passes verification and is published.

On a creation failure, the bundle remains unpublished and service-state recovery is still attempted as failure cleanup. An incomplete directory is never reported as a usable backup. If service-state recovery fails, the command returns `service_state_restore_failed` even when a valid bundle was published.

## 11. Verification lifecycle

`verify <backup-id>` is read-only with respect to production runtime and controller state. It may atomically write or replace `verification.json` inside the bundle after all checks succeed.

Verification checks:

1. strict backup-ID syntax and root containment;
2. bundle directory owner and mode;
3. exact allowed top-level filenames;
4. regular-file type and no-follow safe reads;
5. manifest schema and internal consistency;
6. expected component set and filename uniqueness;
7. component byte size and SHA-256;
8. readable zstd streams;
9. safe tar members:
   - no absolute paths;
   - no empty or dot-only members;
   - no `..` traversal;
   - no member outside its component namespace;
   - no external symlink or hardlink target;
   - no devices, sockets, or FIFOs;
10. mandatory structural entries and recorded absent-path rules;
11. exclusion of Vault, Vault-password, and private-key paths;
12. safe secret identities against the current controller;
13. compatibility of the manifest schema with the current utility.

`verification.json` records the backup ID, UTC verification time, utility version, manifest SHA-256, component SHA-256 values, passed check identifiers, safe secret identities, and `status=ok`.

Any change to the manifest or a component invalidates verification automatically because the recorded hashes no longer match.

## 12. Isolated restore rehearsal

`rehearse <backup-id>` first performs complete verification. It then safely expands every component beneath:

```text
/var/tmp/alt-deploy-restore-test/<backup-id>/
```

The rehearsal extractor must not preserve setuid or setgid bits, create devices, follow extracted symlinks, or write outside the rehearsal root.

The rehearsal validates:

- complete component structure;
- manifest path-presence and absent-path semantics;
- recorded UID/GID and mode metadata;
- runtime Python compilation;
- shell syntax for restored shell entrypoints;
- systemd unit syntax through `systemd-analyze verify` with an isolated unit search path where supported;
- both Ansible playbook syntax checks using the current Vault files without printing or copying their contents into the rehearsal tree;
- strict JSON parsing for jobs, assignments, registrations, machine archives, transaction journals, manifests, and commit evidence;
- committed-generation archive consistency;
- absence of prohibited secret files anywhere in the rehearsal tree.

A successful rehearsal writes `rehearsal.json` atomically. It records the manifest SHA-256, utility version, UTC time, passed checks, safe secret identities, and `status=ok`.

The successful rehearsal tree is deleted. A failed rehearsal tree may remain for diagnosis, but it must stay `root:root` mode `0700` and must never be treated as production state.

## 13. Restore eligibility

`restore <backup-id>` is allowed only when:

- the bundle currently passes full verification;
- `verification.json` exists and matches the current manifest and component hashes;
- `rehearsal.json` exists and matches the same manifest hash;
- the rehearsal schema and utility version are compatible;
- current secret identities match;
- there are no active jobs, transient provision units, pending registrations, or running pending processor;
- the selected bundle is a normal published backup, not `.creating-*`, `pre-restore-*`, or a restore transaction directory.

OR-3P4 must name the exact rollback bundle explicitly. The controlled installer interface becomes:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh \
  --rollback-backup-id <backup-id>
```

Before any OR-3P4 runtime mutation, the installer invokes the installed backup utility to confirm that the named bundle remains verified and rehearsed. It must not silently select the newest bundle.

## 14. Full restore lifecycle

Restore is a complete coordinated operation. No component-selection flags exist.

### 14.1 Pre-mutation checks

The utility:

1. takes the global backup lock;
2. performs complete bundle verification and restore-eligibility checks;
3. records current managed unit states;
4. stops the maintenance units;
5. repeats job, pending-registration, transient-unit, secret, and source checks;
6. creates a protected pre-restore snapshot of the current complete component set.

The pre-restore snapshot is not exposed as a normal backup and cannot satisfy the OR-3P4 rollback gate. It is used only to reverse a failed restore transaction.

### 14.2 Restore transaction journal

A durable transaction journal records ordered phases such as:

```text
prepared
staged
services_stopped
originals_moved
installed
daemon_reloaded
health_checked
rolled_back
committed
manual_recovery_required
```

The journal is fsynced after every phase change. Recovery logic must derive action from durable evidence rather than from temporary filenames alone.

### 14.3 Staging

Every component is extracted into a staging location on the same filesystem as its final destination. Staging is checked for:

- structure and exact allowed roots;
- component SHA-256 provenance;
- source presence/absence semantics;
- safe file types and link targets;
- numeric ownership and modes;
- secret exclusion;
- sufficient space for installation and rollback copies.

The current active Vault file is inserted into the staged Ansible tree only after its identity has been revalidated. The Vault password file and SSH private key remain at their existing paths and are never moved by restore.

### 14.4 Installation

For each managed path, the current object is renamed to a protected rollback name on the same filesystem, then the staged object is renamed into place. Cross-filesystem global atomicity is not claimed; the transaction journal and pre-restore snapshot provide coordinated recovery.

Paths recorded as absent in the backup are removed from the active generation by renaming any current object into rollback storage and installing no replacement.

After all components are installed, restore runs:

```text
systemctl daemon-reload
```

and reconstructs the enabled state from the bundle manifest.

### 14.5 Post-restore health checks

Before maintenance services are returned to their recorded active states, restore validates locally:

- runtime entrypoint presence and syntax;
- strict controller permissions;
- Vault health without exposing values;
- secret identities;
- systemd unit loadability;
- expected enablement;
- Ansible syntax;
- job, assignment, registration, and machine-archive readers;
- loopback registration and static HTTP health when the restored service generation defines them;
- absence of active-job and pending-registration inconsistencies.

The utility then restores the service state stored in the selected backup manifest, not the state observed immediately before restore.

### 14.6 Failed restore

A failure before any active path is moved leaves runtime unchanged.

A failure after active path replacement triggers automatic reversal from the pre-restore snapshot and rollback names. A successful reversal records `rolled_back`, restores the pre-restore service state, and returns the original restore error with safe rollback status.

If automatic reversal cannot prove a complete return to the pre-restore generation, the transaction is marked `manual_recovery_required`, all maintenance services remain stopped, and the command returns:

```text
restore_manual_recovery_required
```

No success result is returned until the complete selected backup generation is installed, health-checked, and its service state restored.

## 15. List and delete behavior

### 15.1 List

`list` returns only safe published bundle directories that contain a parseable manifest. It reports:

- backup ID;
- creation time;
- total component bytes;
- current verification state;
- current rehearsal state;
- manifest hash;
- utility/schema compatibility.

It never reports `.creating-*`, restore transaction directories, or pre-restore snapshots as normal backups. A corrupted published directory may be reported separately as invalid, without reading or exposing component contents.

### 15.2 Delete

`delete <backup-id>` requires an exact normal backup ID. It validates root containment, directory type, owner, mode, and no-symlink traversal before deletion.

It does not require the bundle contents to pass integrity verification; otherwise an operator could not remove a corrupted bundle. It does require the target to be a safe direct child of `/var/backups/alt-deploy` with a valid backup ID.

Deletion is rejected when the bundle is referenced by an active restore transaction. The result exposes only backup ID and deleted byte count.

There is no automatic retention or bulk deletion command.

## 16. Logging and audit

The protected operation log is:

```text
/var/log/alt-deploy-backup.log
```

It is `root:root` mode `0600` and uses bounded, structured records.

The log records:

- command and backup ID;
- operation ID and UTC timestamps;
- maintenance-window start and end;
- safe unit-state transitions;
- component phase completion;
- verification and rehearsal check identifiers;
- restore transaction phases;
- error codes;
- whether automatic restore rollback succeeded.

The log never records:

- archive contents;
- registration JSON bodies;
- job log contents;
- Ansible variable values;
- decrypted Vault content;
- the Vault password;
- password hashes;
- private SSH key bytes;
- raw HMAC keys.

## 17. Public error codes

The initial stable error set is:

```text
backup_not_root
backup_lock_busy
backup_preflight_failed
backup_active_jobs
backup_pending_registration
backup_processor_active
backup_secret_invalid
backup_source_unsafe
backup_component_failed
backup_manifest_invalid
backup_integrity_failed
backup_service_stop_failed
service_state_restore_failed
backup_not_found
backup_not_verified
backup_not_rehearsed
backup_rehearsal_failed
restore_secret_mismatch
restore_staging_failed
restore_health_check_failed
restore_rollback_failed
restore_manual_recovery_required
backup_delete_unsafe
```

Errors before backup publication do not create a usable bundle. Errors before restore path replacement do not change runtime. Errors after replacement either complete automatic rollback or leave maintenance services stopped with `restore_manual_recovery_required`.

## 18. Implementation boundaries

The implementation should separate responsibilities into focused modules:

1. CLI parsing and public JSON/error rendering.
2. Settings and approved path inventory.
3. Safe filesystem primitives and no-follow reads.
4. Component archive creation and validation.
5. Manifest schema and strict parsing.
6. Secret identity provider.
7. Systemd state capture and restoration.
8. Backup repository and publication.
9. Rehearsal extraction and validation.
10. Restore transaction journal and rollback engine.
11. Installer rollback-gate integration.
12. Operation audit logging.

No module should import provisioning worker behavior or contact a workstation.

## 19. Test strategy

Development follows TDD: failing test, minimal implementation, focused green, neighboring regression, and full verification before review.

The minimum automated matrix covers:

1. root-only enforcement;
2. global lock exclusion;
3. active-job refusal;
4. transient-unit refusal;
5. pending-registration refusal;
6. processor-active refusal;
7. exact service-state capture and restoration;
8. service recovery after failed create;
9. secret exclusion from every component;
10. secure Vault-password HMAC and SSH public fingerprint behavior;
11. unsafe source symlink and file-type refusal;
12. tar absolute-path, traversal, external link, FIFO, device, and socket refusal;
13. SHA-256 corruption detection;
14. incomplete bundle non-publication;
15. strict manifest parsing and unknown-version refusal;
16. verification-record invalidation after bundle mutation;
17. rehearsal confinement to temporary roots;
18. Python, shell, systemd, Ansible, and JSON rehearsal checks;
19. restore refusal without current verification and rehearsal;
20. restore refusal on secret mismatch;
21. all-component restore with no partial flags;
22. absent-source removal semantics;
23. staging failure with unchanged production paths;
24. health-check failure with successful rollback;
25. rollback failure with services stopped and manual-recovery state;
26. safe deletion confinement;
27. control-plane installer publication of `alt-deploy-backup` as `root:root 0750`;
28. installer preservation of existing bundles and backup-tool fingerprint state;
29. explicit `--rollback-backup-id` pre-mutation gate;
30. existing OR-3P1 and OR-3P2 regression suites.

Filesystem tests use temporary roots, synthetic owners where supported, fake systemctl/tar/zstd command adapters, and synthetic secret material. CI must not access `192.168.100.17`, `192.168.101.111`, production Vault files, or production SSH keys.

## 20. Repository acceptance criteria

The repository phase is complete only with fresh evidence for:

```text
Focused OR-3P3 tests: PASS
Complete ALT Linux suite: PASS
Complete repository suite: PASS
Python compilation: PASS
Bash syntax: PASS
Ansible syntax: PASS
systemd unit syntax: PASS
git diff --check: PASS
Whole-branch review: no Critical or Important findings
```

The PR remains unmerged until explicit user confirmation.

## 21. Operational acceptance criteria

The live operational gate is complete only after the reviewed OR-3P3 utility is installed on `192.168.100.17` and the operator executes:

```bash
sudo alt-deploy-backup create
sudo alt-deploy-backup verify <backup-id>
sudo alt-deploy-backup rehearse <backup-id>
```

The resulting report must prove:

```text
backup published
component integrity verified
secret identities match
restore rehearsal passed
maintenance services returned to their original state
```

A real restore is not performed before OR-3P4. It remains a manual emergency operation.

OR-3P4 remains blocked until its installer is invoked with the exact successfully verified and rehearsed backup ID. The accepted reference workstation remains out of scope.