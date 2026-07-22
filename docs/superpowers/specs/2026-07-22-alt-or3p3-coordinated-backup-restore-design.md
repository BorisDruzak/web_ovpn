# ALT OR-3P3 Coordinated Backup and Restore Design

**Date:** 2026-07-22  
**Status:** approved design, self-reviewed, implementation not started  
**Repository:** `BorisDruzak/web_ovpn`  
**Controller:** `192.168.100.17`

## 1. Purpose and recovery level

OR-3P3 establishes the mandatory rollback gate before OR-3P4 changes the live ALT workstation provisioning controller.

The selected recovery level is a coordinated rollback on the same controller after an unsuccessful OR-3P4 rollout. It assumes that the controller disk, active Ansible Vault file, Vault password file, SSH private identity, and backup-tool fingerprint key remain present and readable.

OR-3P3 does not provide bare-metal recovery after total controller loss. Secret contents are not exported. A real restore is not performed before OR-3P4; an isolated restore rehearsal is mandatory.

The accepted workstation `192.168.101.111` remains immutable and must not be contacted during development, CI, backup creation, verification, rehearsal, or restore.

## 2. Approved decisions

The design uses:

- a local backup root at `/var/backups/alt-deploy`;
- a short maintenance window;
- full coordinated restore only, with no component selection;
- isolated rehearsal under `/var/tmp/alt-deploy-restore-test`;
- a separate root-only utility independent of `workstationctl`;
- component `tar.zst` archives plus one strict JSON manifest;
- full backup of bootstrap and deployment metadata;
- secret identity verification without archiving secret contents;
- no automatic retention or deletion;
- explicit operator selection of the rollback backup for OR-3P4.

## 3. Safety invariants

1. Backup creation requires no queued or running provision job, no active transient provision unit, no pending registration, and no running pending processor.
2. Runtime code and controller state are one compatibility generation.
3. Restore always applies the complete bundle.
4. Secret contents never enter archives, logs, JSON output, fixtures, or CI artifacts.
5. A bundle must be published, verified, and rehearsed before OR-3P4 can select it.
6. Rehearsal never writes to a production runtime or state path.
7. All controller state mutation remains blocked throughout the quiescent capture and restore transaction.
8. Traversal, symlink escape, hardlink escape, special files, unsafe ownership, or malformed evidence fail closed.
9. A failed restore either proves complete reversal to the pre-restore generation or leaves maintenance services stopped with `restore_manual_recovery_required`.
10. Existing bundles are never removed automatically.

## 4. Non-goals

OR-3P3 does not implement:

- remote replication or off-site storage;
- backup of Vault plaintext, the Vault password, or SSH private-key bytes;
- total-loss recovery of the controller;
- selective or partial restore;
- automatic retention;
- automatic restore from the control-plane installer;
- workstation backup or restore;
- assignment release, reassignment, or job deletion;
- a general release framework for unrelated services.

## 5. Bootstrap-safe installation model

OR-3P3 must be installable before a rollback bundle exists. Therefore the backup tool has a dedicated minimal installer:

```text
deploy/alt-linux/install-backup-tool.sh
```

It installs only:

```text
/usr/local/sbin/alt-deploy-backup
/opt/alt-deploy-backup/alt_deploy_backup/
/var/lib/alt-deploy-backup/
/var/backups/alt-deploy/
/var/log/alt-deploy-backup.log
```

Required ownership and modes:

```text
/usr/local/sbin/alt-deploy-backup        root:root 0750
/opt/alt-deploy-backup                   root:root 0750
Python package files                     root:root 0640
/var/lib/alt-deploy-backup               root:root 0700
/var/backups/alt-deploy                  root:root 0700
/var/log/alt-deploy-backup.log           root:root 0600
```

The dedicated installer:

- requires root;
- performs syntax and source validation before mutation;
- never stops control-plane services;
- never contacts a workstation;
- never modifies provisioning runtime, jobs, assignments, registrations, Vault, or SSH identity;
- preserves existing bundles, operation logs, and the existing fingerprint key;
- verifies the installed utility after publication.

The later control-plane installer must not overwrite the installed backup utility or its private state. OR-3P4 requires a compatible installed backup-tool version and an explicit rehearsed backup ID.

This separation avoids a bootstrap cycle in which `install-control-plane.sh` would require a backup before the tool capable of creating that backup existed.

## 6. Operator interface

The root-only CLI is:

```bash
sudo alt-deploy-backup create
sudo alt-deploy-backup list
sudo alt-deploy-backup verify <backup-id>
sudo alt-deploy-backup rehearse <backup-id>
sudo alt-deploy-backup restore <backup-id>
sudo alt-deploy-backup delete <backup-id>
```

Every command requires effective UID `0` and emits exactly one public JSON object. It exposes stable error codes and bounded safe details only.

The utility must not import provisioning runtime modules from `/opt/alt-deploy-control`. It may reuse formats by implementing strict independent readers, but backup and restore remain usable when the provisioning package is broken.

## 7. Storage layout and identifiers

Published bundles:

```text
/var/backups/alt-deploy/<backup-id>/
```

Creation staging:

```text
/var/backups/alt-deploy/.creating-<backup-id>/
```

Restore transaction state:

```text
/var/backups/alt-deploy/.restore-transactions/<restore-id>/
```

Emergency pre-restore snapshot:

```text
/var/backups/alt-deploy/pre-restore-<timestamp>/
```

Rehearsal root:

```text
/var/tmp/alt-deploy-restore-test/<backup-id>/
```

Backup IDs have the exact form:

```text
backup-YYYYMMDDTHHMMSSZ-<8 lowercase hex>
```

Bundle directories are `root:root 0700`; files are `root:root 0600`. Publication is an atomic rename followed by backup-root `fsync`.

## 8. Bundle format

A normal published bundle contains exactly:

```text
manifest.json
runtime.tar.zst
systemd.tar.zst
ansible.tar.zst
controller-state.tar.zst
registration-state.tar.zst
deployment-assets.tar.zst
```

After successful checks it may additionally contain:

```text
verification.json
rehearsal.json
```

No other top-level object is allowed.

### 8.1 `runtime.tar.zst`

Captures presence or absence and, when present, exact content and metadata for:

```text
/opt/alt-deploy-control
/opt/alt-deploy-api
/usr/local/sbin/workstationctl
/usr/local/libexec/alt-provision-worker
/usr/local/libexec/alt-job-stage
```

A path absent before OR-3P4 is recorded as absent. Full restore removes a post-backup object at that path instead of retaining a new-generation file.

The backup utility and `/opt/alt-deploy-backup` are intentionally outside the restored runtime generation. OR-3P4 must preserve them until its rollback gate is retired.

### 8.2 `systemd.tar.zst`

Captures presence or absence of these exact unit files under `/etc/systemd/system`:

```text
alt-deploy-http.service
alt-deploy-register.service
alt-deploy-process.path
alt-deploy-process.service
```

Enablement symlinks are not archived. The manifest stores `is-enabled`, `is-active`, and failed-state observations. Restore reconstructs enablement through `systemctl` after `daemon-reload`.

Transient `alt-provision-*.service` units are never archived or stopped; any active transient unit blocks backup and restore.

### 8.3 `ansible.tar.zst`

Captures:

```text
/home/altserver/ansible
```

and excludes:

```text
/home/altserver/ansible/group_vars/vault.yml
```

The archive preserves numeric ownership, modes, timestamps, supported ACLs, and supported xattrs. Only symlinks whose resolved target remains within the approved Ansible root are permitted.

Restore builds a staged non-secret Ansible tree, revalidates the live Vault identity, and inserts the existing Vault file into the staged tree without archiving it.

### 8.4 `controller-state.tar.zst`

Captures the complete tree:

```text
/var/lib/alt-deploy
```

including jobs, assignments, machine archives, transaction evidence, and other provisioning state under that root. It is restored only together with the matching runtime generation.

### 8.5 `registration-state.tar.zst`

Captures:

```text
/srv/alt-deploy/registration
```

including ready, failed, archive-related state, and the empty pending directory. Creation is blocked when `pending` contains a registration JSON record.

### 8.6 `deployment-assets.tar.zst`

Captures:

```text
/srv/alt-deploy/bootstrap
/srv/alt-deploy/metadata
```

including `ansible_authorized_keys`, autoinstall metadata, VM profile metadata, package-group archives, installation-script archives, bootstrap scripts, and the register-only helper when present. The authorized key is public material and is included; the SSH private key is excluded.

## 9. Manifest contract

`manifest.json` is strict UTF-8 JSON with a trailing newline. Unknown keys and unsupported schema versions fail closed unless explicitly versioned as extensible fields.

It contains:

- schema and backup-tool versions;
- backup ID and UTC creation time;
- controller hostname, machine ID when available, and OS metadata;
- installed repository/package identity when safely determinable;
- ordered component records with filename, size, SHA-256, allowed roots, and source presence;
- required path metadata with numeric UID/GID, names, modes, and supported ACL/xattr flags;
- exact managed systemd state observed before maintenance;
- preflight check results;
- safe secret identity records;
- the mandatory all-component restore order.

It never contains registration bodies, job logs, Ansible values, decrypted Vault material, passwords, password hashes, private-key bytes, or the HMAC key.

## 10. Secret identity model

Secret contents are never archived:

```text
/home/altserver/ansible/group_vars/vault.yml
/home/altserver/.ansible-vault-pass
/home/altserver/.ssh/id_ed25519
```

The controller-local fingerprint key is:

```text
/var/lib/alt-deploy-backup/fingerprint.key
```

It is `root:root 0600`, created once from cryptographically secure random bytes, never replaced by reinstall, never included in a bundle, and outside all restored roots.

Identity records use:

- encrypted `vault.yml`: file SHA-256 plus Vault-header validation;
- `.ansible-vault-pass`: HMAC-SHA-256 with the fingerprint key, never a plain content hash;
- SSH private key: public-key fingerprint derived with `ssh-keygen`, never a private-byte hash.

The manifest also records path, numeric owner/group, names, mode, and size. Every secret is opened with no-follow semantics and checked for stable device, inode, size, and metadata during reading.

Backup publication, verify, rehearsal, and restore fail when secret type, ownership, mode, format, or identity does not match.

## 11. Locking and snapshot consistency

Every operation takes the root-owned global lock:

```text
/run/lock/alt-deploy-backup.lock
```

The controller's existing lifecycle lock remains the serialization boundary for provisioning, registration admission, machine archive mutation, and job-state mutation.

For `create` and `restore`, after maintenance services stop, the backup utility acquires the controller lifecycle lock and holds it continuously through:

- the second quiescence check;
- source inventory;
- component capture or restore staging validation;
- manifest creation and publication, or restore transaction completion/rollback;
- final state checks.

This maintenance-window lock may be held for the complete archive operation. That is intentional: without it, a root CLI invocation could mutate jobs, assignments, machine archives, or registration state while services were stopped.

Before and after component capture, the utility compares a bounded source inventory containing path, type, device, inode, size, `mtime_ns`, and `ctime_ns`. Any unexplained change aborts publication.

## 12. Backup creation

### 12.1 Preflight without service mutation

`create` verifies:

- root execution;
- GNU `tar`, `zstd`, `python3`, `sha256sum`, `systemctl`, `systemd-analyze`, `ansible-playbook`, and `ssh-keygen`;
- `altserver` account identity;
- safe source roots and sufficient disk space;
- no queued/running job;
- no active `alt-provision-*` unit;
- empty registration pending queue;
- inactive `alt-deploy-process.service`;
- valid secret identities and fingerprint key;
- safe backup, log, state, and lock roots.

No service is stopped on preflight failure.

### 12.2 Maintenance window

The utility records exact managed-unit states and stops, in order:

```text
alt-deploy-process.path
alt-deploy-register.service
alt-deploy-http.service
```

It then acquires the controller lifecycle lock and repeats all quiescence and secret checks. Any mismatch aborts capture.

### 12.3 Component capture

Each archive is written to a temporary regular file in `.creating-<backup-id>`, fsynced, and renamed within that directory.

Capture must:

- use explicit relative namespaces;
- reject absolute, untrusted, or shell-expanded source names;
- reject devices, sockets, FIFOs, and unsafe links;
- exclude all secret paths;
- preserve required metadata;
- compare source inventories before and after capture;
- compute size and SHA-256 from final archive bytes;
- fsync files and containing directories.

### 12.4 Publication and service recovery

The temporary bundle receives `manifest.json` and passes the complete structural/integrity validator. It is then atomically published.

On success, original enablement and active states are restored only after publication. On any create failure, the incomplete directory remains unpublished and service recovery is attempted as failure cleanup.

If service recovery cannot reproduce the recorded state, the command returns `service_state_restore_failed`, even when bundle publication succeeded.

## 13. Verification

`verify <backup-id>` does not modify production runtime or controller state. After success it may atomically create or replace `verification.json`.

It checks:

1. backup-ID syntax and direct-child containment;
2. directory/file owner, mode, type, and no-follow reads;
3. exact allowed top-level set;
4. strict manifest schema and identity;
5. complete ordered component set;
6. component size and SHA-256;
7. readable zstd streams;
8. tar member safety:
   - no absolute paths;
   - no empty or dot-only paths;
   - no `..` traversal;
   - no member outside its namespace;
   - no external symlink or hardlink target;
   - no device, socket, or FIFO;
9. required structure and absent-path semantics;
10. secret exclusion;
11. current secret identity match;
12. backup-tool/schema compatibility.

`verification.json` records the manifest hash, component hashes, utility version, UTC time, safe identities, passed check IDs, and `status=ok`. Bundle mutation invalidates verification through hash mismatch.

## 14. Isolated rehearsal

`rehearse <backup-id>` first performs full verification, then extracts beneath:

```text
/var/tmp/alt-deploy-restore-test/<backup-id>/
```

Extraction forbids setuid/setgid preservation, devices, path escape, and following extracted links.

Rehearsal validates:

- complete component structure and absent-path semantics;
- recorded ownership/modes;
- Python compilation;
- shell syntax;
- `systemd-analyze verify` against the restored absolute unit-file paths;
- both Ansible syntax checks against the staged playbooks;
- Vault loading by referencing the live encrypted Vault and live password file as external read-only command inputs, without copying them into the rehearsal tree or logging values;
- strict parsing of jobs, assignments, registrations, machine archives, transaction journals, manifests, and commit evidence;
- committed-generation consistency;
- absence of prohibited secrets in the rehearsal tree.

Success atomically writes `rehearsal.json` containing the manifest hash, utility version, UTC time, safe identities, passed checks, and `status=ok`.

A successful rehearsal tree is removed. A failed tree may remain `root:root 0700` for diagnosis.

## 15. OR-3P4 rollback gate

OR-3P4 must name the exact rollback bundle:

```bash
sudo bash deploy/alt-linux/install-control-plane.sh \
  --rollback-backup-id <backup-id>
```

Before any runtime mutation, the installer calls the already installed backup utility to prove that:

- the named bundle currently verifies;
- `verification.json` matches current bytes;
- `rehearsal.json` matches the same manifest hash;
- the rehearsal and schema are compatible;
- secret identities still match.

The installer never chooses the newest backup implicitly and never overwrites `/usr/local/sbin/alt-deploy-backup`, `/opt/alt-deploy-backup`, `/var/lib/alt-deploy-backup`, or `/var/backups/alt-deploy`.

## 16. Restore transaction

Restore is root-only and all-component. No component-selection flag exists.

### 16.1 Eligibility

Restore requires:

- current full verification;
- matching verification and rehearsal records;
- compatible utility/schema versions;
- matching secret identities;
- no active job or transient provision unit;
- no pending registration or running processor;
- a normal published backup ID.

### 16.2 Preparation

The utility:

1. takes the global backup lock;
2. records the pre-restore managed-unit state;
3. stops maintenance units;
4. acquires the controller lifecycle lock;
5. repeats eligibility checks;
6. creates a complete protected pre-restore snapshot;
7. creates and fsyncs a restore transaction journal.

The pre-restore snapshot is emergency rollback material only and cannot satisfy the OR-3P4 gate.

### 16.3 Durable phases

The journal uses ordered phases:

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

Every phase transition is fsynced.

### 16.4 Staging and installation

Each component is extracted and validated on the same filesystem as its final destination. Staging checks structure, hashes, allowed types/links, ownership, modes, secret exclusion, absent-path semantics, and free space.

The current Vault file is inserted into the staged Ansible tree only after identity verification. The Vault password and SSH private key remain at their existing paths.

For each managed path, the current object is renamed to protected rollback storage on the same filesystem and the staged object is renamed into place. A path recorded as absent receives no replacement.

Global cross-filesystem atomicity is not claimed; durable journaling and the pre-restore generation provide coordinated recovery.

### 16.5 Service activation and health

After installation:

1. run `systemctl daemon-reload`;
2. reconstruct enabled/disabled states from the backup manifest;
3. validate runtime syntax, permissions, Vault health, secrets, unit loadability, Ansible syntax, and state readers;
4. start only HTTP and registration services recorded active in the backup;
5. perform their loopback health checks when recorded active;
6. start `alt-deploy-process.path` last when recorded active;
7. leave units recorded inactive stopped;
8. verify final unit states exactly match the backup manifest.

No endpoint health check is required for a service that was recorded inactive.

### 16.6 Failure handling

A failure before any active path is moved leaves production unchanged.

A failure after replacement triggers automatic reversal to the pre-restore generation. Successful reversal restores the pre-restore service state and records `rolled_back`.

If complete reversal cannot be proven, the journal records `manual_recovery_required`, all maintenance units remain stopped, and the command returns:

```text
restore_manual_recovery_required
```

Restore succeeds only after the complete selected generation passes health checks and its recorded service state is restored.

## 17. List, delete, and retention

`list` reports normal published bundles with creation time, total bytes, manifest hash, compatibility, and current verification/rehearsal state. It does not present `.creating-*`, restore transactions, or pre-restore snapshots as normal backups. Corrupted directories may be reported as invalid without exposing contents.

`delete <backup-id>` requires an exact valid backup ID and a safe direct child of the backup root. It validates containment, type, owner, mode, and no-symlink traversal. It does not require component integrity, so a corrupted bundle remains deletable. Deletion is blocked while an active restore transaction references the bundle.

There is no bulk delete and no automatic retention.

## 18. Logging and public errors

The bounded operation log is:

```text
/var/log/alt-deploy-backup.log
```

It records commands, IDs, timestamps, maintenance transitions, component phases, check IDs, restore phases, error codes, and automatic rollback outcome.

It never records archive contents, registration bodies, job logs, Ansible values, Vault plaintext, Vault password, password hashes, private-key bytes, or HMAC keys.

Initial stable errors:

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

Errors before publication do not produce a usable backup. Errors before restore replacement do not change production. Errors after replacement either prove automatic rollback or leave services stopped with manual recovery required.

## 19. Implementation boundaries

Separate modules cover:

1. CLI and public JSON rendering;
2. settings and path inventory;
3. safe filesystem primitives;
4. strict source/state readers;
5. component creation and validation;
6. manifest schema;
7. secret identities;
8. systemd state;
9. bundle repository/publication;
10. rehearsal extraction/checks;
11. restore journal and rollback engine;
12. dedicated backup-tool installer;
13. control-plane installer gate;
14. audit logging.

No backup module contacts a workstation or imports provisioning worker behavior.

## 20. TDD and verification matrix

Minimum automated coverage:

1. root-only enforcement;
2. global backup lock;
3. lifecycle lock held through create/restore critical sections;
4. active-job, transient-unit, pending-registration, and processor refusal;
5. exact service-state capture/recovery;
6. service recovery after failed create;
7. secret exclusion from every component;
8. Vault-password HMAC and SSH public fingerprint behavior;
9. fingerprint-key preservation across reinstall;
10. source symlink and special-file refusal;
11. tar traversal, external link, FIFO, device, and socket refusal;
12. source inventory change detection;
13. SHA-256 corruption detection;
14. incomplete bundle non-publication;
15. strict manifest/version rejection;
16. verification invalidation after mutation;
17. rehearsal confinement;
18. Python, shell, systemd, Ansible, and JSON rehearsal gates;
19. restore refusal without current verify/rehearse evidence;
20. restore refusal on secret mismatch;
21. all-component restore and absent-path semantics;
22. staging failure with unchanged production;
23. health failure with successful rollback;
24. rollback failure with services stopped;
25. safe corrupted-bundle deletion;
26. dedicated installer publishes only backup-tool assets;
27. dedicated installer preserves bundles, logs, and fingerprint key;
28. control-plane installer requires explicit backup ID before mutation;
29. control-plane installer preserves backup-tool paths;
30. existing OR-3P1 and OR-3P2 regressions.

Filesystem tests use temporary roots and fake command adapters. CI never accesses the live controller, the accepted workstation, production Vault, or production SSH material.

Repository completion requires fresh evidence:

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

## 21. Operational acceptance

After repository review, the operational sequence on `192.168.100.17` is:

```bash
sudo bash deploy/alt-linux/install-backup-tool.sh
sudo alt-deploy-backup create
sudo alt-deploy-backup verify <backup-id>
sudo alt-deploy-backup rehearse <backup-id>
```

The report must prove:

```text
backup published
component integrity verified
secret identities match
restore rehearsal passed
maintenance services returned to their original state
```

A real restore is not performed before OR-3P4. OR-3P4 remains blocked until `install-control-plane.sh` is invoked with that exact verified and rehearsed backup ID. The accepted reference workstation remains out of scope.