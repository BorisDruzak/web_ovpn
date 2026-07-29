# ALT install execution V2 rollout

This procedure stages only the TLS V2 service on
`192.168.100.17:18092`, publishes one immutable V2 ISO, verifies the Task 6
public evidence, and writes an exclusive production receipt. The V1
`192.168.100.17:18090` listener remains byte-compatible and no-write.

The pilot check is validation-only. It does not authorize execution, inspect
or open a disk, start an installer, or promise recovery of a disk after the
first write. There is no post-write rollback; the named rollback owner owns
the operational response after real-machine execution begins.

## Required inputs

Run as root from a clean checkout at the exact 40-character commit already
merged to `origin/main`. Prepare:

- a named OR-3P3 backup whose `rehearse-status` result is
  `backup_rehearsed`;
- the exact source ISO and its SHA-256;
- an expected SHA-256 for the immutable managed V2 ISO;
- the public plan key, public execution CA, Go binary, release ID and ISO
  directory;
- the root-owned Task 6 `public-evidence` directory from a real QEMU/OVMF
  run against the production TLS contract; and
- a pilot JSON derived from
  `docs/verification/alt-install-execution-v2-pilot-template.md`.

Until that real Task 6 receipt exists and its independent verifier emits
`public_evidence=verified`, rollout fails closed and no production receipt is
created. Contract tests or a simulated receipt are not acceptance.

## Command

```bash
sudo deploy/alt-linux/release/rollout-install-execution-v2.sh \
  --backup-id "$BACKUP_ID" \
  --source-commit "$COMMIT" \
  --source-iso "$SOURCE_ISO" \
  --source-iso-sha256 "$SOURCE_ISO_SHA256" \
  --managed-iso-sha256 "$MANAGED_ISO_SHA256" \
  --release-id "$RELEASE_ID" \
  --iso-dir "$ISO_DIR" \
  --public-key "$PUBLIC_KEY" \
  --execution-ca "$EXECUTION_CA" \
  --go "$GO" \
  --task6-evidence-dir "$TASK6_PUBLIC_EVIDENCE" \
  --pilot-record "$PILOT_RECORD" \
  --receipt "$PRODUCTION_RECEIPT"
```

The command refuses an existing receipt or release filename. It checks the
backup and pilot, rejects every active execution session, verifies the clean
merged commit and source digest, snapshots only the prior V2 runtime, installs
and health-checks only `alt-install-execution.service`, publishes the V2 ISO
without replacement, and then runs the Task 6 verifier. The production
receipt is the final mutation.

## Failure and rollback

Stop at the first failure. A failure before staging changes no service file.
A failure after staging restores only the former V2 unit, current-runtime
pointer and activation state, and removes only the newly staged V2 release.
It does not change V1, `alt-deploy-*`, session state, signing/TLS keys, a
published immutable ISO, Proxmox, VM 114, or a target disk.

A successfully published ISO remains immutable when a later Task 6 gate
fails. Investigate and use a new release ID; never overwrite or delete the
held release as an automatic rollback.

## Pilot boundary

The production receipt records that the pilot syntax and exact ISO binding
were validated. It does not authorize the named workstation. A separate
authorized operator must compare the exact asset ID, DMI UUID, disk
fingerprint, disk path, ISO digest, maintenance start/end and rollback owner
at the real maintenance window. Disk access and root execution authorization
are deliberately outside this rollout.
