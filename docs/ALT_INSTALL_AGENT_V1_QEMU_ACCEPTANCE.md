# ALT install-agent V1 QEMU dry-run acceptance

This manual gate proves that the signed-plan agent reaches its dry-run terminal
state without target writes. It does not authorize installation and it never
starts Alterator, `install2.target`, partitioning, a reboot, or a target-disk
handoff.

## Safety boundary

`run-agent-v1-dry-run-acceptance.sh` does not accept a target-disk argument.
For each run it creates private temporary assets:

1. an Ed25519 signing keypair used only by the disposable controller fixture;
2. a managed ISO embedding only that temporary public key;
3. a 64 GiB sparse qcow2 backing image for each QEMU variant;
4. a writable qcow2 overlay for the writable variant; and
5. a separate copied OVMF variable store for each variant.

The writable VM receives only its disposable overlay. The readonly VM receives
only its disposable qcow2 backing with `readonly=on`. The private key, bearer
credentials, inventory, plans, signatures, mutable OVMF stores, and disposable
images remain under the private work directory and are removed on exit. The
evidence directory contains only sanitized console states, QMP statistics,
SHA-256 records, public build metadata, and a bounded root-approval summary.

Do not modify the harness to accept `/dev/*`, a physical image, or a persistent
VM disk.

## Manual prerequisites

Run this gate on a Linux host as real root. Required packages and inputs are:

- `qemu-system-x86_64`, `qemu-img`, OVMF code and variable templates;
- Python 3 with the repository requirements, including `cryptography`;
- `xorriso`, `cpio`, `gzip`, `patch`, and normal GNU core utilities;
- the exact pinned ALT KWorkstation 11.4 source ISO;
- the verified static Linux amd64 `alt-install-helper`; and
- enough free space for the approximately 10.7 GB source ISO plus the managed
  ISO build workspace.

Check host commands and the root gate before supplying artifacts:

```bash
sudo deploy/alt-linux/qemu/run-agent-v1-dry-run-acceptance.sh \
  --check-prerequisites
```

The check exits nonzero and names every missing command. The full run also
fails closed for unreadable/symlinked input files, a non-root process, a busy
fixture port, missing QMP target statistics, any nonzero QMP `wr_*` counter,
a QMP readonly/topology mismatch, a backing-image SHA-256 change, an
incomplete root approval, or a missing variant.

The harness exposes its immutable target/build boundary without requiring
QEMU or root:

```bash
deploy/alt-linux/qemu/run-agent-v1-dry-run-acceptance.sh \
  --describe-safety-contract
```

That report is generated from the same target-size, format, readonly option,
managed-ISO builder, and source-identity paths used by the full run. The normal
argument parser rejects every caller-supplied target path.

## Run

Example paths for a common Debian/Ubuntu OVMF package are shown below; use the
actual regular-file paths installed on the acceptance host:

```bash
sudo deploy/alt-linux/qemu/run-agent-v1-dry-run-acceptance.sh \
  --source-iso /srv/iso/alt-kworkstation-11.4-install-x86_64.iso \
  --helper /srv/alt-install-helper \
  --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  --evidence-dir /srv/alt-agent-v1-acceptance
```

The test API binds only `127.0.0.1:18089`. QEMU user networking presents that
host service to the guest as the fixed controller address
`192.168.100.17:18089`. The fixture waits for the real agent's
`waiting_for_approval` heartbeat, invokes the production approval service under
effective UID 0, publishes a plan signed by the temporary key, and requires
the final `preflight_ready` heartbeat.

QEMU starts paused. The harness records initial `query-blockstats` and
`query-block`, resumes the VM, waits for the exact guest PASS line, records the
same QMP evidence again, stops QEMU, and compares the backing SHA-256. In both
snapshots, `wr_bytes`, `wr_operations`, and every other reported integer
`wr_*` counter must be zero for the selected target and every nested `parent`
or `backing` block node in its reported graph.

`query-block` independently binds that graph to the configured variant. The
writable overlay must report `inserted.ro=false` and backing depth 1. The
readonly guard must report `inserted.ro=true` and backing depth 0. Every qcow2
format node implied by that depth must have its file-protocol `parent`
statistics, and every backing level implied by the reported depth must be
present. Additional reported parent/backing nodes are also checked for zero
writes. A writable run cannot pass by changing its summary label to
`readonly`.

Success is reported only after both variants and both root-approved sessions
are verified. The last output line is exactly:

```text
PASS: signed plan verified; disk preflight passed; no target writes
```

## Non-secret evidence

The printed `evidence_dir` contains:

- `managed-iso.build-manifest.json`;
- `writable/` and `readonly/` QMP transcripts, backing SHA-256 records,
  sanitized guest states, QEMU diagnostics, and `summary.json`;
- `fixture-report.json`, containing session IDs, public key ID, root UID,
  plan revision, state, and final heartbeat stage only; and
- `acceptance-summary.json`, which is written only by the final two-variant
  gate.

Review the directory before archival. It must not contain a PEM private key,
Bearer credential, raw inventory, `plan.json`, `plan-signature.json`, response
headers/bodies, or mutable disk/firmware images.
