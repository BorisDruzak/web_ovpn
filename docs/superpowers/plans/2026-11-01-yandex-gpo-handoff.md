# Yandex signature policy GPO handoff

> Execute inline using the executing-plans workflow; preserve unrelated local files.

**Goal:** Move the existing Yandex signature-extension policy on the selected ALT
workstation from Ansible JSON ownership to a computer-scoped AD GPO.

**Design / scope:** Preserve the existing extension ID and update URL. Create a
dedicated GPO granting Apply only to the selected computer, linked to its current
OU. gpupdate remains responsible for generating the browser's policies.json.
Record the completed migration in a root-owned receipt on that workstation.
Ansible continues native-host installation, but a migrated computer must verify
the expected GPO provenance and generated policy rather than recreate the legacy
JSON. Unmigrated machines retain their existing behavior. Invalid or missing GPO
evidence on a migrated host must fail before changing its browser configuration.

**Tech stack:** AD GroupPolicy cmdlets, gpupdate 0.16.1, Ansible Core 2.18,
Python standard library, pytest, Yandex browser policy diagnostics.

## Tasks

- [ ] Add failing tests for receipt validation, current GPO provenance, expected
  extension membership, conflicting legacy contents and absent-receipt fallback.
- [ ] Add a read-only role helper and select legacy/GPO ownership explicitly in
  the signature role; remove legacy JSON only after verified GPO handoff.
- [ ] Update the operator guide; run focused tests and the repository suite.
- [ ] Review the complete change, commit, publish to main, and use the guarded
  controller backup/rehearsal/installer workflow to deploy the exact revision.
- [ ] Create the scoped GPO, refresh the target, compare generated settings to
  the original, record the migration receipt and back up/remove the legacy file.
- [ ] Verify browser://policy in an isolated browser profile, native-host
  manifests, repeated gpupdate and an idempotent Ansible policy-only execution.

## Review focus

Receipt absent: no existing-machine regression. Receipt invalid or wrong machine:
no silent fallback. GPO missing or wrong source: no legacy deletion. Local JSON
contains additional/custom policies: stop rather than delete them. Matching GPO
with additional unrelated extensions: preserve its full list. Native messaging
and cryptographic software remain installed by Ansible.

## Verification

Use behavioral helper tests and a controller-local Ansible runtime test for both
ownership modes. The live scope is only the user-selected workstation. Retain AD
GUID, policy/file hashes, browser policy diagnostics and rollback receipts outside
Git. Do not commit machine identities, credentials or operational access data.
