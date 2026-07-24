# ALT stale registration recovery

## Purpose

Provide a narrow, auditable recovery path for a legacy registration record
whose directory state and JSON `status` conflict. The immediate target is the
assigned test machine `cc6f1a81-54b8-47c9-95de-2ac29ee4fbb7`: its file is in
`registration/failed/` while its JSON status is `awaiting_assignment`.

This inconsistency blocks the OR-3P3 backup rehearsal. The recovery does not
modify the target workstation, its assignment, provision jobs, Vault, SSH keys,
or any unrelated registration record.

## Command contract

Add a `workstationctl --json machines recover-stale-registration` command with
two subcommands:

- `preview <machine-identifier>` is read-only and returns the machine identity,
  logical source state, status conflict, file SHA-256, and assignment presence.
- `apply <machine-identifier> --reason <text>` is root-only. It requires the
  same validated stale condition as preview and a non-empty, bounded reason.

The command is intentionally not a generic registration editor or machine
release feature. It accepts only a record in `failed/` whose identity matches
its filename, whose JSON status is `awaiting_assignment`, and whose machine has
an existing assignment. Any symlink, malformed JSON, identity mismatch,
unassigned machine, status without this exact legacy conflict, or active job
fails closed.

## Apply transaction

Under the existing controller lock, apply will:

1. Revalidate the source record and lifecycle state.
2. Copy the original JSON bytes into a new private recovery archive beneath
   `machine-archives/`.
3. Write and fsync a manifest containing the UUID, source state, original
   filename, SHA-256, archive timestamp, operator identity, and reason.
4. Atomically remove the active stale record only after the archive and manifest
   are durable.

The assignment and all job files remain unchanged. A completed archive makes a
repeat apply idempotent: it returns the existing recovery archive and does not
create another one. A failure before completion leaves the source record in
place and reports a specific error.

## Verification

Tests will cover preview, root gating, exact-byte archive preservation,
idempotent retry, status/identity/symlink/unassigned/active-job rejection, and
failure atomicity. The full `tests/alt_linux` suite, Python and Bash syntax
checks, and both Ansible syntax checks must pass before publication.

Only after a merged source revision passes those checks will the controller
perform preview and apply for the one approved test-machine record. The backup
will then be recreated, verified, rehearsed, and supplied to the control-plane
installer.
