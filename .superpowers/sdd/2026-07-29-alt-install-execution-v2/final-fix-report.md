# Final security fix wave report

## Status

Implemented the three final cross-task security fixes without deploying,
starting a real V2 service, building an ISO, running QEMU, or touching a real
target disk.

## Production changes

- `install-install-execution-api.sh` now stops the failed unit before restoring
  any pointer or unit state. Rollback aggregates stop, pointer, unit,
  daemon-reload, enable/disable, active-state, release-removal, and transaction
  cleanup failures. Any failed prerequisite suppresses restart and failed
  release removal and retains the recovery transaction with an explicit
  diagnostic.
- Rollback covers clean-host absence, prior enabled/active runtime, and prior
  enabled/inactive runtime semantics. `disable` is not treated as a stop.
- An occupied `192.168.100.17:18092` is admitted only when the exact listener
  PID equals the active managed unit's `MainPID`, the current pointer resolves
  below the V2 releases root, the installed unit has the exact V2 identity and
  endpoint contract, no wildcard listener is present, and exact TLS health
  succeeds. Foreign, ambiguous, inactive, mismatched-PID, wildcard, and
  unhealthy listeners fail closed.
- Activation now uses explicit enable plus restart so a verified rerun executes
  the newly selected release instead of leaving the old process running.
- Portable Task 6 replay now requires the exact five-key root-authorization
  request, validates session/hash/fingerprint formats, and binds the three
  non-secret authorization digests to a separate receipt authorization object.
  Omitted, extra, or changed request bindings are rejected even after the full
  attestation chain, embedded postflight attestations, receipt hash, evidence
  hashes, seventh seal, and index are validly regenerated.

## TDD evidence

Installer RED:

```text
python -m pytest --noconftest \
  tests/alt_linux/test_install_execution_production_installer.py -q \
  -k "rollback_prerequisite_failure or rollback_restores_clean_active_and_inactive or admits_only_healthy or rejects_unverified"

10 failed, 4 passed, 14 deselected in 4.80s
```

The intended failures showed suppressed rollback prerequisites, pointer/release
deletion after failures, incorrect stop ordering, and the absent owned-listener
admission. Windows/MSYS also exposed test-only path/command portability issues;
the compatibility wrapper is Windows-only, while the authoritative Linux run
uses the real production atomic operations.

Portable replay RED was re-proved with the production binding removed:

```text
python -m pytest \
  tests/test_alt_install_execution_qemu.py::test_signed_no_iso_boot_challenge_is_fresh_single_use_and_finalizes -q

FAILED: DID NOT RAISE AcceptanceError
1 failed in 1.17s
```

After restoring the receipt/request binding:

```text
1 passed in 2.11s
```

## Verification

Local Windows:

```text
Focused installer security slice: 16 passed, 12 deselected
Full installer module: 16 passed, 12 skipped
Full Task 6 QEMU contract module: 34 passed, 1 skipped
```

The skips are the existing platform-gated Linux/POSIX cases.

Authoritative temporary Linux-root archive run on `altserver-100-17`:

```text
sudo -n python3 -m pytest \
  tests/alt_linux/test_install_execution_production_installer.py -q

28 passed in 5.62s
```

The temporary remote tree/archive and local archive were removed after the
run. This was a test-only archive extraction, not a deployment.

Static checks:

```text
bash -n deploy/alt-linux/install-install-execution-api.sh
python -m py_compile <changed Python files>
ruff check <changed Python files>
git diff --check
```

All exited successfully.

## Remaining external boundary

No real QEMU/OVMF acceptance PASS or production rollout is claimed. Those
remain the existing external Task 6/Task 7 gates.

## Final effective-unit identity fix (2026-07-30)

### Status and behavior

The repeat-run occupied-listener admission now fails closed unless the
installed unit is byte-for-byte identical to the packaged V2 unit and systemd
reports that exact file as `FragmentPath`, no loaded `DropInPaths`, and
`NeedDaemonReload=no`. This rejects both a foreign health-compatible
`ExecStart` drop-in and duplicate reset/override directives appended to the
base unit. The genuine healthy managed V2 listener remains admissible.

The change is confined to V2 listener admission. V1 paths and services are
untouched. No deployment, service activation, QEMU run, push, or production
network change was performed.

### TDD evidence

RED, before the effective-unit identity check:

```text
python -m pytest --noconftest \
  tests/alt_linux/test_install_execution_production_installer.py -q \
  -k "foreign_exec_start or admits_only_healthy"

2 failed, 1 passed, 27 deselected in 2.28s
```

Both foreign `ExecStart` variants were incorrectly admitted while the healthy
managed-unit positive control passed.

GREEN, after the identity check:

```text
3 passed, 27 deselected in 1.74s
```

### Verification

Fresh local Windows installer module:

```text
python -m pytest --noconftest \
  tests/alt_linux/test_install_execution_production_installer.py -q

18 passed, 12 skipped in 6.66s
```

The skips are the existing Linux/POSIX-gated production installer cases.

Fresh authoritative temporary Linux-root archive run on `altserver-100-17`:

```text
sudo -n python3 -m pytest --noconftest \
  tests/alt_linux/test_install_execution_production_installer.py -q

30 passed in 5.76s
```

The temporary remote tree/archive and local archive were removed after the
run. This was test-only extraction under `/tmp`, not deployment.

Static checks:

```text
bash -n deploy/alt-linux/install-install-execution-api.sh
python -m py_compile \
  tests/alt_linux/test_install_execution_production_installer.py
python -m ruff check \
  tests/alt_linux/test_install_execution_production_installer.py
git diff --check
```

All exited successfully.

## Final live-process identity fix (2026-07-30)

### Status and behavior

Repeat-run occupied-listener admission now binds systemd's live `MainPID` to
the canonical managed V2 invocation. The process executable from
`/proc/<MainPID>/exe` must resolve to the same executable as
`/usr/bin/python3`, and `/proc/<MainPID>/cmdline` must be NUL-terminated and
contain exactly the packaged interpreter, server path, listen address, listen
port, and expanded credential-key arguments. A second `MainPID` read must
remain identical after process inspection.

This rejects a health-compatible foreign process that was started by an old
override and remains alive after the override is removed, the canonical unit
is restored, and systemd is daemon-reloaded without a restart. Missing
executable or cmdline state and extra process arguments also fail closed. The
genuine managed listener and verified upgrade flow remain admissible.

The change is confined to V2 listener admission. V1 paths and services are
untouched. No deployment, service activation, QEMU run, push, or production
network change was performed.

### TDD evidence

RED, before live-process identity validation:

```text
python -m pytest --noconftest \
  tests/alt_linux/test_install_execution_production_installer.py -q \
  -k "foreign_override_process_after_unit_restore_and_reload or \
      unreadable_or_ambiguous_managed_process_identity or \
      admits_only_healthy"

4 failed, 1 passed, 29 deselected in 3.80s
```

The canonical managed-process positive control passed, while the restored-unit
foreign process and all unreadable or ambiguous process identities were
incorrectly admitted.

GREEN, after live-process identity validation:

```text
python -m pytest --noconftest \
  tests/alt_linux/test_install_execution_production_installer.py -q \
  -k "foreign_override_process_after_unit_restore_and_reload or \
      unreadable_or_ambiguous_managed_process_identity or \
      admits_only_healthy or verified_rerun"

5 passed, 1 skipped, 28 deselected in 3.28s
```

The skip is the existing Linux-only upgrade test on Windows.

### Verification

Fresh local Windows installer module:

```text
python -m pytest --noconftest \
  tests/alt_linux/test_install_execution_production_installer.py -q

22 passed, 12 skipped in 9.80s
```

The skips are the existing Linux/POSIX-gated production installer cases.

Fresh authoritative temporary Linux-root archive run on
`altserver-100-17`:

```text
sudo -n python3 -m pytest --noconftest \
  tests/alt_linux/test_install_execution_production_installer.py -q

34 passed in 5.44s
```

The temporary remote tree/archive and local archive were removed after the
run. This was test-only extraction under `/tmp`, not deployment.

Static checks:

```text
bash -n deploy/alt-linux/install-install-execution-api.sh
python -m py_compile \
  tests/alt_linux/test_install_execution_production_installer.py
python -m ruff check \
  tests/alt_linux/test_install_execution_production_installer.py
git diff --check
```

All exited successfully.
