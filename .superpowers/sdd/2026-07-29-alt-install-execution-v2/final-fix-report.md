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
