# Task 6 report: disposable generic-OVMF execution acceptance

## Result

Implemented the disposable QEMU execution contract and the review fixes
without starting QEMU, generating an ISO, deploying a controller, contacting
Proxmox, or writing a real target.

The executable acceptance path now:

- creates a per-run Ed25519 trust anchor, unpredictable run/challenge, QEMU
  UUID, and exact ISO/target/sentinel path, SHA, and file identities;
- derives the only authorization request from the one authoritative local
  `plan_published`/`preflight_ready` controller session;
- captures initial and immediate-before-authorization QMP/SHA evidence and
  requires all target and sentinel graph writes to remain zero;
- invokes the production root `alt_deploy.cli.main authorize-execution`
  command with exact derived arguments and checks its execution ID plus the
  persisted `authorized` state;
- records real authenticated
  `claimed -> handoff_started -> installer_started -> installed`
  controller transitions;
- boots the target without the ISO, proves its running QMP UUID/block
  identity, then issues a fresh signed single-use boot nonce;
- installs a minimal first-boot reporter through `install-scripts.tar`; the
  reporter sends its real kernel boot ID through the V2 TLS postflight API;
- accepts PASS only after the exact signed run/session/controller chain and
  mandatory portable QMP/SHA/ISO/postflight corpus replay successfully;
- records work-directory device/inode at creation and isolates the TAP in an
  anonymous namespace whose holder process and namespace identities are
  pidfd-bound at cleanup.

The old caller-supplied `--timeline` and `--postflight` route was removed.
Console prefixes are no longer evidence or authorization.

## Second review hardening

The second review round additionally:

- captures two ordered, signed authorization-boundary documents, each from
  one contemporaneous QMP query followed by exact target/sentinel SHA
  measurements, and requires the root observation plus controller
  authorization to follow those documents;
- reaches the real production CLI/service/repository by default in a
  non-injected POSIX integration test;
- binds the install ISO's canonical path, device, inode, size, and SHA-256 at
  run creation, rechecks them immediately before QEMU, and requires the exact
  read-only `install-iso` QMP device in both authorization boundaries;
- records work-directory ownership immediately after `mktemp` and performs
  cleanup through stable directory descriptors; TAP cleanup is bound to the
  recorded kernel ifindex and uses netlink instead of a reused name;
- writes the receipt and root-owned public proof outside the disposable work
  directory. A seventh signed attestation seals the six-entry transition
  chain, receipt, public key, manifest, and raw evidence hashes. The package
  is independently verifiable after work-directory cleanup and contains no
  private key or controller credential.

## Third review hardening

The third review round closes the remaining code-real gaps:

- signed boundary captures have hard freshness ceilings: 10 seconds per
  capture, 30 seconds from pending capture to preauthorization start, and 10
  seconds from preauthorization capture to the root CLI observation;
- the managed-ISO verifier returns its verified digest. `create-run` copies
  only bytes matching that digest from an already-open source descriptor into
  a private `0400` run artifact while hashing and fsyncing it. QEMU and QMP
  bind only to that copy;
- the host TAP deletion path is gone. The harness creates an anonymous
  dedicated network namespace, runs TAP/DHCP/API/QEMU inside it, and tears it
  down through a pidfd-anchored holder after exact process-start-time and
  namespace device/inode checks. A reused process is never signaled;
- public export requires one exact corpus, including all QMP/SHA/boundary,
  ISO, controller attestation, delivery, boot-reporter, and postflight
  evidence. The verifier semantically replays it from portable copied bytes
  and rejects missing, empty, extra, external-reference, and validly resealed
  semantic mutations.

## TDD evidence

Initial Task 6 red:

```text
pytest tests/test_alt_install_execution_qemu.py -q
17 failed, 1 error
```

Review-fix red slices:

```text
pytest tests/test_alt_install_execution_qemu.py -q -k \
  'run_state or bound_qmp or bound_sha or signed_chain or authorization_boundary or cleanup_rejects or root_authorization'
7 failed

pytest --noconftest \
  tests/alt_linux/test_install_execution.py::test_installer_and_postflight_are_contiguous_single_use_transitions \
  tests/alt_linux/test_install_execution_api.py::test_installer_started_and_signed_postflight_are_real_state_transitions -q
2 failed

pytest tests/test_alt_install_execution_agent.py -q
3 failed, 10 passed
```

The failures were the expected missing run trust state, exact QMP/SHA
bindings, real installer/postflight transitions, and installer-started agent
protocol call.

Review-fix green:

```text
pytest tests/test_alt_install_execution_qemu.py -q
20 passed

pytest --noconftest \
  tests/alt_linux/test_install_session_cli.py \
  tests/alt_linux/test_install_execution.py \
  tests/alt_linux/test_install_execution_api.py -q
56 passed, 5 skipped

pytest tests/test_alt_install_execution_agent.py -q
13 passed
```

The skips are existing POSIX/root-only cases on Windows. Pytest emitted only
the repository's existing `pytest-asyncio` loop-scope deprecation warning.

Static verification:

```text
python -m py_compile <changed Python files>
exit 0

ruff check <changed production and focused test files>
All checks passed!

bash -n <changed shell files>
exit 0

git diff --check
exit 0
```

Second review red:

```text
pytest tests/test_alt_install_execution_qemu.py -q -k \
  'install_boundary or authorization_boundary_captures or cleanup_before_tap \
  or replacement_race or tap_cleanup or signed_no_iso or harness_uses'
8 failed, 18 deselected
```

Second review green:

```text
pytest tests/test_alt_install_execution_qemu.py \
  tests/test_alt_install_execution_agent.py -q
39 passed

pytest --noconftest \
  tests/alt_linux/test_install_session_cli.py \
  tests/alt_linux/test_install_execution.py \
  tests/alt_linux/test_install_execution_api.py -q
56 passed, 5 skipped
```

The new non-injected production CLI integration is POSIX-only because the
production repository locking implementation requires `fcntl`; it is
collected for Linux CI and is skipped on this Windows development host.

Third review red slices:

```text
pytest tests/test_alt_install_execution_qemu.py -q \
  -k 'overlong_capture or stale_but_ordered_boundaries'
3 failed, 26 deselected

pytest tests/test_alt_install_execution_qemu.py -q \
  -k 'source_iso_replaced or launches_owned_iso_copy'
2 failed, 29 deselected

pytest tests/test_alt_install_execution_qemu.py::test_signed_no_iso_boot_challenge_is_fresh_single_use_and_finalizes -q
1 failed

pytest tests/test_alt_install_execution_qemu.py::test_network_namespace_cleanup_cannot_signal_a_reused_process -q
1 failed
```

Each failure was the intended absent ceiling, owned copy, mandatory semantic
replay, or identity-anchored namespace behavior.

Third review green:

```text
pytest tests/test_alt_install_execution_qemu.py \
  tests/test_alt_install_execution_agent.py -q
44 passed, 1 skipped

pytest --noconftest \
  tests/alt_linux/test_install_session_cli.py \
  tests/alt_linux/test_install_execution.py \
  tests/alt_linux/test_install_execution_api.py -q
56 passed, 5 skipped

pytest tests/test_alt_install_execution_iso.py -q
30 passed
```

The one QEMU-contract skip is the POSIX-only test that replaces an ISO path
while its original descriptor remains open. The behavior is implemented for
the Linux acceptance host and cannot be exercised on Windows file-sharing
semantics.

## Specification self-review

Verdict: **PASS for the implementation contract; no QEMU execution PASS
claimed.**

- C1: the root boundary is the real production CLI/service/repository path,
  after two ordered signed, exact-identity, zero-write QMP/SHA boundary
  documents; a caller-independent observation time and the controller
  authorization time are persisted in signed evidence and must be
  contemporaneous within fixed 10/30/10-second ceilings.
- C2: every run has unpredictable trust material and exact
  ISO/VM/target/sentinel/controller bindings. The verifier-derived digest is
  copied from an open descriptor into a private run-owned ISO, which is
  reverified immediately before QEMU and against the exact QMP CD-ROM. The
  actual no-ISO QMP boot precedes nonce generation. The real first-boot
  component and TLS API consume it once; stale or replayed evidence is
  rejected.
- I3: QMP response IDs, `inserted.file`, canonical SHA filenames, and
  device/inode file identities are exact.
- I4: work-directory ownership is recorded immediately after creation and
  cleanup walks stable directory descriptors. Network resources live in a
  dedicated anonymous namespace; pidfd plus process/namespace identity checks
  eliminate the host TAP ifindex ABA deletion window.
- I5: the public, non-secret proof has an exclusive hash-linked index and a
  seventh Ed25519 seal. Its exact mandatory portable corpus is semantically
  replayed without live artifact paths and remains independently verifiable
  after private work-directory cleanup.
- There is no CLI route for an existing disk, infrastructure VM, Proxmox, VM
  114, an arbitrary authorization request, a caller timeline, or a caller
  postflight result.

## Quality and safety self-review

Verdict: **PASS**

- Bounded strict JSON rejects duplicate keys and ambiguous evidence.
- Per-run signatures bind sequence, previous-attestation digest, UTC
  timestamps, run, challenge, key ID, controller execution, VM, boot nonce,
  and boot ID.
- QMP requires exact response IDs and checks all target/sentinel graph write
  counters; nested sentinel writes fail.
- The receipt and public evidence package are exclusive and contain no
  Bearer credential, password/hash, TLS key, or attestation private key.
- The API's postflight verifier is disabled in normal service startup and is
  enabled only with the harness-owned acceptance state directory.
- Cleanup preserves resources when ownership identity cannot be proven.

## Remaining external acceptance work

An actual accepted run still requires a dedicated Linux/root host with QEMU,
OVMF, anonymous network namespaces, `setns`, pidfd, TAP/DHCP, AF_UNIX, the
held release archives containing the reporter, a previously built verified
V2 ISO, and a locally prepared V2 session. That real-QEMU proof is the
remaining external platform gate. Those preconditions are absent on this
Windows host, so no QEMU run or PASS receipt was produced or simulated.
