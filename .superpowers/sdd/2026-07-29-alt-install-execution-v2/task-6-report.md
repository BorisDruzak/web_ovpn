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

## Fourth review hardening

The fourth review round closes the final ordering and cleanup races:

- the boundary and root-observation clocks serialize canonical UTC with six
  fractional digits, and an actual `main()` wrapper regression proves a
  same-second microsecond boundary reaches the production CLI call;
- QEMU, dnsmasq, and execution-API termination now opens a pidfd first,
  verifies the recorded process start time after anchoring, signals only
  through the pidfd, and waits at most five seconds. PID reuse is rejected
  without signaling the replacement;
- namespace-stop verification or timeout is recorded in
  `cleanup-failures.log` and does not fall through to an unbounded shell
  `wait`. Any process or namespace cleanup failure preserves the work
  directory and live resources for investigation;
- portable replay now binds every delivery and authenticated-reporter
  schema/run/challenge/VM/controller/session/boot identity field to the
  manifest and signed lifecycle chain. Individually mutated and validly
  resealed variants all fail semantic verification.

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

Fourth review red:

```text
pytest tests/test_alt_install_execution_qemu.py -q -k \
  'authorization_wrapper_reaches_cli_with_same_second_boundary or \
  owned_process_cleanup_cannot_signal_a_reused_process or \
  harness_cleanup_has_no_check_then_raw_signal_or_failed_netns_wait or \
  signed_no_iso_boot_challenge_is_fresh_single_use_and_finalizes'
4 failed, 31 deselected
```

The four failures were the intended missing precise `main()` wrapper path,
absent generic pidfd cleanup, raw shell signals/wait, and unbound resealed
postflight fields.

Fourth review green:

```text
pytest tests/test_alt_install_execution_qemu.py \
  tests/test_alt_install_execution_agent.py -q
47 passed, 1 skipped

pytest --noconftest \
  tests/alt_linux/test_install_session_cli.py \
  tests/alt_linux/test_install_execution.py \
  tests/alt_linux/test_install_execution_api.py -q
56 passed, 5 skipped

pytest tests/test_alt_install_execution_iso.py -q
30 passed
```

## Specification self-review

Verdict: **PASS for the implementation contract; no QEMU execution PASS
claimed.**

- C1: the root boundary is the real production CLI/service/repository path,
  after two ordered signed, exact-identity, zero-write QMP/SHA boundary
  documents; a canonical microsecond observation time and the controller
  authorization time are persisted in signed evidence and must be
  contemporaneous within fixed 10/30/10-second ceilings. Boundary and
  observation clocks always serialize the same six-digit fractional
  precision.
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
  dedicated anonymous namespace; every QEMU/DHCP/API/namespace termination is
  pidfd-anchored and bounded after process/namespace identity checks. Cleanup
  failure is recorded without waiting on or deleting beneath a live owner.
- I5: the public, non-secret proof has an exclusive hash-linked index and a
  seventh Ed25519 seal. Its exact mandatory portable corpus is semantically
  replayed, including every delivery and authenticated postflight identity,
  without live artifact paths and remains independently verifiable after
  private work-directory cleanup.
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

## Fifth review hardening

The fifth review round removes the remaining socket-directed cleanup path.
`stop_qemu` no longer sends `qmp-command quit` to a pathname before checking
the recorded process identity. Install and postflight QEMU cleanup now use
only `stop-owned-process`: it opens the pidfd, validates the recorded
`/proc/<pid>/stat` start time after anchoring, signals through the pidfd, and
waits on that descriptor for at most five seconds. A replaced QMP socket is
therefore never a cleanup target, and a reused PID still fails closed without
being signaled.

### Fifth review TDD evidence

Baseline focused tests:

```text
pytest tests/test_alt_install_execution_qemu.py -q -k \
  "harness_cleanup_has_no_check_then_raw_signal_or_failed_netns_wait or \
  owned_process_cleanup_cannot_signal_a_reused_process"
..                                                                       [100%]
2 passed, 33 deselected in 0.32s
```

Red after adding the QMP-cleanup regression:

```text
pytest tests/test_alt_install_execution_qemu.py -q -k \
  "harness_cleanup_uses_only_identity_bound_process_termination"
F                                                                        [100%]
E       assert 'qmp-command' not in cleanup_source
1 failed, 34 deselected in 0.47s
```

Focused green after removing socket-directed cleanup:

```text
pytest tests/test_alt_install_execution_qemu.py -q -k \
  "harness_cleanup_uses_only_identity_bound_process_termination or \
  owned_process_cleanup_cannot_signal_a_reused_process"
..                                                                       [100%]
2 passed, 33 deselected in 0.34s
```

Full relevant verification:

```text
pytest tests/test_alt_install_execution_qemu.py -q
..............s....................                                      [100%]
34 passed, 1 skipped in 6.40s

pytest tests/test_alt_install_execution_agent.py -q
.............                                                            [100%]
13 passed in 3.95s

pytest tests/test_alt_install_execution_iso.py -q
..............................                                           [100%]
30 passed in 17.90s

pytest --noconftest \
  tests/alt_linux/test_install_session_cli.py \
  tests/alt_linux/test_install_execution.py \
  tests/alt_linux/test_install_execution_api.py -q
......s..................................sss................             [100%]
56 passed, 5 skipped in 11.19s
```

The skips are the existing platform-gated POSIX/root cases. Pytest emitted
only the repository's existing `pytest-asyncio` loop-scope deprecation
warning.

Static verification:

```text
python -m py_compile tests/test_alt_install_execution_qemu.py
exit 0

ruff check tests/test_alt_install_execution_qemu.py
All checks passed!

bash -n deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh
exit 0

git diff --check
exit 0
```

Prerequisite reporting on the Windows development host:

```text
bash deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh \
  --check-prerequisites
agent-v2-qemu: Missing required command: qemu-system-x86_64
agent-v2-qemu: Missing required command: qemu-img
agent-v2-qemu: Missing required command: xorriso
agent-v2-qemu: Missing required command: cpio
agent-v2-qemu: Missing required command: socat
agent-v2-qemu: Missing required command: ip
agent-v2-qemu: Missing required command: dnsmasq
agent-v2-qemu: Missing required command: unshare
agent-v2-qemu: Required Python cryptography/AF_UNIX/netns support is unavailable
agent-v2-qemu: Real root execution is required for execution authorization and TAP ownership
exit 1
```

No acceptance PASS was claimed or emitted.
