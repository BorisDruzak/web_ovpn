# Task 6 report: disposable generic-OVMF execution acceptance

## Result

Implemented the Task 6 acceptance harness and evidence gate without starting
QEMU, generating an ISO, deploying a controller, contacting Proxmox, or
writing any real target.

The implementation adds:

- `run-agent-v2-execution-acceptance.sh`
  - has no target, block-device, Proxmox VM, controller, or TAP input;
  - creates a 64 GiB writable qcow2 target and 8 MiB read-only qcow2
    sentinel;
  - attaches them as distinct QMP devices named `target` and `sentinel`;
  - captures both devices before authorization and after stock-installer
    completion;
  - boots installation with the verified V2 ISO, then boots the same target
    without an ISO for postflight;
  - requires root-owned mode `0600` authorization/postflight evidence;
  - creates and validates ownership of its QEMU process, DHCP process, TAP,
    copied OVMF variables, and temporary directory before cleanup.
- `agent_v2_test_api.py`
  - captures bounded `query-blockstats` plus `query-block` transcripts over
    QMP;
  - reconstructs and validates both complete reported qcow2 graphs;
  - rejects any target write before authorization, any sentinel graph write,
    a writable sentinel, a read-only target, missing target writes, unchanged
    target SHA-256, or changed sentinel SHA-256;
  - strictly validates the exact root-authorization timeline and
    authenticated no-ISO postflight schema;
  - writes one exclusive non-secret receipt and prints the PASS line only
    after every gate succeeds.
- `tests/test_alt_install_execution_qemu.py`
  - exercises the verifier through its CLI with real JSON/SHA files;
  - mutation-tests the write, topology, hash, timeline, and authentication
    gates;
  - executes the shell prerequisite, safety-description, argument-rejection,
    disposable-storage, and cleanup interfaces.
- `docs/verification/alt-install-execution-v2-qemu.md`
  - documents the generic-OVMF-only scope, exact schemas, execution sequence,
    ownership boundary, receipt, invocation, and distinction between contract
    tests and an actual accepted QEMU run.

## TDD evidence

The first required focused run was executed after adding the tests and before
either production file existed:

```text
pytest tests/test_alt_install_execution_qemu.py -q
17 failed, 1 error
```

The setup error and all failures were the expected missing
`agent_v2_test_api.py` and
`run-agent-v2-execution-acceptance.sh` interfaces.

The first verifier slice then passed:

```text
pytest tests/test_alt_install_execution_qemu.py -q -k 'evidence or receipt'
11 passed, 7 deselected
```

Final focused verification:

```text
pytest tests/test_alt_install_execution_qemu.py -q
18 passed
```

Pytest emitted only the repository's existing `pytest-asyncio` default-loop-
scope deprecation warning.

Static verification:

```text
bash -n deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh
exit 0

python -m py_compile \
  deploy/alt-linux/qemu/agent_v2_test_api.py \
  tests/test_alt_install_execution_qemu.py
exit 0

ruff check \
  deploy/alt-linux/qemu/agent_v2_test_api.py \
  tests/test_alt_install_execution_qemu.py
All checks passed!

git diff --check
exit 0
```

## Host prerequisite evidence

The required command was run on this Windows development host:

```text
deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh --check-prerequisites

Missing required command: qemu-system-x86_64
Missing required command: qemu-img
Missing required command: xorriso
Missing required command: cpio
Missing required command: socat
Missing required command: ip
Missing required command: dnsmasq
Required Python cryptography/AF_UNIX support is unavailable
Real root execution is required for execution authorization and TAP ownership
exit 1
```

The check enumerated all observed missing prerequisites and printed neither
the prerequisites-available line nor the execution PASS line.

## Specification self-review

Verdict: **PASS for the acceptance contract; no execution acceptance
claimed.**

- The only disk eligible for writes is a harness-created qcow2 exposed as
  `/dev/vda`.
- The sentinel is independently attached `readonly=on`, independently
  identified in QMP, graph-checked at both snapshots, and hash-checked.
- Zero writes are required before the root-authorization timeline; positive
  target writes are required after installer completion.
- The timeline binds operator UID `0`, `/dev/vda`, the canonical session ID,
  and strictly ordered waiting, preflight, authorization, claim, verified
  handoff, installer, and authenticated-postflight events.
- The postflight must be authenticated, `installed`, and identified as
  `target-without-iso`.
- The receipt contains no credential, password/hash, Bearer value, private
  key, or private material.
- VM 114, caller targets, Proxmox and controller deployment are outside the
  CLI and outside the evidence schema.
- The host gate failed honestly; no PASS receipt was produced.

## Quality and safety self-review

Verdict: **PASS**

- Tests assert behavior at CLI/filesystem boundaries rather than grepping
  implementation text.
- QMP evidence is bounded, duplicate-device evidence is rejected, mandatory
  counters and parent/backing topology are required, and every write counter
  is type/range checked.
- JSON parsing rejects duplicate keys and exact-schema mutations.
- Receipt creation is exclusive and refuses overwrite.
- The shell contract test proves both disposable images are created only
  below one private temporary directory and that validated cleanup removes
  it.
- Runtime cleanup targets only the recorded process IDs, an `aiv2<digits>`
  TAP that exists, and the validated `.alt-agent-v2-qemu-work.*` directory.
- Caller evidence and firmware/ISO inputs are never deleted.

## Remaining acceptance work

An actual accepted run still requires a dedicated Linux/root host with the
listed QEMU, OVMF, TAP/DHCP, ISO verification, and AF_UNIX prerequisites; a
previously built and verified V2 ISO; and the local root-only acceptance
controller integration that emits the documented serial milestones and
root-owned timeline/postflight documents. None of those external
preconditions exists on this host, so this task makes no claim that ALT was
installed in QEMU.
