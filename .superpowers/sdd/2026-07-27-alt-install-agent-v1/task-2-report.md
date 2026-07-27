# Task 2 Report: PR4a Go Helper and Shared Vectors

## Status

Implemented Task 2 only in the isolated worktree
`C:\Users\admin-2\Documents\ui_vpn\.worktrees\alt-install-agent-pr4a`.
No initrd agent shell, ISO build, deployment, controller protocol, or remote
host work was performed.

The helper provides the three stable commands from the binding design:

- `inventory --output <path>`
- `verify-plan --plan <path> --signature <path> --public-key <path> --inventory <path> --session <id>`
- `disk-preflight --plan <path> --inventory <path>`

The implementation uses the Go standard library only. The deterministic build
sets `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`,
`-trimpath`, `-buildvcs=false`, and an empty build ID.

## Commits

- `b03ccd3` — `feat: add ALT install helper`
- A follow-up documentation commit contains this report; its hash is recorded
  in the task handoff because a commit cannot contain its own final hash.

## Files

### Helper module and command

- `deploy/alt-linux/install-agent/helper/go.mod`
- `deploy/alt-linux/install-agent/helper/go.sum`
- `deploy/alt-linux/install-agent/helper/Makefile`
- `deploy/alt-linux/install-agent/helper/cmd/alt-install-helper/main.go`
- `deploy/alt-linux/install-agent/helper/errors.go`
- `deploy/alt-linux/install-agent/helper/canonical.go`
- `deploy/alt-linux/install-agent/helper/inventory.go`
- `deploy/alt-linux/install-agent/helper/plan.go`
- `deploy/alt-linux/install-agent/helper/verify.go`
- `deploy/alt-linux/install-agent/helper/preflight.go`
- `deploy/alt-linux/install-agent/helper/collector.go`
- `deploy/alt-linux/install-agent/helper/command.go`

### Go tests and shared vectors

- `deploy/alt-linux/install-agent/helper/golden_test.go`
- `deploy/alt-linux/install-agent/helper/verify_test.go`
- `deploy/alt-linux/install-agent/helper/preflight_test.go`
- `deploy/alt-linux/install-agent/helper/collector_test.go`
- `deploy/alt-linux/install-agent/helper/command_test.go`
- `deploy/alt-linux/install-agent/helper/internal_test_helpers_test.go`
- `deploy/alt-linux/install-agent/helper/testdata/v1/golden.json`

### Python parity and CI

- `tests/alt_linux/test_install_helper_vectors.py`
- `.github/workflows/alt-install-helper.yml`

## Implemented Contract

### Strict parsing and canonical bytes

- Rejects duplicate object keys at every nesting level.
- Rejects unknown contract fields.
- Rejects non-integer JSON numbers and out-of-range integers.
- Rejects invalid raw UTF-8, trailing JSON data, excessive nesting, strings,
  arrays, objects, and documents.
- Produces Python-compatible `ensure_ascii=True`, sorted-key, compact canonical
  JSON, including U+007F and surrogate-pair escaping.
- Requires downloaded `plan.json` bytes to equal the canonical plan bytes
  exactly; whitespace, a newline, or reordered keys fail closed.

### Source ISO and signature verification

- Reads the source ISO identity from
  `/usr/share/alt-install/source_iso.json`.
- Keeps `agent.iso_sha256` bound to the upstream source ISO identity.
- Binds the signed plan to source ISO ID/hash, canonical inventory SHA-256,
  session ID, disk identity, UEFI state, and exactly one routed NIC.
- Strictly validates Ed25519 public-key and signature metadata.
- Recomputes the public key ID and plan SHA-256.
- Verifies the exact canonical plan bytes with Ed25519.
- Rejects expired plans.

### Inventory and disk preflight

- Collects DMI, firmware, memory, source/build identity, interfaces, route,
  disks, filesystem signatures, and `/image` boot media through a read-only
  probe surface using fixed `lsblk` and `ip` queries.
- Records the top-level block-device ancestor for partitioned boot media, so
  `/dev/sdb1` mounted at `/image` excludes physical `/dev/sdb`.
- Recollects inventory for `disk-preflight`.
- Re-evaluates the exact checked-in PR3 `standard-office` V1 eligibility
  boundary: physical disk, no boot-media disk, no removable physical disk,
  minimum 53,687,091,200 bytes, and exactly one eligible disk.
- Compares selected path, size, model, serial, WWN, and canonical fingerprint.
- Compares boot-media identity, UEFI state, and routed NIC name/MAC.
- Accepts missing serial and WWN for dry-run fixtures and returns
  `weak_disk_identity: true`.
- `DiskPreflight` is a pure byte/in-memory comparison and has no filesystem or
  block-device writer. The command test snapshots all input/target sentinel
  files before and after preflight.

### Command boundary

- Success emits one JSON object on stdout, bounded to 4096 bytes.
- Failure emits only `ALT_INSTALL_ERROR <stable_code>` on stderr and leaves
  stdout empty.
- Input paths must be bounded regular files.
- Inventory output rejects non-regular existing targets and uses a mode-0600
  temporary sibling, sync, close, and rename.

## TDD Evidence

### Baseline

The repository POSIX `conftest.py` intentionally skips this suite on Windows.
The same `--noconftest` mode already used by repository CI was therefore used
for local focused tests.

Command:

```text
python -m pytest --noconftest tests/alt_linux/test_install_inventory.py tests/alt_linux/test_install_plan.py tests/alt_linux/test_install_session_signing.py -q
```

Result:

```text
18 passed in 0.22s
```

### Initial RED

Tests and shared golden vectors were written before production helper code.

Command, from `deploy/alt-linux/install-agent/helper`:

```text
go test ./...
```

Result: exit 1, expected feature-missing build failure:

```text
collector_test.go:73:14: undefined: collectSystemInventory
command_test.go:26:10: undefined: runCommand
command_test.go:26:108: undefined: commandDependencies
command_test.go:52:10: undefined: runCommand
command_test.go:59:23: undefined: commandDependencies
command_test.go:79:10: undefined: runCommand
command_test.go:81:23: undefined: commandDependencies
FAIL .../helper [build failed]
```

### First GREEN

After the minimal strict parser, typed contracts, collector, verifier,
preflight, and command implementation:

```text
go test ./...
?    .../cmd/alt-install-helper    [no test files]
ok   .../helper                    0.040s
```

### Canonical U+007F regression RED/GREEN

An explicit comparison with Python `json.dumps(..., ensure_ascii=True)` found
that Python escapes U+007F while the first Go encoder left it raw.

RED:

```text
go test ./... -run TestCanonicalInventoryEscapesPythonASCIIUpperBoundary -count=1
--- FAIL: TestCanonicalInventoryEscapesPythonASCIIUpperBoundary
canonical inventory did not use Python ensure_ascii escaping: ...QEMU\x7fHARDDISK...
```

The encoder boundary changed from `> 0x7f` to `>= 0x7f`.

GREEN:

```text
go test ./... -run TestCanonicalInventoryEscapesPythonASCIIUpperBoundary -count=1
ok   .../helper  0.017s
```

### Independent review RED/GREEN

An independent read-only review identified partitioned boot-media ancestry,
minimum-size parity, removable-disk parity, and CI input filters.

RED command:

```text
go test ./... -run 'TestInventoryDisksUsesBootMediaTopLevelAncestor|TestDiskPreflightIgnoresExtraDiskBelowPR3MinimumSize|TestDiskPreflightRejectsAnyRemovablePhysicalDiskLikePR3Policy' -count=1
```

RED result:

```text
boot media identity = {Path:/dev/sdb1 ...}, want top-level /dev/sdb ancestor
preflight_disk_ambiguous: exactly one eligible disk is required
expected preflight_disk_removable, got nil
FAIL
```

After the three focused fixes:

```text
ok   .../helper  0.027s
```

The focused re-review returned `ADDRESSED` with no remaining Critical or
Important findings.

## Final Verification

Toolchain:

```text
go version go1.22.12 windows/amd64
```

Uncached Go tests:

```text
go test ./... -count=1
?    .../cmd/alt-install-helper    [no test files]
ok   .../helper                    0.055s
```

Static analysis:

```text
go vet ./...
```

Result: exit 0, no output.

Standard-library-only module check:

```text
go list -m all
github.com/BorisDruzak/ui_vpn/deploy/alt-linux/install-agent/helper
```

Focused Python PR2/PR3 plus shared-vector tests:

```text
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest --noconftest \
  tests/alt_linux/test_install_inventory.py \
  tests/alt_linux/test_install_plan.py \
  tests/alt_linux/test_install_session_signing.py \
  tests/alt_linux/test_install_helper_vectors.py -q
.................... [100%]
20 passed in 0.23s
```

Workflow parse:

```text
workflow parsed: helper job present
```

Two independent Linux/amd64 builds:

```text
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false -ldflags=-buildid= ...

build_a_sha256=80d99620732b9c1296fa83c8188667615fb6c48592ff1a43d3d5150731f9dc8e
build_b_sha256=80d99620732b9c1296fa83c8188667615fb6c48592ff1a43d3d5150731f9dc8e
```

Embedded Go build settings:

```text
go1.22.12
-buildmode=exe
-compiler=gc
-trimpath=true
CGO_ENABLED=0
GOARCH=amd64
GOOS=linux
```

Staged diff validation before the implementation commit:

```text
git diff --cached --check
```

Result: exit 0, no whitespace errors.

## Risks and Follow-up Boundaries

- PR4b must embed `source_iso.json` at
  `/usr/share/alt-install/source_iso.json`, a managed build ID at
  `/usr/share/alt-install/build-id`, and the trusted public-key document.
- PR4b must ensure the initrd contains compatible `lsblk` and `ip` commands,
  mounts the install medium at `/image`, and supplies
  `sosnadmin.controller=<URL>` on the kernel command line.
- Helper V1 intentionally supports only the checked-in `standard-office`
  profile version 1 for disk preflight. A new profile or minimum disk policy
  requires an explicit helper update and new shared vectors.
- Serial-and-WWN-less disks remain weak identity and are accepted only for the
  specified dry-run boundary. No destructive stage is authorized by this work.
- The new GitHub Actions workflow was parsed locally but has not yet run on a
  GitHub-hosted Ubuntu runner in this worktree.
- Go's race detector requires CGO and was therefore not used for this required
  `CGO_ENABLED=0` helper. The pure unit/command suite and deterministic static
  cross-build completed successfully.
