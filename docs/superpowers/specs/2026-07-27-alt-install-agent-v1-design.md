# ALT install-agent V1 and dry-run preflight design

## Goal

Deliver a signed-plan, initrd-resident agent that can reach `READY FOR
INSTALLATION — DRY RUN` without starting Alterator, `install2.target`, a
reboot, partitioning, or any target-disk write. A later PR deploys the already
tested controller endpoint to `.17`; it does not authorize an installation.

## Delivery boundaries

### PR4a: protocol and helper

PR4a adds a statically linked amd64 Go helper and controller protocol changes.
It has three stable commands:

* `inventory --output <path>` writes the exact canonical `InstallInventoryV1`.
* `verify-plan --plan <path> --signature <path> --public-key <path> --inventory
  <path> --session <id>` validates strict JSON, exact canonical plan bytes,
  signature metadata, Ed25519 signature, expiry, source ISO identity and plan
  bindings.
* `disk-preflight --plan <path> --inventory <path>` recollects inventory and
  fails closed unless the selected disk, boot media, UEFI state and routed NIC
  are unchanged and still unambiguous.

The helper uses only Go's standard library, `CGO_ENABLED=0`, Go 1.22.x pinned
in CI, `-trimpath -buildvcs=false`, and a committed `go.mod`/`go.sum`. It emits
one bounded JSON object on stdout and stable error codes on stderr; it never
writes a block device.

`source_iso.json` is embedded in the managed ISO and names the verified upstream
ALT 11.4 ISO identity used by PR3 policy. `agent.iso_sha256` remains that source
ISO hash, never the hash of the repacked managed ISO. The managed ISO has its
own build ID and SHA-256 manifest for build provenance.

The create request receives `create_nonce`: a 32-byte URL-safe random value
generated once in `/run`. The server stores its SHA-256 with the session and
returns the same session/credential to an identical nonce plus canonical
inventory hash; a mismatch fails closed. A session becomes inactive when it is
cancelled or expires. Awaiting approval expires after 30 minutes and a
published session expires at its signed plan expiry. This prevents reboot/test
loops from exhausting the 5-session DMI quota.

The versioned agent heartbeat vocabulary is exactly:
`agent_started`, `inventory_validated`, `waiting_for_approval`,
`plan_downloaded`, and `preflight_ready`. Unknown values are rejected.

### PR4b: agent, ISO and acceptance

PR4b embeds the helper, source-ISO manifest and public key JSON in a new initrd
overlay. Bash is a network/UI orchestrator only. It creates `/run/alt-install`
with mode `0700`; every child file is created through a temporary sibling and
renamed with mode `0600`. It never writes credentials, plan data, response
bodies or headers to logs.

The agent does DHCP, verifies a route, generates inventory and a create nonce,
then performs idempotent create. It retries transport failures with bounded
exponential backoff, never retries a semantically rejected request, follows no
redirects, and sets explicit connect/total timeouts and response size limits.
It polls status, downloads exact plan/signature bytes after `plan_published`,
runs `verify-plan` and `disk-preflight`, reports `preflight_ready`, displays the
dry-run ready state, and holds forever.

HTTP without TLS is an explicit PR4 limitation. A network attacker can cause
availability loss or steal a Bearer credential, but cannot forge a plan because
the ISO embeds the trusted Ed25519 public key. There is no destructive handoff
in PR4. HTTPS/mTLS is required before any future installation-capable release.

QEMU acceptance runs two disposable variants: a writable qcow2 target proves
the agent itself made no writes through QMP counters and backing-file SHA-256;
a readonly target is an independent guard. Both require valid signature,
matching source ISO identity, one eligible disk and route NIC, then the exact
final line `PASS: signed plan verified; disk preflight passed; no target writes`.

### PR5: controller deployment

Only after PR4a/PR4b CI and manual QEMU acceptance are green, PR5 installs a
dedicated non-root API service on `.17`, creates the production signing key
outside git, installs public key/profile/session permissions, binds only the
approved controller address, and performs read-only health checks plus rollback
instructions. It does not launch an installer or mutate a workstation disk.

## Strict parsing and disk identity

Go parsing rejects unknown fields, duplicate object keys, non-integer numbers,
invalid UTF-8, oversized strings/arrays, and non-canonical plan bytes. Shared
golden fixtures assert Python's canonical bytes, SHA-256 and disk fingerprint
match Go exactly.

The preflight compares plan path, size, model, serial, WWN and fingerprint,
rejects removable and boot-media disks, re-evaluates exactly-one eligibility,
and compares routed NIC name/MAC and UEFI firmware. Missing serial and WWN are
accepted for the dry-run compatibility fixtures but are recorded as weak
identity; no future destructive stage may accept weak identity without a
separate policy decision.

## Verification gates

* Go unit tests and Python golden-vector tests for every helper command.
* API tests for nonce replay/mismatch, expiry and every heartbeat stage.
* Agent contract tests for private `/run` state, no credential logging, retries,
  redirect refusal and all terminal errors.
* ISO payload verification and QEMU writable/readonly zero-write acceptance.
* CI installs Go and runs Go tests, focused Python tests and static shell/ISO
  contract checks.
* Before PR5, a separate human-approved deployment runbook validates `.17`
  service ownership, firewall binding, key modes and rollback without exposing
  a private key.
