# ALT install execution V2 design

## Purpose

This design adds the first deliberate target-disk-write path to the managed
ALT KWorkstation 11.4 installation system.  It preserves the deployed V1
signed-plan preflight as a no-write operation and introduces a separate V2
execution path.  V2 may be exercised on disposable QEMU targets only until a
separate pilot approval identifies a real workstation.

The old static autoinstall deployment is not the execution mechanism.  It was
validated for ALT 11.2, selects the first available disk, uses a fixed
unauthenticated HTTP directory, and contains model-specific NIC assumptions.
It remains a legacy recovery artefact until retirement, but a managed ISO must
never fetch `/metadata/` from it.

## Facts established against the exact 11.4 source ISO

The exact source ISO contains `installer-common-base-stage2-1.16.34-alt1`.
Its `install2.target` invokes `cp-metadata`; when `ai curl=<base-url>` is on
the kernel command line it fetches fixed names by unauthenticated HTTP GET:

```text
<base-url>/autoinstall.scm
<base-url>/vm-profile.scm
```

Other installer stages can fetch `pkg-groups.tar` and
`install-scripts.tar`.  `cp-metadata` has no Bearer-header support.  Therefore
placing a session credential in the controller URL, query string, or legacy
directory would disclose a credential and would not bind metadata to the
signed plan.  V2 instead uses a local loopback relay after the agent has
authenticated and verified every artefact.

## Chosen architecture

```text
V2 execution menu (install2.target, ai curl=127.0.0.1)
        |
        v
initrd agent: inventory -> signed-plan verification -> disk preflight
        |
        +-- wait for distinct root execution approval
        |
        v
TLS controller API (separate V2 listener)
  signed execution manifest + four session-bound artefacts
        |
        v
agent re-verifies plan and disk, then starts a 127.0.0.1 metadata relay
        |
        v
stock ALT install2 / Alterator consumes only the cached loopback artefacts
        |
        v
first-boot postflight agent -> TLS controller evidence -> pilot gate
```

The new managed-ISO menu entry is opt-in, not the default entry.  The existing
V1 preflight entry remains visibly labelled **DRY RUN** and still has no code
path that starts `install2.target`.

## Transport and secrets

V2 uses `https://192.168.100.17:18092`; V1 remains unchanged on the deployed
HTTP `:18090` endpoint.  The V2 ISO embeds only the controller CA certificate,
the controller public plan-verification key and an HTTPS URL with an IP SAN
match.  It contains no server private key, account password hash, session
credential, or execution bundle.

The V2 listener must require normal certificate verification.  It must reject
HTTP, certificate-name mismatch, TLS downgrade, redirect, proxy environment,
and response bodies above the declared endpoint limit.  A session credential
is created and subsequently used only over TLS.  This is server-authenticated
TLS rather than mTLS: the random Bearer credential is the client capability,
and TLS protects its issue and use.

The rendered execution bundle may contain yescrypt hashes.  It is therefore
not written to Git, the release manifest, status JSON, audit receipt, shell
arguments, or service logs.  On the controller it is a regular `0600` file in
the session's `0700` private directory; only root and the dedicated
install-session service account can read it.  The service only streams a
named artefact to an authenticated V2 session over TLS with
`Cache-Control: no-store`.

## Execution authorization and state

Plan approval and execution approval are intentionally different root actions.
The existing approval creates an immutable signed `InstallPlanV1` and remains
valid for the V1 dry run.  It cannot cause disk writes.

After an agent reports `preflight_ready`, root runs a new
`workstationctl install-sessions authorize-execution` command.  It requires:

- session ID;
- the exact immutable plan SHA-256;
- the inventory SHA-256 and disk fingerprint already in that plan;
- a 1--256 character operator reason; and
- a one-time `--confirm-target <exact /dev path>` acknowledgement.

The command re-loads the session and signed plan, refuses expired, cancelled,
already-used, or non-preflight-ready sessions, renders the bundle from the
validated plan plus a root-only typed secret object, and creates a signed
`ExecutionManifestV1`.  The manifest binds the session ID, plan digest,
inventory digest, disk fingerprint, target path, profile/version, ISO identity,
the SHA-256 and byte length of all four artefacts, authorization time, and a
five-minute expiry.  It has no password hash or credential.

The status document gains an optional `execution` object while preserving all
V1 fields and semantics.  Its only valid transitions are:

```text
not_authorized -> authorized -> claimed -> handoff_started
not_authorized|authorized|claimed -> cancelled|expired
handoff_started -> installer_started -> installed|failed
```

Each transition records an RFC3339 UTC timestamp and is append-only.  A
cancelled, expired, used, or failed authorization cannot be reused or replaced
by a second authorization.  A controller restart must retain these facts.
The V1 endpoint never exposes the execution object or bundle unless the
request arrives on the V2 TLS listener with the session capability.

## Artefact and relay contract

The controller publishes exactly these immutable files for one execution
revision:

```text
autoinstall.scm
vm-profile.scm
pkg-groups.tar
install-scripts.tar
```

`autoinstall.scm` and `vm-profile.scm` are rendered only from the validated
plan and the typed root secret object.  `pkg-groups.tar` is extracted from the
exact ISO named in the plan and verified against a release-held SHA-256.
`install-scripts.tar` is a versioned, deterministic archive that installs the
postflight service and CA material; arbitrary shell supplied by a request is
not accepted.  Every filename, content length and digest is checked before
the manifest is signed.

The initrd helper gets two new commands:

```text
download-execution-bundle --manifest ... --destination ...
verify-execution-bundle --manifest ... --plan ... --inventory ...
serve-execution-metadata --directory ... --port 18192 --deadline ...
```

The Bash agent performs a fresh `verify-plan` and `disk-preflight` immediately
after bundle verification and immediately before starting the relay.  It
refuses any changed disk, route NIC, boot medium, plan digest, expiry, missing
file, wrong length, wrong hash, unexpected filename, or non-regular artefact.

The relay binds only `127.0.0.1:18192`, accepts only `GET` and `HEAD` for the
four exact paths, rejects query strings, traversal, redirects and every other
request, returns fixed content lengths and `Cache-Control: no-store`, and
never logs body bytes.  It stops after all required files have been served or
on the authorization deadline.  The execution menu contains the fixed kernel
argument:

```text
ai curl=http://127.0.0.1:18192
```

The agent starts the relay and returns from the initrd hook only after the
controller records `handoff_started`; that allows the stock
`systemd.unit=install2.target` boot flow to continue.  Any failure before that
return enters an infinite no-write terminal hold.  There is no claim of
rollback after the first partition-table write: cancellation and expiry are
guaranteed only before handoff.

## Installer and postflight scope

The V2 generated Scheme must configure only the signed target path, exactly
one eligible internal disk, UEFI, the approved Btrfs layout and the route NIC
from the plan.  The acceptance suite must demonstrate that the installer does
not write to a second sentinel disk.  No arbitrary Alterator method, raw disk
command, package command, hostname or Scheme fragment is accepted from the
API or the operator.

The versioned `install-scripts.tar` installs a one-shot postflight service in
the newly installed system.  It uses the embedded controller CA to report the
session ID, plan digest, installed-system boot ID, target-disk identity and
bounded installer-result digest to the V2 TLS API.  It has no privilege to
request a new execution authorization.  The controller records
`installed` only after that authenticated report passes schema and binding
checks.  Existing unauthenticated `:8087` bootstrap and `:8088` registration
are not completion evidence for V2.

## Delivery sequence

1. **PR6a -- V2 TLS and authorization domain.** Add settings, root-owned TLS
   material installer, execution state, root command, signed manifest and
   API tests.  It makes no ISO change and cannot start an installer.
2. **PR6b -- V2 artefacts, initrd relay and managed ISO.** Add the fixed
   bundle builder, static helper commands, the opt-in execution boot entry and
   ISO verifier.  Unit and integration tests prove every rejection path; the
   QEMU target is read-only for all pre-handoff cases.
3. **PR6c -- disposable write acceptance and postflight.** Run the exact
   managed ISO in generic OVMF QEMU with a writable disposable target and a
   separate read-only sentinel disk.  Evidence must show the root
   authorization, manifest verification, bounded write operations on the
   selected target only, installed system boot, and authenticated postflight.
4. **PR6d -- production rollout and pilot gate.** Backup-gate deployment,
   publish a fresh immutable V2 ISO, repeat PR6c against the production TLS
   listener, and write a non-secret receipt.  The command must refuse a real
   workstation until a separate pilot record names its asset identity, disk
   fingerprint, approved ISO release, rollback owner and maintenance window.

No PR automatically enables the execution menu as a default, connects the
old static metadata endpoint, or selects a real workstation target.

## Acceptance requirements

- Existing V1 tests and production no-write acceptance remain green.
- TLS tests cover trusted CA success and wrong CA, expired certificate, plain
  HTTP, redirect and oversized-response rejection.
- Authorization tests cover plan/inventory/fingerprint/path mismatch,
  duplicate authorization, cancellation, expiry, concurrent claim, and a
  non-root caller.
- Bundle tests cover a valid deterministic bundle and every missing, extra,
  symbolic-link, wrong-size, wrong-digest and malformed-manifest case without
  leaking secret content.
- Relay tests cover exact paths, method/path/query rejection, loopback-only
  binding, expiry and no body logging.
- QEMU pre-handoff tests prove zero writes to both target and sentinel disks.
- QEMU execution acceptance proves writes occur only after the distinct root
  authorization, only on the selected disposable target, then reaches a
  postflight `installed` report.  QMP counters and before/after hashes are the
  authoritative disk evidence.
- The production receipt records commit, backup ID, ISO and key IDs, manifest
  digest, controller unit status, QEMU evidence paths and target/sentinel
  counters; it contains no credentials, hashes or bundle bytes.

## Explicit non-goals

- automatic deployment to a real workstation or a default destructive boot;
- rollback of an already repartitioned disk;
- reuse, modification or publication of legacy `/metadata` for V2;
- a web UI that can issue execution authorization;
- password, private-key, certificate-private-key or bundle persistence in the
  repository, ISO release manifest or rollout receipt.
