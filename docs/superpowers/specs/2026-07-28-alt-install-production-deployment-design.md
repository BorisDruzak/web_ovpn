# ALT Install Production Deployment Design

## Status and goal

This design turns the verified PR4 dry-run agent into a controlled production
*release path*, while retaining its no-write installer boundary.  A successful
rollout publishes a signed managed ISO and makes a narrowly scoped
install-session API available to that ISO.  It does not enable Alterator,
`install2.target`, partitioning, an automatic installation, reboot, or any
target-disk write.

The design is intentionally split into PR5a, PR5b and PR5c.  Each PR has a
separate acceptance gate and can be rolled back independently.

## Current facts

- The controller is `192.168.100.17` (`altserver`).  Existing
  `alt-deploy-*` services are active.
- TCP `18089` is occupied by a disposable PR1 spike fixture and must never be
  repurposed as a production endpoint.
- The controller has insufficient durable capacity for the fixed-point managed
  ISO build.  Proxmox node `pve2` (`10.83.1.12`) has the exact source ISO in
  its `local` ISO storage and sufficient free capacity.
- Proxmox VM `114` is the disposable acceptance VM.  It is not a production
  workstation target.
- PR3's API factory and PR4's agent are verified but are deliberately not yet
  deployed services.

## Chosen architecture

```text
operator/root approval
        |
        v
controller 192.168.100.17:18090
  alt-install-session.service (altserver)
        | reads published session state
        | root-only workstationctl signs plans
        v
root-owned Ed25519 private key          public-key JSON
        |                                      |
        +---------------+----------------------+
                        v
             pve2 release builder (10.83.1.12)
                        |
                        v
         atomic Proxmox local:iso publication
                        |
                        v
           VM 114 UEFI dry-run acceptance
```

The controller is the sole holder of private signing material.  The Proxmox
builder receives only a validated public-key JSON snapshot and never receives
the private key, a session credential, a plan, or controller state.

## PR5a — controller install-session service and signing key

### Network and process boundary

`alt-install-session.service` binds `192.168.100.17:18090` only.  The port is
not shared with the test fixture.  The service runs as `altserver:altserver`
and executes a dedicated production entry point which calls
`create_install_session_server(Settings.from_env(), ...)`.

The unit must use `NoNewPrivileges=true`, `PrivateTmp=true`,
`PrivateDevices=true`, `ProtectSystem=strict`, `ProtectHome=read-only`,
`RestrictAddressFamilies=AF_INET AF_INET6`, `CapabilityBoundingSet=`, and a
minimal `ReadWritePaths` allowlist for the install-session state and lock.
The unit must not read the private signing key.

The listener accepts only the existing API's allowed source range and retains
its bounded request parsing, Bearer credential checks, session state machine,
and `Cache-Control: no-store` responses.  A new `/health` endpoint returns a
constant non-secret JSON result without opening or mutating a session.

### Key lifecycle

The installer creates `/var/lib/alt-deploy-secrets` as `root:root`, mode
`0700`.  It creates a PKCS#8 Ed25519 private key exactly once at
`install-plan-ed25519.pem`, regular file, `root:root`, `0600`.  Its public key
JSON is derived deterministically at `/etc/alt-deploy/install-plan-ed25519.pub`,
regular file, `root:root`, `0644`.

An existing key pair is validated through no-follow descriptors and retained
only when it has the required metadata and matching key ID.  The installer
must fail closed on a mismatch or unsafe ownership/mode; it must never rotate
or overwrite a key implicitly.  Rotation is a separately approved operation.

Root uses `workstationctl install-sessions approve` to read the private key
and publish an immutable plan.  The API service reads only session state and
the public key path is used only by release tooling.

### PR5a acceptance

The test suite covers the production entry point, loopback health endpoint,
source-address rejection, service unit hardening, key creation metadata,
idempotent existing-key validation, mismatch refusal, and a real root approval
against a disposable state directory.  A controller rollout runs backup
preflight before installing files, verifies `systemd-analyze security`, starts
the service, and checks `http://192.168.100.17:18090/health`.

Rollback stops and disables only `alt-install-session.service`, restores the
previous staged runtime, and preserves signing keys and immutable sessions.

## PR5b — Proxmox managed ISO release builder

### Input contract

The release command accepts exactly:

- an immutable Git commit already merged to `main`;
- the exact source ISO already stored as
  `local:iso/alt-kworkstation-11.4-install-x86_64.iso` on `pve2`;
- a controller public-key JSON snapshot fetched by a read-only command;
- `http://192.168.100.17:18090` as the managed ISO controller URL; and
- a release ID in `YYYYMMDDTHHMMSSZ-<short-commit>` form.

It checks the source manifest and public-key JSON before building.  The builder
clones or exports only the named commit into a private work directory on pve2,
builds the static helper with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, and uses
the existing fixed-point ISO builder and verifier.

The private key, install session files, credentials, and plans are prohibited
from the build host and its logs.  The controller URL is an explicit build
parameter rather than a hard-coded fixture address.

### Publication contract

The output name is
`alt-kworkstation-11.4-agent-v1-<release-id>.iso`; its sidecar manifest is
named `<ISO>.build-manifest.json`.  Files are staged privately on pve2, fully
verified, then atomically renamed into Proxmox `local:iso`.  A release index
contains release ID, Git commit, source ISO SHA-256, managed ISO SHA-256,
helper SHA-256, public key ID, and creation time.  It contains no secret.

No existing release name may be overwritten.  Pruning is a separate explicit
command and is outside this design.

### PR5b acceptance

Static tests reject unsafe release IDs, controller URLs, output paths, public
key metadata, mismatching sidecars, non-atomic replacement, and secret-like
paths.  The remote acceptance gate builds one disposable release on pve2 and
verifies its embedded controller URL is `:18090` and its public key ID matches
the controller's public key.  Attaching the ISO to VM 114 is deferred to the
separate PR5c production-listener acceptance gate.

## PR5c — backup-gated rollout and rollback

PR5c provides a root-only operator command that performs the following in
order:

1. verifies a supplied, successful `alt-deploy-backup` generation;
2. verifies no active provisioning jobs or install sessions exist;
3. stages PR5a runtime from the named merged commit without replacing a live
   runtime in place;
4. installs and health-checks `alt-install-session.service` on `:18090`;
5. invokes PR5b with the exact merged commit and records its release index;
6. runs VM 114's UEFI signed-plan dry-run acceptance against the production
   listener; and
7. records a non-secret rollout receipt containing commit, backup ID, release
   ID, key ID, ISO SHA-256, unit status, and QEMU evidence path.

Any failed gate stops before the next mutation.  Rollback restores the staged
controller runtime and stops the new service.  It does not restore session
state over a newer state and it does not delete an ISO release automatically.

## Explicit non-goals

- target-disk write, partitioning, Alterator, `install2.target`, reboot, or
  first-boot automation;
- HTTPS/mTLS, which requires a separately managed trust and certificate
  lifecycle;
- private-key replication to Proxmox or any workstation;
- replacement of the `:18089` spike fixture;
- release pruning, ISO garbage collection, or changing Proxmox storage;
- changing existing `alt-deploy-http`, registration, or processing services.

## Completion evidence

The deployment chain is complete only when all three PRs are merged with green
CI, the controller's health endpoint and unit hardening pass, the signing key
metadata is correct without exposing secret bytes, the named ISO is verified
in `pve2` storage, and VM 114 emits the signed-plan dry-run PASS line with
QMP and backing-image evidence of zero target writes.
