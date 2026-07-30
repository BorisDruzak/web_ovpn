# ALT V2 bootstrap and production-key QEMU acceptance design

## Purpose

The V2 UEFI menu entry must be able to start from an empty initrd and reach a
root-authorized installation only on the harness-created disposable target.
The existing V2 entry incorrectly assumed that V1 session state already
existed.  It cannot do so: the V2 boot is a fresh initrd and V1's entry is not
run for `sosnadmin.mode=agent-v2`.

The same correction makes the real-QEMU acceptance executable without copying
the controller's plan-signing or TLS private keys to Proxmox.

## Boundaries

- The production plan-signing key and execution TLS private key remain on
  `192.168.100.17` only.  They are never copied to Proxmox, the ISO, evidence,
  Git, command output, or a shell environment.
- Proxmox provides the managed and upstream ISO only by a temporary,
  read-only, root-owned transport.  The transport is removed after acceptance.
- The acceptance target remains a harness-created 64 GiB qcow2.  No existing
  block device, Proxmox VM, or workstation disk is accepted as input.
- The V1 and V2 API instances used by the acceptance are bound only inside the
  harness-owned network namespace at `192.168.100.17:18090` and `:18092`.
  They cannot conflict with the controller's host-network units.
- A disposable acceptance session is the only session the harness may approve.
  It must match its generated QEMU identity and `/dev/vda`; all other sessions
  fail closed.  The V1 plan approval and V2 execution authorization are
  distinct root actions and evidence events.

## V2 bootstrap

V2 reuses the V1 preflight implementation rather than duplicating protocol or
cryptographic code.  The V1 entrypoint gains a library-only mode already
present in the current code; the V2 agent sources that entrypoint and then its
own V2 functions.  A new V1 configuration helper accepts only
`sosnadmin.mode=agent-v2`, reads the embedded V1 controller URL
`http://192.168.100.17:18090`, and deliberately ignores the V2 kernel
controller argument for V1 traffic.  V2's own config independently validates
the pinned HTTPS execution endpoint.

The V2 lifecycle is:

1. validate both pinned controller configurations and initialise private
   state;
2. obtain DHCP and verify the route;
3. generate inventory and a one-time create nonce;
4. create exactly one V1 session, report bounded V1 heartbeats, await a
   signed plan, download it, verify it, and perform V1 disk preflight;
5. report `preflight_ready`, then request the V2 execution bundle;
6. preserve the existing V2 bundle verification, claim, repeated preflight,
   relay, handoff, installer-started, and postflight flow.

No V2 path uses caller-supplied session IDs, credentials, plans, disk paths,
or controller URLs.  A bootstrap error remains a terminal non-install state.

## Controller-side QEMU orchestration

The acceptance harness starts both controller APIs inside its owned network
namespace.  Before the first QEMU boot it records the existing session set.
After the guest creates exactly one new awaiting-approval session, it obtains
the authoritative inventory digest and disk fingerprint from the repository,
requires the generated VM identity and target path `/dev/vda`, and invokes the
real root plan-approval CLI with a fixed acceptance reason.  It records a
signed plan-approval attestation.

Only after this preflight completes and the guest reaches
`terminal=execution_pending` may the existing root execution-authorization
sequence run.  The harness retains its two QMP zero-write boundaries before
execution authorization, its pidfd/namespace identity cleanup, target-only
postflight, and sealed public evidence package.

The harness runs on the controller host so the real controller-owned keys and
release archives are local.  Its ISO paths may be a temporary read-only mount
from Proxmox.  Evidence and qcow2 files are local controller-owned files; the
runner refuses unsafe, writable remote input paths and insufficient local free
space before boot.

## Tests and acceptance evidence

- Unit tests prove V2 runs the full V1 preflight sequence before requesting a
  V2 bundle, pins V1 and V2 endpoints separately, and terminal-holds on every
  failed bootstrap stage.
- Harness tests prove the V1 API starts before QEMU, exactly one newly created
  session is root-approved, existing/ambiguous sessions are rejected, and no
  V2 authorization is attempted before plan approval and both zero-write
  boundaries.
- A real controller-host run uses the exact verified V2 ISO and canonical
  source ISO, emits the existing unique PASS line, and exports the sealed
  public evidence package.  The package must contain the plan-approval and
  execution-attestation chain without private material.

## Rejected alternatives

Copying a production private key or controller state to Proxmox is rejected:
it violates the deployment boundary and makes a builder compromise a signing
compromise.  Fabricating a local controller key is rejected because the ISO
pins the production public key and the result would not validate the release.
Skipping V1 session creation or injecting a credential into the boot command
is rejected because it cannot work from a clean boot and would expose a bearer
credential.
