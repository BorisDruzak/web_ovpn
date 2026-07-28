# ALT install-agent V1: boot-media identity contract

## Decision

The initrd agent must not require `/image` to be mounted. ALT 11.4 invokes the
`network-up` hook before that mount exists, so `/proc/self/mountinfo` contains
no `/image` entry even though the managed ISO has booted correctly.

The managed ISO will embed an immutable `source_size_bytes` alongside its
existing source ISO ID and SHA-256. The value comes from the pinned upstream
source contract, not from a guest measurement.

Boot-media discovery is ordered and fail-closed:

1. When `/image` is mounted, retain the physical-top-level ancestor rule.
2. When `/image` is absent, select exactly one removable top-level `type=rom`
   whose byte size exactly equals `source_size_bytes`.
3. Zero or multiple matches return a stable discovery error before session
   creation or approval.

The fallback does not broaden target eligibility: ROM devices are never
installation candidates, and it does not trust a model string or `/dev` name.

## Contract changes

`source_iso.json` gains required positive integer `source_size_bytes`. Strict
Go parsing, Python vectors, the builder and the verifier use the same document:

```json
{"schema_version":1,"iso_id":"alt-kworkstation-11.4-install-x86_64","iso_sha256":"…","source_size_bytes":10710822912}
```

Changing any field invalidates exact source-identity verification. No target
device write is added.

## Implementation boundaries

* Preserve read-only sysfs and `blkid` collection.
* Pass parsed source size into boot-media selection.
* Reject fallback candidates of type `disk`, `loop`, `ram`, `dm` or `zram`.
* Continue exact boot-media comparison during disk preflight.
* Treat optional `serial`/`wwid` `ENOENT` and `ENXIO` as absent; keep every
  other identity-read error fail-closed.

## Required tests and evidence

1. Source identity rejects missing, zero, fractional, negative and unknown size.
2. Unit tests retain `/image` selection, select one matching ROM without it,
   and reject zero/multiple matches or same-sized non-ROM devices.
3. Golden Python/Go vectors and plan verification cover the four-field source
   identity.
4. Builder/verifier assert the embedded identity includes source size.
5. Writable and read-only ALT QEMU variants reach the unique PASS line and
   prove zero target writes through QMP and qcow2 hashes.

## Production gate

PR5 deployment remains blocked until this matrix is green and evidence is
reviewed. The change does not alter the controller, production network, VM
disks or installation flow.
