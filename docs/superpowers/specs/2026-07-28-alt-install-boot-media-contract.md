# ALT install-agent V1: boot-media identity contract

## Decision

The initrd agent must not require `/image` to be mounted. ALT 11.4 invokes the
`network-up` hook before that mount exists, so `/proc/self/mountinfo` contains
no `/image` entry even though the managed ISO has booted correctly.

The managed ISO will embed a separate `managed_iso_size_bytes` runtime asset.
It is computed from the final managed ISO by the builder, not copied from the
upstream source contract. The source ISO ID and SHA-256 remain the immutable
source-identity binding for plan verification.

Boot-media discovery is ordered and fail-closed:

1. When `/image` is mounted, retain the physical-top-level ancestor rule.
2. When `/image` is absent, select exactly one removable top-level `type=rom`
   whose byte size exactly equals `managed_iso_size_bytes`.
3. Zero or multiple matches return a stable discovery error before session
   creation or approval.

The fallback does not broaden target eligibility: ROM devices are never
installation candidates, and it does not trust a model string or `/dev` name.

## Contract changes

`source_iso.json` remains the three-field source identity used by signed-plan
verification. A new payload-hashed `managed_iso_size_bytes` file carries the
positive byte size of the final managed ISO. The builder produces it by a
bounded fixed-point build: create a staged ISO directly from the upstream
source, inject its measured size into the initrd, create the final ISO directly
from the same source, and require the final ISO size to equal that value.

```json
{"schema_version":1,"iso_id":"alt-kworkstation-11.4-install-x86_64","iso_sha256":"…"}
```

Changing source identity invalidates plan verification; changing the managed
media-size asset invalidates the ISO payload hash. No target-device write is
added.

## Implementation boundaries

* Preserve read-only sysfs and `blkid` collection.
* Pass the read and validated managed-media size into boot-media selection.
* Reject fallback candidates of type `disk`, `loop`, `ram`, `dm` or `zram`.
* Continue exact boot-media comparison during disk preflight.
* Treat optional `serial`/`wwid` `ENOENT` and `ENXIO` as absent; keep every
  other identity-read error fail-closed.

## Required tests and evidence

1. The managed-media size asset rejects missing, zero, fractional, negative,
   oversized and non-canonical values.
2. Unit tests retain `/image` selection, select one matching ROM without it,
   and reject zero/multiple matches or same-sized non-ROM devices.
3. Golden Python/Go vectors preserve the existing three-field source identity.
4. Builder/verifier assert the payload-hashed managed-media-size fixed point.
5. Writable and read-only ALT QEMU variants reach the unique PASS line and
   prove zero target writes through QMP and qcow2 hashes.

## Production gate

PR5 deployment remains blocked until this matrix is green and evidence is
reviewed. The change does not alter the controller, production network, VM
disks or installation flow.
