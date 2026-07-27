# ALT Install Plan PR2 — design

## Purpose and boundary

PR2 implements a pure controller-side domain layer for a managed ALT
KWorkstation 11.4 installation.  It accepts only synthetic, sanitised input and
produces deterministic installation artefacts.  It does not start Alterator,
serve a production HTTP API, communicate with an installed VM, modify an ISO,
or perform disk I/O.

The required pipeline is:

```text
validated InstallInventory V1
  + standard-office policy V1
  + explicit operator selection
  -> immutable InstallPlan V1
  -> autoinstall.scm, vm-profile.scm, sha256sums
```

The controller, not an agent, adds the peer source IP in a later transport
layer.  `source_ip` is therefore not an accepted inventory field in PR2.

## Modules and ownership

New production modules live in `deploy/alt-linux/control/alt_deploy/`:

| Module | Responsibility |
| --- | --- |
| `install_inventory.py` | Parse, strictly validate, canonically serialise, and hash `InstallInventoryV1`. |
| `install_policy.py` | Load `standard-office-v1`, validate machine/ISO/network constraints, and compute eligible disks and route-capable NICs. |
| `install_fingerprint.py` | Build the versioned SHA-256 disk fingerprint from canonical disk identity fields. |
| `install_plan.py` | Combine validated inventory, policy, and operator selection into a new immutable plan revision. |
| `install_renderer.py` | Render a validated plan plus controller-side secrets into three deterministic output files. |

Policy JSON belongs in `deploy/alt-linux/autoinstall/profiles/`; templates in
`deploy/alt-linux/autoinstall/templates/`; sanitised golden material in
`deploy/alt-linux/autoinstall/snapshots/`.  JSON is used rather than YAML so
the controller has no PyYAML runtime dependency.

No module takes Scheme fragments, shell, Alterator method names, package
commands, raw disk commands, or arbitrary template variables as input.

## InstallInventory V1

The inventory top-level object has exactly these fields:

```json
{
  "schema_version": 1,
  "agent": {},
  "machine": {},
  "interfaces": [],
  "disks": [],
  "boot_media": {}
}
```

`agent` carries bounded strings for version, boot ID, build ID, ISO ID and ISO
SHA-256.  `machine` carries DMI UUID, manufacturer, product name, serial
number, firmware, memory bytes and CPU architecture.  Interfaces identify a
name, MAC, addresses and whether the interface has the route to the
controller.  Disks identify type, path, removability, size, model, serial,
WWN and bounded filesystem signatures.  `boot_media` identifies the install
medium using the same bounded identity vocabulary needed to exclude it.

The validator rejects unknown fields at every object depth.  It bounds strings
and integers, accepts at most 16 interfaces and disks, at most 16 addresses
per interface, and at most 16 filesystem signatures per disk.  It canonicalises
JSON with stable key ordering and compact separators before calculating the
inventory SHA-256.

## Standard-office policy V1

`standard-office-v1.json` is a versioned data-only profile.  It requires:

- ALT KWorkstation 11.4 with the exact expected ISO ID and SHA-256;
- UEFI firmware and `x86_64` architecture;
- DHCP networking;
- exactly one eligible internal disk;
- whole-disk wipe, no encryption, RAID, or LVM;
- Btrfs with `@` mounted at `/` and `@home` at `/home`;
- a fixed 4 GiB swap, a 40 GiB Btrfs minimum, and a 50 GiB physical-disk
  minimum; all remaining eligible space grows Btrfs;
- the exact package set `standard-office-v1`.

The 50 GiB minimum is intentional: a 32 GiB disk returns `disk_too_small`.
Changing that figure needs a separate acceptance matrix and is not part of
this PR.

An eligible disk is `type=disk`, non-removable, not boot media, at least the
policy minimum, and neither loop, ram, nor zram.  Its device path must pass a
strict safe-device-path check.  Zero eligible disks returns `disk_missing`;
more than one returns `disk_ambiguous`.  The operator never supplies an
arbitrary `/dev/sdX` path.

Exactly one interface must be marked route-capable.  Absence returns
`network_missing`; multiple such interfaces return `network_ambiguous`.

## Fingerprint and immutable plan

The disk fingerprint is `sha256:` plus a SHA-256 digest of a canonical JSON
object containing only `path`, `size_bytes`, `model`, `serial`, and `wwn`.
Missing serial or WWN is represented as JSON `null`, never an omitted or
empty-string field.

`InstallPlanV1` contains a schema version, session ID, monotonic revision,
inventory SHA-256, profile ID and version, ISO identity, firmware, selected
disk fingerprint, selected NIC name/MAC, fixed layout, package set, temporary
hostname, approval timestamp, and expiry timestamp.  The plan is a value
object: after construction it has no mutation API.  Any changed inventory,
policy, ISO value, disk, NIC, or approval yields a newly constructed plan and
new revision.

The digest is deliberately external to the plan: output is `plan.json` and
`plan.sha256`.  PR2 implements no cryptographic signing, session persistence,
or key lifecycle.

## Deterministic renderer

The renderer accepts only a validated `InstallPlanV1` and a typed
controller-side secret object.  It emits:

- `autoinstall.scm`;
- `vm-profile.scm`;
- `sha256sums`.

For byte-identical plan and secret inputs, all three files are byte-identical.
Ordering, whitespace, encodings, final newlines and checksum order are fixed.
Secrets (including active password hashes) are never placed in inventory,
policy, plan, fixtures, snapshots, logs, or plan digests.

## Tests and acceptance

Tests reside in `tests/alt_linux/` with synthetic fixtures in
`tests/alt_linux/fixtures/install/`.  Required successful cases cover 50,
100, and 200 GiB disks, varied NIC names, absent serial, absent WWN, and
repeat byte-identical rendering.

Required rejected cases cover a 32 GiB disk, BIOS, incorrect ISO ID or hash,
no or multiple eligible disks, boot-media and removable disk selection, zero
or multiple route-capable NICs, unknown profile or profile version, unsafe
device path, oversized inventory, and unknown inventory fields.  Golden
snapshots contain no real hash, token, secret, or personally identifying
metadata.

The PR is complete when the domain tests and the repository regression pass,
and none of its code introduces network listeners, disk-writing commands, ISO
changes, or Alterator execution.
