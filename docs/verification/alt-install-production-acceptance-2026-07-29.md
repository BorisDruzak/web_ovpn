# ALT install production no-write acceptance

The canonical PR5c acceptance ran on `pve2` (`10.83.1.12`) with a disposable
generic-OVMF QEMU guest bridged to `vmbr1`.  Generic OVMF is intentional: it
is the verified firmware path for the managed ISO.  VM 114 remains an optional
Proxmox-template compatibility probe and is not a release gate.

## Result

- deployed commit: `bf84ee348bd808194ddbd6637043ff4bafb76e8c`;
- rollback generation: `backup-20260729T081711Z-cc3efe6d`;
- managed ISO release: `20260729T080738Z-f86138fa820e`;
- managed ISO SHA-256:
  `363f35ee4769ad20d299662546a733d4581284b5a115e346817ff66a997515af`;
- controller: `http://192.168.100.17:18090`;
- session: `install-20260729T091627Z-3a5ad7dd`;
- agent terminal result:
  `PASS: signed plan verified; disk preflight passed; no target writes`.

The controller recorded `plan_published` and the agent's final reported stage
was `preflight_ready`.  QMP reported zero target `wr_bytes` and
`wr_operations`; the disposable target qcow2 SHA-256 was unchanged.  The QEMU
process and its bridge tap were removed after evidence capture.

The authoritative non-secret receipt is root-owned mode `0600` on the
controller at:

`/var/lib/alt-deploy/production-acceptance/receipt-20260729T091549Z-production-fixed.json`.

## Boundary

This proves only signed-plan retrieval and disk preflight.  It does not enable
Alterator, `install2.target`, partitioning, package installation, reboot, or
any target-disk write.
