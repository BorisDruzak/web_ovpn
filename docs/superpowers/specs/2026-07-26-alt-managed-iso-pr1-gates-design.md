# ALT Managed ISO PR1 Gates Design

## Goal

Prove that the ALT 11.4 early-agent spike reaches DHCP, inventory submission,
fixture-session creation and administrator approval without transferring control
to the vendor installer or issuing write I/O to the test disk.

## Scope

This design resolves only the three gates that precede PR1 implementation:

1. a precise, fail-closed initrd handoff hook;
2. a safe UEFI default path to an installed local operating system;
3. an empirical no-write-I/O acceptance run.

It does not start Alterator, `alterator-autoinstall`, `install2.target`,
partitioning, formatting, rebooting or power-off.

## Gate 1: Exact initrd handoff

The exact ALT Workstation K 11.4 initrd handoff is
`etc/rc.d/rc.sysexec`. Its final operation is:

```bash
exec runas /sbin/init /bin/environ -cf /.initrd/kernenv \
  /sbin/sysexec "$rootmnt" "$INIT" "$@"
```

The ISO builder shall patch this file exactly once, immediately before that
`exec`. The patch shall run the early agent only when
`sosnadmin.mode=spike` is an exact kernel-command-line token. It shall then
enter a non-returning hold loop. It shall never execute the original `exec` in
spike mode, including after network, protocol or approval errors.

Normal boot has no `sosnadmin.mode=spike` token and follows the unmodified
vendor path. The build shall abort unless the source ISO, `boot/initrd.img`,
`etc/rc.d/rc.sysexec`, and the one expected anchor all match pinned hashes.

## Gate 2: UEFI local-disk boot

The managed UEFI GRUB menu shall default, after five seconds, to a local-disk
entry. The entry shall search only for installed-system EFI loader paths in
this priority order:

```text
/EFI/altlinux/shimx64.efi
/EFI/altlinux/grubx64.efi
/EFI/Microsoft/Boot/bootmgfw.efi
```

It shall chainload the first matching path and return to the menu with a clear
message when none is found. It shall not search for
`/EFI/BOOT/BOOTX64.EFI`, because the installation ISO itself contains that
fallback path and could be selected recursively.

The current ALT 11.4 UEFI test VM proves the first two candidate paths exist:

```text
/boot/efi/EFI/altlinux/shimx64.efi
/boot/efi/EFI/altlinux/grubx64.efi
```

The managed entry shall retain the vendor installation command line and add
only `ip=dhcp`, `sosnadmin.mode=spike`, the fixed spike controller URL, and a
build identifier. It shall not contain `ai`, `curl=`, or `automatic`.

Legacy BIOS is out of scope for managed installation in PR1. Its default shall
remain the existing hard-drive entry; normal ALT installation remains manual.

## Gate 3: No-write-I/O acceptance

Acceptance shall run on a disposable UEFI QEMU VM, not on an installed test
workstation. The ISO is attached as read-only CD-ROM. The synthetic target
disk is attached read-only at the QEMU block layer. The VM must have DHCP
reachability to the temporary spike fixture.

Before boot, the test records the target backing-file SHA-256 and QEMU block
statistics. During and after boot it records the serial console and final QEMU
block statistics. The gate passes only when all of these are true:

- the guest reports the target block device as read-only;
- no QEMU write operation or write byte counter is present for that disk;
- the backing-file SHA-256 is unchanged;
- the serial console proves successful DHCP, inventory, fixture-session
  creation, `waiting_for_approval`, and `spike_approved`;
- the serial console contains neither the handoff marker after the agent gate
  nor an installer start;
- the agent remains in a non-returning hold after approval.

The test fails on any attempted write, stage-2 handoff, installer launch,
reboot, power-off, missing approval state or backing-file hash change.

## Safety Boundaries

- The early agent is Bash-only and uses only initrd-proven tools.
- The spike fixture is a foreground, rootless process on port 18089 and stores
  state outside production controller paths.
- The fixture approval changes only the local spike screen. It never permits
  installation.
- HTTP is allowed only on the isolated spike test network and carries no
  credentials or production authorization.
- Static source tests must reject dangerous commands in the managed agent
  path, but they complement rather than replace the QEMU read-only acceptance
  run.
