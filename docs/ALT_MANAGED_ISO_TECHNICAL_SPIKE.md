# ALT 11.4 managed ISO technical spike

This PR is an early-agent integration spike for exactly `ALT Workstation K 11.4`.
It is intentionally not an installation feature. The ISO validates the source
manifest, obtains DHCP, sends bounded inventory to a local fixture, creates a
fake session, and waits for administrator approval. It performs **no write I/O**
to the target disk, is designed for a **read-only** QEMU target, and does not start Alterator.

## Scope and safety boundary

The only supported source is
`/var/alt-kworkstation-11.4-install-x86_64.iso`. The inspector pins the ISO,
initrd, GRUB, Syslinux and the initrd runlevel dispatcher hashes. A mismatch
stops the build. The agent is an initrd `post/network-up` hook, which invokes
the bundled `udhcpc` client before waiting for the controller route and runs
before the next `bootchain` service. In spike
mode it never returns from that gate, whether the fixture says `waiting`,
`approved`, `cancelled`, or becomes unavailable. There is no `ai`, `curl=`,
`automatic`, disk utility, stage-2 handoff, reboot, or poweroff path in the
managed menu entry or agent.

This PR changes neither controller runtime nor `/srv/alt-deploy` or
`/var/lib/alt-deploy`. The fixture is a rootless Python process on port `18089`;
plain HTTP at this address is a test-only boundary, not a production protocol.

## Build and static verification

Run on the ALT build host with sufficient free space under `/var`:

```bash
bash deploy/alt-linux/iso/inspect-upstream-iso.sh \
  --source /var/alt-kworkstation-11.4-install-x86_64.iso \
  --manifest deploy/alt-linux/iso/manifests/alt-kworkstation-11.4-install-x86_64.json

bash deploy/alt-linux/iso/build-spike-iso.sh \
  --source /var/alt-kworkstation-11.4-install-x86_64.iso \
  --output /var/tmp/alt-kworkstation-11.4-sosnadmin-spike.iso

bash deploy/alt-linux/iso/verify-spike-iso.sh \
  --iso /var/tmp/alt-kworkstation-11.4-sosnadmin-spike.iso \
  --manifest deploy/alt-linux/iso/manifests/alt-kworkstation-11.4-install-x86_64.json
```

The builder works in a private temporary directory and writes an output ISO
only after all patches apply with `--fuzz=0`. It replays the original boot
geometry. The source ISO is never mounted writable or modified.

## Boot menus

After 60 seconds the default is `Boot from local disk`; an inserted USB must
not cause a reinstallation after reboot. Under UEFI the entry searches, in
order, ALT shim, ALT GRUB, then Windows Boot Manager. It deliberately does not
chainload the removable-media fallback `EFI/BOOT/BOOTX64.EFI`.

`Sosnadmin managed installation [SPIKE]` adds `ip=dhcp`,
`sosnadmin.mode=spike`, and the fixture controller
`http://192.168.100.17:18089`. `Normal ALT installation` remains the vendor
manual entry. Diagnostics are read-only; the spike never transitions to
Alterator after approval.

## Fixture lifecycle

In a dedicated terminal on the controller, run the test-only fixture as the
unprivileged service account:

```bash
state=/var/tmp/alt-install-spike
rm -rf -- "$state"
python3 deploy/alt-linux/install-agent/spike-server/server.py \
  --listen 192.168.100.17 --port 18089 --state "$state"
```

When the guest reaches `waiting_for_approval`, list its generated session ID
and approve or cancel it from a second terminal:

```bash
python3 deploy/alt-linux/install-agent/spike-server/ctl.py --state "$state" list
python3 deploy/alt-linux/install-agent/spike-server/ctl.py --state "$state" approve <session-id>
python3 deploy/alt-linux/install-agent/spike-server/ctl.py --state "$state" cancel <session-id>
```

Expected agent states are `waiting_for_network`, `controller_unavailable`,
`waiting_for_approval`, `spike_approved`, `spike_cancelled`, and
`spike_failed`. On all of them the early gate holds instead of starting
Alterator. Error display uses `dialog` when an interactive tty exists and a tty
fallback otherwise. `wizard.log` and Alterator error screens are not created in
the managed path because Alterator does not start; this is an explicit exit
boundary for the spike.

Stop the fixture with `Ctrl-C` before cleanup. Only then remove its disposable
state and generated ISO if desired:

```bash
rm -rf -- /var/tmp/alt-install-spike
rm -f -- /var/tmp/alt-kworkstation-11.4-sosnadmin-spike.iso
```

## Read-only QEMU acceptance

Use a disposable disk image and OVMF firmware. The harness writes evidence,
OVMF variable copy, and logs, but attaches the target with `readonly=on`.

```bash
bash deploy/alt-linux/qemu/run-spike-readonly-acceptance.sh \
  --iso /var/tmp/alt-kworkstation-11.4-sosnadmin-spike.iso \
  --ovmf-code /usr/share/OVMF/OVMF_CODE.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS.fd \
  --target /var/tmp/spike-target.img \
  --fixture-url http://192.168.100.17:18089 \
  --fixture-state /var/tmp/alt-install-spike
```

The harness uses a local VNC UNIX socket with legacy serial disabled, so OVMF
serial-terminal probing cannot stall the guest. It records the fixture's
`waiting_for_approval` and `approved` session JSON, target hashes, and QMP
`query-blockstats` before and after approval. It passes only when no
Alterator/install2/handoff marker appears, target hashes are identical, and
QMP reports zero write statistics. Its successful terminal line is
`PASS: no target-disk write I/O`.
Its user-mode QEMU network is an isolated `192.168.100.0/24` DHCP segment with
`192.168.100.17` mapped to the host, so the guest exercises the exact spike
controller URL without changing the physical network.

## Findings proved by this spike

The installer initrd is gzip/newc CPIO and starts in a Bash/SysV environment;
stage 2 later uses systemd. The managed kernel entry requests DHCP with
`ip=dhcp`, and the agent explicitly calls the bundled `udhcpc` before it
contacts the controller. The initrd contains the Bash/curl/ip/
findmnt/udevadm/blkid/sha256sum/dialog toolset needed by this agent, but not a
Python runtime. Local metadata may be placed under `/Metadata`; it is not used
by this spike. The installer USB can be identified from the `/image` mount via
`findmnt`. A future approved implementation may use these facts to hand off to
Alterator and capture `wizard.log`; that work is explicitly out of scope here.
