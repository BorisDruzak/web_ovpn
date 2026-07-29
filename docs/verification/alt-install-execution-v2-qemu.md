# ALT V2 disposable OVMF execution acceptance

This is the destructive-execution acceptance gate for the V2 managed ISO.
It is limited to a harness-created generic-OVMF guest. It has no option for
an existing disk, block device, Proxmox VM, controller deployment, or VM 114.

## Safety and trust boundary

The harness creates one 64 GiB writable qcow2 target exposed as `/dev/vda`,
one 8 MiB read-only qcow2 sentinel, a copied OVMF variable store, a unique
TAP, and a private work directory. The first boot includes the verified V2
ISO; the postflight boot has no ISO drive.

At run creation, the harness creates:

- an unpredictable 256-bit run ID and 256-bit challenge;
- a per-run Ed25519 key pair;
- the QEMU UUID;
- canonical ISO, target, and sentinel paths;
- SHA-256 and device/inode/size identities for all three artifacts.

Every QMP transcript must contain the exact request IDs and exact
`query-block` `inserted.file` paths. SHA records must name those same
canonical files and retain their device/inode creation identity.

Cleanup records the work-directory device/inode and TAP name/ifindex
immediately after creation. It removes the TAP and directory only if those
identities still match. A replacement is preserved for investigation.

## Authorization sequence

The harness does not accept timeline, authorization, session, target, or
postflight files from its caller.

1. The guest reaches its pre-authorization hold.
2. QMP and SHA evidence are captured with every target and sentinel write
   counter at zero.
3. `create-authorization-request` reads the one local controller session in
   `plan_published`/`preflight_ready`, hashes its immutable `plan.json`, and
   writes the exact `/dev/vda` request under the private run state.
4. A second immediate QMP and SHA capture must still show zero writes and
   unchanged files.
5. As real root, the support program calls the production
   `alt_deploy.cli.main` `authorize-execution` command with the exact derived
   plan, inventory, disk fingerprint, session, and `/dev/vda` values.
6. The returned execution ID and `authorized` state are checked against the
   authoritative repository and signed as attestation 1.
7. The authenticated V2 TLS service records the single-use
   `claimed -> handoff_started -> installer_started` transitions. Their
   persisted timestamps are signed as attestations 2 through 4.

Console milestones are only liveness cues. They cannot authorize execution
or satisfy the receipt.

## Authenticated target-only postflight

The held `install-scripts.tar` installs a one-shot first-boot service and the
public execution CA into the target. The postflight QEMU process exposes a
virtio serial port named `alt.install.postflight`.

After QEMU is running, the harness queries QMP `query-status`, `query-uuid`,
and `query-block`. The response IDs must be exact, the UUID must match this
run, target and sentinel files must match, and no ISO/removable medium may be
inserted. Only then does the harness generate a fresh nonce and sign
attestation 5. It sends that delivery document over the live virtio port.

The newly booted installed system adds its kernel boot ID and UTC timestamp,
then posts the exact document to the real TLS
`/execution/postflight` endpoint. The server verifies the per-run Ed25519
chain and consumes the nonce once before making the real
`installer_started -> installed` transition. Replays, stale prior-run
documents, wrong UUIDs, wrong challenges, and pre-existing files fail
closed. The final repository state and authenticated boot identity become
attestation 6.

## Running

Inspect the host without creating resources:

```bash
deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh \
  --check-prerequisites
```

On a dedicated Linux acceptance host with a locally prepared V2 install
session and controller settings:

```bash
sudo deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh \
  --iso /acceptance/alt-kworkstation-11.4-agent-v2.iso \
  --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  --controller-credential-key /run/alt-deploy/execution-credential.key \
  --evidence-dir /var/lib/alt-v2-acceptance
```

Do not use a host with an existing `192.168.100.17/24` test network. The
command deliberately has no caller-supplied target, TAP, session,
authorization request, timeline, or postflight result.

## Receipt rule

`finalize-evidence` accepts only the six-entry signed run chain. It also
rechecks the initial, immediate-before-authorization, after-install, and
target-only boot QMP transcripts plus all bound SHA records.

PASS requires zero target and sentinel writes through authorization,
positive target writes after installation, zero sentinel writes at every
graph level, a changed target SHA, an unchanged sentinel SHA, and the
authenticated no-ISO `installed` transition for the same run, VM, session,
controller execution, boot nonce, and boot ID.

The only successful terminal line is:

```text
PASS: root-authorized install wrote only the disposable target; authenticated postflight installed
```

Contract tests do not constitute this acceptance. The Windows development
host cannot provide KVM/QEMU, Linux root/TAP, or AF_UNIX prerequisites. No
ISO was generated, no guest was started, no controller was deployed, and no
execution PASS is claimed by the implementation tests.
