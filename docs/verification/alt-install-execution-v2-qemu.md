# ALT V2 disposable OVMF execution acceptance

This is the destructive-execution acceptance gate for the V2 managed ISO.
It is intentionally limited to a harness-created generic-OVMF guest. It has
no option for an existing disk, block device, Proxmox VM, controller
deployment, or VM 114.

## Safety boundary

The harness creates:

- one 64 GiB writable qcow2 target, exposed to the guest as `/dev/vda`;
- one 8 MiB qcow2 sentinel, attached with `readonly=on`;
- one copied OVMF variable store;
- one process-local QEMU instance at a time;
- one uniquely named TAP and its `dnsmasq` process;
- one private temporary directory.

Cleanup validates the harness prefixes before removing its QEMU process, DHCP
process, TAP, or temporary directory. Caller-supplied ISO, OVMF firmware,
timeline, postflight report, and evidence root are never removed.

The installation boot includes the verified V2 ISO. The postflight boot
starts the same target and sentinel without any ISO drive. The harness does
not generate or publish an ISO and does not deploy a controller.

## Required external inputs

The ISO must already have passed
`deploy/alt-linux/iso/agent-v2/verify-managed-iso.sh`. The root-only local
acceptance controller must write two regular, root-owned mode `0600` files:

1. an ordered authorization timeline after the real
   `authorize-execution` operation for exactly `/dev/vda`;
2. an authenticated postflight result from the no-ISO target boot.

The timeline has this exact schema:

```json
{
  "schema_version": 1,
  "session_id": "install-YYYYMMDDThhmmssZ-1234abcd",
  "target_disk": "/dev/vda",
  "operator_uid": 0,
  "waiting_for_authorization_at": "UTC ISO timestamp",
  "preflight_ready_at": "UTC ISO timestamp",
  "root_authorized_at": "UTC ISO timestamp",
  "execution_claimed_at": "UTC ISO timestamp",
  "verified_handoff_at": "UTC ISO timestamp",
  "installer_completed_at": "UTC ISO timestamp",
  "postflight_authenticated_at": "UTC ISO timestamp"
}
```

Every timestamp must be strictly later than the preceding one. The postflight
document has the exact keys `schema_version`, `session_id`, `authenticated`,
`boot_source`, `state`, and `reported_at`; accepted values are
`authenticated=true`, `boot_source=target-without-iso`, and
`state=installed`.

The local acceptance integration must emit these serial milestones only after
the corresponding real conditions:

```text
terminal=execution_pending
ALT install execution: verified_handoff
ALT install execution: installer_completed
```

The first line is captured before execution authorization. The latter two
mean the signed bundle and repeated disk preflight completed, the relay was
ready, handoff was durably recorded, and the stock installer completed.

## Running

First inspect the host without creating anything:

```bash
deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh \
  --check-prerequisites
```

The check enumerates every missing command, Python capability, and real-root
requirement. It prints no PASS line when anything is absent.

On a dedicated Linux acceptance host:

```bash
sudo deploy/alt-linux/qemu/run-agent-v2-execution-acceptance.sh \
  --iso /acceptance/alt-kworkstation-11.4-agent-v2.iso \
  --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  --timeline /run/alt-v2-acceptance/authorization-timeline.json \
  --postflight /run/alt-v2-acceptance/postflight.json \
  --evidence-dir /var/lib/alt-v2-acceptance
```

Do not use a workstation with an existing `192.168.100.17/24` test network.
The command deliberately has no caller-supplied target or TAP argument.

## Receipt and acceptance rule

`agent_v2_test_api.py finalize-evidence` parses both QMP block graphs, not
console summaries. Acceptance requires:

- target and sentinel counters are zero before authorization;
- the target is writable and has positive QMP `wr_bytes` after installation;
- the target qcow2 SHA-256 changes;
- the sentinel is QMP-confirmed read-only at both captures;
- every sentinel graph counter stays zero and its SHA-256 is unchanged;
- the timeline is exact, root-authorized, and strictly ordered;
- postflight is authenticated, reports `installed`, and comes from the
  target-only boot.

The non-secret receipt contains only the session ID, target path, timestamps,
selected QMP write bytes, read-only flags, before/after SHA-256 values, and
postflight result. It contains no Bearer credential, password/hash, signing
private key, or TLS private key.

The only successful terminal line is:

```text
PASS: root-authorized install wrote only the disposable target; authenticated postflight installed
```

Contract tests do not constitute this acceptance. Save the receipt and PASS
line only from a completed Linux/OVMF run.

## Current host result

The Windows development host cannot run the acceptance. Its prerequisite
check reports the absent QEMU/ISO tooling and the real-root/TAP requirement.
No ISO was generated, no QEMU guest was started, no controller was deployed,
and no execution PASS is claimed here.
