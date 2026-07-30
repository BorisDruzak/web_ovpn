# ALT install execution V2 real-machine pilot record template

This is a validation-only record. Completing or validating it does not
authorize execution, access a disk, boot an ISO, or start installation.
V1 remains no-write at `192.168.100.17:18090`; the approved V2 ISO must name
only the TLS controller `192.168.100.17:18092`.

Copy the JSON below to a new, separately controlled evidence file and replace
every example value with the exact approved value. Do not add approval,
credential, authorization, command, or execution fields.

```json
{
  "schema_version": 1,
  "asset_id": "ALT-WS-017",
  "dmi_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "disk": {
    "fingerprint": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "path": "/dev/disk/by-id/ata-EXACT-PILOT-DISK-ID"
  },
  "iso_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  "maintenance_window": {
    "starts_at": "2026-08-01T06:00:00Z",
    "ends_at": "2026-08-01T07:00:00Z"
  },
  "rollback_owner": "Named accountable operator"
}
```

Required comparison evidence:

- asset ID and DMI UUID read from the approved workstation inventory;
- exact disk fingerprint and exact `/dev/...` path from the approved
  preflight, without opening that path in the validator;
- exact immutable V2 ISO digest from the published sidecar;
- bounded UTC maintenance start and end; and
- a named rollback owner who understands that there is no automatic
  post-write disk rollback.

Validate only:

```bash
python3 deploy/alt-linux/release/verify-install-execution-pilot.py \
  --record "$PILOT_RECORD" \
  --expected-iso-sha256 "$MANAGED_ISO_SHA256"
```

Success reports `"validation_only":true`. It does not authorize execution;
root authorization and any real disk access remain separate controlled
operations.
