# netopsctl Internet-policy rollout

This runbook enables the bounded `WEBOVPN-INTERNET-DENY` control plane. It
does not authorize arbitrary RouterOS changes.

## Preconditions

1. Confirm the web service uses trusted HTTPS and scoped `network:*` bearer
   credentials. Keep the legacy API token out of these endpoints.
2. Confirm the socket is owned by `netopsctl:netopsctl`, mode `0660`, and
   that its two allow-listed peer UIDs are separate: `openvpn-web` for web
   plan actions and `netopsctl-reconcile` for `policy.reconcile` only.
3. Confirm the web signing key, RouterOS password reference, audit signing
   key and audit-sink SSH identity are readable only by their service users.
   Do not put key material in the repository or environment JSON.
4. Back up `/var/lib/netopsctl/netopsctl.sqlite` and the netctl SQLite
   database using SQLite's online backup API. Record checksums and run
   `PRAGMA integrity_check` on each copy.
5. Verify the independent audit checkpoint receiver accepts a fresh signed
   checkpoint. Until it is healthy, leave production writes disabled.
6. Verify exactly one RouterOS firewall anchor has the fixed comment
   `web_ovpn:internet-policy-anchor:v1`, `forward/drop`,
   `WEBOVPN-INTERNET-DENY`, WAN egress and logging disabled.
7. Set and record bounded runtime values: `NETOPSCTL_PLAN_TTL_SECONDS` is at
   most 900 (normally 300), and
   `NETOPSCTL_IDENTITY_OBSERVATION_MAX_AGE_SECONDS` is at most 900.
8. Before enabling the timer, provision a distinct reconcile signing key and
   configure its public key under the `netopsctl-reconcile` UID with only
   `policy.reconcile`; do not reuse the web signing key.

## Dry run and controlled test

1. Start `netopsctl.socket`; keep production writes disabled. Confirm a
   signed `status` request works and unknown actions, peer UIDs and replayed
   nonces fail.
2. Create a deny plan only for an approved disposable test asset. Use the
   `/api/v1/network-changes/plans` endpoint with an `Idempotency-Key` and the
   smallest required scoped credential.
3. Inspect the plan. Review its stable asset key, exact IPv4 targets,
   enforcement source, ownership comments and rollback steps.
4. Approve, enable writes for the single controlled test window, apply and
   verify. Confirm Internet traffic is denied while required internal access
   remains reachable.
5. Roll back, verify Internet restoration and verify that no managed address
   list entry remains for the test asset.
6. Disable writes again unless all production gates below are satisfied.

## Production enablement gates

- The audit checkpoint is independently healthy and continuously verified.
- Apply revalidates the plan basis immediately before every RouterOS write;
  stale identity, changed anchor, ambiguous attachment, duplicate or changed
  IP observations and expired plans must require a newly approved plan.
- A device-scoped mutex prevents concurrent apply or rollback operations.
- The five-minute `netopsctl-reconcile.timer` is enabled only after the
  controlled rollback succeeds. It may reconcile fresh active policies but
  never create policy, and adds a newly confirmed deny entry before removing
  the superseded address.
- The rollback path removes only the exact policy-and-asset ownership marker.

## Rollback

1. Disable `netopsctl-reconcile.timer` and production writes.
2. Roll back each affected plan through the signed endpoint; do not delete
   RouterOS entries by address alone.
3. Stop the web service and broker only if application rollback is required.
   Restore verified SQLite backups atomically, verify integrity and restart
   the socket, broker and web service.
4. Check the audit chain and external checkpoint before declaring the
   incident closed.
