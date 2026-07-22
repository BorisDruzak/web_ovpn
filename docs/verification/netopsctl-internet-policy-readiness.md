# Netopsctl Internet-policy readiness

Verified against published release `440dbcb` on 2026-07-22. This record is
sanitized and excludes device addresses, RouterOS exports, and credentials.

## Broker and audit evidence

- The deployed netopsctl migration ledger is `1..8`.
- The online backup is
  `/var/backups/netctl-correlated-control-plane/20260722T193100Z/netopsctl-before.sqlite`.
  Its SHA-256 is `0a10454decc10ba3979b9d2613ec8d15de9ab1514a6a3c06c3c75d9005e62c4b`;
  `PRAGMA integrity_check` returned `ok`.
- `netopsctl.socket`, `netopsctl.service`, and `openvpn-web.service` are
  active. A signed web-to-broker `status` smoke test returned
  `writes_enabled: false`.
- The local audit chain verified successfully with 15 signed events.
- An independently signed checkpoint for that chain was successfully delivered
  to the configured audit sink. The audit checkpoint health gate is now true.
- The broker has separate principals: the web service can use plan/read
  actions, while `netopsctl-reconcile` has only `policy.reconcile`.

## Controlled policy evidence

Two prior controlled test plans have final status `rolled_back`; the desired
policy ledger contains one policy record. The current release preserved this
evidence and did not issue a RouterOS write. The reconciler timer is installed
but deliberately disabled until a fresh controlled deny/verify/rollback window
is approved.

## Production gate

`NETOPSCTL_AUDIT_CHECKPOINT_HEALTHY` is true, while
`NETOPSCTL_PRODUCTION_WRITES_ENABLED` is false. Therefore apply, rollback, and
reconciler writes remain fail-closed. Enabling production writes still requires
the approved controlled deny/verify/rollback window in
`docs/runbooks/netopsctl-internet-policy-rollout.md`; this document does not
authorize that change.
