# Recovery after a first join without an AD computer

This operator-only procedure handles a closed full-Setup UNKNOWN whose original
assignment was local and whose failed phase was the first domain join. Fresh
state must have an AD authentication scheme but no AD computer, keytab or machine
secret. Existing computers use [GUID recovery](../ALT_RECOVERY_OPERATOR.md).
Neither path replays an old job. There is no web recovery button.

## Preconditions and rollout

Read the original job, run, configuration result and complete event stream.
Keep their bytes and both legacy reservations. The controller independently
checks UUID, IP, hostname, pinned SSH identity, employee GUID/SID, OU, profiles,
absence of any matching computer/SPN, trust, process/package health, clock,
services, native executable hashes and authentication files. Incomplete LDAP
reads and unsupported native layouts deny recovery.

Install the matching native backup tool first using
`deploy/alt-linux/install-backup-tool.sh`. Stage the exact published source in a
new root-managed release directory. The old installed CLI cannot parse the new
option: use trusted staged `alt_deploy.cli` under the normal service identity and
configured environment:

```sh
python3 -m alt_deploy.cli --json setup jobs maintenance-plan --all-closed
python3 -m alt_deploy.cli --json setup jobs maintenance-confirm PLAN_ID --confirm-sha256 SHA256
```

Present actual SHA, expiration and closed-job scope for confirmation first.
Schema 2 covers the exact unreviewed closed full-Setup jobs and their leases.
Running or unsupported failures deny maintenance. Its six-hour receipt grants
only controller maintenance, with no Setup, local-recovery or queue permission.
Create, verify and rehearse a fresh controller backup with
`alt-deploy-backup COMMAND [BACKUP_ID] --maintenance-review SHA256`. Use the normal
guarded installer with the actual backup ID and review SHA; keep all checks enabled.

Rehearse the exact helper on a disposable disconnected ALT clone with matching
native hashes. Remove all NICs before first boot and verify fresh VM identity.
Use loopback SSH, pinned keys and throwaway fixture credentials. Prove fresh
administrator/password and ansible/key access with sudo before and after the
transition; test uncertain completion without retrying its claim. Retain private
evidence before deleting only the verified disposable clone.
Root-managed `/srv/alt-deploy/metadata/partial-local-rehearsal.json` must contain actual
passing helper/native fingerprints. Missing or stale evidence denies planning
and apply. Synthetic pytest results alone cannot produce this record.

## One local transition

```sh
workstationctl --json setup recovery partial-local plan ORIGINAL_JOB_ID
workstationctl --json setup recovery partial-local apply PLAN_ID --confirm-sha256 SHA256
workstationctl --json setup recovery partial-local status PLAN_ID
```

Present actual machine, scope, private backup manifest, SHA and expiration;
obtain confirmation of that exact plan. Plans last 30 minutes. Replace an expired
unentered plan only after fresh checks. Once the original failure's claim is
entered, a new plan cannot retry it.

The fixed target protocol verifies a private root-only authentication snapshot,
records intent and invokes only `/usr/sbin/system-auth write local` once, without
`--gpo`. Three PAM links and local passwd/group/shadow NSS sources may change.
Other authentication configuration, accounts, credentials, inactive services and
tools must remain unchanged. No AD object operation, join, package operation or
automatic rollback is performed. The controller independently rereads the target
backup/result and makes a fresh pinned SSH/sudo observation with complete AD
absence. Protected backup history includes plans, capsules, claims and results;
restore cannot erase an entered claim.

## Failure and lost replies

After timeout, disconnect or restart, use `status PLAN_ID`. Never apply again to
discover whether a mutation happened. Missing or uncertain terminal evidence
remains `unknown_requires_review`; target writes stop. Ordinary jobs, legacy
configure, readiness and maintenance/backup remain blocked. Preserve original IDs.
Do not delete claims, edit receipts/revisions or restore older history to bypass it.

| Code | Meaning / action |
| --- | --- |
| `setup_partial_local_unresolved` | Entered attempt lacks verified successful receipt; inspect original status. |
| `setup_partial_local_runtime_unverified` | Source, rehearsal, target evidence or fresh state differs; investigate. |
| `setup_partial_local_invalid` | Protected plan/history/claim differs; retain original evidence. |

Safe first-join stage/effect diagnostics expose bounded codes, never raw native
output or credentials. Missing historical diagnostics do not prove the original
exception and cannot authorize replay.

## Separate ordinary Setup successor

After successful local recovery and fresh verification:

```sh
workstationctl --json setup recovery partial-local continue-plan RECOVERY_PLAN_ID
workstationctl --json setup apply NEW_SETUP_PLAN_ID --confirm-sha256 NEW_SHA256 --detach
workstationctl --json setup jobs status NEW_JOB_ID
workstationctl --json setup verify MACHINE_UUID
```

Confirm new Setup SHA separately. It retains employee, OU and profiles, uses the
existing sequential worker and consumes this predecessor once. The old UNKNOWN,
requests and events stay unchanged. A later new join failure with a real computer
remains inspectable by GUID recovery. A foreign healthy closed UNKNOWN can still
require the existing candidate-bound queue review; maintenance does not supply it.

Inspect the actual new job and every event page in web/MCP. Technical completion,
employee login and application functionality are separate checks. Reboot and real
employee login require their separately authorized scope. Never create a synthetic
home to satisfy verification.
