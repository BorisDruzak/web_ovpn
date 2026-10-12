# Limited recovery terminal handoff contract

Status: design for implementation and independent review; no live execution
approval. This continues the selected partial-join recovery scope and preserves
the original failed run, binding and computer identity. No other machine or AD
employee can be selected by this phase.

## Required inputs and approval

The existing confirmed recovery/base plan and combined startup/native/user
attachment must remain valid before reservation. A separate immutable terminal
attachment must pin the fixed terminal sources, a read-only original-policy
baseline projection, conservative startup-effect inventory/review, selected employee and
computer GUID/SID/OU/domain, service/unit/source observations, and an explicit
normal-policy effect statement. Old startup-only/native-only/user approvals do
not confer terminal authority. Source or observed-policy drift requires a new
plan. The attachment is part of the final operator confirmation before any
recovery password write, not an approval inferred after services have started.

Before reservation, a separate read-only baseline collector must observe the
protected original main bytes/metadata with empty host conf.d, pinned parser/
module/source hashes, configured values and independently checked default
semantics. The terminal attachment approves its stable projection: original
metadata digest, parser/tool/module digest and configured values, together with
the reviewed default/effect statement. This collector cannot require future
import/Kerberos/policy receipts or an installed suppression snippet.
After suppressed startup, the existing original-policy observer reproduces the
same projection. Its full post-install request/receipt hashes are bound in the
permanent terminal intent; they are not described as preapproved receipts.
The baseline collector and its non-executable operator command are implemented.
The ten-field path has separate read-only installed parser acceptance. Extended
operative inventory is now exposed through `policy-effects`; its installed
parser acceptance and reviewed default/helper/effect manifest must precede
terminal authority. Neither collector grants reservation or execution authority.

The normal-policy effect statement must say that restoring configured/default
SSSD policy may enable ordinary machine renewal and dynamic DNS activity. Missing
configured attributes are unresolved defaults until the pinned runtime/package
behavior has been checked. Inventory hashes alone do not approve hooks, manager
actions, environment or unresolved destinations. Normal service behavior does
not authorize network-policy edits or an additional manual AD reset.

## Fixed execution order

1. Under the existing machine/recovery lock, verify the genuine retained
   suppressed startup/native/user chain and current exact SSSD invocation.
   Observe the original configuration in isolation and match the stable baseline
   projection in the terminal attachment. Verify fresh employee/computer identity, TTL, source hashes,
   original history and absence of conflicting manager jobs.
2. Persist a permanent root-private terminal intent before the first service
   action. It binds request, all input receipts, approved effects and sources.
   Recheck the same protected state after intent and before the fixed command.
3. Stop only the observed SSSD invocation through the fixed systemctl command.
   Check inactive/dead, MainPID/ControlPID zero, no SSSD process and no pending
   manager jobs. Unit source/environment/restart policy, retained history and
   all unrelated authentication service state must still match. Local snapshots
   are bounded observations, not an exclusive lease over the system manager.
4. Remove only the exact owned recovery snippet, after its bytes and metadata
   match the approved evidence. Preserve the main configuration, conf.d directory
   and original artifacts. Do not edit a substituted file or another snippet.
   Fsync and require the original-policy verifier to reproduce the exact approved
   observation with empty host conf.d.
5. Restore only smb/nmb that were active in the original quiescence snapshot;
   keep originally inactive units inactive and winbind inactive. Start each
   allowed service once, recording intent and observed result. Use fixed
   reviewed startup behavior and detect unapproved dependencies/manager actions.
6. Start SSSD once under the restored ordinary policy. Require a new nonzero
   invocation different from the suppressed invocation, running PID, unchanged
   unit sources/environment, NRestarts exactly zero after each manual start,
   and stable repeated observations.
   Retained suppressed proofs are now historical: do not call their current
   suppressed-state verifier to certify this running phase.
7. Obtain fresh ordinary-policy acceptance: current service state, original
   configured-policy observation, Samba machine trust, selected-user NSS lookup,
   local-duplicate absence and authenticated AD GUID/SID/OU/domain continuity.
   NSS resolution is not password/GUI login or online employee authentication.
   Retain new receipts without modifying the original directory-write result.

## Ordinary renewal and credential continuity

Before normal start, require the exact manually reset KVNO and imported machine
credentials. After normal start, accept unchanged KVNO/credentials only with
fresh proof. An ordinary renewal may be accepted solely under a preapproved
bounded rule: same immutable computer/domain/OU, exactly one KVNO increment from
the manually reset result, locally consistent renewed keytab/secrets and fresh
machine authentication/trust. Historical pre-renewal import/Kerberos receipts
remain preserved and are not rewritten to describe the new credentials.
Larger/unknown deltas, inconsistent credentials or inadequate attribution fail
closed; there is no automatic second reset, password rollback or rejoin.
The implementation must not claim this rule is established by configured values
or by a command exit code alone. If safe attribution cannot be established, the
result remains UNKNOWN and requires separately reviewed recovery.

## Failure and continuation

After terminal intent, any failure retains all evidence and permanently excludes
replay of the same attempt. There is no automatic restart, snippet reinstatement,
service cleanup or password rollback. The status must identify the last verified
phase so the operator can review the retained condition without a repeated write.

Only a fresh successful terminal receipt plus current identity/trust proof can
support an additive recovery-resolution receipt. Setup continuation uses a new
plan/SHA and existing fixed stage-03 pipeline, skips join only under fresh proof,
and preserves the original five failed-history records byte-for-byte. Graphical
login/home, GPO and core-apps/signature checks remain separate live acceptance.

## Pinned lifecycle documentation check

Context7 identifies upstream systemd source, but its available version is newer
than the reviewed service-manager package (258.9-alt1). The tagged
[systemd v258.9 service source](https://github.com/systemd/systemd/blob/v258.9/src/core/service.c)
was checked directly: manual stop sets the restart-forbidden flag; manual start
acquires a new invocation ID and resets NRestarts. The tagged
[unit source](https://github.com/systemd/systemd/blob/v258.9/src/core/unit.c)
implements control-group killing on the normal stop path. This explains the
planned observations; it does not attest the installed ALT binary, eliminate
manager races, establish post-stop InvocationID retention or replace native
service/process checks. Do not assume stopped InvocationID is cleared without
pinned runtime evidence.
