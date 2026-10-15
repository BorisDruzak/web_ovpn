# ALT controller maintenance stability - 2026-10-15

Runtime source: `598073ac5202dc7debc017d06faed62061c28e17`. Implementation commits:
`d72a1d6e668befeebfdad8b0953055df4f35afc2` (`fix(alt-setup): preserve backup inventory
during idle lock polling`) and `598073ac5202dc7debc017d06faed62061c28e17`
(`fix(alt-setup): await safe lifecycle lock handoff for maintenance`).

Two reproducible lock defects explain the observed failure classes. The original
interrupted runs lacked per-path/gate-phase observations, so their exact actors remain
unproven. Their retained failure logs were not replaced by successful results.

1. Lifecycle-lock preparation unconditionally chmodded an already-correct private
   directory and lock file before acquiring flock. POSIX updates ctime even for the same
   mode. A waiting idle worker could therefore invalidate a backup generation held by
   another process. The fix avoids redundant chmod while preserving creation and
   incorrect-mode enforcement. Strict before/after source inventory comparison is
   unchanged.
2. Maintenance review immediately denied brief lifecycle contention from the normal
   worker. The fix awaits ownership for at most five monotonic seconds within the same
   request, then revalidates the named inode, owner, mode and directory types before all
   fresh history, identity, active-work, health and SHA/TTL checks. Persistent holders,
   unsafe/replaced paths, genuine drift and expiry still deny. No entire backup,
   deployment, Setup job or target operation is automatically repeated.

## Evidence and scope

Before the change, bounded real-worker syscall observation showed redundant chmod/fchmod
and ctime-only inventory drift on the state root/lifecycle lock while held. The actual
installed protected CLI refused while the lock was held and passed after release. These
observations reproduce both mechanisms without changing guards or claiming exact
historical attribution.

TDD used real POSIX flock and native backup publication. Inventory RED: 2 failed/4
passed; focused GREEN: 18 passed. Handoff RED after fixture correction: 4 failed/5
passed; maintenance/queue/backup GREEN: 94 passed. Additional
filesystem/installer/worker/CLI regression: 45 passed. These overlapping selections are
not summed into unique test counts.

Independent implementation review found no Critical or Important issues. Optional
additional owner/ancestor contention cases were not added in this bounded change;
post-acquisition checks are present, with explicit inode/symlink/mode/expiry/history
denial coverage. Operational helper review also passed after strengthening phase
invocation receipts and syscall interval/inode correlation.

GitNexus mapped maintenance/queue callers before source inspection. Shared
directory-helper impact was broader, so the no-op chmod fix stays in lifecycle locking;
no shared JSON helper, dependency, external HTTP contract, schema, Ansible role, target
executor or AD write behavior changed.

Exact-source `python -m pytest -q`: **5756 passed, 90 skipped, 3315 warnings in
1044.81s**, `exit 0`
([CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38720139860)); artifact
log/exit code retained. Main fast-forward publication is confirmed. The automatic `main`
full regression also passed for the same runtime SHA: 5756 passed, 90 skipped, 3315
warnings in 1590.97s, `exit 0` ([main
CI](https://github.com/BorisDruzak/web_ovpn/actions/runs/38722409330)); its output/exit
artifact is retained. The [main ISO-contract
check](https://github.com/BorisDruzak/web_ovpn/actions/runs/38722409292) passed. These
runs are not added into a larger test count.

The stock backup-tool installer preserved 39 prior utility destinations, existing valid
key bytes, protected inputs and all retained history. Hybrid verification matched 261
installed paths: new private/public validators with the old lifecycle implementation
until the controller installer. Fresh native maintenance-plan/confirm passed. Native
restore-capacity initially refused the current space budget; this preparation refusal
was retained. Bounded native deletion of three explicitly verified obsolete bundles,
after active restore/permit checks, reclaimed 6,937,412,292 bytes (6.46 GiB) and
preserved the latest two rehearsed copies. Capacity and projected space for both planned
backups passed before capture.

The first preinstallation backup, while controller locking was still old, refused
`controller_sources_changed`. It is retained as a failed single invocation. One bounded
diagnostic capture observed the actual native before/after inventory returns without
replacing guards or values. That transition capture had zero changes and passed; six
components were verified, all 11 rehearsal checks passed, native eligibility/capacity
passed and the worker was active/enabled afterward. Its initial failure path/actor
remains unproven. This transition is not presented as first-attempt acceptance of fixed
code.

One instrumented lock probe was correctly refused after acquiring the lock: its UID-only
`strace -u` launcher retained root HOME instead of the normal service environment.
Isolated read-only Vault checks reproduced failure with inherited HOME and success when
only HOME was corrected. Sudo privilege-query controls passed in both modes. The failed
trace and environment controls are retained. The corrected probe launches the actual
installed wrapper through the usual `sudo -u` environment under tracing; runtime files,
receipts and admission checks were unchanged. Its successful request is counted
separately from that failed diagnostic probe; no claim is made that every
instrumentation experiment passed.

## Installed acceptance

The unchanged stock `install-control-plane.sh --rollback-backup-id <eligible-backup>
--maintenance-review <current-review>` ran **once** with the normal worker active at
installer launch. All source and hybrid-baseline checks, active-job and
rollback-eligibility gates passed. Its mandatory `python -m pytest -q tests/alt_linux`
finished with **3156 passed, 1 skipped in 1087.81s (0:18:07)**. Guarded installation,
activation, readiness and rollout completion passed in that same invocation; no manual
idle-worker stop or full installer retry was used.

All **261** installed file hashes then matched the accepted runtime source. Installed
scoped active jobs were **0**, controller readiness was true and the worker was
active/enabled. The rollout marker was absent. Existing keys, protected identities, both
retained UNKNOWN records, native predecessor links and all original ledger digests
remained valid. The only history additions were the new native maintenance plan and
confirmation; no job, claim, reservation, target or AD object was reset/replayed.

The bounded installed probe observed actual kernel contention on the lifecycle inode. A
fresh normal worker tick attempted that inode inside the measured **2.5-second** held
interval. Its source inventory changed **0** entries and it issued **0** chmod/fchmod
calls. One actual installed protected CLI request encountered EAGAIN, waited for
release, then completed successfully with zero scoped active jobs. Ownership waiting and
subsequent fresh admission are separate phases; the five-second bound applies to lock
ownership, not the full identity/health observation.

A separate postinstallation acceptance backup on the fixed code completed on its **first
create invocation** with the normal worker initially active. Native verification,
**11/11** rehearsal checks, rehearsal eligibility and restore-capacity checks passed on
that same bundle, each invoked once. The standard backup's own service stop/restore
remains part of its normal operation; no manual quiet-worker workaround was used. Both
the transition rollback bundle and the postinstallation bundle are retained.

Final independent checks reconfirmed the installed hashes, valid unchanged original
ledger, two preserved UNKNOWN records, native predecessor review, zero scoped active
jobs, readiness, worker active/enabled, backup evidence, protected inputs and native
restore capacity. Free space was **3.33 GiB on `/`** and **12.09 GiB on `/var`**. The
previously accepted root-space policy was not changed.

This acceptance covers the two reproduced lock mechanisms and the observed installed
controller flow. Exact actors in the historical and initial transitional refusals remain
unproven. Real source mutation, unsafe/replaced locks, persistent contention, active
execution, changed identity/history and expired SHA/TTL remain refusals. First-attempt
claims apply to the guarded installer and acceptance backup on fixed code; the failed
old-code preinstallation capture and bounded diagnostic transition are explicitly
retained above.

Approved Ansible components continue through the existing [catalog extension
workflow](../ALT_COMPONENT_CATALOG.md), source validation, current protected maintenance
scope and native guarded deployment. No dependency, schema or external API migration is
required. Root-private receipts and the hash-verified local evidence archive retain
operational details without publishing admission hashes, credentials or private
identities.
