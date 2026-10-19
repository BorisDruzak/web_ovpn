# Partial first-join recovery: verification, 2026-10-19

## Current result

Implementation and guarded controller deployment are verified at
`59e643581ae338d3924d2b526f17bf42c0f7386c`. Actual workstation acceptance remains
in progress: two distinct local recoveries succeeded once each. The first
recovery's separately confirmed Setup closed UNKNOWN. After the environment and
source fixes, a separately confirmed new ordinary Setup passed automatic
admission, completed application and reached `waiting_reboot`. Native verification
confirms domain trust, SSSD and lookup of the selected employee. Reboot, first
graphical employee login and functional acceptance remain pending. No original
job or consumed claim was replayed.

## Source and release

| Revision | Purpose and result |
| --- | --- |
| `e72328f14cd9b5f5fe61ab0e7d97f50d9bf809f4` | Original approved recovery/maintenance/diagnostics implementation; published and deployed with exact CI and native backup/rehearsal. |
| `33b42ba730f2c1f5c8f642de9757e43a006c07d7` | Preserve validated failed-successor ancestry; published, but its installer stopped before rollout because operator job checks missed validated ancestor leases. |
| `59e643581ae338d3924d2b526f17bf42c0f7386c` | Align CLI jobs/readiness with canonical reviewed-lease validation; published and successfully deployed. |

The operator explicitly authorized the two exact follow-up deployments while
their full CI continued. Both full candidate gates subsequently passed; no guard
or test was disabled. Source trees for ordinary-user verification and mandatory
root installer tests were separate. Publication used normal fast-forwards and
preserved pre-existing user files.

## Verification

| Check | Authoritative result |
| --- | --- |
| Clean Linux `python -m pytest -q`, Python 3.12.7 / Ansible Core 2.18.6 | 6304 passed, 107 skipped, 3504 warnings, 1811.33 s, exit 0. |
| [Exact candidate CI 39269435158](https://github.com/BorisDruzak/web_ovpn/actions/runs/39269435158) | Both jobs succeeded; retained artifact exit code 0, 6304 passed / 107 skipped / 3504 warnings, 1596.91 s. |
| [Main push CI 39270893463](https://github.com/BorisDruzak/web_ovpn/actions/runs/39270893463) | Both jobs succeeded for the same full source revision. |
| Guarded install mandatory root `python -m pytest -q tests/alt_linux` | 3431 passed, 2 skipped, 1290.07 s; actual installer exited 0. |
| Maintenance entrypoint regression | RED: 2 failed / 4 passed; GREEN: 6 passed. Final expanded CLI/readiness/continuation/admission selection: 102 passed, plus successful compilation. |
| Independent installed files / owners / modes | All 283 expected files match the published revision. |
| Immutable historical baseline at deployment | All 3558 files unchanged. |
| Installed native controller readiness | ready=true; all 15 checks passed; failed_checks empty. |
| Native controller backup | Six components created and verified; eleven restore-rehearsal checks passed. Fresh native eligibility recheck passed after the aborted precheck-only install. |

Exact original logs, backup/review receipts, target identities and authentication
manifests remain in protected operational evidence, outside this repository.

## What the live failures established

The complete directory creator-SID count proved that the join principal's machine
account quota was exhausted and no applicable computer-create delegation existed.
The operator authorized computer-only CreateChild permission on every existing
OU. Full ACE multisets, owner/group and global quota were preserved; independent
checks on both directory controllers confirmed replication. The bounded native
failure receipt does not prove the historical raw exception.

A newly failed successor exposed incomplete ancestry handling in closure and
submission. The repair validates exact reviewed ancestors and the current failed
pair, seals the predecessor evidence and revalidates it archivally. Each distinct
failed job retains one local-recovery claim and each successful receipt one new
ordinary Setup successor.

The first follow-up install then exposed a separate operator-consumer mismatch:
CLI jobs/readiness considered validated ancestor reservations unresolved even
though canonical backup admission excluded them. Both consumers now call the
existing reviewed-legacy-run validator. Missing review evidence, foreign leases,
uncovered current failures and no-scope calls still deny maintenance. A live
candidate preflight proved jobs count=0 and all fifteen readiness checks before
the successful guarded install.

## Native rehearsal and workstation evidence

The unchanged fixed local helper was rehearsed on a disconnected disposable ALT
clone, with fresh key and administrator SSH/sudo before and after the real local
transition. A distinct synthetic claim tested lost reply after a real transition;
uncertainty remained UNKNOWN, redispatch was denied, and original evidence was
preserved. These are isolated native rehearsal results, separate from live
workstation acceptance.

The original actual local recovery succeeded once, verified its private backup,
preserved accounts and established fresh SSH/sudo. Its separately confirmed
ordinary Setup passed automatic queue admission, then returned a native join
failure; all 196 events were retained without gaps or unreachable events. That
failed job remains UNKNOWN. A fresh recovery for this distinct failed job was
confirmed and applied once after the successful controller deployment. Its result
verified local authorization, preserved account fingerprints, the private backup,
fresh SSH/sudo and complete absence of a computer object/credentials. The next
ordinary Setup was confirmed within its native TTL and applied once. It passed
automatic queue admission and completed all nine component application stages.
Native first join returned `first_join_ok`; fresh independent queries to both
directory controllers returned the same enabled computer object in the selected
OU. A bounded UTC-filtered security capture recorded computer creation and
successful Kerberos activity. This proves the new join, not the raw cause of a
historical failure.

All 524 job events were retained without sequence gaps, failed tasks or
unreachable tasks. The authenticated web job view and MCP both showed the actual
new job and its progress. Independent post-application checks matched all 283
installed source files and all 3776 pre-application historical files, including
both old UNKNOWN jobs and consumed recovery receipts.

The new job now waits for reboot. Native verification reports trust, SSSD and
selected-user lookup true, with no local duplicate and no employee home yet. The
domain component's separate recipe remains `drifted`: policy is enabled with the
expected backend and policy, but the policy service has no start timestamp in the
current boot. Application receipts verify the office programs; dependency and
user-home component acceptance remains unverified. No overall success or working
employee session is claimed. A separately scoped reboot request is pending;
after an actual reboot, verify continuation of this same job and then perform the
real employee login and functional checks. Reboot and real employee login retain their
separate authorization boundary; no synthetic home directory is used.

## Review and limits

Independent follow-up source reviews found no unresolved Critical/Important
issues. One earlier Important uncertainty-classification defect was reproduced
and fixed before the original release. One deferred Minor remains: recursive
archival validation can multiply I/O for longer recovery chains. The bounded live
closure passed in 1.366 s; this is not evidence for unbounded chain performance.
The narrow maintenance-entrypoint follow-up introduced no new Minor findings.
The actual new job spent approximately 163 seconds awaiting automatic admission;
that elapsed time includes its live checks and is not a measurement of archival
validation alone.

GitNexus was unavailable in the tool inventory. Dynamic closure, proof, admission,
worker and backup consumers were inspected in source and tests; no new external
HTTP or cross-repository contract was introduced. Reviewers did not grade live
acceptance, full test results or the historical raw error; executor evidence for
those areas is distinguished above.

Before the next ordinary Setup, a new root-private immutable baseline captured
3775 files, including both successful recovery claims/results and a prepared
plan. The final pre-application baseline added the fresh confirmed plan for a
total of 3776 files. It independently proved that the earlier 3558-file baseline
remained unchanged. Fresh read-only ACL checks explicitly targeted each directory
controller and confirmed matching complete ACL aggregates.
