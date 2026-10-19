# Partial first-join recovery: verification, 2026-10-19

## Current result

Implementation and guarded controller deployment are verified at
`59e643581ae338d3924d2b526f17bf42c0f7386c`. Actual workstation acceptance remains
in progress: two distinct local recoveries succeeded once each. The first
recovery's separately confirmed Setup closed UNKNOWN. After the environment and
source fixes, a separately confirmed new ordinary Setup passed automatic
admission and completed application. One separately authorized reboot was
performed and proved by a changed boot ID with unchanged machine identity and
fresh pinned SSH/sudo access. Explicit continuation verification of the same job
now reports `waiting_first_login`. Domain trust, SSSD and selected-employee lookup
pass. First graphical employee login and functional acceptance remain pending.
No original job or consumed claim was replayed.

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
| Actual post-reboot continuation through MCP | Original operation succeeded; same job advanced to `waiting_first_login`, reboot_required=false. Base, domain and four office application components are compliant and installed_verified. |

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

Before reboot, the domain component's separate recipe reported `drifted`: policy
was enabled with the expected backend and policy, but the policy service had no
start timestamp in that boot. After the single authorized reboot, the service
reported a successful execution with a nonzero start timestamp. The ordinary
continuation verifier then marked the domain component compliant without any new
Setup, join or policy repair.

The same job now waits for the real selected employee's first graphical login.
Base, domain, browser, office editor, sync client and enterprise web-access agent
are compliant and installed_verified. The web-access agent still requires its
functional acceptance; desktop, certificate and shortcut user checks wait for
the real employee home. The authenticated web page shows `waiting_first_login`
and all 524 events. Post-reboot comparison again matched all 283 installed files
and 3776 historical files. No overall success or working employee session is
claimed; no synthetic home directory is used.

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
