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
advanced through `waiting_first_login` to `successful` after the employee's real
domain login. All nine selected components are compliant and installed_verified.
The employee confirmed that the Plasma desktop appeared and input worked after
a bounded temporary XRDP workaround. The enterprise web-access agent still
requires its real business-workflow acceptance. No original job or consumed
claim was replayed.

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
| Actual post-login continuation through MCP | Original operation succeeded; same job advanced to `successful`. All nine selected components are compliant and installed_verified; eight are technical_verified, and the enterprise web-access agent retains functional_verification_required. |

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

The employee subsequently authenticated through the existing domain PAM/SSSD
configuration. PAM created the real home and applied user policy, and the X11
session started Plasma, its window manager and shell. Explicit continuation of
the same job returned `successful`, with all nine selected components compliant
and installed_verified. The authenticated web page independently showed
completion and all 524 events. Post-login comparison again matched all 283
installed controller files and 3776 historical files. No synthetic home directory
was used. The employee confirmed a working desktop and input; the web-access
agent's real business scenario remains functionally unaccepted.

## Additional components after first login

The operator subsequently requested the complete software set and KRFB on the
same workstation. The original nine-component Setup and its profile were not
rewritten. Four distinct native component plans were reviewed and applied once:
CryptoPro CSP, CAdES, GosPlugin and KRFB. Their original jobs completed
successfully, with compliant / installed_verified results and respectively
92, 80, 102 and 80 contiguous events. The GosPlugin web job independently showed
completion and all 102 events. One earlier blocked GosPlugin plan was never
applied; the replacement plan was prepared after package activity ended.

Independent package checks confirmed CSP 5.0.13600-7, CAdES 2.0.15700-1,
GosPlugin 1.3.42.0-1 and KRFB 26.04.3-alt1. The CSP license utility reported a
permanent client license matching the protected configured license. No license
serial was included in the retained redacted evidence. The actual user's browser
profile contained the CryptoPro and current GosPlugin extensions with empty
disable-reason lists. Their native messaging manifests and executable paths were
present. The missing CryptoPro desktop launcher was copied from the installed
package into the existing correctly owned desktop without replacing user files.
These checks do not establish a successful signature with a real certificate or
token, or the web-access agent's business workflow.

KRFB's network prerequisite was established on this workstation with a dedicated
persistent host rule rejecting non-loopback TCP port 5900 for IPv4 and IPv6.
Other host rules and network infrastructure were not changed. After all earlier
component jobs ended, the idle ordinary worker was paused under the existing
lifecycle lock with empty-queue and recovery checks. The unchanged published
native component CLI and worker ran the sole KRFB job with a per-process network
confirmation backed by fresh kernel-rule evidence. The ordinary worker was
restored after the one-shot worker and original job finished. No global network
admission flag, raw Ansible dispatch or controller source change was introduced.

An already running user-launched KRFB process predated the protected configuration
and retained its old password in memory. The first actual RFB authentication
failed. After verifying there were no connected VNC clients, only that exact KRFB
process was gracefully restarted; the approved configuration was preserved across
its shutdown. The existing Plasma and RDP session remained intact. A subsequent
RFB 3.8 challenge-response through pinned SSH authenticated successfully, returned
the existing 1600-by-900 framebuffer and transferred a one-pixel raw update that
was immediately discarded. No input, password or desktop image was retained.
Direct network connection to port 5900 was rejected. KRFB autostart and protected
configuration were verified; pre-login screen sharing was not tested or claimed.

Post-component comparison again matched all 283 installed controller source files
and all 3776 historical baseline files. UNKNOWN records and consumed recovery
receipts remained unchanged. The controller's profile-selection correction is a
separate pending change; these workstation results do not claim that it is deployed.

## Subsequent application and final resolver request

The operator separately requested installation of the selected VK WorkSpace RPM
and a final workstation DNS change. The RPM's SHA-256 matched a fresh stream from
the vendor's official download link. Native transaction simulation passed;
inspection of the main binary and bundled Qt libraries found all 108 referenced
libraries in the bundle or system cache. This inspection did not execute the
application or vendor installation scripts.

The actual authorized installation then added VK WorkSpace 26.4.0.141207-1.el8
without upgrading or removing other packages. Installed RPM files verified. The
application started in the existing selected employee X11 session, its helper
processes remained alive and a mapped application window was detected. A desktop
launcher was added without replacing existing user files. Authentication to a
workspace and application business workflows were not tested. This explicitly
requested package operation is distinct from a published catalog component;
controller integration remains pending.

The first DNS update attempt exposed a read-only NetworkManager/Etcnet settings
backend: it refused connection modification despite sufficient root permissions.
The active resolver remained unchanged. A backend-specific correction updated
the persistent interface resolver, reloaded connection profiles and reapplied
only the active device. Addressing, routes, DHCP options, network connection and
employee desktop were preserved. Persistent and active DNS then matched the
operator-selected final resolver. Fresh AD discovery, external-name resolution,
selected domain identity and machine-keytab Kerberos authentication passed after
the change. Protected backups were retained; ephemeral ticket caches were removed.
Persistence across a further actual reboot has not been claimed.

Post-application/final-DNS comparison again matched all 283 installed controller
source files and 3776 historical baseline files. Old UNKNOWN and recovery records
were not changed. The full future workflow, including automatic first-login KRFB
and final DNS, requires a separate reviewed controller implementation.

## Temporary remote support

The operator separately authorized temporary XRDP through an SSH tunnel. This
did not change the confirmed Setup profile or turn remote support into a new
published catalog component. Four packages were installed from the approved OS
repository without upgrading or removing existing packages. Services were masked
before installation, configured for a loopback-only TLS listener and restricted
to the selected employee before starting. Automatic service startup remains
disabled. Existing domain PAM, account and NSS files were independently checked
unchanged. The active support connection remains available for the employee;
ending it must preserve the employee's home and work.

The first actual remote login exposed a separate packaged XRDP crash: its child
process received SIGSEGV in the fast-path input stack after successful domain
authentication. The existing Plasma session survived. A one-setting workaround
disabled fast-path input for new connections, preserving TLS, loopback binding
and output acceleration. No service, desktop session or workstation reboot was
performed for that adjustment. [Version-matched upstream source](https://github.com/neutrinolabs/xrdp/blob/v0.10.6.1/libxrdp/xrdp_rdp.c#L353)
confirms that connection initialization reads the setting. Reconnection to the existing
session succeeded, and the employee confirmed the visible desktop and working
input. This is a verified configuration workaround, not a source-level repair
of the packaged XRDP binary. A credential-free TLS probe alone had not exercised
that graphical-login path.

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
