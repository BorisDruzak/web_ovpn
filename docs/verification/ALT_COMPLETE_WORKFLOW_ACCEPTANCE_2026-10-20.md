# Complete workstation workflow acceptance — 2026-10-20

Source and clean-workstation acceptance passed for
`c7e269d452a616855eaf27d1dee13ac93c9016cf`, published to `main`.
The subsequent maintenance-only revision
`9a1cddbfcaf9ffefb0c1659e8a1ce936b01ae679` is published to `main`; its exact hosted
regression passed both jobs. The installer-only correction
`6376e25aa669b71375219a84a3680c71401db5a6` and its test-contract correction
`4e4b9b1126452e6fc7fcb5267636a38efb338f4e` are published; exact hosted
regression for the latter passed both jobs. The further installer cache correction
`8efd188a7d0bebdebbdfc83692a22b02afbe13c9` is published; its exact hosted
regression, root-owned-source gate and guarded production deployment passed.
The controller and all six web files were verified on 2026-10-21. Technical
acceptance of this release does not establish fleet readiness.

## Accepted behavior

The web wizard selects one complete `workstation-full-v1` preset with 17
components. One original job progresses through system configuration, the actual
employee desktop session, and final DNS. The worker admits later phases without
an additional operator SSH command or replaying consumed mutations.

The preset installs the office applications, VK WorkSpace, licensed CryptoPro,
CAdES and ГосПлагин; provisions seven pinned CA identities; configures direct
password-authenticated KRFB; conditionally repairs the confirmed empty-name
KWallet defect; creates employee shortcuts; and applies the protected final DNS
policy last. AD effective computer-create rights and quota evidence are checked
before local authentication changes. Explicit OU delegation provides the
quota-independent path without changing the general domain quota.

The removed CryptoPro forced-extension policy entry stays removed. Legacy
profiles, API requests, UNKNOWN jobs, claims and receipts remain readable and
are never used as authority to repeat old work.

## Verification

| Check | Evidence | Result |
| --- | --- | --- |
| Clean-workstation baseline CI | Run `39464833223`, `c7e269d` | Both jobs successful |
| Full Linux regression | Retained `pytest-full-runtime-identity` artifact | 7,335 passed, 107 skipped; exit 0; 2,150.50 s |
| Final DNS related regression | Eight relevant Linux test files | 219 passed; 65.83 s |
| Browser checks | Existing JavaScript tests and synthetic complete journey | 19 passed; real browser journey passed |
| Prior installer CI | Run `39488710136`, `4e4b9b1`; retained full artifact | Both jobs successful; 7,344 passed, 107 skipped; exit 0; 1,356.87 s |
| Exact release CI | [Run 39495334530](https://github.com/BorisDruzak/web_ovpn/actions/runs/39495334530), `8efd188`; retained full artifact | Both jobs successful; 7,346 passed, 107 skipped; exit 0; 1,565.07 s |
| Published read-only source gate | Native `run_repository_verification` from the root-owned `8efd188` tree | 4,367 passed, 86 skipped; exit 0; 1,722.42 s; private cache removed |
| Installer regressions | All 29 `test_*install*.py` modules, including the static asset contract and real read-only compiler cases | 323 passed, 6 skipped; 76.45 s |
| Native guarded installation | Published `8efd188` through the unchanged mandatory installer | 4,367 passed, 86 skipped; 1,758.73 s; installer exit 0 and explicit success |
| Installed production files | Independent source/hash/owner/mode manifest | All 335 files verified; 26 additional sources preserved |
| Original production history | Independent immutable baseline | 5,569 files and attributes unchanged; original 24 jobs and five UNKNOWN preserved |
| Production web and MCP | Complete catalog, used plan, job progress; desktop and 390 px browser | All 17 components; no console/page/API errors or new plan/apply requests |
| Narrow real browser | Complete wizard at 390 px; device-table scroll | No body overflow or browser errors; no mutating requests |
| Whole-change review and subsequent material deltas | Independent reviewer | No remaining Critical/Important findings |
| Real web Setup | One fresh plan and one apply on a uniquely identified clean clone | Successful; all 17 components compliant |
| Original event stream | Retained contiguous native events | 940 events, no gaps |
| Original user-phase proof | First attempt | Authenticated direct VNC and requested pixel verified |
| Final DNS | Original private helper receipt | `applied_verified`; no failure or rollback |
| Trust stores | Independent read-only certificate inspection | Seven valid payloads; four system roots; four NSS identities; seven machine-CSP and seven employee-CSP entries; no intermediate anchors |
| Cloud browser | Yandex in the actual employee KDE 6 session | Nextcloud login page without TLS bypass or certificate errors |
| Second approved reboot | New boot ID independently confirmed through Qemu and pinned SSH | DNS, domain discovery, external lookups and machine Kerberos ticket passed |
| Direct VNC after that reboot and employee login | Independent external connection | Automatic KRFB startup, password-only security type 2 and pixel update passed |

The available clean image reports ALT Workstation K 11.3; the approved
upgrade produces 11.4. This is not fresh-image ALT 11.2 runtime acceptance.
Private snapshot/UUID/SSH bindings, plan/operation/job IDs, original events,
helper receipts, screenshots and full logs remain in the ignored evidence
workspace rather than this tracked report.

## Final DNS corrections proved by the native cycle

NetworkManager activation now preserves external IP addresses and routes,
uses the bound applied-connection version, and changes only DNS settings in the
original applied configuration. It cannot activate unrelated saved changes.
Rollback refuses foreign persistent or runtime DNS changes.

The helper waits read-only for two consecutive exact original-network hashes
within the existing deadline. UUID, boot, connection, source and ownership
checks remain immediate. No mutation retry or relaxed network hash is used.
Private bounded before/transition records retain the original observations.

The accepted original invocation recorded a transient DHCP network hash at
331 ms, followed by the exact pre-change network hash at 1,538 ms, and converged
after six observations. Active and persistent DNS both became the protected
resolver. The complete original job remained successful after the further
reboot; no Setup or phase was replayed.

Earlier failed clones retain UNKNOWN and their unused final reboots were not
performed. Later successful observations are not substituted for their original
failed proof. The exact unretained cause of earlier generic RFB failures remains
unproven; protocol fixtures and later original pixel proofs establish the scope
of the implemented parser corrections.

## Maintenance with a larger retained ledger

The production ledger contained 4,701 history entries whose canonical map was
652,708 bytes, exceeding the unchanged 524,288-byte private state limit. Native
fresh snapshot validation passed but publication of its full plan could not.

The maintenance-only correction retains the complete before/after map checks.
For larger ledgers, the published review payload contains a domain-separated
SHA-256 commitment to the complete sorted path/hash map. Confirmation and every
maintenance admission rebuild and compare it freshly. No history is omitted,
deleted or rewritten, and generic record limits, exact SHA/TTL confirmation,
UNKNOWN semantics and candidate-specific queue review remain unchanged.

Six large-history regressions first failed and then passed. A reviewer found
that the inherited snapshot method also serves queue admission; the final
purpose guard and its regression preserve that execution boundary. Related
backup/restore/maintenance checks passed 189 tests with one skip; the final
scope and queue run passed 47 tests. Exact hosted run `39473763785` passed both jobs: 7,342 passed, 107 skipped,
exit 0, 1,872.76 seconds. The full artifact is retained.

A native read-only preview on the actual production history passed with a
4,853-byte payload covering the one unreviewed closed UNKNOWN and its two
leases. It created neither a plan nor a receipt. All 5,569 originally retained
files still match the independent immutable-history baseline.

The new revision changes only three backup-maintenance modules and four test
files. Its exact execution-source fingerprint matches the accepted clean-clone
revision; controller execution and Ansible assets are byte-identical. The
workstation cycle is not replayed for this maintenance-only correction.

## Installer correction commits

| Revision | Commit message | Files |
| --- | --- | --- |
| `6376e25aa669b71375219a84a3680c71401db5a6` | `fix(maintenance): run installer tests as the service account` | `deploy/alt-linux/install-control-plane-lib.sh`; `tests/alt_linux/test_or3p1_installer.py`; `tests/alt_linux/support/installer_sandbox.py` |
| `4e4b9b1126452e6fc7fcb5267636a38efb338f4e` | `test(maintenance): align installer asset check with cache policy` | `tests/alt_linux/test_install_assets.py` |
| `8efd188a7d0bebdebbdfc83692a22b02afbe13c9` | `fix(maintenance): isolate installer test bytecode caches` | `deploy/alt-linux/install-control-plane-lib.sh`; `tests/alt_linux/test_or3p1_installer.py`; `tests/alt_linux/support/installer_sandbox.py` |

## Installer preflight identity

The initial guarded installation stopped before replacing any runtime assets.
Its mandatory pytest command ran as root, while real graphical-session fixtures
explicitly require a non-root UID. The original test reproduced that assertion;
the identical root-owned source passed when invoked through sudo as the service
account. This is a deployment test-runner defect, not a workstation or join
failure.

The installer now runs the complete mandatory ALT suite as the service account,
without a pytest source cache, and propagates sudo/test failures before mutation.
The published staging tree must be readable and traversable by that account;
runtime Vault and access material remain private and outside that plain tree.
Two regressions first failed and then passed; the related installer suite passed
32 tests with one skip, and the original real-account reproduction passed.
The full CI exposed one stale static command marker; its test-only update
passed the expanded installer group: 321 tests with six skips. The
independent review found no Critical/Important issues.

The subsequent native precheck exposed a second environment difference: nested
`py_compile` calls attempted to create bytecode inside the root-owned published
source. The failing backup-installer group passed against the same source with
a private Python cache. The selected interpreter now creates a private temporary
cache for the unprivileged pytest process and its children, then cleans it before
returning the original exit code. Root and production-worker environments remain
unchanged. No source permission is relaxed and no tests are bypassed.

Real read-only compiler cases observed RED and GREEN, covering both success and
exit 23, unchanged source bytes, cache ownership/mode and cleanup. The expanded
29-module installer group passed 323 tests with six skips. The new exact hosted regression passed 7,346 tests with 107 skips and exit 0.
A pure test gate from the root-owned publication tree also passed: 4,367 tests,
86 skips, exit 0. Its private cache was confirmed absent afterwards.

All 335 installed-file entries and their hashes remain identical to the
`9a1cddb` maintenance release; the accepted managed execution fingerprint is unchanged. No workstation
Setup or clone cycle is replayed for this installer-only correction.

## Interrupted operational attempt and durable continuation

A later native installer attempt stopped during its mandatory test gate. No
completion or process exit was retained; the exact cause of process loss is not
proven. On resumption, its original processes were absent, all 236 existing
runtime files still matched the prior published revision, and the 5,569 original
historical files and attributes were unchanged. No runtime replacement had begun.
The old idle worker was restored while preparing a fresh maintenance receipt.

The continuation uses a separate systemd unit with no automatic restart. Its
root-private log, dispatch identity and retained unit result survive SSH/chat
loss. Existing unit/log/dispatch records block another launch. This changes only
the operational invocation: the exact published installer, mandatory suite,
backup eligibility, native review and rollout guards remain unchanged. A zero
dispatch code is not an installer success claim.

The first durable invocation also stopped before runtime replacement: its
restrictive invocation umask made root-generated public bytecode unreadable to
the unprivileged Ansible fixture. The original case reproduced the permission
error. A fresh publication tree with identical source hashes and the normal
verified umask passed all 16 cases in the owning Ansible module. The corrected
invocation retains explicit 0600 log/receipt modes inside its root-private
parent. No published source, test or runtime file changed for this correction;
the original failed unit and journal remain retained.

## Functional limits

Technical installation does not prove signing with a real certificate or an
application account transaction. Directum, VK WorkSpace, CryptoPro/CAdES and
ГосПлагин retain their separate functional-acceptance flags. Site detection of
the repaired CAdES plugin on the existing workstation was confirmed by the
operator; an actual signature was not tested.

KRFB shares the selected employee's running graphical desktop. The reboot
check includes employee login; it does not claim a VNC desktop before login.
KWallet repair changes only the confirmed defect; healthy wallets and open
user applications are preserved.
Existing catalog component titles retain some legacy English wording. The full
preset and wizard bind KRFB unconditionally and explain its actual login boundary.

## Production deployment — 2026-10-21

The current exact native maintenance review was confirmed. The single protected
final-DNS Vault setting was provisioned while all other decrypted values stayed
unchanged. The fresh controller backup was created and verified; restore
rehearsal passed all 11 checks. Its current native eligibility and restore
capacity checks passed again without rewriting the verification evidence.

The published release `8efd188a7d0bebdebbdfc83692a22b02afbe13c9` completed the
mandatory guarded installer: 4,367 passed, 86 skipped in 1,758.73 seconds,
installer exit 0, and the explicit installed-success message. The retained
systemd unit is exited successfully and has no automatic restart. Earlier
failed/interrupted attempts remain recorded; none is represented as success.

Independent installed-source verification matched all 335 manifest entries,
including owner and mode. The 26 additional source files remained unchanged.
The complete installed execution fingerprint is
`14edbea16fbb2599cd0ae9e119ffdb3268652486d0dadfdcdc59cfd3c72c3e9a`.
The pinned VK RPM and protected final-DNS policy passed. All original 24 jobs,
five UNKNOWN and all 5,569 historical files and attributes remain unchanged.
No old Setup, join, recovery or workstation reboot ran in this maintenance.

The new non-root worker uses the installed entrypoint, remains active and has
no test-cache environment variable. A standalone maintenance-readiness read
initially encountered the worker's lifecycle lock. Kernel lock ownership was
checked; the same bounded read-only wait used by the installer passed on its
second attempt with all 15 checks true. No guard or receipt was weakened and
the installer was not relaunched.

The first web exchange stopped before replacing any file because the private
transaction directory and application had different filesystems. All six
original contents, owners, modes and inodes were verified unchanged before
restoring the old service. Review then identified that equal device IDs also
do not establish a shared bind-mount namespace, as documented by
[rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html).
A fixture reproduced EXDEV between two mounts of the same device.

The corrected operational helper keeps its closed root-owned transaction
directory inside the application's actual mount. Before stopping the service,
it verifies mount IDs for every target parent and binds directory identities;
it rechecks those identities during exchange and rollback. Real cross-directory
exchange and rollback on that mount preserved owner, mode and extended
attributes. Foreign preimages and namespace replacement were detected. These
rehearsals changed no application files. The fix changed only the operational
invocation; the published six-file source payload and controller remained the
same verified release.

The actual six-file protected web exchange then completed successfully. The web
service is active and all six installed hashes and modes match the publication;
private before-copies, displaced originals and the installed receipt remain
retained. The real authenticated browser verified the fixed full preset with
VK WorkSpace and direct VNC, disabled employee creation, an already-used plan
with repeat apply disabled, and a successful historical job's progress view.
Desktop and narrow-screen screenshots were inspected after the mobile menu's
transition finished. There was no body overflow, console/page error or failed
workstation API response, and no new plan/apply request.

Current MCP calls returned the complete 17-component preset, the four compatible
legacy profiles, an empty execution queue and all five historical UNKNOWN.
Controller, AD, DNS and network source attempts were successful and fresh.
An earlier transient network-source error recovered through the normal
scheduled reconciliation; no manual collection or network write was needed.

The installed Codex plugin cache still has the earlier skill text. The user
has deferred its app-level refresh. The source skill/MCP changes and the live
server contracts are verified separately from this client-cache boundary.
