# Recovery selected-user NSS worker

Preparation only. This internal worker has no operator execution command or
independent authority to recover a computer account. The controller must bind
an explicit employee-check scope, freshly validate the enabled employee GUID,
SID, login and UPN, and retain genuine native/startup authorization before
transporting it. Those controller and transport steps remain unfinished.

The worker validates retained temporary SSSD policy and native-check evidence,
then runs one fixed `getent -s sss passwd APPROVED_UPN`. It rejects a local
duplicate, ambiguous or malformed output, root/nonnumeric IDs, changed service
identity, dependencies or protected evidence. It records only numeric IDs and
bound digests, never the raw passwd row. Retained verification repeats proof
checks without another user lookup. An entered failure permanently excludes
replay and retains its failure marker; no automatic cleanup is attempted.

Initial worker RED: 20 failures because the module was absent. The initial
implementation passed 20 tests in 28.89 seconds. Independent review found that
pinning getent alone omitted its dynamically loaded SSSD NSS module. Two
before/after module-substitution regressions reproduced that defect: two
failures in 4.06 seconds. The fixed probe freezes both executables/dependencies
before recovery; the worker checks their original protected ancestry, metadata,
SHA-256 and exact package, and performs command-free rereads after callbacks.
Read-only inspection of the selected disposable PC confirmed canonical
`/usr/lib64/libnss_sss.so.2` and package `sssd-client 2.9.8-alt3`, alongside
`glibc-utils 2.38.0.223.f053ff-alt1.p11.1`. This inspection did not run a domain
user lookup or change services or AD. Focused worker/facts suite: **47 tests
passed in 32.25 seconds** before the final facts assertion extension.

An NSS result can come from SSSD cache. Its receipt explicitly keeps
`login_verified=false` and `online_user_authentication_verified=false`. It
does not prove a graphical login, home creation, trust, GPO or terminal policy
restoration. Original failed-run evidence remains outside this worker's writes.
Independent source re-review confirmed the NSS finding closed and reported no
new actionable worker finding. It did not certify live acceptance or the
unfinished controller authority. Full root ALT regression passed **2052 tests,
one original skip, in 454.25 seconds**. All **91 controller Python modules**
compiled; `git diff --check` passed. Source/test SHA-256 values matched the
isolated tested copy. Candidate tree `ef7643a17e2ff40fb1d5b14f2b1abbd326cf7f75`
was frozen before recording these final results; only this report changed
afterward. Exact-commit general CI remains separate after publication.
