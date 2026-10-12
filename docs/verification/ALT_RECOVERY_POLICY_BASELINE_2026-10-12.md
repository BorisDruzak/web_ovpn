# Recovery pre-reservation original-policy baseline

Preparation only. `setup_recovery_policy_baseline` collects original configured
policy without future import/Kerberos/startup/policy evidence. Its closed request
binds fresh existing recovery backup facts, validated target/domain metadata and
source digest. It requires empty host conf.d and unchanged authentication/tool
metadata, then uses the existing fixed isolated original-policy parser. Only
private temporary scratch under protected /var/lib is written and removed; no
AD contact, authentication, service action, snippet or persistent workstation
artifact is introduced by this worker.

The closed stable projection contains original metadata/tool/module digests,
configured values and false defaults/running/trust claims. It matches the later
original-policy observer while excluding post-only request/receipt hashes, so
terminal preapproval no longer requires evidence that will exist only after the
password write. The future authority/transport must pin the actual source bundle,
selected target and this projection in an immutable approval. This internal
worker itself supplies no execution authority or operator CLI.

RED: missing module produced **22 failures in 1.21 seconds**. First GREEN passed
**22 tests in 6.87 seconds**. Tests remove future evidence before observation,
compare the genuine baseline/original-observer projections, refuse stale facts,
metadata/bytes/snippets/packages, close module/config/database/request and final
collector drift, and reject altered or falsely typed projection claims. An
additional case removes imported secrets/keytab and rebinds fresh facts to check
that absent credentials do not block this read-only baseline. A standalone-source load test exposed a relative-import incompatibility
(**one failure in 0.62 seconds**). The worker now receives its genuine original
module explicitly; package-free source loading passes. Independent re-review
found no issue with that correction. Parser and collector callbacks remain
synthetic; genuine parser and complete transport compatibility are unproven.
The earlier full run was deliberately stopped around 35 percent before copying
the corrected source and is not PASS.

Independent review found no actionable issue. All **96 controller Python modules**
compiled. Final baseline/original/temporary-policy focused suites passed
**76 tests in 21.54 seconds**. The baseline full ALT collection passed **2221
tests, one original skip, in 536.23 seconds**. All **257 baseline controller/
test Python files** matched the isolated copy at candidate tree
`aa99ab97be20ffd42b1309a66d6807984f3d231c`; baseline source/test delta remained
unchanged during that run. Separate transport development added two files after
collection; its 23 focused cases are not included in this full result and require
a new combined regression before their publication. `git diff --check` passed.
Exact-commit CI remains a separate publication check. The default/effect manifest and actual terminal service handoff,
source/target approval binding, operator execution and live acceptance remain
unfinished. No recovery has been executed or deployed by this block.

For later effect review, Context7 returned no matching SSSD documentation; the
[upstream 2.9.8 AD manual](https://github.com/SSSD/sssd/blob/2.9.8/src/man/sssd-ad.5.xml)
was checked. It documents 30-day machine-password age, enabled dynamic DNS and
site discovery by default, an initial renewal task delay, and disabled Samba
password synchronization by default. These are upstream references, not installed
ALT-package attestation or an approved manifest. Other configured renewal/DNS
options and package patches must be considered before ordinary startup. Missing
configured values therefore remain unverified defaults in this worker's output.
