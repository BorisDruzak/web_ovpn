# ALT OR-3P2 Verification Evidence

**Date:** 2026-07-21

## Verified source

```text
branch source SHA: 3b1b74ab3492bd8e132fe1f20b560754c46d9af5
verified pull-request merge ref: 357f3e651bd5410e99ff31f11dcd6d6589f7bdae
merge base: 6eeaf514bda322ba73188ce625005e73d869dfcf
GitHub Actions run: 29851231553
```

The source commit removes the one-time whitespace-normalization workflow. The verified merge ref combines that source with the current `main` base.

## Test results

Focused OR-3P2 contract matrix:

```text
140 passed in 12.99s
```

Complete ALT Linux suite:

```text
396 passed in 15.15s
```

Complete repository suite:

```text
939 passed, 102 warnings in 46.58s
```

The warnings are existing deprecation warnings from Passlib, FastAPI startup events and Starlette template argument ordering. No OR-3P2 test warning or failure remained.

## Static and syntax gates

```text
Python compilation: PASS
Bash syntax: PASS
Ansible 01-preflight.yml syntax: PASS
Ansible 02-provision-account.yml syntax: PASS
git diff --check origin/main...HEAD: PASS
clean checkout after verification: PASS
```

Ansible syntax used a CI-only temporary Vault password file and a temporary plaintext `vault.yml` copied from the repository example. Both were removed before the clean-tree check. Production Vault configuration and `/home/altserver/.ansible-vault-pass` were not changed or accessed.

## Focused coverage

The focused matrix covers:

- no-follow registration-record parsing and exact-byte legacy generations;
- protected archive persistence, immutable manifest/commit evidence and fail-closed scanning;
- lifecycle discovery, assignment/job blockers and exact-generation active registry filtering;
- read-only preview, root-only apply, audit reason validation, postcommit cleanup recovery and idempotency;
- CLI JSON and safe stderr contracts;
- registration admission, concurrent request serialization and HTTP mapping;
- pending processor archive-first race suppression and lock duration;
- register-only workstation helper behavior and bootstrap ordering;
- installer helper publication, archive preservation, private roots/lock and systemd sandbox access;
- controller readiness including the served registration helper;
- existing OR-3P1 installer and permission regressions.

## Safety evidence

During implementation and CI:

- controller `192.168.100.17` was not accessed or modified;
- reference workstation `192.168.101.111` was not accessed or modified;
- no real workstation SSH, preflight or provisioning operation was performed;
- no production Vault password, decrypted Vault content, password hash or private SSH key was used;
- filesystem tests used temporary roots and synthetic identities;
- HTTP handler tests used loopback only;
- helper tests used fake commands and synthetic responses;
- jobs, logs and assignments were not deleted by archive operations;
- archive apply contains no target-side SSH operation;
- existing archive records are preserved byte-for-byte by installer tests.

## Operational boundary

OR-3P2 is verified in the repository only. It must not be installed on the live controller until OR-3P3 backup/restore is approved, executed and restore-tested.

The next acceptance target must be a new disposable and unassigned VM or workstation. Do not use `192.168.101.111`.

## Cleanup before Ready for review

Before marking PR #22 Ready for review:

1. remove `.github/workflows/temp-or3p2-task1.yml`;
2. confirm no other temporary workflow or CI-only fixture remains in the diff;
3. run the repository's standard context-stage and runtime-identity workflows on the clean final head;
4. confirm PR head and check results;
5. do not merge without explicit user confirmation.
