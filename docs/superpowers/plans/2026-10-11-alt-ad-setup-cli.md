# ALT AD Setup CLI implementation plan

**Goal:** Deliver the operator CLI and acceptance evidence required by the supplied ALT AD Setup CLI V1 specification.

**Architecture:** Add a read-only directory boundary, separate protected domain assignments and immutable setup plans, and a setup orchestrator using the existing ConfigureRequest/ConfigurePlanner. Preserve the fixed stage-03 playbook and all existing commands.

**Execution:** Implement sequentially in this chat, with RED/GREEN per block and an independent final review. The supplied specification explicitly authorizes implementation and synthetic verification; production changes require the separate live gate.

## Constraints

- No user AD mutations, computer deletion/reset/move, automatic reboot, arbitrary playbooks or shell input.
- No workstation contact before L0; no deployment before operator approval and OR-3P3 evidence.
- Use protected controller state; secrets never enter CLI arguments, output, Git or public reports.
- User identity must include immutable SID/GUID and verified account status; UNKNOWN blocks apply.
- Domain bindings are separate from local provision assignments. Different bindings fail closed.
- Planning creates only its protected plan. Machine probes are read-only, with no registry persistence.
- Exact Git SHA, CI, deployment and live workstation acceptance are distinct results.

## A: Baseline and audit

- [x] Fetch main, inspect clean local diff, record `74e195abf376cb03537eedcd482d1cdd2d8bfac3`.
- [x] Query GitNexus web_ovpn and inspect ConfigurePlanner, registration, assignments, locks and domain roles.
- [x] Confirm both baseline CI failures from their original GitHub run logs.
- [x] Read-only controller tools/readiness probe: readiness true; no current service Kerberos cache.
- [x] Reproduce baseline failures in isolated Linux copy and fix each with minimal independent changes.
- [x] Verify authenticated LDAP capability without changing controller configuration or exposing secrets.

## B: Directory boundary

Create `alt_deploy/ad_directory.py`, transport/config module and `tests/alt_linux/test_ad_directory.py`.
- [x] RED: exact user-only filter, escaping, immutable identifiers, disabled/expired/locked/unknown state, bounded results, malformed LDIF, ambiguous matches, DC/TLS/Kerberos errors.
- [x] Implement fixed ldapsearch operations, validated transport and certificate checking. Prefer SASL/GSSAPI; optional encrypted password mode uses separate Vault read-only identity and protected ephemeral files.
- [x] GREEN: synthetic transport/integration tests; verify no directory write operation exists.

## C: Setup planning

Create `alt_deploy/setup_plans.py`, `setup_assignments.py`, `setup.py`; extend `registry.py` with unambiguous hostname resolution.
- [x] RED: UUID/hostname selection, ambiguous hostname, OU approval, identity mismatch, existing computer conflicts, provision/domain binding conflicts, TTL, hash tampering, unsafe paths/permissions.
- [x] Build ConfigureRequest with identical selected test/assigned domain user, verify-only hostname mode, allowlisted profiles and explicit approved OU.
- [x] Canonical content hash binds registration, user, OU, profiles, observed domain state and changes; volatile plan metadata is outside the deterministic content digest but protected and integrity-checked.
- [x] Persist immutable plans with private exclusive creation. No AD, workstation, registration or policy writes.
- [x] GREEN: snapshot state before/after plan, deterministic semantic digest and all refusals.

## D: Apply and verification

- [x] RED: stale/mismatched SHA, changed user/login/state, registration/OU drift, simultaneous apply, active jobs, failed execution and partial results.
- [x] Under lifecycle lock, revalidate all bindings and runtime prerequisites, reserve protected assignment and run before mutation; execute ConfigurePlanner.start once.
- [x] Persist safe audit/result, partial failure, reboot/deferred actions. No automatic repeat of ambiguous failure.
- [x] Read-only verify checks actual machine UUID, hostname/domain, trust, SSSD, getent selected user and local duplicate; AD computer identity and OU must match.
- [x] GREEN: existing ConfigureRequest/Planner tests and synthetic orchestration tests.

## E: CLI and documentation

- [x] Add ad users search/show, ad ous list, ad computers check; setup plan/apply/status/verify, argparse help and JSON/text output.
- [x] Preserve configure --vars-file and machines list contracts.
- [x] Write `docs/ALT_OPERATOR_SETUP_CLI.md`, update manual MVP and create dated acceptance report with anonymized live evidence.
- [x] GREEN: invoke actual CLI with synthetic dependencies; exact help, exit codes, safe errors, old CLI regression.

## F: Verification and publication

- [x] Focused directory/setup/ConfigurePlanner/domain/security tests; full tests/alt_linux; full pytest regression; compileall; Ansible syntax; git diff --check.
- [x] Independent review, fix findings and repeat affected tests.
- [x] Atomic Conventional Commits, publish main, record exact SHA and its GitHub CI; independent full-regression failures explicitly retained in the acceptance report.

## L: Production acceptance

- [x] L0: operator selected disposable target and employee, approved checks, selected-user enable exception and separately approved reboot; reference PC excluded.
- [x] L1/L2: real read-only AD and three deployed plans; identical semantic digests and before/after PC configuration and AD digest checks passed.
- [x] L3 controller deployment: exact ea29741 SHA, successful backup/verify/rehearsal and independent recovery access; native guarded installer and readiness passed.
- [ ] L3 workstation acceptance: exact confirmed plan was applied, but partial join failed with domain_join_failed; preserve failed binding/run and newly created computer object.
- [ ] L4/L5: actual trust/SSSD/user/GPO/results/idempotence and safe negative cases. New join and already-configured acceptance are reported separately.
- [x] Preserve partial-failure evidence and safe replay/expiry refusals; authorized reboot completed and deployed verify still failed trust/SSSD/user lookup. No overall completion claim; computer-object recovery remains separately gated.
