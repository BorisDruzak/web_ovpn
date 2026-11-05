# Faster guarded Setup and controller verification

The user approved implementing the three remedies from the workstation-111
process analysis: early compatibility, one ALT test environment, and native
continuation after a transient failure. Implement inline in the existing checkout.

## Approach and boundaries

Extend the existing inspected gpupdate helper rather than duplicate its supported
versions in a new catalog. Simulate the prejoin APT upgrade after metadata refresh,
then resolve missing policy-client packages. Refuse unsupported/mixed, removed,
ambiguous or unavailable results before the real upgrade. Simulation must be
read-only and bounded. Existing post-install byte/owner checks stay mandatory.
This predicts versions, not the hashes of packages that have not been installed.

Provide one Linux Python 3.12 runner using the altserver account, a sanitized
environment, umask 022, short private temporary paths and a private Python cache.
Use it both for focused developer verification and the installer's full serial
suite. Run syntax/import/environment smoke checks before expensive tests.

Add an explicit --resume-verification option to the controller installer. A
successful full verification creates a root-private, bounded-age receipt bound
to the entire immutable source tree and test environment. Resume can reuse only
that verification; all backup, active-job, vault, permission, registration and
rollout guards run freshly. Refuse stale/tampered evidence. Do not resume a
partially mutated rollout, replay workstation jobs, clear UNKNOWN, or grant
permission through a receipt. Known workstation prejoin successors already exist
and remain unchanged. A quick live precheck runs before tests, with a second
fresh check after them.

Alternatives: repeating all tests retains the observed delay; automatically
replaying failed workstation jobs loses the existing uncertainty boundary.
Neither meets the requested behavior. Async admission and automatic service
quiescence are separate changes and are outside these three deliverables.

## Verification

Exercise the actual helpers with safe subprocess fakes and Linux filesystem
tests: future unsupported versions, missing dependencies, removals, malformed
simulation, timeouts; environment leakage; receipt expiry/source/environment
drift/symlinks/permissions/failed tests; fresh guard failure after receipt reuse.
Use targeted RED/GREEN first, one stabilized full ALT run, then one whole-branch
independent review. Publish verified commits to main per AGENTS.md. No repeat
Setup or changes on the completed employee workstation are needed for validation.
