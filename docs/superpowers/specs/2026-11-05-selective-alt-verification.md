# Selective verification of ALT component releases

The release gate automatically compares a protected source snapshot with the
last successfully verified snapshot in a root-private cache. Known isolated
component roles and their owned tests select their complete test group plus
mandatory integration and gate contracts. Browser/CryptoPro/CAdES/GosPlugin form
one coupled group. Other explicit groups cover office, Nextcloud, Directum, VK,
gpupdate compatibility, desktop integration and KRFB. Shared code and input
remain outside these scopes.

Unknown paths, source deletion/rename, permission changes, shared fixtures,
installer/control/backup code, shared catalog/profile/schema changes, policy or
environment drift require full verification. No baseline also requires full.
Role meta/handlers/plugins and cross-role or ambiguous Ansible task imports
require full verification. Only ordinary tasks/files/templates/defaults/vars
are component-owned; the YAML parser runtime is bound to the policy signature.
Documentation accompanying component changes is limited to explicitly static
operator/runbook/design Markdown paths. No caller-supplied component or test
list can authorize a release. The developer's focused runner remains separate.

The full suite includes tests/alt_linux and the standalone integration tests
referenced by the component matrix. Both modes use the existing sanitized
Python3.12/altserver serial worker, syntax checks, private temporary/cache paths.
--full-verification forces full; --plan reports a read-only preliminary decision.

Successful tests and unchanged before/after source/environment produce a
content-addressed root-private proof containing the source manifest, environment
and policy hashes, exact tests, scope, time and parent/full-foundation provenance.
Atomic receipt/baseline pointers inherit only previously verified coverage.
Selected snapshots must retain the full foundation's global inputs. Root-owned
proof state is the authority; Git refs and historical schema1 receipts are not.
The current receipt is invalidated before a fresh attempt. A failed new candidate
does not invalidate its unchanged parent; a failed retest of an already trusted
snapshot revokes its foundation family until a new full pass. This prevents a
contradictory earlier pass authorizing later descendants.

Exact-source resume retains its six-hour lifetime. The baseline itself remains
eligible while its foundation, environment and selection policy are unchanged;
elapsed time alone does not demand another full suite. Resume validates the
proof's actual mode and promotes the verified snapshot as the next baseline.
Forced-full resume cannot reuse a selective proof. Cache corruption cannot
produce a selective pass. Unsafe cache/source paths are refused.

Use one native flock across legacy/new verification, atomic/fsynced protected
files, bounded strict JSON, complete source manifests and source/environment
checks after tests. Every ancestor and revocation is validated back to the full
foundation. Directory permissions are included in the source identity.
Snapshot coverage is inductive root-created evidence, not an authorization to
deploy. Backup/verify/rehearse, live jobs, Vault, permissions,
pending registration and native rollout/readiness remain mandatory and fresh.

Alternatives rejected: a user-selected --component could hide shared changes;
GitNexus-only dynamic impact is incomplete for Ansible; all changes since the
last full run would accumulate unrelated component reruns. The explicit matrix
and last verified snapshot keep small changes small while retaining fallback.

Validate the new gate with full verification once, then a real comment-only
component/test change in a separate protected source tree using automatic
selection. Do not deploy the synthetic candidate. Restore the published full
snapshot as the baseline through native --resume, never by editing cache state.
