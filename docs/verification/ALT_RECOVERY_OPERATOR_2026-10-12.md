# ALT bounded operator recovery verification

The operator envelope composes one GUID-only password Modify, protected local
credential import, machine Kerberos/native trust/NSS proof, a fixed normal-policy
SSSD handoff and a separate fresh normal Setup continuation. Approval remains a
human gate: no live reservation, machine reset, credential import or recovery
service operation occurred during these checks.

## Evidence

- Final immutable source copy: 111 control modules; local control and Ansible
  bytes matched the tested Linux copy.
- Final combined Linux suite: **396 passed**, 204.21 seconds. This includes
  operator/CLI, continuation/execution, terminal worker/runtime, reviewed-policy
  worker/runtime, source-stdin, startup authorization/user scope/user worker and
  all six migrated transports.
- Supplementary regression: 311 general tests passed (three TLS tests initially
  skipped without root and then passed under root).
- Exact control `python3 -m compileall -q deploy/alt-linux/control/alt_deploy`
  passed with a separate bytecode-cache prefix.
- `ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg ansible-playbook -i
  localhost, --syntax-check deploy/alt-linux/ansible/playbooks/03-setup-controller-preflight.yml`
  passed; the same command for `03-configure-domain-workstation.yml` passed.
- Five installer/bootstrap `bash -n` checks passed.
- `git diff --check` passed. Independent source review found no remaining
  blockers after operator authority, final callback, symlink and NSS corrections.
- Genuine selected-PC read-only closed-policy capture passed: source bytes,
  main configuration, machine snapshot and original five history blobs remained
  unchanged; no service or AD write was authorized.
- Genuine production composition created an operator execution envelope from
  fresh protected history and actual AD/PC reads; no execution/reservation.

The first broad sandbox accidentally omitted documentation: 28 documentation
FileNotFound failures occurred, with 2489 passes and one skip. A complete frozen
copy passed **2517 tests, one skipped**, 705.70 seconds. This broad copy
preceded the final six NSS and four alias negative cases; the final 396-case
suite above includes the final production bytes and those cases. The omitted-doc
harness failure is not treated as acceptance.

## Compatibility and adversarial checks

Stock ALT Samba uses four exact alternatives links to two protected canonical
binaries. Only these link targets are admitted; roots, ancestry, owner/group,
metadata, package and binary bytes remain guarded. Pre/post link substitution
and forged metadata refuse admission. Generic protected-file symlink refusal
is unchanged.

The stock NSS library is mode 0644. The fixed library needs owner-read permission;
getent still needs executable bits. Genuine worker/scope tests first failed,
then passed after the narrow correction; nonexecutable getent and unreadable or
writable libraries refuse before lookup.

Operator intent/ready and exact child-plan authority are checked before stage
mutation and fixed external operations. Final protected local records are read
again after callback boundaries. Genuine POSIX lock composition tests prohibit
nested lifecycle-lock acquisition. Entered failure permanently excludes replay.

## Remaining live gate

Publication, exact-SHA guarded controller installation, fresh backup/rehearsal
and installed readiness must precede a new operator plan and human reset
approval. Returning ordinary SSSD policy can trigger renewal, Samba effects,
AD reconciliation and DNS updates. Any changed reset credentials/KVNO/AD
continuity remains UNKNOWN; there is no automatic second reset or cleanup.
NSS is not GUI/password authentication. Setup continuation requires a separate
fresh standard plan/SHA; original failed evidence is archived unchanged before
normal binding revision advances. Live recovery and workstation acceptance
remain unverified until explicitly approved and executed.

## Non-root CI fixture admission

The protected-policy worker cases initially failed 18/18 on a normal UID because
fixture files were compared against production root metadata. The tests now
require an explicit fakeroot child for those same 18 cases on non-root runners;
exit zero, all 18 passes and no child skips are required. Root execution passed
19 tests including the inert wrapper; non-root execution passed the required
wrapper, which proves all 18 child cases (the outer duplicates are explicitly
skipped). No production owner/permission guard or recovery source changed.
The obsolete general CI run was cancelled after this reproducible harness
failure; a new exact revision must pass CI before controller installation.

Terminal fixtures also exposed the UID/GID ownership assumption with an ordinary
UID and a different allowed primary group. The six new controller/terminal
suites passed 113 tests on a matching normal UID/GID; 64 coordinator/continuation/
operator cases passed under unequal UID/GID. Required bounded root children then
executed all 38 terminal worker and 11 runtime cases with zero skips. Parent
wrappers passed; parent duplicates are explicitly skipped. A fakeroot-only
worker iteration timed out at 240 seconds and is not counted as PASS. The final
terminal driver prefers eligible passwordless sudo, uses an inner fixed timeout
with TERM/KILL teardown, Python -B and no pytest cache, and has a fakeroot
fallback. This changes only fixture execution, not production checks.

Final teardown pins the initial parent directory dev/inode/UID/GID/mode, opens
that parent O_DIRECTORY|O_NOFOLLOW and removes only the fixed root-worker-child
basename with fd-relative, symlink-attack-resistant rmtree. The final runtime
wrapper passed with all 11 child cases and directory absence asserted in both
sudo and forced fakeroot fallback modes. Historical disposable pytest garbage
was not modified; old cleanup warnings were not treated as production failures.
