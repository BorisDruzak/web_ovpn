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
