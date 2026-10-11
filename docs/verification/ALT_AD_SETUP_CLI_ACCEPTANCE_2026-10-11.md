# ALT AD Setup CLI acceptance — 2026-10-11

**Implementation verified; live workstation acceptance BLOCKED pending L0 approval of exact target/actions.** No workstation contacted, no controller deployment performed. Full regression is not green; independent baseline failures are listed below.

## Baseline

Fresh HEAD/origin main: `74e195abf376cb03537eedcd482d1cdd2d8bfac3`, initial tree clean. GitHub runs `38084079111` and `38084079137` both failed at this SHA. Reproduced collection collisions and two execution_release_invalid failures in isolated Linux copy. Fixes rename endpoint test modules and emulate ownership of explicit synthetic fixture inodes; production ownership/mode/hash/no-follow checks remain active, non-root owner/group negative tests added.

## Controller evidence

Read-only commands: tool/version checks, klist -s, workstationctl --json controller readiness, workstationctl --json vault check. Readiness true, failed_checks empty, no active jobs; Vault healthy. Python 3.12.7, OpenLDAP 2.6.9, Samba 4.20.8-alt2. No existing service ticket. Private temporary probe acquired a ticket from existing delegated Vault identity and performed base-scope domain-object LDAP query with GSSAPI/minssf=56, return code 0. Cache destroyed. Only booleans/return code emitted; no credentials or real identifiers. workstation_contacted=false, directory_write=false. Capability proof does not constitute selected-user L1 or workstation acceptance.

## Implementation checks

Read-only AD commands and setup plan/apply/status/verify implemented with protected TTL/SHA plans, separate bindings, fixed ConfigurePlanner, strict read-only SSH and machine-account identity. Legacy mutation paths cannot bypass domain bindings.

Final focused directory/setup and existing configure/domain contracts: **363 passed**. Baseline-fix focused tests: **62 passed, 3 skipped**; Setup/runtime/precheck set: **29 passed**. Isolated root production-installer module: **36 passed**. Compileall and setup-controller-preflight/stage-03 Ansible syntax passed; diff check passed.

First publication `473ffdbc5b95e4099a2a5dc8634f998f74caae8b`: focused-runtime-identity CI passed. [Managed contract run 38126837966](https://github.com/BorisDruzak/web_ovpn/actions/runs/38126837966) uncovered the next synthetic-fixture dependency: GitHub has no `altserver` service account, so the two CLI tests reached `install_session_storage_failed` after passing the corrected release-ownership checks. RED reproduced on Linux with `ALT_DEPLOY_SERVICE_USER=codex-fixture-account-not-installed` (**2 failed**). Fixture now selects the real test runner's account for synthetic storage, preserving actual mode/ownership handoff operations and all production checks. Same command GREEN: **2 passed**; the workflow's eight-module install-session command GREEN: **34 passed**. Final publication/CI outcomes are in the accompanying delivery message.

Full Linux regression (root in isolated repository and synthetic host roots): **3584 passed, 9 failed, 5 skipped** in 697.65s. Four subsequent concurrency/source-drift/computer-identity regression cases also passed in the final focused run. Every one of these nine full-run failures was separately reproduced on the untouched exact `74e195ab` archive under the same interpreter/environment: **9 failed** in 3.47s. They are independent baseline failures, not new AD/Setup failures:

| Test | Baseline failure |
|---|---|
| test_ansible_assets::test_roles_contain_no_unsafe_ansible_patterns | Existing software_endpoint_agent shell tasks |
| test_alt_install_execution_qemu::test_run_state_has_unpredictable_trust_anchor_and_exact_artifact_identity | Assertion rejects the runner's private temporary-directory name |
| test_install_execution_authorization: three authorization tests | Signing-key fixture parent ownership |
| test_inventory_endpoint_web::test_pc_card_keeps_agent_summary_small_and_shows_endpoint_values_by_field | Old inventory CSS version assertion |
| test_netctl_client::test_run_netctl_transmits_projection_only_through_stdin | Synthetic executable has no POSIX shebang |
| test_vpnctl_management::test_web_summary_returns_only_dashboard_metrics | ALT service-state expectation mismatch |
| test_vpnctl_management::test_management_kill_command | Test runner lacks the expected service group |

Ordinary-user full ALT run earlier: 7 failed, 962 passed, 5 skipped; six installer cases need ownership privileges in their synthetic roots and passed when run as root. These environment requirements remain distinct from the nine failures above. No tests were disabled or security checks weakened.

Commands:

```sh
.venv/bin/python -m pytest -q tests/alt_linux/test_ad_directory.py tests/alt_linux/test_setup_plans.py tests/alt_linux/test_setup_service.py tests/alt_linux/test_setup_runtime.py tests/alt_linux/test_setup_cli.py tests/test_alt_manual_configure_request.py tests/test_alt_domain_ansible_assets.py tests/test_alt_domain_resilience_assets.py --tb=short
.venv/bin/python -m pytest -q tests/alt_linux/test_install_execution.py tests/alt_linux/test_install_session_cli.py tests/test_endpoint_execution_manifest.py tests/test_endpoint_execution_tls.py --tb=short
sudo -n .venv/bin/python -m pytest -q tests --tb=short
sudo -n python3 -m pytest -q --noconftest tests/alt_linux/test_install_execution_production_installer.py
.venv/bin/python -m compileall -q deploy/alt-linux/control/alt_deploy
ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg ansible-playbook -i localhost, --syntax-check deploy/alt-linux/ansible/playbooks/03-setup-controller-preflight.yml
ANSIBLE_CONFIG=deploy/alt-linux/ansible/ansible.cfg ansible-playbook -i localhost, --syntax-check deploy/alt-linux/ansible/playbooks/03-configure-domain-workstation.yml
git diff --check
```

GitNexus `web_ovpn` query/context/impact located the committed ConfigurePlanner boundary and indexed CLI consumer. Dynamic source inspection confirmed reuse of the fixed stage-03 entrypoint and shared controller lifecycle/binding state. Existing HTTP APIs, Endpoint SDK/OpenAPI and network-write paths were not changed. GitNexus backup query plus source inspection confirmed the whole controller_state component includes the new state directories; root-owned directory configuration requires a separate backup as documented.

Independent review identified seven defects: lifecycle/binding bypass, descendant OU acceptance, computer identity replacement, lost partial-result/reboot evidence, missing text run ID, omitted role scripts/templates in source fingerprint, and false reboot state on unavailable results. All corrected and re-reviewed with no remaining actionable findings. Linux concurrency, source drift and GUID/SID replacement regressions passed. Review/synthetic tests do not constitute workstation acceptance.

## Live gates

| Gate | Status / reason |
|---|---|
| L0 | BLOCKED: exact target, employee and actions not approved |
| L1 | Pending: directory capability only; selected-user/OU/computer check awaits L0 |
| L2 | Pending: no workstation plan/probe executed |
| L3 | BLOCKED: no deployment approval; release-specific OR-3P3/recovery audit pending |
| L4 | Pending: no real apply/trust/SSSD/getent/GPO/idempotence acceptance |
| L5 | Pending: synthetic negatives only |

PC type: none; neither configured nor new disposable PC participated. No first-join or installed-app acceptance claimed.

## Continuation and publication

Operator selects registered UUID/hostname, existing employee, exact approved OU, profiles and read-only/idempotent or disposable end-to-end scope. After code/CI and approved guarded deployment, follow docs/ALT_OPERATOR_SETUP_CLI.md, compare plan bindings, confirm SHA, inspect status and verify. Reboot/login require separate approval. Preserve all state on failures.

Implementation commits: `3ff6a77f14be43e58493f8496faf5658cf6ffb2f` (baseline fixture/module isolation), `a5dd3f4de5a50a2d4c1b8daea179142710a88164` (AD/Setup runtime, CLI, tests, operator documentation), `fa7e4893aa49472e149cd5d49be8f284608df912` (additional concurrency/identity regressions). The publication SHA also contains this report and the implementation checklist. Read [GitHub Actions](https://github.com/BorisDruzak/web_ovpn/actions) for that exact SHA; no green full-CI claim is made while independent failures remain. Publication evidence and exact-SHA run results are reported in the accompanying delivery message. No controller install is claimed.
