# gpupdate compatibility playbook implementation plan

> Execute inline with executing-plans; use TDD and one final whole-change review.

**Goal:** Deliver a standalone Ansible playbook for the three proven gpupdate client fixes and make new ALT Setup apply them before the first policy refresh.

**Architecture:** A shared protected role runs a self-contained, hash-gated Python patch helper. It accepts only the inspected RPM/module baseline, plans all changes before mutation, backs up exact original bytes and metadata, writes atomically, and supports guarded rollback. The existing prerequisites role invokes it after package installation; the client role rechecks it before enabling/applying GPO. The standalone playbook is limited to one explicitly selected inventory host per invocation.

**Tech stack:** Ansible Core 2.18.6, Python standard library, ALT gpupdate/gpoa-lib 0.16.1-alt1, pytest.

**Spec:** User request in this chat: add the existing gpupdate fixes to Ansible, support a separate playbook, test first on the existing pilot, and prepare new ALT installations automatically.

## Constraints and review focus

- Preserve the running session, existing GPO settings, browser/Nextcloud state, domain membership and UNKNOWN history.
- Include serviceAction setter, headless KDE/Qt handling and machine-to-user shortcut metadata fixes.
- Do not guess at changed/newer source files or overwrite unknown patches; reject before the first write.
- Check mode must predict without modifying client modules or creating backup/lock state.
- A fully fixed client must be a no-op; unsupported versions, unsafe paths, concurrent package/GPO operations, partial failure and rollback must be tested.
- Do not revert working pilot modules to broken code for testing; use original module copies in an isolated tree, then run the real standalone playbook on the live pilot.
- Normal Setup uses the same role before policy application; do not add an unrestricted catalog component or bypass controller guards.
- Publish verified work to main; controller deployment uses fresh native backup/verify/rehearsal and installation gates. Existing computers receive no mass execution.

## Tasks

- [x] Capture and verify original/patched source identities and write failing patch/transaction/behavior tests.
- [x] Implement the shared helper, backup/rollback and standalone role/playbook with red/green evidence.
- [x] Integrate prerequisites and pre-application checks; verify the normal workflow contracts.
- [x] Run focused and broad tests, and review the complete change.
- [x] Test isolated original modules, check mode and repeated live playbook runs on the pilot; verify machine/user gpupdate and current GPO outputs.
- [x] Publish, deploy the exact verified controller revision with native rollback gates, and repeat acceptance from the deployed playbook.

## Execution ledger

- Baseline: 9a42eeaa111dcfa3fe87317e0b7b423f21b34bcc. Reusing the clean attached worktree on codex/gpupdate-client-fixes.
- Read-only capture confirmed the three original and patched module SHA256 identities and installed gpupdate/gpoa-lib 0.16.1-alt1. Controller Ansible is 2.18.6.
- Ruling: retain standalone patching and policy refresh as separate operations. New installations need repairs before domain join; a patch playbook must not trigger join, apply unrelated GPOs or restart a user session.
- Red/green: initial helper tests failed before implementation; unknown source, unsafe paths/versions, rollback metadata, post-rename write failure and real standalone variable loading regressions were reproduced and corrected. Focused integration suite: 161 passed; strengthened final helper/real-Ansible suite: 30 passed.
- Review: no remaining Important/Critical findings after adding the standalone vars_files import and its real-Ansible boundary regression.
- Pilot acceptance before publication: three original modules were repaired and rolled back in an isolated root using actual RPM-owner/version checks. Live --check and both standalone applications reported changed=0; working module hashes/timestamps were unchanged. Machine gpupdate and user service succeeded with application/Qt errors=0; desktop GPO verifier remained ready.

- Final readability regression: a matching module with root-only read permissions is rejected before mutation. Red/green witnessed; final helper/real-Ansible suite 31 passed and follow-up review found no Important/Critical issues.
- Final verification: 3099 panel tests passed (21 skipped); native installer ran 4367 ALT tests successfully (143 skipped) and installed 95b3421af35c85ab13447f653acce140b8661ab4 with exit 0 after fresh backup creation, verification and all 11 rehearsal checks.
- Deployed acceptance: all six changed runtime/role/playbook files match published source. Installed standalone --check and both apply runs reported changed=0, failed=0 and all three fixes already_fixed. Original live module hashes/timestamps stayed unchanged. Fresh machine/user policy cycles succeeded without application/Qt errors; desktop GPO verification remained true.
- Managed controller units are active and rollout guard is clear. Queue is empty and retained UNKNOWN/legacy history is unchanged. Only the selected pilot was executed; a fresh OS installation was not performed.
