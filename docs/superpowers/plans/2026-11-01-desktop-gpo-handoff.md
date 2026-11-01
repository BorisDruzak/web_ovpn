# Desktop shortcuts and Nextcloud GPO handoff

> Execute inline with executing-plans. Run a fresh whole-branch review before publication.

**Goal:** Test and then deploy GPO ownership of application launchers and Nextcloud
autostart on the explicitly selected ALT workstation only.

**Architecture:** Use a computer-filtered GPO and the client's native machine-to-user
shortcut mechanism. Verify existing and future-profile behavior before handoff.
A root-owned per-machine receipt lets the Ansible role verify GPO provenance and
effective launchers without rewriting them. Unmigrated machines retain their current
behavior. Preserve personal network-folder processing and package installation.

**Tech stack:** ALT gpupdate 0.16.1, native GPP Shortcuts XML, AD GroupPolicy,
Ansible Core 2.18, Python standard library, pytest.

**Spec:** User request in this chat: test first; migrate shortcuts and Nextcloud
autostart; deploy only after successful testing; restrict to the selected computer.

## Constraints and review focus

- Preserve launcher commands, icons, localization, ownership and unrelated desktop files.
- Verify computer-only scope also covers user-context refreshes without affecting another PC.
- Detect client limitations by isolated native-GPO probes before changing production launchers.
- Back up current files and each changed client module before live testing.
- Never silently return to Ansible ownership if a migration receipt is invalid or GPO is missing.
- A successful verifier must not depend on byte equality with distro launchers after GPO edits.
- Preserve network-folder ACL checks, Nextcloud account data, the running user session and UNKNOWN jobs.
- Publish source to main and deploy the controller only through native maintenance/backup/rehearsal/install gates.

## Tasks

- [x] Prove native shortcut delivery, machine merge, autostart destinations and recreation in an isolated pilot probe.
- [x] If a client defect is reproduced, add a failing behavioral regression test and apply the smallest backed-up correction on the pilot.
- [x] Add failing tests for migrated/unmigrated ownership, wrong machine/GPO, missing launchers and unsafe profiles.
- [x] Implement a read-only ownership verifier and condition only the legacy launcher/autostart writes.
- [x] Update native component verification to accept verified GPO-owned launcher semantics.
- [x] Exercise the real role on temporary paths and then on the pilot; demonstrate repeated Ansible runs do not rewrite GPO edits.
- [x] Complete the scoped live GPO, verify machine/user cycles and launcher/autostart execution behavior.
- [x] Review, publish, create/verify/rehearse a fresh controller backup and deploy the exact tested revision.
- [x] Repeat live acceptance after deployment, retain rollback evidence and clean up only temporary probes.

## Execution ledger

- Source baseline: e44f3a988b6829bda40bad8d0a301c297c3ac81c; existing unrelated screenshots remain in the original checkout.
- Ansible catalogue and native client code inspected. The current shortcut applier supports ShortcutsMerge; its behavior must be tested rather than inferred from module presence.
- User confirmed that deployment remains limited to the selected workstation.
- Ruling: repair the pilot's native shortcut merge before handoff. Five of six behavioral cases failed: URL type, icon/comment, UID, disabled state and lifecycle flags were discarded. A backed-up minimal correction made all six pass; no other computer was patched.
- Native computer-filtered probe created both application and per-user home URL shortcuts in skel and the existing profile, with correct icons and ownership.
- Ownership and real Ansible write-boundary tests passed. The native component collector now delegates only to a fixed root-protected read-only verifier whose SHA matches the published role source.

- Live acceptance: all seven missing user files were recreated by native refresh; a central GPO name edit was applied and preserved by a repeated Ansible run (changed=0). All 14 skel/profile file hashes and metadata stayed unchanged through the ownership test. The native component probe returned ready=true.
- Nextcloud desktop entry validation and the isolated systemd XDG generator produced its autostart unit. The running session was preserved; a real logout/new login was not performed.
- Verification before publication: focused Linux tests 76 passed; remaining panel tests 3099 passed, 21 skipped. Whole-branch review findings were corrected with regression tests; no Important/Critical findings remain. Native installer will execute the full ALT suite before mutation.

- Final acceptance: native installer deployed 7019132b7151945e5da1de12d98804eb1458ca85 and returned exit 0 after 4336 ALT tests passed (143 skipped). The coordinated rollback generation was created, verified and rehearsed with all 11 rehearsal checks passing.
- Compatibility rulings: pre-install observation of an older role grants no GPO helper execution pin; the isolated inherited-link fixture explicitly declares Ansible ownership. Reproduced failures were corrected and the complete native suite rerun successfully.
- Post-install acceptance: deployed Ansible reported changed=0 and preserved all 14 managed files including contents, timestamps, permissions, owners and groups. The deployed native component probe returned ready=true. Fresh machine/user gpupdate completed without application or Qt errors; GPO application remained limited to the selected computer on both DCs.
- The current user session was preserved. Fresh user-file creation and the actual XDG autostart generator were tested; a real logout/new login was not performed. The backed-up client shortcut-merge correction must be rechecked after gpupdate package upgrades.
