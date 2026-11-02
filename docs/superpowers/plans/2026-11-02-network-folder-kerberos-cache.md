# Network-folder Kerberos cache repair

**Goal:** Repair the optional network-folder probe and create the selected user's links without repeating full Setup.

**Scope:** Keep AD/NTFS permissions, personal desktop files, browser state and historical Setup records intact. Publish only the verified fix. Deploy only the changed controller helper with a retained rollback copy while the native lifecycle lock excludes concurrent target work.

## Steps

- [x] Reproduce Samba 4.21 failure with `-N` and verify read access using the user's cache.
- [x] Add regression coverage for KEYRING/FILE caches and missing cache evidence; observe expected failures.
- [x] Select the cache reported by the verified `klist`, pass it explicitly, and remove `-N`.
- [x] Run focused Python and real Ansible integration tests on Linux.
- [x] Back up and atomically replace the one controller helper after exact preimage/hash and quiescence checks.
- [x] Run only the optional network-folder Ansible tasks for the selected workstation; verify URL ownership/access and a second unchanged run.
- [x] Review, commit and publish task files; record runtime evidence outside Git without credentials.

## Verification

- Windows focused tests: 29 passed; Linux focused Python and real Ansible integration tests: 34 passed.
- Installed role: first scoped run changed one task and verified two links; second run returned changed=0, failed=0, rescued=0.
- Both desktop URLs passed SMB directory reads and noninteractive KDE/KIO metadata queries in the selected user's graphical session.
- Original Setup job files and native job list were unchanged. No full Setup, reboot, AD permission change or browser restart was performed.
- Initial scoped operator playbook encountered a vars-file login override and stopped before changes; the corrected scoped playbook passed both runs. Controller rollback copy and operational receipts are retained outside Git.
