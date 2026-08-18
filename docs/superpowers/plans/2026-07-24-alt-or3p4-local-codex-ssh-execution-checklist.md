# ALT OR-3P4 Local Codex SSH Gate Checklist

This checklist is a concise operator view. It does not replace the execution plan or mandatory review notes.

- [ ] Local POSIX/WSL2 shell, clean repository, OpenSSH and approved key available.
- [ ] Controller host key pinned and verified out of band.
- [ ] Existing issue-30 RED/GREEN history verified on `192.168.100.17` and pushed to GitHub.
- [ ] Issue-30 PR reviewed, CI green, explicitly approved, and merged.
- [ ] Ten controller-only test-harness failures reproduced on the unchanged merge.
- [ ] Portability fix changes only the three named test files.
- [ ] Exact ten tests and complete `tests/alt_linux` pass as real `altserver` on the controller.
- [ ] Portability PR reviewed, CI green, explicitly approved, and merged.
- [ ] Exact rollout merge SHA fetched into a clean detached controller worktree.
- [ ] Complete controller ALT suite and syntax checks pass before runtime mutation.
- [ ] Active jobs, pending registrations, processor, transient jobs, rollout, and restore gates are clear.
- [ ] Existing failed rehearsal evidence is preserved and marked non-reusable.
- [ ] Exact merged backup tool installed and source hash verified.
- [ ] One fresh backup created, verified once, rehearsed once, and checked with `rehearse-status`.
- [ ] Protected controller state inventoried by path, metadata, size, and SHA-256.
- [ ] Human approves the exact control-plane install command and rollback ID.
- [ ] Installer exits `0`; readiness, Vault, permissions, and unit states are healthy.
- [ ] Protected pre/post inventories are identical.
- [ ] Every installer-managed source file matches the exact rollout worktree by SHA-256.
- [ ] Old failed rehearsal tree removed safely; old bundle and diagnostics retained.
- [ ] New disposable workstation accepted end to end; reference workstation untouched.
- [ ] Repeat provisioning is rejected.
- [ ] Sanitized rollout closure PR passes CI and is merged.
