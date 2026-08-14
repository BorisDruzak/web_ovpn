# Yandex Profile Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export and restore a full Yandex Browser profile with a user-controlled browser-close pause and verifiable controller storage.

**Architecture:** A Bash collector owns interactive SSH and archive creation; a Python launcher reads only READY manifests; a fixed Ansible playbook performs target validation and atomic restore.

**Tech Stack:** Bash, OpenSSH, tar/zstd, Python 3, Ansible, RPM.

## Global Constraints

- Never persist or print an SSH password.
- Do not signal the source or target browser; wait for normal closure.
- Copy the full profile except `SingletonLock`, `SingletonSocket`, `SingletonCookie`.
- Publish migration data only after SHA-256 verification and `READY`.
- Preserve the target profile before replacement.

### Task 1: Add failing asset tests

- [ ] Add tests that require strict SSH, an interruptible browser-close wait, stream archiving, checksum/READY publication, and a fixed Ansible restore path.
- [ ] Run the tests and observe missing-script failures.

### Task 2: Implement collector and launcher

- [ ] Add `collect-yandex-profile.sh` and `restore-yandex-profile.py`.
- [ ] Verify shell syntax, Python compilation and asset tests.

### Task 3: Implement Ansible restore role

- [ ] Add fixed playbook and role with checksum validation, pre-migration backup, staging and atomic replacement.
- [ ] Verify Ansible syntax and role-asset tests.

### Task 4: Install and canary-test

- [ ] Install the utilities through the guarded controller installer.
- [ ] Run a collector and restore on explicitly selected test source and target machines.
