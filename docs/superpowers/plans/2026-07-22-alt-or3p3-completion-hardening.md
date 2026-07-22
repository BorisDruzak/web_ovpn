# ALT OR-3P3 Completion Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Every behavior change follows RED, GREEN and neighboring regression.

**Goal:** Complete OR-3P3 Tasks 10-13 and close the restore, rollout, installer and static-serving safety findings.

**Architecture:** Extend the independent backup package with a durable recoverable restore state machine, private rollout guard state and bounded audit. Add a bootstrap-safe backup installer, gate the control-plane installer on one exact rehearsed backup, and replace the root static file server with an allowlisted unprivileged server.

**Tech Stack:** Python 3 standard library, Bash, systemd, GNU tar, zstd and pytest.

## Tasks

1. Durable restore journal, per-path progress, `aborted`, common rollback and `recover <restore-id>`.
2. Per-filesystem restore capacity preflight and secret-free CLI audit.
3. Persistent rollout marker, ephemeral permits, guard command and guard systemd unit.
4. Dedicated backup-tool installer and exact `--rollback-backup-id` control-plane gate.
5. Allowlisted unprivileged static provisioning server with no-follow non-blocking file reads.
6. Operator runbook, synchronized context, full verification evidence, temporary workflow cleanup and draft PR update.

## Global constraints

- No live controller or workstation access during repository work.
- No secret contents in archives, logs, JSON, fixtures or CI artifacts.
- Restore remains all-component, same-controller and explicit.
- No automatic backup selection, retention, deletion or live restore.
- Do not merge PR #24 without explicit user confirmation.
