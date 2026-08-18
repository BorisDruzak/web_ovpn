# Gov74 DNS Self-Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent a temporary DNS failure from exhausting the Gov74 AnyConnect systemd restart limit.

**Architecture:** A root-owned pre-start script waits until `vpn-ra.gov74.ru` resolves to IPv4. A systemd drop-in runs it before the existing OpenConnect wrapper and permits that wait to outlive the default start timeout. The installer deploys only these assets and reloads systemd; it does not restart unrelated VPN services.

**Tech Stack:** POSIX shell, systemd, pytest.

**Spec:** `docs/superpowers/specs/2026-08-18-gov74-self-recovery-design.md`

## Global Constraints

- Preserve the existing Gov74 OpenConnect command, credentials, `cisco0` name, egress guard, output guard, and routes.
- Do not create unbounded authentication retries against Gov74.
- Treat a missing DNS record as a waiting condition, not an OpenConnect failure.
- Deploy only after repository tests and `systemd-analyze verify` pass.

---

### Task 1: Test and implement DNS waiting

**Files:**
- Create: `tests/test_deploy_gov74_dns_wait.py`
- Create: `deploy/gov74-wait-dns.sh`
- Create: `deploy/gov74-anyconnect-dns-wait.conf`
- Modify: `deploy/install-openvpn-web.sh`

- [x] Write a failing pytest contract for the script, drop-in, and installer.
- [x] Run it and confirm the expected missing-asset failures.
- [x] Implement the smallest DNS pre-start mechanism and installer wiring.
- [x] Run the focused pytest checks and shell syntax validation.

### Task 2: Deploy and validate

**Files:**
- Create on server: `/usr/local/sbin/gov74-wait-dns`
- Create on server: `/etc/systemd/system/gov74-anyconnect.service.d/dns-wait.conf`

- [x] Copy only verified assets to the server.
- [x] Run `systemctl daemon-reload` and `systemd-analyze verify gov74-anyconnect.service`.
- [x] Confirm the connected tunnel stays active with `cisco0` present.
