# ALT install production release PR5b implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a verified immutable managed ISO to Proxmox `pve2` (`10.83.1.12`) targeting the deployed API at `192.168.100.17:18090` and embedding only its public verification key.

**Architecture:** Parameterize the existing ISO builder with an embedded controller URL and prove equality in initrd, GRUB and sidecar. A root-only Proxmox builder stages an exact merged commit privately, builds the static helper, verifies all artefacts, then atomically publishes an ISO, sidecar and canonical non-secret index. PR5c alone may change VM 114.

**Tech Stack:** Bash, Python standard library, Go 1.22, xorriso, pytest.

## Global constraints

- `:18090` is the only PR5b release controller; `:18089` remains QEMU-fixture-only.
- Source SHA-256 is `2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf784e8f9388243a`.
- Build host uses only canonical public-key JSON; it never receives, prints, copies or logs PEM, credentials, sessions or plans.
- Release ID is exactly `YYYYMMDDTHHMMSSZ-<7..12 lowercase hex>`; ISO, sidecar and index entry never overwrite existing content.
- Private staging is mode `0700`; publication is same-filesystem `mv` after complete verification.
- PR5b does not change VM 114, disks, Alterator, `install2.target`, partitioning, reboot, service state, key lifecycle or release retention.

---

### Task 1: Parameterize controller URL in managed ISO

**Files:**
- Modify: `deploy/alt-linux/iso/agent-v1/build-managed-iso.sh`
- Modify: `deploy/alt-linux/iso/agent-v1/verify-managed-iso.sh`
- Modify: `deploy/alt-linux/iso/agent-v1/boot-menu/grub.cfg.patch`
- Modify: `deploy/alt-linux/install-agent/v1/lib/config.sh`
- Modify: `tests/test_alt_install_agent_v1.py`, `tests/test_alt_install_agent_v1_qemu.py`

**Interfaces:** Builder gains required `--controller-url URL`; it accepts only `http://192.168.100.17:18089` and `http://192.168.100.17:18090`, writes `usr/share/alt-install/controller-url`, sets sidecar `controller_url`, and substitutes the GRUB placeholder. Agent configuration requires the command-line URL equal the embedded URL.

- [ ] **Step 1: Write a failing test** — assert builder contains `--controller-url` and `__ALT_INSTALL_CONTROLLER_URL__`; assert config references `/usr/share/alt-install/controller-url`; assert verifier requires the sidecar field, mode `0644`, initrd asset and equal GRUB value.
- [ ] **Step 2: Run red** — `python -m pytest -q tests/test_alt_install_agent_v1.py -k controller`; expect failure because `:18089` is hard-coded.
- [ ] **Step 3: Implement minimally** — validate URL with a two-value `case`; write one newline-terminated initrd asset; substitute only `__ALT_INSTALL_CONTROLLER_URL__`; include asset in payload/mode/sidecar verification; make QEMU harness supply fixture `:18089` explicitly.
- [ ] **Step 4: Run green** — `python -m pytest -q tests/test_alt_install_agent_v1.py tests/test_alt_install_agent_v1_qemu.py`.
- [ ] **Step 5: Commit** — stage exact builder, verifier, boot patch, config and tests; commit `feat(alt-install): parameterize managed ISO controller`.

### Task 2: Private Proxmox builder and immutable release index

**Files:**
- Create: `deploy/alt-linux/release/build-managed-iso-release.sh`
- Create: `deploy/alt-linux/release/lib/release-contract.py`
- Create: `tests/test_alt_install_agent_v1_release.py`

**Interfaces:** `build-managed-iso-release.sh --source-commit COMMIT --source-iso PATH --public-key PATH --release-id ID --iso-dir DIR --go GO` emits `alt-kworkstation-11.4-agent-v1-ID.iso`, its `.build-manifest.json` and `alt-install-agent-v1-releases.json`. Canonical index fields: `schema_version`, release ID, commit, source ISO SHA-256, managed ISO SHA-256, helper SHA-256, public key ID and creation time.

- [ ] **Step 1: Write failing tests** — invalid IDs (`bad`, uppercase hash, 6 or 13 hex), fixture `:18089`, existing ISO/sidecar/index ID, malformed index, cross-device stage and secret-like output names all fail closed. Fake git/go/builder/verifier proves private stage, sidecar-before-index validation and atomic same-directory moves.
- [ ] **Step 2: Run red** — `python -m pytest -q tests/test_alt_install_agent_v1_release.py`; expect absent-command failure.
- [ ] **Step 3: Implement minimally** — require regular non-symlink inputs and `git rev-parse --verify "$commit^{commit}"`; export only that commit privately; run `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$go" build -trimpath -buildvcs=false -ldflags='-buildid='`; invoke checked-out ISO builder with `:18090`; invoke verifier; validate exact sidecar fields in `release-contract.py`; use `mv -n` for ISO/sidecar and atomic replacement for regenerated canonical index.
- [ ] **Step 4: Run green** — `python -m pytest -q tests/test_alt_install_agent_v1_release.py tests/test_alt_install_agent_v1.py tests/test_alt_install_agent_v1_qemu.py`.
- [ ] **Step 5: Commit** — stage exact release files/tests; commit `feat(alt-install): add immutable Proxmox ISO release builder`.

### Task 3: PR5b operational contract and merge-gated release

**Files:**
- Create: `docs/runbooks/alt-install-production-release-pr5b.md`
- Modify: `docs/superpowers/specs/2026-07-28-alt-install-production-deployment-design.md`
- Modify: `tests/test_alt_install_agent_v1_release.py`

**Interfaces:** Runbook consumes merged commit, `/var/lib/vz/template/iso/alt-kworkstation-11.4-install-x86_64.iso`, public JSON and a fresh release ID; it produces only ISO/sidecar/index evidence.

- [ ] **Step 1: Write a failing runbook test** — require `192.168.100.17:18090`, text that a private key must never be copied, `pve2`, and text that VM 114 must not be changed.
- [ ] **Step 2: Run red** — `python -m pytest -q tests/test_alt_install_agent_v1_release.py -k runbook`; expect missing runbook.
- [ ] **Step 3: Implement documentation** — correct design hostname `pve1` to observed `pve2`; require source identity, public-key-only transfer, sidecar/index verification and explicitly defer VM 114 to PR5c.
- [ ] **Step 4: Full verification** — `python -m pytest -q`; run `git diff --check origin/main...HEAD`.
- [ ] **Step 5: Publish and accept** — push ready PR, wait green CI, merge, then publish one fresh uniquely named release with the runbook. Do not touch VM 114.

## Self-review

Task 1 closes the `:18089`/`:18090` incompatibility. Task 2 supplies public-key-only fixed-point build, immutable output and index. Task 3 records pve2-correct merge-gated operation. The plan has no VM or target-disk mutation.
