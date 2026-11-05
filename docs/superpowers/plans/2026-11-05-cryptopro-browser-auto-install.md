# CryptoPro browser automatic installation implementation plan

> **For agentic workers:** Use superpowers:executing-plans inline.

**Goal:** Install the current CryptoPro browser extension automatically on the next workstation.
**Architecture:** Separate exact ExtensionSettings policy, read-only ownership/conflict guard, independent native-origin/readback checks; preserve GosPlugin/GPO ownership.
**Tech Stack:** Python standard library, Ansible core 2.18, ALT Linux, Yandex Browser.
**Spec:** docs/superpowers/specs/2026-11-05-cryptopro-browser-auto-install.md

## Constraints and review focus

- Fixed Opera extension ID and HTTPS update URL; never restore the removed Chrome ID.
- Preserve all unrelated policy, GosPlugin and GPO handoff, user profiles and UNKNOWN history.
- Refuse customized owned files, duplicate JSON keys, competing ExtensionSettings, unsafe filesystem entries and conflicting same-ID update URLs.
- Native origin must match before policy publication; missing browser download is pending, not installed.
- Test both local/GPO GosPlugin sources and repeated application; verify a fresh isolated profile before freezing source.

## Task 1: Guard, automatic policy and regression

- [ ] Write failing pure guard and real Ansible-slice tests.
- [ ] Run RED using the shared ALT runner.
- [ ] Add read-only policy guard and role tasks, independent readback/native-origin assertions.
- [ ] Run focused tests and isolated browser acceptance; preserve profile isolation and global policy.
- [ ] Update operator guide; review complete diff and one final branch review.
- [ ] Freeze source; run one full ALT suite, commit/publish main and canonical guarded deployment.
- [ ] Record actual installed checks, restore service state and retain audit evidence.
