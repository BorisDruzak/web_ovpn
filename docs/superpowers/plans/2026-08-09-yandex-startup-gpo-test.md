# Yandex Browser Startup GPO Pilot Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify managed Yandex Browser startup-page policy delivery from the existing Pilot AD GPO to `alt-a1-pc2`.

**Architecture:** The existing computer GPO writes the ADMX-defined registry values in `Software\Policies\YandexBrowser`. ALT `gpupdate` translates the GPO to the browser managed-policy JSON; the browser exposes it at `browser://policy`.

**Tech Stack:** Windows Server Group Policy, YandexBrowser.admx Central Store, ALT `gpupdate`, Yandex Browser.

## Global Constraints

- Modify only `ALT - Yandex Browser - Pilot`, already linked to the Pilot OU.
- Do not create Ansible browser-policy files or change non-Pilot GPOs.
- Keep the test policy until the user explicitly requests removal.

---

### Task 1: Back up and populate the Pilot GPO

**Files:**
- Create: a timestamped GPO backup on AD-MAIN.
- Modify: AD GPO `ALT - Yandex Browser - Pilot`.

- [ ] **Step 1: Export the current GPO before mutation**

```powershell
Backup-GPO -Name 'ALT - Yandex Browser - Pilot' -Path C:\GPO-Backups\ALT-Yandex-startup-test
```

- [ ] **Step 2: Write managed startup values from the installed ADMX contract**

```powershell
$key = 'HKLM\Software\Policies\YandexBrowser'
Set-GPRegistryValue -Name 'ALT - Yandex Browser - Pilot' -Key $key -ValueName RestoreOnStartup -Type DWord -Value 4
Set-GPRegistryValue -Name 'ALT - Yandex Browser - Pilot' -Key "$key\RestoreOnStartupURLs" -ValueName 1 -Type String -Value 'https://portal.dom.gosuslugi.ru/'
```

- [ ] **Step 3: Verify GPO report contains both values**

```powershell
[xml](Get-GPOReport -Name 'ALT - Yandex Browser - Pilot' -ReportType Xml)
```

### Task 2: Refresh and verify the ALT pilot

**Files:** No repository source changes.

- [ ] Force computer policy update on `alt-a1-pc2` with `gpupdate --target Computer --system --force`.
- [ ] Verify `/etc/opt/yandex/browser/policies/managed/policies.json` contains `RestoreOnStartup` and the approved URL.
- [ ] Restart the test user's browser and verify the values appear as enforced in `browser://policy` and the URL opens at startup.
