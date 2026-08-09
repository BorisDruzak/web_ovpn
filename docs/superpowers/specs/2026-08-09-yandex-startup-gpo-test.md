# Yandex Browser startup GPO pilot test

## Goal

Verify delivery of a Yandex Browser Group Policy from Windows AD to ALT pilot workstations without using Ansible for browser settings.

## Scope

The existing `ALT - Yandex Browser - Pilot` computer GPO, linked only to `OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local`, receives two managed values:

- `Software\Policies\YandexBrowser\RestoreOnStartup` as DWORD `4`.
- `Software\Policies\YandexBrowser\RestoreOnStartupURLs\1` as the URL `https://portal.dom.gosuslugi.ru/`.

The pilot `alt-a1-pc2` receives a forced computer GPO refresh. Verification requires non-empty browser managed-policy JSON and the same values in `browser://policy` after the browser is restarted.

## Constraints

- No Ansible browser policy file is created or changed.
- No GPO outside the Pilot OU is changed.
- The test policy remains in the Pilot GPO until the user explicitly requests removal.
