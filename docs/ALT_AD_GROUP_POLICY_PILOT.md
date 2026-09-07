# ALT Pilot: Yandex Browser and Group Policy

Ansible installs the approved Yandex Browser RPM only. It does not create
browser policy JSON, preferences, extension settings, or user profiles.

The GPO `ALT - Yandex Browser - Pilot` is linked only to:

```text
OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local
```

Browser settings are changed in that GPO, never in Ansible files.

Pilot acceptance has two independent checks:

```bash
rpm -q yandex-browser-stable
rpm -q --qf '%{VERSION}-%{RELEASE}\n' yandex-browser-stable
```

After a domain-user login, open `browser://policy` and confirm that only
deliberately configured policies from the Pilot GPO are present.
