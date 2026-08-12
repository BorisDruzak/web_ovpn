# Manual ALT bootstrap MVP

This temporary pilot path starts after a manual ALT Workstation K 11.x installation. It does not replace managed ISO or legacy `ai curl=` autoinstall.

## Preconditions

- The computer is on trusted provisioning network `192.168.100.0/23`.
- ALT Workstation K 11.x is already installed manually.
- The operator created and can use local administrator `osn-admin`.
- A default route reaches `192.168.100.17`.

## Run on the workstation

```bash
curl --noproxy '*' -fsS --connect-timeout 5 --max-time 30 \
  http://192.168.100.17:8087/bootstrap/start-bootstrap.sh \
  -o /tmp/start-alt-bootstrap.sh && \
bash /tmp/start-alt-bootstrap.sh
```

The launcher elevates interactively: through `sudo` when it is installed, or through the standard ALT `su` root prompt on a clean installation. The root password created during ALT installation is required only for that first `su` prompt. Do not put either password in a command, file, request or log.

Domain join and software installation are controller-only.

## Controller handoff

Before the local command, an authorized controller operator creates one
strict request file named for the registered machine UUID in the private
configure-requests directory. The file contains hostname, hostname mode,
profile, domain values, OU and test user only; it contains no password,
controller secret or key.

After registration, the controller automatically runs preflight, preview and configuration as the altserver service account. It loads only the file whose
name exactly matches the registered UUID, requires preview UUID and target IP
to match registration, and then invokes the fixed configuration playbook.

Controller state is owned by altserver; the workstation operator does not run Ansible, system-auth or any domain join command.

preview is non-mutating: it validates the request and registration only. It
does not test the target hostname, DNS, NTP or AD connectivity.

The request contains no passwords, service credentials or key values. Its hostname must match
^(lin|alt|win|deb)-[a-z][0-9]?-(pc[1-9][0-9]*)$, for example alt-a1-pc3.
Use hostname_mode verify to require that the installed hostname already equals
final_hostname. Use hostname_mode change_confirmed only when an approved rename
is required. The computer OU is always
OU=Pilot,OU=Linux,OU=Устройства,DC=sosnadmin,DC=local.

## Pilot acceptance

1. Confirm controller endpoints from the workstation:

   ```bash
   curl --noproxy '*' -fsS http://192.168.100.17:8087/health
   curl --noproxy '*' -fsS http://192.168.100.17:8088/health
   ```

2. Run the manual bootstrap command once and record only its exit status and registration UUID.
3. Run the same command a second time. It must exit zero and print either `Machine registration completed` or `Machine already registered`.
4. On the controller, verify that the registration progressed to configured
   or, when request creation is intentionally deferred, awaiting_assignment:

   ```bash
   sudo -u altserver /usr/local/sbin/workstationctl machines list
   ```

5. The workstation operator does not run controller commands. The worker
   checks preview UUID and target IP before it starts configuration.

6. After a successful new join, reboot the station and sign in once with the
   existing domain user. Confirm the SSSD lookup works and the user's home
   directory was created automatically.

Live pilot acceptance is pending a user-designated disposable workstation or VM. Do not select, repurpose, or wipe a target for this checklist without that designation.

## Recovery

The bootstrap is safe to rerun after a transient download, network, or
controller-registration failure. It reconciles its own ansible SSH key,
sudoers file and SSH service on each run. If the controller is unavailable
after technical setup, a local persistent timer retries registration every
five minutes; it never performs domain join locally.

## Security

HTTP without SHA-256 verification is accepted only for this trusted pilot network. Do not use this manual path outside `192.168.100.0/23`.
