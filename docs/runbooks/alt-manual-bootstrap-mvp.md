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
  http://192.168.100.17:8087/bootstrap/bootstrap.sh \
  -o /tmp/alt-bootstrap.sh && \
sudo env no_proxy=192.168.100.17 NO_PROXY=192.168.100.17 \
  bash /tmp/alt-bootstrap.sh
```

The local sudo prompt is the only place where the pilot local-administrator password is entered. Do not put it in a command, file, request or log.

Domain join and software installation are controller-only.

## Controller handoff

After registration is ready, an authorized controller operator runs preflight, preview and configuration as the `altserver` service account. Controller state is owned by `altserver`; running these commands as root can create files that the service account cannot access. The workstation operator does not run Ansible, `system-auth`, or any domain join command.

```bash
sudo -u altserver /usr/local/sbin/workstationctl preflight <machine-uuid>
sudo -u altserver /usr/local/sbin/workstationctl configure preview <machine-uuid> --vars-file <request.json>
sudo -u altserver /usr/local/sbin/workstationctl configure start <machine-uuid> --vars-file <request.json>
```

## Pilot acceptance

1. Confirm controller endpoints from the workstation:

   ```bash
   curl --noproxy '*' -fsS http://192.168.100.17:8087/health
   curl --noproxy '*' -fsS http://192.168.100.17:8088/health
   ```

2. Run the manual bootstrap command once and record only its exit status and registration UUID.
3. Run the same command a second time. It must exit zero and print either `Machine registration completed` or `Machine already registered`.
4. On the controller, verify the machine is ready:

   ```bash
   sudo -u altserver /usr/local/sbin/workstationctl machines list
   sudo -u altserver /usr/local/sbin/workstationctl preflight <machine-uuid>
   ```

5. Do not run `configure start` until preview shows the expected UUID and target IP.

Live pilot acceptance is pending a user-designated disposable workstation or VM. Do not select, repurpose, or wipe a target for this checklist without that designation.

## Recovery

The bootstrap is safe to rerun after a transient download, network, or controller-registration failure. A rerun does not repair intentionally deleted SSH keys or sudoers files; restore those through the approved controller process before rerunning.

## Security

HTTP without SHA-256 verification is accepted only for this trusted pilot network. Do not use this manual path outside `192.168.100.0/23`.
