# PR5a install-session API rollout and evidence

This runbook deploys only the independently installed
`alt-install-session.service` on `192.168.100.17:18090`.  It consumes a
successful OR-3P3 backup ID and a named commit already merged to `main`.
It does not authorize a production installation or any change outside this
new service and its staged runtime.

## Safety boundary

Port `18089` is the disposable ISO-spike fixture port and must not be reused,
stopped, reconfigured, or contacted by this rollout.  All existing
`alt-deploy-*` services are out of scope and must not be started, stopped,
enabled, disabled, restarted, or reconfigured.

ISO builds, Proxmox, VM 114, installer handoff, Alterator, partitioning, and
every target-disk write are out of scope.  Do not build an ISO, attach a VM,
or access a target disk while carrying out this runbook.

The private key at
`/var/lib/alt-deploy-secrets/install-plan-ed25519.pem` must never be printed,
copied, redirected, or included in evidence.  Record only the public key ID.

## Preconditions and rollout

Run these commands on the controller as an authorized operator.  Substitute a
successful OR-3P3 `BACKUP_ID` and a named merged `COMMIT`; retain the command
exit status and the non-secret output named in [Evidence](#evidence).

```bash
/usr/local/sbin/alt-deploy-backup rehearse-status BACKUP_ID
git rev-parse --verify COMMIT^{commit}
git fetch origin main
test "$(git rev-parse --verify HEAD^{commit})" = "$(git rev-parse --verify COMMIT^{commit})"
git merge-base --is-ancestor COMMIT refs/remotes/origin/main
git status --short --untracked-files=all -- deploy/alt-linux/api deploy/alt-linux/control deploy/alt-linux/autoinstall/profiles deploy/alt-linux/systemd/alt-install-session.service deploy/alt-linux/install-install-session-api.sh
bash deploy/alt-linux/install-install-session-api.sh --source-commit COMMIT --rollback-backup-id BACKUP_ID
```

Stop at the first non-zero exit status.  The backup rehearsal must identify
the supplied backup ID as successful, and the commit verification must resolve
the intended merged commit before installation begins.

## Verification

Run the following commands after the installer returns zero.  Record each
exit status.  The `systemctl cat` output is the binding proof: its `ExecStart`
must contain `--listen-address 192.168.100.17 --listen-port 18090`; no other
binding is accepted.

```bash
systemctl cat alt-install-session.service
systemctl is-enabled alt-install-session.service
systemctl is-active alt-install-session.service
systemd-analyze security alt-install-session.service
curl --noproxy '*' --fail --silent --show-error http://192.168.100.17:18090/health
sudo -u altserver test ! -r /var/lib/alt-deploy-secrets/install-plan-ed25519.pem
stat -c '%U:%G %a %F' /var/lib/alt-deploy-secrets /var/lib/alt-deploy-secrets/install-plan-ed25519.pem /etc/alt-deploy/install-plan-ed25519.pub
python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["key_id"])' /etc/alt-deploy/install-plan-ed25519.pub
```

The public health response must be exactly this Task 1 health document:

```json
{"schema_version":1,"service":"alt-install-session","status":"ok"}
```

`systemctl is-enabled` and `systemctl is-active` must report `enabled` and
`active`.  The security analysis, private-key unreadability check, and metadata
check must all exit zero.  The `stat` output must show the private directory
and private key as root-owned modes `0700` and `0600`, and the public key as a
root-owned regular file with mode `0644`.

## Evidence

Create a reproducible, non-secret rollout record containing only:

- named merged commit and the `git rev-parse` exit status;
- successful OR-3P3 backup ID and `rehearse-status` exit status;
- public key ID printed by the final verification command;
- `systemctl cat` binding proof, `is-enabled`/`is-active` output, and their
  exit statuses;
- the exact health JSON above and the curl exit status; and
- `systemd-analyze security`, private-key unreadability, and metadata check
  exit statuses.

Do not record private-key bytes, private-key-derived text, session contents,
credentials, plans, or unrelated service output.

## Scoped rollback

If the rollout or any verification gate fails, stop and run only the new
service rollback:

```bash
bash deploy/alt-linux/install-install-session-api.sh --rollback
systemctl is-active alt-install-session.service
```

Record the rollback command exit status and the `systemctl is-active` result;
the latter must report `inactive` (and therefore normally exits non-zero).
Rollback disables only `alt-install-session.service` and restores only its
previous staged runtime.  It must preserve the signing-key pair and existing
install-session state.  Do not use rollback to change port 18089, any
`alt-deploy-*` service, ISO, Proxmox resource, VM 114, or target disk.
