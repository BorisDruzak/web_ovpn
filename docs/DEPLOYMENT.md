# Deployment Runbook

This project is deployed as a FastAPI service on the OpenVPN host. The current production host is `openvpm@192.168.100.30`, reachable from the operator workstation as:

```bash
ssh ui-vpn-deploy
```

## Repository Layout

- `app/` - FastAPI web UI, API routes, templates, static assets, auth, audit and sync helpers.
- `deploy/vpnctl` - privileged OpenVPN control CLI. The web service calls it with `--json`.
- `deploy/install-openvpn-web.sh` - installer used to copy the app to `/opt/openvpn-web`, install systemd units and configure env files.
- `mcp/openvpn_mcp_server.py` - local stdio MCP server that calls the HTTP API.
- `tests/` - smoke, API, MCP and `vpnctl` regression tests.

## First-Time GitHub Publish

The repository can be published over SSH:

```bash
git remote add origin git@github.com:BorisDruzak/web_ovpn.git
git branch -M main
git add .
git commit -m "Initial OpenVPN web manager"
git push -u origin main
```

Before committing, verify that `.gitignore` excludes local virtual environments, caches, generated `.ovpn` files, tokens, passwords and private key material.

## Local Verification

From the project root:

```bash
python -m pytest -q
```

On the Windows Codex workstation the bundled Python runtime can be used if system Python is not configured:

```powershell
& 'C:\Users\admin-2\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q
```

## Deploy To OpenVPN Host

Package and copy the local source tree:

```powershell
tar --exclude='.git' --exclude='.pytest_cache' --exclude='__pycache__' -czf "$env:TEMP\openvpn-web-src.tgz" -C "C:\Users\admin-2\Documents\ui_vpn" .
scp "$env:TEMP\openvpn-web-src.tgz" ui-vpn-deploy:/tmp/openvpn-web-src.tgz
```

Install on the host:

```bash
ssh ui-vpn-deploy "rm -rf /tmp/openvpn-web-src && mkdir -p /tmp/openvpn-web-src && tar -xzf /tmp/openvpn-web-src.tgz -C /tmp/openvpn-web-src && cd /tmp/openvpn-web-src && SUDO_PASSWORD='<sudo-password>' bash deploy/install-openvpn-web.sh"
```

Do not commit or publish the sudo password. For interactive deployment, enter it only in the shell command or through the operator's secret store.

## Remote Verification

After deployment:

```bash
ssh ui-vpn-deploy "cd /opt/openvpn-web && .venv/bin/python -m pytest -q"
ssh ui-vpn-deploy "systemctl is-active openvpn-web && systemctl is-active openvpn-server@server"
ssh ui-vpn-deploy "systemctl is-active netctl-collect.timer"
```

Useful live checks:

```bash
ssh ui-vpn-deploy "journalctl -u openvpn-web -n 100 --no-pager"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json status"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json logs -n 50"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json sources list"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json dashboard"
```

## SSH Server Draft Checks

The Test servers page verifies an existing SSH target from the gateway; it does
not enroll the target as a Network Observer collector. The observer private key
remains gateway-only and is never downloaded, displayed, copied, or stored with
the draft.

For each target:

1. Download or copy the displayed observer public key from `/network/server-drafts`.
2. Install that public key in the target account's `~/.ssh/authorized_keys`.
3. Create a server draft with the target name, host, SSH user, and port; the worker scans the target host key.
4. Compare the displayed host-key fingerprint with a trusted, out-of-band source, then confirm the fingerprint in the page.
5. Wait for the worker to complete the pinned SSH check, then read its fixed SSH result in the draft list.

Drafts only request these scan, confirmation, and pinned-check actions. They do
not add collector targets, change the target's host key, or expose host keys or
private storage beyond the fixed check result.

## SSH Server Draft Worker Handoff and Rollback

This is a deliberately narrow handoff for the SSH server-draft worker. It must
not be used to change Network Observer collection or OpenVPN. In particular,
do **not** restart OpenVPN, and do **not** create, edit, remove, test, or
otherwise modify any collector configuration, `/etc/netctl`, or
`netctl-collect` unit.

Run it only on an existing OpenVPN web deployment that already has the
`openvpn-web` and `openvpm` accounts plus the regular
`/etc/openvpn-web/server-observer.key` file. The scoped installer verifies
those prerequisites and refuses to create or modify them.

Before running the installer, make a timestamped backup containing **only**
the scoped installer-mutated assets: the draft-worker wrapper, root-owned
isolated worker runtime, both draft-worker systemd units, the path-unit
enablement symlink, the derived observer public key, the draft state directory, and the metadata of its
`/var/lib/openvpn-web` parent. The parent is archived without recursion. GNU
`cp` and `tar` preserve ownership, mode, timestamps, ACLs, xattrs, and SELinux
context. The manifest distinguishes an existing prior asset from an asset
absent before a first deployment. The backup rejects a pre-existing failed
path or service state before it stops the path trigger, so `systemctl stop`
cannot clear a failure before it is reported. It then waits for any
already-running or queued oneshot worker to finish before copying any asset:
the service must be `inactive` and have no pending systemd job. A service that
fails while quiescing is also rejected. During the copy it temporarily locks
the validated draft parent. An EXIT trap restores both the parent's captured
metadata and the path unit's prior active state on success and failure; path
enablement is never changed by the backup.

```bash
(
set -euo pipefail

BACKUP_ROOT="/root/openvpn-web-server-drafts-backup-$(date -u +%Y%m%d%H%M%S)"
backup_name="$(basename -- "$BACKUP_ROOT")"
if ! [[ "$backup_name" =~ ^openvpn-web-server-drafts-backup-[0-9]{14}$ ]] \
  || ! [[ "$BACKUP_ROOT" == "/root/$backup_name" ]]; then
  echo 'refusing an invalid draft-worker backup root name' >&2
  exit 2
fi

# mkdir without -p is the atomic reservation. A repeated or concurrent run
# with the same timestamp fails instead of reusing or appending to a backup.
sudo mkdir --mode=0700 -- "$BACKUP_ROOT"
if sudo test -L "$BACKUP_ROOT" || ! sudo test -d "$BACKUP_ROOT"; then
  echo 'draft-worker backup root is not a real directory' >&2
  exit 2
fi
resolved_backup_root="$(sudo readlink -e -- "$BACKUP_ROOT")"
backup_root_metadata="$(sudo stat -c '%u:%g:%a' -- "$BACKUP_ROOT")"
if ! [[ "$resolved_backup_root" == "/root/$backup_name" ]] \
  || ! [[ "$backup_root_metadata" == "0:0:700" ]]; then
  echo 'draft-worker backup root failed canonical ownership validation' >&2
  exit 2
fi
BACKUP_ROOT="$resolved_backup_root"
DRAFT_PARENT=/var/lib/openvpn-web
DRAFT_ROOT="$DRAFT_PARENT/server-drafts"
for namespace_component in /var /var/lib; do
  if sudo test -L "$namespace_component" || ! sudo test -d "$namespace_component" \
    || ! [[ "$(sudo readlink -e -- "$namespace_component")" == "$namespace_component" ]] \
    || ! [[ "$(sudo stat -c '%U:%G:%a' -- "$namespace_component")" == root:root:755 ]]; then
    echo "draft-worker namespace component is unsafe: $namespace_component" >&2
    exit 2
  fi
done
if sudo test -L "$DRAFT_PARENT" || ! sudo test -d "$DRAFT_PARENT"; then
  echo 'draft-worker parent is not a real directory' >&2
  exit 2
fi
resolved_draft_parent="$(sudo readlink -e -- "$DRAFT_PARENT")"
draft_parent_metadata="$(sudo stat -c '%U:%G:%a' -- "$DRAFT_PARENT")"
if ! [[ "$resolved_draft_parent" == "$DRAFT_PARENT" ]]; then
  echo 'draft-worker parent is outside its canonical path' >&2
  exit 2
fi
case "$draft_parent_metadata" in
  openvpn-web:openvpn-web:755|root:openvpn-web:1770) ;;
  *)
    echo 'draft-worker parent has unconstrained ownership or mode' >&2
    exit 2
    ;;
esac

# BEGIN draft-worker backup quiescence
draft_worker_path_was_active=inactive
draft_parent_restore_needed=false
parent_metadata_archive=''
systemd_unit_property() {
  local unit="$1" property="$2" value
  if ! value="$(sudo systemctl show --property="$property" --value "$unit")" \
    || [[ -z "$value" ]]; then
    echo "cannot determine $property for $unit" >&2
    exit 2
  fi
  printf '%s' "$value"
}
restore_draft_worker_path_after_backup() {
  if [[ "$draft_worker_path_was_active" == active ]]; then
    sudo systemctl start server-draft-worker.path
  fi
}
finish_draft_worker_backup() {
  local backup_rc=$? restore_rc=0
  trap - EXIT
  if [[ "$draft_parent_restore_needed" == true ]]; then
    sudo tar --extract --file="$parent_metadata_archive" \
      --acls --xattrs --selinux --numeric-owner --same-owner --same-permissions --no-recursion \
      --directory=/ var/lib/openvpn-web/ || restore_rc=$?
  fi
  restore_draft_worker_path_after_backup || restore_rc=$?
  if (( restore_rc != 0 )); then
    echo 'failed to restore the pre-backup draft-worker state' >&2
    if (( backup_rc == 0 )); then
      backup_rc="$restore_rc"
    fi
  fi
  exit "$backup_rc"
}
trap finish_draft_worker_backup EXIT

draft_worker_path_load_state="$(systemd_unit_property server-draft-worker.path LoadState)"
case "$draft_worker_path_load_state" in
  loaded)
    draft_worker_path_active_state="$(systemd_unit_property server-draft-worker.path ActiveState)"
    case "$draft_worker_path_active_state" in
      active) draft_worker_path_was_active=active ;;
      inactive) ;;
      failed)
        echo 'draft-worker path is already failed; no backup was taken' >&2
        exit 2
        ;;
      *)
        echo "draft-worker path has an unexpected active state: $draft_worker_path_active_state" >&2
        exit 2
        ;;
    esac
    ;;
  not-found) ;;
  *)
    echo "draft-worker path has an unexpected load state: $draft_worker_path_load_state" >&2
    exit 2
    ;;
esac

# Reject a pre-existing service failure before stopping the path trigger. The
# stop operation can normalize a failed path unit, which would otherwise hide
# the failed lifecycle state from this backup.
draft_worker_service_load_state="$(systemd_unit_property server-draft-worker.service LoadState)"
case "$draft_worker_service_load_state" in
  loaded)
    draft_worker_service_active_state="$(systemd_unit_property server-draft-worker.service ActiveState)"
    case "$draft_worker_service_active_state" in
      failed)
        echo 'draft-worker service is already failed; no backup was taken' >&2
        exit 2
        ;;
      inactive|active|activating|deactivating|reloading) ;;
      *)
        echo "draft worker has an unexpected active state: $draft_worker_service_active_state" >&2
        exit 2
        ;;
    esac
    ;;
  not-found) ;;
  *)
    echo "draft worker has an unexpected load state: $draft_worker_service_load_state" >&2
    exit 2
    ;;
esac

if [[ "$draft_worker_path_load_state" == loaded ]]; then
  sudo systemctl stop server-draft-worker.path
fi
# Stopping the path prevents a new activation. Let an invocation that already
# started or was queued before the stop finish normally instead of terminating
# it during a state write. A snapshot is safe only after systemd reports both
# the terminal inactive state and no pending service job.
draft_worker_quiesced=false
for _ in {1..180}; do
  draft_worker_service_load_state="$(systemd_unit_property server-draft-worker.service LoadState)"
  case "$draft_worker_service_load_state" in
    not-found)
      draft_worker_quiesced=true
      break
      ;;
    loaded)
      draft_worker_service_active_state="$(systemd_unit_property server-draft-worker.service ActiveState)"
      case "$draft_worker_service_active_state" in
        inactive)
          draft_worker_service_job="$(systemd_unit_property server-draft-worker.service Job)"
          if [[ "$draft_worker_service_job" == 0 ]]; then
            draft_worker_quiesced=true
            break
          fi
          ;;
        failed)
          echo 'draft worker service failed while quiescing; no backup was taken' >&2
          exit 2
          ;;
        active|activating|deactivating|reloading) ;;
        *)
          echo "draft worker has an unexpected active state: $draft_worker_service_active_state" >&2
          exit 2
          ;;
      esac
      ;;
    *)
      echo "draft worker has an unexpected load state: $draft_worker_service_load_state" >&2
      exit 2
      ;;
  esac
  sleep 1
done
if [[ "$draft_worker_quiesced" != true ]]; then
  echo 'draft worker did not quiesce within 180 seconds; no backup was taken' >&2
  exit 2
fi
# END draft-worker backup quiescence

rollback_manifest="$BACKUP_ROOT/rollback.assets"
sudo install -m 0600 /dev/null "$rollback_manifest"

parent_metadata_archive="$BACKUP_ROOT/openvpn-web-parent.tar"
sudo tar --create --file="$parent_metadata_archive" \
  --acls --xattrs --selinux --numeric-owner --no-recursion \
  --directory=/ var/lib/openvpn-web/
if ! [[ "$(sudo tar --list --file="$parent_metadata_archive")" == "var/lib/openvpn-web/" ]]; then
  echo 'draft-worker parent metadata archive is incomplete or unsafe' >&2
  exit 2
fi

# The parent entry cannot be replaced because /var/lib was validated as
# root-owned. Lock it while the draft source is inspected and copied, and use
# the EXIT trap to restore the exact pre-backup metadata before restarting the
# path unit.
lock_draft_parent_for_backup() {
  draft_parent_restore_needed=true
  sudo chown root:openvpn-web "$DRAFT_PARENT"
  sudo chmod 1750 "$DRAFT_PARENT"
  if sudo test -L "$DRAFT_PARENT" || ! sudo test -d "$DRAFT_PARENT" \
    || ! [[ "$(sudo readlink -e -- "$DRAFT_PARENT")" == "$DRAFT_PARENT" ]] \
    || ! [[ "$(sudo stat -c '%U:%G:%a' -- "$DRAFT_PARENT")" == root:openvpn-web:1750 ]]; then
    echo 'draft-worker parent lock did not hold during backup' >&2
    exit 2
  fi
}

reject_nested_symlinks() {
  local root="$1" symlink_path
  if ! symlink_path="$(sudo find -P "$root" -type l -print -quit)"; then
    echo "cannot inspect draft tree for nested symlinks: $root" >&2
    exit 2
  fi
  if [[ -n "$symlink_path" ]]; then
    echo "refusing nested symlink in draft tree: $symlink_path" >&2
    exit 2
  fi
}

lock_draft_parent_for_backup

# Each manifest line records whether the prior asset was present or absent.
# "absent" is the expected, distinct first-deployment state; symlinked or
# unexpected source types are never backed up. The one expected symlink is
# the exact systemd wants link which records the prior enablement state.
backup_asset() {
  local asset_name="$1" asset_type="$2" source_path="$3"
  if [[ "$asset_type" != -L ]] && sudo test -L "$source_path"; then
    echo "refusing symlinked draft-worker asset: $source_path" >&2
    exit 2
  elif sudo test "$asset_type" "$source_path"; then
    sudo cp --archive --preserve=all -- "$source_path" "$BACKUP_ROOT/$asset_name"
    printf '%s=present\n' "$asset_name" | sudo tee -a "$rollback_manifest" >/dev/null
  elif sudo test -e "$source_path" || sudo test -L "$source_path"; then
    echo "refusing unexpected draft-worker asset type: $source_path" >&2
    exit 2
  else
    printf '%s=absent\n' "$asset_name" | sudo tee -a "$rollback_manifest" >/dev/null
  fi
}

DRAFT_PATH_WANTS=/etc/systemd/system/multi-user.target.wants/server-draft-worker.path
if sudo test -L "$DRAFT_PATH_WANTS" \
  && ! [[ "$(sudo readlink -- "$DRAFT_PATH_WANTS")" == "../server-draft-worker.path" ]]; then
  echo 'refusing an unexpected draft-worker path enablement symlink' >&2
  exit 2
fi

backup_asset server-draft-worker -f /usr/local/sbin/server-draft-worker
backup_asset server-draft-worker.service -f /etc/systemd/system/server-draft-worker.service
backup_asset server-draft-worker.path -f /etc/systemd/system/server-draft-worker.path
backup_asset server-draft-worker.path.wants -L /etc/systemd/system/multi-user.target.wants/server-draft-worker.path
backup_asset server-observer.pub -f /etc/openvpn-web/server-observer.pub
if sudo test -d /usr/local/lib/openvpn-web-server-draft-worker; then
  reject_nested_symlinks /usr/local/lib/openvpn-web-server-draft-worker
fi
backup_asset server-draft-worker-runtime -d /usr/local/lib/openvpn-web-server-draft-worker
if sudo test -d "$DRAFT_ROOT"; then
  reject_nested_symlinks "$DRAFT_ROOT"
fi
backup_asset server-drafts -d /var/lib/openvpn-web/server-drafts
if sudo test -d "$BACKUP_ROOT/server-drafts"; then
  reject_nested_symlinks "$BACKUP_ROOT/server-drafts"
fi
printf 'openvpn-web-parent-metadata=present\n' | sudo tee -a "$rollback_manifest" >/dev/null
printf 'server-draft-worker.path.active=%s\n' "$draft_worker_path_was_active" \
  | sudo tee -a "$rollback_manifest" >/dev/null
sudo test -s "$rollback_manifest"
printf 'Draft-worker rollback backup: %s\n' "$BACKUP_ROOT"
)
```

Copy the reviewed source bundle to the host as described in [Deploy To OpenVPN
Host](#deploy-to-openvpn-host), then invoke only the dedicated draft-worker
installer from the extracted source directory:

```bash
cd /tmp/openvpn-web-src
SUDO_PASSWORD='<sudo-password>' bash deploy/install-server-draft-worker.sh
```

That installer installs only `/usr/local/sbin/server-draft-worker`, the
root-owned `/usr/local/lib/openvpn-web-server-draft-worker` bootstrap/module
runtime, the two `server-draft-worker` unit files, the three `server-drafts`
directories, and the derived observer public key. The runtime executes through
root-owned `/usr/bin/python3 -I`; it never imports code, an interpreter, or
dependencies from the generic web-writable `/opt/openvpn-web` bundle. It also changes `/var/lib/openvpn-web` from
the legacy `openvpn-web:openvpn-web 0755` state to `root:openvpn-web 1770`, and
establishes `server-drafts` as `root:openvpn-web 0750`. Group write keeps the
web application's SQLite directory usable; the sticky parent prevents the web
account from replacing the root-owned draft root. The installer validates every
existing draft-path component and canonical path before this mutation and
rejects existing symlinks or any unconstrained parent metadata. During both a
legacy migration and a hardened retry it temporarily removes web write access,
revalidates the namespace, and chooses either an exclusive root creation or an
already-root-owned entry; it never follows a check-then-chown path while the
parent is web-writable. It reloads
systemd and enables only
`server-draft-worker.path`; it does not alter the application bundle, collector
configuration or timers, OpenVPN, or any unrelated service. Do not enable or
start `server-draft-worker.service` directly. The path unit starts the worker
only when a public queue entry changes. Verify that boundary and the public-key
access required by the web application:

If the installer exits after locking the namespace, it deliberately leaves the
parent non-web-writable instead of reopening a partially hardened path. Use the
validated rollback below to restore the captured parent metadata; do not repair
ownership or modes ad hoc.

```bash
sudo systemctl is-enabled server-draft-worker.path
sudo systemctl is-active server-draft-worker.path
sudo systemctl status server-draft-worker.path --no-pager
sudo stat -c '%U:%G %a %n' /etc/openvpn-web/server-observer.pub
sudo -u openvpn-web test -r /etc/openvpn-web/server-observer.pub
```

The public key must be readable through the `openvpn-web` group (the installer
sets it to `root:openvpn-web` with mode `0644`). Do not run a target SSH test
as part of this deployment rehearsal. A target interaction begins only after
an operator has intentionally created a draft in `/network/server-drafts` and
completed the documented fingerprint-confirmation workflow.

### Rollback

If this handoff must be rolled back, first set `BACKUP_ROOT` to the exact path
printed by the backup command above. The validation below rejects a guessed,
unrelated, or symlinked backup root and verifies every restore source before
stopping services, replacing units, or deleting draft state:

```bash
(
set -euo pipefail

BACKUP_ROOT='/root/openvpn-web-server-drafts-backup-20260720120000'
backup_name="$(basename -- "$BACKUP_ROOT")"
if ! [[ "$backup_name" =~ ^openvpn-web-server-drafts-backup-[0-9]{14}$ ]] \
  || ! [[ "$BACKUP_ROOT" == "/root/$backup_name" ]]; then
  echo 'refusing an unvalidated draft-worker backup root' >&2
  exit 2
fi
# Reject the supplied directory itself before readlink can hide that symlink.
if sudo test -L "$BACKUP_ROOT"; then
  echo 'refusing a symlinked draft-worker backup root' >&2
  exit 2
fi
resolved_backup_root="$(sudo readlink -e -- "$BACKUP_ROOT")"
if ! [[ "$resolved_backup_root" == "/root/$backup_name" ]]; then
  echo 'refusing a resolved backup root outside the draft-worker backup namespace' >&2
  exit 2
fi
BACKUP_ROOT="$resolved_backup_root"
rollback_manifest="$BACKUP_ROOT/rollback.assets"
if ! sudo test -d "$BACKUP_ROOT" || sudo test -L "$BACKUP_ROOT" || \
  ! sudo test -f "$rollback_manifest" || sudo test -L "$rollback_manifest"; then
  echo 'draft-worker rollback backup root or manifest is incomplete or unsafe' >&2
  exit 2
fi
backup_root_metadata="$(sudo stat -c '%u:%g:%a' -- "$BACKUP_ROOT")"
manifest_metadata="$(sudo stat -c '%u:%g:%a' -- "$rollback_manifest")"
if ! [[ "$backup_root_metadata" == "0:0:700" ]] \
  || ! [[ "$manifest_metadata" == "0:0:600" ]]; then
  echo 'draft-worker rollback backup ownership or mode is unsafe' >&2
  exit 2
fi

# A present source must be a non-symlinked regular file/directory. If the
# prior asset was absent, the manifest must not smuggle a restore source into
# the backup. This preserves the first-deployment state during rollback.
asset_state() {
  local asset_name="$1" asset_type="$2" source_path="$3"
  local present_count absent_count
  present_count="$(sudo grep -Fxc "$asset_name=present" "$rollback_manifest" || true)"
  absent_count="$(sudo grep -Fxc "$asset_name=absent" "$rollback_manifest" || true)"
  if [[ "$present_count" == 1 && "$absent_count" == 0 ]]; then
    if ! sudo test "$asset_type" "$source_path" \
      || { [[ "$asset_type" != -L ]] && sudo test -L "$source_path"; }; then
      echo "draft-worker rollback source is unsafe: $asset_name" >&2
      exit 2
    fi
    printf 'present'
  elif [[ "$present_count" == 0 && "$absent_count" == 1 ]]; then
    if sudo test -e "$source_path" || sudo test -L "$source_path"; then
      echo "draft-worker rollback has an unexpected source for absent asset: $asset_name" >&2
      exit 2
    fi
    printf 'absent'
  else
    echo "draft-worker rollback manifest lacks a valid state for: $asset_name" >&2
    exit 2
  fi
}

reject_nested_symlinks() {
  local root="$1" symlink_path
  if ! symlink_path="$(sudo find -P "$root" -type l -print -quit)"; then
    echo "cannot inspect draft tree for nested symlinks: $root" >&2
    exit 2
  fi
  if [[ -n "$symlink_path" ]]; then
    echo "refusing nested symlink in draft tree: $symlink_path" >&2
    exit 2
  fi
}

worker_wrapper_state="$(asset_state server-draft-worker -f "$BACKUP_ROOT/server-draft-worker")"
worker_service_state="$(asset_state server-draft-worker.service -f "$BACKUP_ROOT/server-draft-worker.service")"
worker_path_state="$(asset_state server-draft-worker.path -f "$BACKUP_ROOT/server-draft-worker.path")"
worker_path_wants_state="$(asset_state server-draft-worker.path.wants -L "$BACKUP_ROOT/server-draft-worker.path.wants")"
observer_public_key_state="$(asset_state server-observer.pub -f "$BACKUP_ROOT/server-observer.pub")"
worker_runtime_state="$(asset_state server-draft-worker-runtime -d "$BACKUP_ROOT/server-draft-worker-runtime")"
draft_state="$(asset_state server-drafts -d "$BACKUP_ROOT/server-drafts")"
if [[ "$worker_runtime_state" == present ]]; then
  reject_nested_symlinks "$BACKUP_ROOT/server-draft-worker-runtime"
fi
if [[ "$draft_state" == present ]]; then
  reject_nested_symlinks "$BACKUP_ROOT/server-drafts"
fi

if [[ "$worker_path_wants_state" == present ]] \
  && ! [[ "$(sudo readlink -- "$BACKUP_ROOT/server-draft-worker.path.wants")" == "../server-draft-worker.path" ]]; then
  echo 'refusing an unexpected draft-worker path enablement symlink' >&2
  exit 2
fi
parent_metadata_archive="$BACKUP_ROOT/openvpn-web-parent.tar"
if ! sudo test -f "$parent_metadata_archive" || sudo test -L "$parent_metadata_archive" \
  || ! sudo grep -Fxq 'openvpn-web-parent-metadata=present' "$rollback_manifest" \
  || ! [[ "$(sudo tar --list --file="$parent_metadata_archive")" == "var/lib/openvpn-web/" ]]; then
  echo 'draft-worker parent metadata archive is incomplete or unsafe' >&2
  exit 2
fi
if sudo grep -Fxq 'server-draft-worker.path.active=active' "$rollback_manifest" \
  && ! sudo grep -Fxq 'server-draft-worker.path.active=inactive' "$rollback_manifest"; then
  worker_path_active_state=active
elif sudo grep -Fxq 'server-draft-worker.path.active=inactive' "$rollback_manifest" \
  && ! sudo grep -Fxq 'server-draft-worker.path.active=active' "$rollback_manifest"; then
  worker_path_active_state=inactive
else
  echo 'draft-worker rollback manifest lacks one prior path active state' >&2
  exit 2
fi

# The deployed parent is normally group-writable so the web SQLite file remains
# usable. Lock it before any target revalidation, removal, or archive copy. The
# metadata-only archive validated above restores the captured pre-handoff state
# after the draft root is safely restored.
DRAFT_PARENT=/var/lib/openvpn-web
lock_draft_parent_for_restore() {
  local path resolved metadata
  for path in /var /var/lib; do
    if sudo test -L "$path" || ! sudo test -d "$path"; then
      echo "unsafe rollback namespace component: $path" >&2
      exit 2
    fi
    resolved="$(sudo readlink -e -- "$path")"
    metadata="$(sudo stat -c '%U:%G:%a' -- "$path")"
    if [[ "$resolved" != "$path" ]] || [[ "$metadata" != root:root:755 ]]; then
      echo "unexpected rollback namespace metadata: $path" >&2
      exit 2
    fi
  done
  if sudo test -L "$DRAFT_PARENT" || ! sudo test -d "$DRAFT_PARENT"; then
    echo 'draft-worker rollback parent is not a real directory' >&2
    exit 2
  fi
  resolved="$(sudo readlink -e -- "$DRAFT_PARENT")"
  metadata="$(sudo stat -c '%U:%G:%a' -- "$DRAFT_PARENT")"
  if [[ "$resolved" != "$DRAFT_PARENT" ]]; then
    echo 'draft-worker rollback parent is outside its canonical path' >&2
    exit 2
  fi
  case "$metadata" in
    openvpn-web:openvpn-web:755|root:openvpn-web:1770|root:openvpn-web:1750) ;;
    *)
      echo 'draft-worker rollback parent has unconstrained ownership or mode' >&2
      exit 2
      ;;
  esac

  # /var/lib is root-owned and was just validated, so the parent entry cannot
  # be replaced. Keep chmod immediately adjacent to chown: after these two
  # commands neither the web owner nor openvpn-web group can mutate children.
  sudo chown root:openvpn-web "$DRAFT_PARENT"
  sudo chmod 1750 "$DRAFT_PARENT"

  for path in /var /var/lib; do
    if sudo test -L "$path" || ! sudo test -d "$path" \
      || [[ "$(sudo readlink -e -- "$path")" != "$path" ]] \
      || [[ "$(sudo stat -c '%U:%G:%a' -- "$path")" != root:root:755 ]]; then
      echo "rollback namespace changed while locking: $path" >&2
      exit 2
    fi
  done
  if sudo test -L "$DRAFT_PARENT" || ! sudo test -d "$DRAFT_PARENT" \
    || [[ "$(sudo readlink -e -- "$DRAFT_PARENT")" != "$DRAFT_PARENT" ]]; then
    echo 'draft-worker rollback parent changed while locking' >&2
    exit 2
  fi
  metadata="$(sudo stat -c '%U:%G:%a' -- "$DRAFT_PARENT")"
  if [[ "$metadata" != root:openvpn-web:1750 ]]; then
    echo 'draft-worker rollback parent lock did not hold' >&2
    exit 2
  fi
}

validate_locked_live_draft_root() {
  local draft_root=/var/lib/openvpn-web/server-drafts resolved metadata
  if sudo test -L "$draft_root"; then
    echo 'refusing a symlinked live draft root during rollback' >&2
    exit 2
  elif sudo test -e "$draft_root"; then
    if ! sudo test -d "$draft_root"; then
      echo 'live draft root has an unexpected type during rollback' >&2
      exit 2
    fi
    resolved="$(sudo readlink -e -- "$draft_root")"
    metadata="$(sudo stat -c '%U:%G:%a' -- "$draft_root")"
    if [[ "$resolved" != "$draft_root" ]] \
      || [[ "$metadata" != root:openvpn-web:750 ]]; then
      echo 'live draft root is outside the locked rollback contract' >&2
      exit 2
    fi
  fi
}

lock_draft_parent_for_restore

# From this point every failure stops the procedure before later mutations.
# BEGIN draft-worker rollback unit quiescence
systemd_unit_load_state() {
  local unit="$1" load_state
  if ! load_state="$(sudo systemctl show --property=LoadState --value "$unit")" \
    || [[ -z "$load_state" ]]; then
    echo "cannot determine LoadState for $unit during rollback" >&2
    exit 2
  fi
  printf '%s' "$load_state"
}

draft_worker_path_load_state="$(systemd_unit_load_state server-draft-worker.path)"
case "$draft_worker_path_load_state" in
  loaded)
    sudo systemctl stop server-draft-worker.path
    sudo systemctl disable server-draft-worker.path
    ;;
  not-found) ;;
  *)
    echo "draft-worker path has an unexpected rollback load state: $draft_worker_path_load_state" >&2
    exit 2
    ;;
esac

draft_worker_service_load_state="$(systemd_unit_load_state server-draft-worker.service)"
case "$draft_worker_service_load_state" in
  loaded) sudo systemctl stop server-draft-worker.service ;;
  not-found) ;;
  *)
    echo "draft worker has an unexpected rollback load state: $draft_worker_service_load_state" >&2
    exit 2
    ;;
esac
# END draft-worker rollback unit quiescence
validate_locked_live_draft_root
if sudo test -d "$DRAFT_PARENT/server-drafts"; then
  reject_nested_symlinks "$DRAFT_PARENT/server-drafts"
fi

restore_asset() {
  local state="$1" asset_type="$2" source_path="$3" target_path="$4"
  [[ "$asset_type" == -f || "$asset_type" == -L ]]
  sudo rm -f -- "$target_path"
  if [[ "$state" == present ]]; then
    sudo cp --archive --preserve=all -- "$source_path" "$target_path"
  fi
}

restore_asset "$worker_wrapper_state" -f "$BACKUP_ROOT/server-draft-worker" /usr/local/sbin/server-draft-worker
restore_asset "$worker_service_state" -f "$BACKUP_ROOT/server-draft-worker.service" /etc/systemd/system/server-draft-worker.service
restore_asset "$worker_path_state" -f "$BACKUP_ROOT/server-draft-worker.path" /etc/systemd/system/server-draft-worker.path
restore_asset "$observer_public_key_state" -f "$BACKUP_ROOT/server-observer.pub" /etc/openvpn-web/server-observer.pub
for runtime_namespace_component in /usr /usr/local /usr/local/lib; do
  if sudo test -L "$runtime_namespace_component" \
    || ! sudo test -d "$runtime_namespace_component" \
    || [[ "$(sudo readlink -e -- "$runtime_namespace_component")" != "$runtime_namespace_component" ]] \
    || [[ "$(sudo stat -c '%U:%G:%a' -- "$runtime_namespace_component")" != root:root:755 ]]; then
    echo "unsafe draft-worker runtime namespace: $runtime_namespace_component" >&2
    exit 2
  fi
done
if sudo test -L /usr/local/lib/openvpn-web-server-draft-worker; then
  echo 'refusing a symlinked live draft-worker runtime during rollback' >&2
  exit 2
elif sudo test -e /usr/local/lib/openvpn-web-server-draft-worker \
  && ! sudo test -d /usr/local/lib/openvpn-web-server-draft-worker; then
  echo 'live draft-worker runtime has an unexpected type during rollback' >&2
  exit 2
fi
sudo rm -rf -- /usr/local/lib/openvpn-web-server-draft-worker
if [[ "$worker_runtime_state" == present ]]; then
  sudo cp --archive --preserve=all -- "$BACKUP_ROOT/server-draft-worker-runtime" /usr/local/lib/openvpn-web-server-draft-worker
fi
sudo rm -rf -- /var/lib/openvpn-web/server-drafts
if [[ "$draft_state" == present ]]; then
  sudo cp --archive --preserve=all -- "$BACKUP_ROOT/server-drafts" /var/lib/openvpn-web/server-drafts
fi
restore_asset "$worker_path_wants_state" -L "$BACKUP_ROOT/server-draft-worker.path.wants" /etc/systemd/system/multi-user.target.wants/server-draft-worker.path
# Restore parent metadata last, after draft-root removal/copy changed its mtime.
sudo tar --extract --file="$parent_metadata_archive" \
  --acls --xattrs --selinux --numeric-owner --same-owner --same-permissions --no-recursion \
  --directory=/ var/lib/openvpn-web/
sudo systemctl daemon-reload
if [[ "$worker_path_active_state" == active ]]; then
  sudo systemctl start server-draft-worker.path
fi
)
```

Do not disable or restart OpenVPN, and do not change collector configuration or
collector timers during rollback. This rollback intentionally leaves all
non-draft services and assets untouched. It validates the complete backup set
before locking `/var/lib/openvpn-web` to `root:openvpn-web 1750`; only then does
it stop the draft units, revalidate the live root, remove it, and copy the
archive into a destination the web group cannot replace. A successful rollback
restores the captured parent metadata last. If rollback fails after the lock,
leave the parent locked and resume the same validated procedure rather than
reopening a partially restored namespace by hand.

## Network Observer Setup

The installer creates:

- `/usr/local/sbin/netctl`
- `/etc/netctl/sources.d/mikrotik-main.yaml`
- `/etc/netctl/sources.d/mikrotik-hex.yaml`
- `/etc/netctl/secrets.env`
- `/var/lib/netctl/netctl.sqlite`
- `netctl-collect.service`
- `netctl-collect.timer`
- Linux service user `netctl`; automatic collection runs as this user, not root.

Before the first real collection, configure a read-only RouterOS API user and put its password into `/etc/netctl/secrets.env`:

```bash
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S install -m 0640 -o root -g netctl /dev/null /etc/netctl/secrets.env"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S sh -c 'printf %s\\n \"NETCTL_SECRET_MIKROTIK_MAIN_PASSWORD='\"'\"'STRONG_PASSWORD'\"'\"'\" > /etc/netctl/secrets.env'"
```

For the remote m-arhiv hEX, `netctl` uses SSH because that router is RouterOS 6 and may not expose API to the OpenVPN host. The installer creates `/etc/netctl/sources.d/mikrotik-hex.yaml`; the required private key is `/var/lib/netctl/.ssh/m_arhiv_hex_rsa`, owned by `netctl` with mode `0600`.

Recommended RouterOS configuration:

```routeros
/user group add name=netobserver policy=read,api,test,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!romon
/user add name=netobserver group=netobserver password="STRONG_PASSWORD"
/ip service set api-ssl disabled=no address=192.168.100.30/32 port=8729
/ip service set api disabled=yes
```

Temporary non-TLS API fallback:

```routeros
/ip service set api disabled=no address=192.168.100.30/32 port=8728
```

Remote hEX SSH requirements:

```routeros
/ip service set ssh address=192.168.99.176/32,192.168.100.30/32
/user ssh-keys import user=asmr_admin public-key-file=netctl-openvpn-to-m-arhiv.pub
```

Verify:

```bash
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json sources test mikrotik-main"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json sources test mikrotik-hex"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json ipsec status"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json collect mikrotik-main"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/netctl --json hosts list"
```

The web pages are:

- `/network/dashboard`
- `/network/hosts`
- `/network/sources`
- `/network/interfaces`
- `/network/routes`
- `/network/ipsec`
- `/network/backups`
- `/network/collect`

OpenVPN addressing and site-to-site checks:

```bash
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json server-config inspect"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json validate-network-plan"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json nat-status"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json site-routes list"
ssh ui-vpn-deploy "printf '%s\n' '<sudo-password>' | sudo -S /usr/local/sbin/vpnctl --json preview test_router_s2s router_vipnet 192.168.50.201 --client-type router_site_to_site --remote-lan 192.168.51.0/24 --create-server-route"
```

Expected addressing:

- OpenVPN tunnel pool: `192.168.50.0/24`.
- OpenVPN server tunnel IP: `192.168.50.1`.
- User VPN-IP range: `192.168.50.2-199`.
- Router VPN-IP range: `192.168.50.200-249`.
- Remote LANs behind site-to-site routers: `192.168.51.0/24`, `192.168.52.0/24`.

The expected production design is routing without SNAT from OpenVPN to ViPNet. `nat-status` should report `mode=disabled_expected`; legacy `vipnet-openvpn-nat.service` and `VIPNET_OPENVPN_SNAT` should be inactive or absent.

`openvpn-server@server.service` starts OpenVPN with `--status /run/openvpn-server/status-server.log`; this command-line setting overrides any `status` directive in `server.conf`. Set `STATUS_LOG` to that runtime path so `vpnctl connected --source status-log` uses the live fallback file.

## WireGuard policy-routing health

The VLAN50 (`ens18.50`) egress policy is intentionally narrow: only mark `0x1`,
priority `1000`, table `123`, and the `VPN_POLICY_MARK` / `VPN_POLICY_NAT`
chains belong to `vpn-policy.service`. `wg0.conf` must retain `Table = off` so
WireGuard cannot install a global default route.

`vpn-policy-reconcile.timer` runs once per minute and repairs only drift in
those owned objects. It first probes the active state (when `wg0` exists) or
the fail-closed state (when it does not); a healthy state is not flushed or
rebuilt. The reconciler shares `/run/lock/vpn-policy.lock` with
`vpn-policy.service`, so a timer tick cannot race the normal policy-service
lifecycle. It never starts, restarts, stops, or reconfigures WireGuard or
OpenVPN. If a WG peer fails, VLAN50 remains fail-closed until an operator or
the normal WG service lifecycle brings `wg0` back.

`vpn-runtime-health.timer` is deliberately separate and alarm-only: it runs
`vpnctl --json runtime-health --strict` once per minute and records an error in
journald if OpenVPN management, `wg0`, the handshake, table 123 or its managed
chains disappear. It never changes routes, firewall rules, or services.

Use these post-deploy checks or an explicit scoped repair:

```bash
sudo systemctl status vpn-policy-reconcile.timer vpn-runtime-health.timer --no-pager
sudo systemctl start vpn-policy-reconcile.service
sudo /usr/local/sbin/vpnctl --json runtime-health --strict
curl -fsS -H "Authorization: Bearer $OPENVPN_WEB_API_TOKEN" http://127.0.0.1:8088/api/v1/runtime-health
```

`systemctl start vpn-policy-reconcile.service` is the explicit repair command:
it only writes the managed PBR/NAT objects if its probe finds drift, and never
starts, stops, or restarts WireGuard or OpenVPN. The other commands shown are
read-only. The final command is the read-only Bearer integration endpoint. Browser users
do not use that token: an authenticated session can view the same sanitized
state in `/network/dashboard`, whose VPN Runtime card polls
`/network/runtime-health` every 30 seconds. An unauthenticated request to the
session endpoint redirects with HTTP 303 to `/login`. The card displays only
the health fields and redacts key-like values, endpoint names, IP addresses,
and ports from warning/error text before rendering it.

Use the acceptance and maintenance-window procedure in
[`wg-policy-resilience-deploy-rollback.md`](runbooks/wg-policy-resilience-deploy-rollback.md).

## Route Update Behavior

When client networks are changed from the web UI or API, the app writes CCD through `vpnctl`, runs auto sync, then calls `reconnect-client`. If the client is connected and OpenVPN management is available, the session is dropped so the client reconnects and receives fresh pushed routes. If the client is offline, the new CCD is applied at the next connection.

For `router_site_to_site` clients, `vpnctl` writes an `iroute` into the CCD and can add the matching server `route` only inside its managed block. Do not add remote LAN routes by hand outside the managed block; use `vpnctl --json site-routes add ...` and run `vpnctl --json validate-network-plan` before and after changes.

## Safety Rules

- Do not edit OpenVPN PKI, CRL, CCD, `.ovpn`, iptables or systemd directly from the web app.
- Use `vpnctl --json` for all privileged OpenVPN changes.
- Do not expose a delete-client API or MCP tool. Disable clients instead.
- Require `confirm_client` and `reason` for client-impacting API/MCP actions.
- Keep bearer tokens, password files, generated configs and private keys out of git.
