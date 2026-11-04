#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Apply only the three inspected ALT client backports; never execute policy."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid

PATCHES = json.loads(r'''
[
  {
    "id": "services",
    "evr": "0.16.1-alt1",
    "package": "gpupdate",
    "after_sha256": "5fb2f4d8428aa2889f76e31314140f465f66dbb18c7120b6797d76e6baac9c85",
    "path": "/usr/lib/python3/site-packages/gpoa/gpt/services.py",
    "before_sha256": "b3cceeeb49349ca0e70694007f997d0d678f36066d1e2c79866653336baca3e5",
    "patch": "--- services.before\n+++ services.after\n@@ -36,7 +36,7 @@\n         props = srv.find(\u0027Properties\u0027)\n         startup_type = props.get(\u0027startupType\u0027)\n         srv_obj.set_servicename(props.get(\u0027serviceName\u0027))\n-        srv_obj.set_serviceaction(props.get(\u0027serviceAction\u0027))\n+        srv_obj.set_servact(props.get(\u0027serviceAction\u0027))\n         timeout = props.get(\u0027timeout\u0027)\n         srv_obj.set_disabled(srv.get(\u0027disabled\u0027) == \u00271\u0027)\n \n"
  },
  {
    "id": "kde",
    "evr": "0.16.1-alt1",
    "package": "gpoa-lib",
    "after_sha256": "d89d7d67f0fbce56b81f2be291ca03c76683e1561ff3127341d0311f748437cf",
    "path": "/usr/lib/python3/site-packages/gpoa_lib/frontend/kde_applier.py",
    "before_sha256": "7bbcb7c4620940b605e6dd71b9b2eafd87f3c80bef321e484b8cc8964b102552",
    "patch": "--- kde.before\n+++ kde.after\n@@ -31,6 +31,9 @@\n from ..util.util import get_homedir\n \n from .applier_frontend import applier_frontend, DualContextApplier, check_enabled\n+\n+\n+KDE_TOOL_PATH = \u0027/usr/lib/kf5/bin:/usr/lib/kf6/bin:/usr/bin\u0027\n \n \n class kde_applier(applier_frontend):\n@@ -81,7 +84,6 @@\n         self.locks_dict = {}\n         self.locks_data_dict = {}\n         self.all_kde_settings = {}\n-        kde_applier_user.kde_version = get_kde_version()\n         kde_filter = \u0027{}%\u0027.format(self.__hkcu_branch)\n         locks_filter = \u0027{}%\u0027.format(self.__hkcu_lock_branch)\n         self.locks_settings = self.storage.filter_hkcu_entries(locks_filter)\n@@ -111,6 +113,12 @@\n         \u0027\u0027\u0027\n         if self.__module_enabled:\n             log(\u0027D200\u0027)\n+            if not self.kde_settings:\n+                return\n+            if kde_applier_user.kde_version is None:\n+                kde_applier_user.kde_version = get_kde_version()\n+            if kde_applier_user.kde_version not in (5, 6):\n+                raise RuntimeError(\u0027Unable to determine KDE configuration tool version\u0027)\n             create_dict(self.kde_settings, self.all_kde_settings, self.locks_settings, self.locks_dict, self.file_cache, self.username, self.plasma_update_flag)\n             apply(self.all_kde_settings, self.locks_dict, self.username)\n         else:\n@@ -134,18 +142,26 @@\n \n def get_kde_version():\n     try:\n-        kinfo_path = shutil.which(\"kinfo\", path=\"/usr/lib/kf5/bin:/usr/bin\")\n+        kinfo_path = shutil.which(\u0027kinfo\u0027, path=KDE_TOOL_PATH)\n         if not kinfo_path:\n-            raise FileNotFoundError(\"Unable to find kinfo\")\n-        output = subprocess.check_output([kinfo_path], text=True, env={\u0027LANG\u0027:\u0027C\u0027}, timeout=15)\n+            raise FileNotFoundError(\u0027Unable to find kinfo\u0027)\n+        env = os.environ.copy()\n+        env[\u0027LANG\u0027] = \u0027C\u0027\n+        env[\u0027LC_ALL\u0027] = \u0027C\u0027\n+        # kinfo needs a Qt platform even when producing text output.\n+        env[\u0027QT_QPA_PLATFORM\u0027] = \u0027offscreen\u0027\n+        output = subprocess.check_output([kinfo_path], text=True, env=env, timeout=15)\n         for line in output.splitlines():\n-            if \"KDE Frameworks Version\" in line:\n-                frameworks_version = line.split(\":\", 1)[1].strip()\n-                major_frameworks_version = int(frameworks_version.split(\".\")[0])\n-                return major_frameworks_version\n+            if \u0027KDE Frameworks Version\u0027 in line:\n+                version = int(line.split(\u0027:\u0027, 1)[1].strip().split(\u0027.\u0027)[0])\n+                if version in (5, 6) and shutil.which(f\u0027kwriteconfig{version}\u0027, path=KDE_TOOL_PATH):\n+                    return version\n     except Exception as exc:\n         log(\u0027D270\u0027, {\u0027exc\u0027: str(exc)})\n-        return None\n+    # Do not guess on mixed KDE 5/6 installations.\n+    versions = [version for version in (5, 6)\n+                if shutil.which(f\u0027kwriteconfig{version}\u0027, path=KDE_TOOL_PATH)]\n+    return versions[0] if len(versions) == 1 else None\n \n \n def create_dict(kde_settings, all_kde_settings, locks_settings, locks_dict, file_cache = None, username = None, plasmaupdate = False):\n@@ -233,7 +249,7 @@\n                     try:\n                         clear_locks_settings(username, file_name, key)\n                         env_path = dict(os.environ)\n-                        env_path[\"PATH\"] = \"/usr/lib/kf5/bin:/usr/bin\"\n+                        env_path[\"PATH\"] = KDE_TOOL_PATH\n                         subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_path, timeout=15)\n                     except Exception as exc:\n                             logdata = {\u0027command\u0027: command, \u0027exc\u0027: exc}\n@@ -299,7 +315,7 @@\n         env_path[\"XDG_DATA_DIRS\"] = \"/usr/share/kf5:\"\n         env_path[\"DISPLAY\"] = \":0\"\n         env_path[\"XDG_RUNTIME_DIR\"] = f\"/run/user/{os.getuid()}\"\n-        env_path[\"PATH\"] = \"/usr/lib/kf5/bin:/usr/bin\"\n+        env_path[\"PATH\"] = KDE_TOOL_PATH\n         env_path[\"DBUS_SESSION_BUS_ADDRESS\"] = f\"unix:path=/run/user/{os.getuid()}/bus\"\n         if not flag:\n             if os.path.isfile(path_to_wallpaper):\n"
  },
  {
    "id": "shortcuts",
    "evr": "0.16.1-alt1",
    "package": "gpupdate",
    "after_sha256": "dc4ff287135f11ce553afb2fb304d12a5d28ad58b1062351e6d791e0018374c4",
    "path": "/usr/lib/python3/site-packages/gpoa/frontend/shortcut_applier.py",
    "before_sha256": "133167fc9c9f1b7808e364e8825a4f857331d5a174fd77993318fbbc252e98d8",
    "patch": "--- shortcuts.before\n+++ shortcuts.after\n@@ -191,8 +191,15 @@\n                     obj.get(\u0027arguments\u0027),\n                     obj.get(\u0027name\u0027),\n                     obj.get(\u0027action\u0027),\n-                    get_ttype(obj.get(\u0027target_type\u0027)))\n+                    get_ttype(obj.get(\u0027type\u0027, obj.get(\u0027target_type\u0027))))\n                 shortcut_machine.set_usercontext(1)\n+                shortcut_machine.set_icon(obj.get(\u0027icon\u0027))\n+                shortcut_machine.set_comment(obj.get(\u0027comment\u0027, \u0027\u0027))\n+                shortcut_machine.set_disabled(obj.get(\u0027disabled\u0027, False))\n+                shortcut_machine.set_uid(obj.get(\u0027uid\u0027))\n+                shortcut_machine.set_remove_policy(obj.get(\u0027remove_policy\u0027, False))\n+                shortcut_machine.set_bypass_errors(obj.get(\u0027bypass_errors\u0027, False))\n+                shortcut_machine.set_apply_once(obj.get(\u0027apply_once\u0027, False))\n                 result.append(shortcut_machine)\n         except Exception as exc:\n             log(\u0027D207\u0027, {\u0027exc\u0027: str(exc)})\n"
  }
]
''')
BACKUPS = Path('var/backups/alt-gpupdate-compat')

# 0.16.4 carries the KDE and shortcut fixes upstream. Their exact vendor bytes
# are accepted without rewriting them; the unchanged service parser still needs
# the inspected setter correction. Keep 0.16.1 recipes for legacy backups.
PATCH_SETS = {
    '0.16.1-alt1': PATCHES,
    '0.16.4-alt1': [
        dict(PATCHES[0], evr='0.16.4-alt1'),
        dict(PATCHES[1], evr='0.16.4-alt1', patch='',
             before_sha256='52838e1c47815d192c391f0be63157950c9e79a46cad997d3cb1ba8b4d9fa365',
             after_sha256='52838e1c47815d192c391f0be63157950c9e79a46cad997d3cb1ba8b4d9fa365'),
        dict(PATCHES[2], evr='0.16.4-alt1', patch='',
             before_sha256='0498f7a2fa15aab0489f805a5fa785c9ded33d314e3ada3fb0f6141ff9f51eba',
             after_sha256='0498f7a2fa15aab0489f805a5fa785c9ded33d314e3ada3fb0f6141ff9f51eba'),
        {'id': 'shortcut_model', 'package': 'gpupdate', 'evr': '0.16.4-alt1',
         'path': '/usr/lib/python3/site-packages/gpoa/gpt/shortcuts.py', 'patch': '',
         'before_sha256': '718f3aefd17e5ccc2e9161153e84e8ec43291fdb12abc00f60b8436018d5deef',
         'after_sha256': '718f3aefd17e5ccc2e9161153e84e8ec43291fdb12abc00f60b8436018d5deef'},
    ],
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def patched(data, patch):
    if sha(data) != patch['before_sha256']:
        raise ValueError('source_unknown')
    lines = data.decode('utf-8').splitlines(True)
    output, cursor = [], 0
    diff = patch['patch'].splitlines(True)
    i = 2
    if len(diff) < 3 or not diff[0].startswith('--- ') or not diff[1].startswith('+++ '):
        raise ValueError('patch_invalid')
    while i < len(diff):
        match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', diff[i])
        if not match: raise ValueError('patch_invalid')
        start, count, new_start, new_count = (int(v) if v is not None else 1 for v in match.groups())
        start -= 1
        if start < cursor: raise ValueError('patch_overlap')
        output.extend(lines[cursor:start]);cursor = start
        if len(output) != new_start-1: raise ValueError('patch_offset')
        old_used = new_used = 0
        i += 1
        while i < len(diff) and not diff[i].startswith('@@ '):
            prefix, content = diff[i][:1], diff[i][1:]
            if prefix in (' ', '-'):
                if cursor >= len(lines) or lines[cursor] != content: raise ValueError('patch_context')
                cursor += 1;old_used += 1
            if prefix in (' ', '+'): output.append(content);new_used += 1
            if prefix not in (' ', '-', '+'): raise ValueError('patch_invalid')
            i += 1
        if (old_used, new_used) != (count, new_count): raise ValueError('patch_count')
    result = ''.join(output+lines[cursor:]).encode('utf-8')
    if sha(result) != patch['after_sha256']: raise ValueError('patch_result_unknown')
    compile(result, patch['path'], 'exec')
    return result


def safe(path, root, owner, *, directory=False):
    if not path.is_relative_to(root): raise ValueError('path_outside_root')
    for parent in (path if directory else path.parent, *(path.parents if directory else path.parent.parents)):
        if not parent.is_relative_to(root): break
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('parent_unsafe')
    info = path.lstat()
    if directory: return info
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o7022
            or info.st_nlink != 1 or info.st_size > 262144): raise ValueError('file_unsafe')
    return info


def metadata(info):
    return {key: getattr(info, 'st_'+key) for key in ('uid','gid','mode','mtime_ns','atime_ns','ino','dev')}


def package_info(path):
    r = subprocess.run(['/usr/bin/rpm','-qf','--qf','%{NAME}|%{VERSION}-%{RELEASE}\n',str(path)],
                       capture_output=True, text=True, timeout=15)
    parts = r.stdout.strip().split('|')
    if r.returncode or len(parts) != 2 or '\n' in r.stdout.strip(): raise ValueError('package_unverified')
    return tuple(parts)


def busy_client():
    names = {'gpupdate','gpoa','gpupdate-user','gpupdate-setup','apt-get','apt','rpm','epm'}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name) == os.getpid(): continue
        try: args = p.joinpath('cmdline').read_bytes().decode().split('\0')
        except (OSError, UnicodeError): continue
        if any(Path(a).name in names for a in args[:3] if a): return True
    return False


def ensure_directory(path, root, owner):
    if path.exists() or path.is_symlink():
        safe(path, root, owner, directory=True)
        return
    ensure_directory(path.parent, root, owner)
    path.mkdir(mode=0o700)
    safe(path, root, owner, directory=True)
    sync_directory(path.parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


@contextmanager
def locked(root, owner):
    directory = root/'run/alt-gpupdate-compat'
    ensure_directory(directory, root, owner)
    path = directory/'repair.lock'
    if path.exists() or path.is_symlink(): safe(path, root, owner)
    fd = os.open(path, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    try:
        actual = os.fstat(fd)
        if actual.st_uid != owner or stat.S_IMODE(actual.st_mode) != 0o600: raise ValueError('lock_unsafe')
        try: fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('client_busy') from None
        yield
    finally: os.close(fd)


def replace_module(path, data, info, *, restore_times=False):
    fd, name = tempfile.mkstemp(prefix='.gpupdate-compat-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), stat.S_IMODE(info['mode']))
            os.fchown(output.fileno(), info['uid'], info['gid'])
            output.write(data);output.flush();os.fsync(output.fileno())
        os.replace(name, path)
        if restore_times: os.utime(path, ns=(info['atime_ns'],info['mtime_ns']))
        sync_directory(path.parent)
    finally:
        if os.path.exists(name): os.unlink(name)


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as output:
        output.write(data);output.flush();os.fsync(output.fileno())
    sync_directory(path.parent)


def save_manifest(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()
    fd, temporary = tempfile.mkstemp(prefix='.manifest-', dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as output:
            output.write(data);output.flush();os.fsync(output.fileno())
        os.replace(temporary,path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def plan(root, owner, package_query):
    first = root/PATCHES[0]['path'].lstrip('/')
    try: safe(first,root,owner)
    except OSError: raise ValueError('module_unavailable') from None
    package, version = package_query(first)
    recipes = PATCH_SETS.get(version)
    if package != 'gpupdate' or recipes is None: raise ValueError('package_version_unsupported')
    rows = []
    for patch in recipes:
        path = root/patch['path'].lstrip('/')
        try: info = safe(path,root,owner)
        except OSError: raise ValueError('module_unavailable') from None
        if stat.S_IMODE(info.st_mode) & 0o444 != 0o444:
            raise ValueError('module_permissions_unsafe')
        if package_query(path) != (patch['package'],patch['evr']): raise ValueError('package_version_unsupported')
        before = path.read_bytes();digest = sha(before)
        if digest not in (patch['before_sha256'],patch['after_sha256']): raise ValueError('source_unknown')
        fixed = digest == patch['after_sha256']
        rows.append({'patch':patch,'path':path,'info':metadata(info),'before':before,
                     'after':before if fixed else patched(before,patch),'fixed':fixed})
    return rows


def unchanged(row, root, owner):
    info = safe(row['path'],root,owner)
    if (info.st_dev,info.st_ino,info.st_mtime_ns,sha(row['path'].read_bytes())) != (
            row['info']['dev'],row['info']['ino'],row['info']['mtime_ns'],sha(row['before'])):
        raise ValueError('source_changed')


def repair(*, root=Path('/'), owner=0, package_query=package_info, busy=busy_client, apply=False):
    root = Path(root)
    rows = plan(root,owner,package_query)
    pending = [r for r in rows if not r['fixed']]
    result = {'schema':1,'changed':bool(pending),'backup_id':None,'fixes':[
        {'id':r['patch']['id'],'state':'already_fixed' if r['fixed'] else 'would_patch'} for r in rows]}
    if not apply or not pending: return result
    if busy(): raise ValueError('client_busy')
    with locked(root,owner):
        rows = plan(root,owner,package_query);pending = [r for r in rows if not r['fixed']]
        if not pending: return dict(result,changed=False,fixes=[dict(id=r['patch']['id'],state='already_fixed') for r in rows])
        if busy(): raise ValueError('client_busy')
        parent = root/BACKUPS;ensure_directory(parent,root,owner)
        identifier = 'gpupdate-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:12]
        backup = parent/identifier;backup.mkdir(mode=0o700);sync_directory(parent)
        manifest = {'schema':2,'state':'prepared','backup_id':identifier,'modules':[
            {'id':r['patch']['id'],'path':r['patch']['path'],'metadata':r['info'],
             'package':r['patch']['package'],'evr':r['patch']['evr'],
             'before_sha256':r['patch']['before_sha256'],'after_sha256':r['patch']['after_sha256']} for r in pending]}
        for row in pending: private_write(backup/(row['patch']['id']+'.original'),row['before'])
        private_write(backup/'rollback.py',Path(__file__).read_bytes())
        save_manifest(backup/'manifest.json',manifest)
        written = []
        try:
            for row in pending:
                unchanged(row,root,owner)
                written.append(row)
                replace_module(row['path'],row['after'],row['info'])
                if sha(row['path'].read_bytes()) != row['patch']['after_sha256']: raise ValueError('write_unverified')
            manifest['state']='applied';save_manifest(backup/'manifest.json',manifest)
        except Exception:
            try:
                for row in reversed(written):
                    safe(row['path'],root,owner)
                    digest = sha(row['path'].read_bytes())
                    if digest == row['patch']['before_sha256']: continue
                    if digest != row['patch']['after_sha256']: raise ValueError('rollback_collision')
                    replace_module(row['path'],row['before'],row['info'],restore_times=True)
                manifest['state']='rolled_back';save_manifest(backup/'manifest.json',manifest)
            except Exception: raise ValueError('apply_failed_rollback_unverified') from None
            raise ValueError('apply_failed_rolled_back') from None
        return dict(result,backup_id=identifier,fixes=[dict(id=r['patch']['id'],state='already_fixed' if r['fixed'] else 'patched') for r in rows])


def rollback(identifier, *, root=Path('/'), owner=0, package_query=package_info):
    if not re.fullmatch(r'gpupdate-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}',identifier): raise ValueError('backup_id_invalid')
    root = Path(root);backup = root/BACKUPS/identifier
    safe(backup,root,owner,directory=True)
    with locked(root,owner):
        safe(backup/'manifest.json',root,owner)
        manifest = json.loads((backup/'manifest.json').read_bytes())
        if (type(manifest.get('schema')) is not int or manifest['schema'] not in (1, 2) or manifest.get('backup_id') != identifier
                or manifest.get('state') not in ('prepared','applied','rolled_back')
                or not isinstance(manifest.get('modules'),list) or not 0<len(manifest['modules'])<=len(PATCHES)):
            raise ValueError('backup_manifest_invalid')
        rows = [];seen = set()
        for row in manifest['modules']:
            # Schema-1 receipts predate version selection and remain pinned to
            # 0.16.1. Never reinterpret their identical service bytes as 0.16.4.
            recipes = PATCHES if manifest['schema'] == 1 else (
                PATCH_SETS.get(row.get('evr'), []) if isinstance(row.get('evr'),str) else [])
            patch = next((p for p in recipes if p['id']==row['id'] and
                          (manifest['schema']==1 or p['package']==row.get('package'))),None)
            if (not patch or row['id'] in seen or any(row.get(k)!=patch[k] for k in ('path','before_sha256','after_sha256'))):
                raise ValueError('backup_manifest_invalid')
            seen.add(row['id']);path=root/patch['path'].lstrip('/');current=safe(path,root,owner)
            original=backup/(patch['id']+'.original');safe(original,root,owner)
            data=original.read_bytes();digest=sha(path.read_bytes())
            meta=row.get('metadata')
            if (not isinstance(meta,dict) or set(meta)!={'uid','gid','mode','mtime_ns','atime_ns','ino','dev'}
                    or any(type(v) is not int or v<0 for v in meta.values())
                    or not stat.S_ISREG(meta['mode']) or meta['uid']!=owner or meta['mode'] & 0o7022
                    or (current.st_uid,current.st_gid,current.st_mode)!=(meta['uid'],meta['gid'],meta['mode'])):
                raise ValueError('backup_metadata_invalid')
            if (sha(data)!=patch['before_sha256'] or digest not in (patch['before_sha256'],patch['after_sha256'])
                    or package_query(path)!=(patch['package'],patch['evr'])):raise ValueError('rollback_unverified')
            rows.append((path,data,meta,digest!=patch['before_sha256'],digest))
        if busy_client(): raise ValueError('client_busy')
        for path,data,info,needed,digest in rows:
            if needed:
                safe(path,root,owner)
                if sha(path.read_bytes())!=digest:raise ValueError('rollback_source_changed')
                replace_module(path,data,info,restore_times=True)
        manifest['state']='rolled_back';save_manifest(backup/'manifest.json',manifest)
        return {'schema':1,'changed':any(r[3] for r in rows),'backup_id':identifier}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check',action='store_true');group.add_argument('--apply',action='store_true')
    group.add_argument('--rollback',metavar='BACKUP_ID')
    args=parser.parse_args()
    if os.geteuid()!=0: raise ValueError('root_required')
    result=rollback(args.rollback) if args.rollback else repair(apply=args.apply)
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        code=str(exc) if isinstance(exc,ValueError) else 'operation_failed'
        print(json.dumps({'status':'error','code':code}));raise SystemExit(2)
