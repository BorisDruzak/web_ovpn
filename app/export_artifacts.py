"""Private, expiring operation artifacts; separate from VPN download roots."""
from pathlib import Path
from contextlib import contextmanager
import os
import re
import subprocess
import threading
import time
from uuid import uuid4

from .config import get_settings
from .xlsx_export import ExportLimit,MAX_FILE_BYTES

EXPORT_TYPES = frozenset({'inventory-xlsx','inventory-deleted','network-xlsx'})
MAX_STORED_BYTES = 200 * 1024 * 1024
MAX_STORED_FILES = 64
_NAME = re.compile(r'export-[0-9a-f]{32}\.xlsx\Z')
_lock = threading.Lock()


@contextmanager
def _storage_lock(root):
    if (root/'.storage.lock').is_symlink():
        raise ExportLimit('Некорректный файл блокировки экспорта')
    descriptor = os.open(root/'.storage.lock',os.O_RDWR|os.O_CREAT,0o600)
    with os.fdopen(descriptor,'r+b') as file:
        # Windows permits locking a range beyond EOF. Reading/initializing the
        # sentinel before acquisition would race with another process's lock.
        deadline = time.monotonic()+5
        while True:
            try:
                if os.name == 'nt':
                    import msvcrt
                    file.seek(0)
                    msvcrt.locking(file.fileno(),msvcrt.LK_NBLCK,1)
                else:
                    import fcntl
                    fcntl.flock(file.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic()>=deadline:
                    raise ExportLimit('Хранилище экспорта занято. Повторите позже') from None
                time.sleep(.05)
        try:
            yield
        finally:
            if os.name == 'nt':
                file.seek(0)
                msvcrt.locking(file.fileno(),msvcrt.LK_UNLCK,1)
            else:
                fcntl.flock(file.fileno(),fcntl.LOCK_UN)


def _purge(root):
    ttl = get_settings().download_ttl_minutes * 60
    files = []
    for path in root.iterdir():
        if not _NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_mtime + ttl <= time.time():
            path.unlink()
        else:
            files.append(path)
    return files


def cleanup_exports():
    root = export_root()
    if not root.exists() or root.is_symlink():
        return
    with _lock,_storage_lock(root):
        _purge(root)


def start_cleanup(app):
    stop = threading.Event()
    def run():
        while not stop.is_set():
            try:
                cleanup_exports()
            except (OSError,ExportLimit):
                pass  # Next tick retries; expired files cannot be downloaded.
            if stop.wait(60):
                break
    thread = threading.Thread(target=run,name='export-artifact-cleanup',daemon=True)
    app.state.export_cleanup = (stop,thread)
    thread.start()


def stop_cleanup(app):
    state = getattr(app.state,'export_cleanup',None)
    if state:
        state[0].set()
        state[1].join(timeout=6)


def export_root():
    default = (Path(os.environ.get('LOCALAPPDATA',str(Path.home()))) / 'OpenVPNWeb' / 'private-exports'
        if os.name == 'nt' else get_settings().inventory_photo_root.parent / 'private-exports')
    return Path(os.environ.get('PANEL_EXPORT_ROOT',str(default))).expanduser().absolute()


def _private_directory(root):
    if root.is_symlink():
        raise ExportLimit('Каталог экспорта не может быть символической ссылкой')
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    if os.name == 'nt':
        system = Path(os.environ.get('SystemRoot','C:/Windows'))/'System32'
        result = subprocess.run([str(system/'whoami.exe'),'/user','/fo','csv','/nh'],capture_output=True,text=True,timeout=5,check=True)
        sid = re.search(r'S-1-\d+(?:-\d+)+',result.stdout)
        if not sid:
            raise ExportLimit('Не удалось определить владельца каталога экспорта')
        # Replace the DACL rather than preserving explicit broad old grants.
        import ctypes
        from ctypes import wintypes
        api = ctypes.WinDLL('advapi32',use_last_error=True)
        convert = api.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.DWORD)]
        convert.restype = wintypes.BOOL
        get_acl = api.GetSecurityDescriptorDacl
        get_acl.argtypes = [ctypes.c_void_p,ctypes.POINTER(wintypes.BOOL),ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.BOOL)]
        get_acl.restype = wintypes.BOOL
        set_acl = api.SetNamedSecurityInfoW
        set_acl.argtypes = [wintypes.LPWSTR,ctypes.c_int,wintypes.DWORD]+[ctypes.c_void_p]*4
        set_acl.restype = wintypes.DWORD
        free = ctypes.WinDLL('kernel32').LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        descriptor = ctypes.c_void_p()
        sddl = 'D:P(A;OICI;FA;;;'+sid.group()+')(A;OICI;FA;;;SY)'
        if not convert(sddl,1,ctypes.byref(descriptor),None):
            raise ExportLimit('Не удалось защитить каталог экспорта')
        try:
            present,defaulted,acl = wintypes.BOOL(),wintypes.BOOL(),ctypes.c_void_p()
            if not get_acl(descriptor,ctypes.byref(present),ctypes.byref(acl),ctypes.byref(defaulted)) or not present:
                raise ExportLimit('Не удалось защитить каталог экспорта')
            if set_acl(str(root),1,4|0x80000000,None,None,acl,None):
                raise ExportLimit('Не удалось защитить каталог экспорта')
        finally:
            free(descriptor)
    else:
        root.chmod(0o700)


def assert_export_file(path):
    root = export_root().resolve()
    original = Path(path)
    resolved = original.resolve()
    if original.is_symlink() or resolved.parent != root or not _NAME.fullmatch(resolved.name) or not resolved.is_file():
        raise ValueError('export file is outside private artifact storage')
    ttl = get_settings().download_ttl_minutes * 60
    if resolved.stat().st_mtime + ttl <= time.time():
        raise ValueError('export file expired')
    return resolved


def store_export(payload):
    if len(payload)>MAX_FILE_BYTES:
        raise ExportLimit('Файл превышает бюджет Excel')
    with _lock:
        root = export_root()
        _private_directory(root)
        with _storage_lock(root):
            return _store_locked(root,payload)


def _store_locked(root,payload):
    files = _purge(root)
    if len(files)>=MAX_STORED_FILES or sum(path.stat().st_size for path in files)+len(payload)>MAX_STORED_BYTES:
        raise ExportLimit('Хранилище экспорта заполнено. Повторите после истечения срока файлов')
    path = root / ('export-'+uuid4().hex+'.xlsx')
    descriptor = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(descriptor,'wb') as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path.resolve()


def check_export_permission(user,file_type):
    from .permissions import check_user_permission
    area = 'network' if file_type == 'network-xlsx' else 'inventory'
    check_user_permission(user,area+':read')
    check_user_permission(user,area+':export')
    if file_type == 'inventory-deleted':
        check_user_permission(user,'inventory:delete')
