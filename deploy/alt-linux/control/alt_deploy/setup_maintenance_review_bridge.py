"""Thin adapter to the one trusted native backup maintenance validator."""
import importlib
from pathlib import Path
import stat
import sys

from .ad_directory import fail


def review_service(settings):
    sibling = Path(__file__).parents[2]/'backup'
    root = sibling if sibling.exists() else Path('/opt/alt-deploy-maintenance')
    module = root/'alt_deploy_backup/setup_maintenance_review.py'
    for path in (root, *root.parents, module.parent):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise fail('setup_maintenance_code_unsafe', 'Native maintenance validator code is unsafe')
    info = module.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise fail('setup_maintenance_code_unsafe', 'Native maintenance validator code is unsafe')
    sys.path.insert(0, str(root))
    loaded = importlib.import_module('alt_deploy_backup.setup_maintenance_review')
    if Path(loaded.__file__).resolve() != module.resolve():
        raise fail('setup_maintenance_code_unsafe', 'Native maintenance validator origin differs')
    return loaded.MaintenanceReview(settings)
