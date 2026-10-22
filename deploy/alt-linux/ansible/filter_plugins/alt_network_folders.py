"""Fixed optional probe bundle and a total, sanitized result decoder."""
import json
from pathlib import Path


def unknown():
    return {'status': 'unknown', 'code': 'network_folders_unverified', 'changed': False,
            'ad_verified': False, 'created_count': 0, 'unknown_count': 0, 'preserved_count': 0}


def result(value):
    try:
        if not isinstance(value, dict) or value.get('rc') != 0:
            return unknown()
        raw = value.get('stdout', '')
        if not isinstance(raw, str) or len(raw.encode()) > 4096:
            return unknown()
        document = json.loads(raw)
        if (not isinstance(document, dict) or document.get('status') not in ('ok', 'partial', 'unknown')
                or type(document.get('changed')) is not bool
                or type(document.get('ad_verified')) is not bool
                or document.get('code') not in ('checked', 'no_accessible_folders', 'network_folders_unverified')
                or any(type(document.get(k, 0)) is not int or not 0 <= document.get(k, 0) <= 128
                       for k in ('created_count', 'unknown_count', 'preserved_count'))
                or document['status'] in ('ok', 'partial') and document['ad_verified'] is not True):
            return unknown()
        return {key: document.get(key, default) for key, default in unknown().items()}
    except (ValueError, TypeError, UnicodeError):
        return unknown()


def program(role_path):
    """No target installation: execute only source from this published role."""
    try:
        role = Path(role_path)
        network = (role / 'files/network_folders.py').read_text(encoding='utf-8')
        session_path = role / '../../../control/alt_deploy/user_session.py'
        if not session_path.is_file():
            session_path = Path('/opt/alt-deploy-control/alt_deploy/user_session.py')
        session = session_path.read_text(encoding='utf-8')
        value = 'import sys,types\n'
        for name, source in (('alt_network_user_session', session), ('alt_network_folders', network)):
            value += (f"m=types.ModuleType({name!r});sys.modules[m.__name__]=m;"
                      f"exec(compile({source!r},'<published-{name}>','exec'),m.__dict__)\n")
        value += f'm.PERSONAL_PROGRAM={network!r}\nraise SystemExit(m.main())\n'
        if len(value.encode()) > 120000:
            raise ValueError
        return value
    except (OSError, ValueError, TypeError):
        return 'print(' + repr(json.dumps(unknown())) + ')'


class FilterModule:
    def filters(self):
        return {'alt_network_folders_program': program, 'alt_network_folders_result': result}
