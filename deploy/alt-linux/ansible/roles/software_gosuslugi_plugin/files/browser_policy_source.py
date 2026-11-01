#!/usr/bin/python3
"""Read-only ownership gate for a workstation explicitly migrated to Yandex GPO."""
import ast
import configparser
import json
from pathlib import Path
import stat
import sys
import uuid

EXTENSION = 'jabjbhgjaidecageckilhonbggakppme;https://clients2.google.com/service/update2/crx'
MANAGED = Path('/etc/opt/yandex/browser/policies/managed')
LEGACY = MANAGED / 'alt-signature-suite.json'
GENERATED = MANAGED / 'policies.json'
RECEIPT = Path('/etc/gpupdate/yandex-signature-gpo.json')
CACHE = Path('/etc/dconf/db/policy.d/policy.ini')


def literal(value):
    """Unwrap dconf's quoted metadata without executing policy content."""
    for unused in range(2):
        if not isinstance(value, str):
            break
        try:
            value = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            break
    return value


def select_source(receipt, generated, cache_text, machine_uuid, legacy):
    if receipt is None:
        return {'source': 'ansible', 'policy_path': str(LEGACY)}
    if not isinstance(receipt, dict) or receipt.get('schema') != 1:
        raise ValueError('invalid Yandex GPO migration receipt')
    if not all(isinstance(receipt.get(key), str) for key in ('machine_uuid', 'gpo_id', 'gpo_name')):
        raise ValueError('invalid Yandex GPO receipt identity')
    if str(uuid.UUID(receipt['machine_uuid'])) != str(uuid.UUID(machine_uuid)):
        raise ValueError('Yandex GPO receipt belongs to another workstation')
    gpo_id = str(uuid.UUID(receipt['gpo_id']))
    gpo_name = receipt.get('gpo_name')
    if not isinstance(gpo_name, str) or not gpo_name.strip():
        raise ValueError('missing GPO name')
    if not isinstance(generated, dict):
        raise ValueError('invalid generated browser policy object')
    extensions = generated.get('ExtensionInstallForcelist', [])
    if not isinstance(extensions, list) or EXTENSION not in extensions:
        raise ValueError('required signature extension is missing from generated GPO policy')
    extension_id = EXTENSION.split(';')[0]
    if sum(isinstance(item, str) and item.split(';')[0] == extension_id for item in extensions) != 1:
        raise ValueError('conflicting signature extension entries')
    cache = configparser.RawConfigParser(strict=False)
    cache.optionxform = str
    cache.read_string(cache_text)
    current_gpos = [dict(cache[section]) for section in cache.sections()
                    if section.startswith('Software/BaseALT/Policies/GpoPriority/Machine/')]
    if sum(literal(item.get('display_name', '')) == gpo_name for item in current_gpos) != 1:
        raise ValueError('missing or ambiguous GPO display name in machine provenance')
    if not any(str(literal(item.get('name', ''))).strip('{}').lower() == gpo_id
               and literal(item.get('display_name', '')) == gpo_name for item in current_gpos):
        raise ValueError('expected GPO is absent from current machine policy provenance')
    branch = 'Software/Policies/YandexBrowser/ExtensionInstallForcelist'
    if not cache.has_section(branch) or not cache.has_section('Source/' + branch):
        raise ValueError('missing signature policy source metadata')
    backed = False
    for key, value in cache[branch].items():
        metadata = literal(cache['Source/' + branch].get(key, ''))
        if literal(value) == EXTENSION and isinstance(metadata, dict) and metadata.get('policy_name') == gpo_name:
            backed = True
    if not backed:
        raise ValueError('signature extension does not originate in the expected GPO')
    if legacy is not None and legacy != {'ExtensionInstallForcelist': [EXTENSION]}:
        raise ValueError('legacy policy contains unexpected settings; retain it for review')
    return {'source': 'gpo', 'policy_path': str(GENERATED), 'gpo_id': gpo_id}


def protected_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('unsafe policy evidence file: ' + str(path))


def main():
    if not RECEIPT.exists() and not RECEIPT.is_symlink():
        print(json.dumps(select_source(None, {}, '', '', None)))
        return
    for path in (RECEIPT, GENERATED, CACHE):
        protected_file(path)
    receipt = json.loads(RECEIPT.read_text())
    if not isinstance(receipt, dict):
        raise ValueError('invalid Yandex GPO migration receipt object')
    legacy = None
    if LEGACY.exists() or LEGACY.is_symlink():
        protected_file(LEGACY)
        legacy = json.loads(LEGACY.read_text())
        if not isinstance(legacy, dict):
            raise ValueError('invalid legacy browser policy object; retain it for review')
    result = select_source(receipt, json.loads(GENERATED.read_text()),
                           CACHE.read_text(), Path('/sys/class/dmi/id/product_uuid').read_text().strip(), legacy)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, configparser.Error) as error:
        print('ALT_PREFLIGHT_FAILURE:gosuslugi_plugin_browser_gpo_unverified: ' + str(error), file=sys.stderr)
        sys.exit(2)
