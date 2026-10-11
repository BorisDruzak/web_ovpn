from __future__ import annotations

import copy
import json
import os

import pytest

META = {'hostname': 'alt-a1-pc3', 'realm': 'sosnadmin.local', 'workgroup': 'SOSNADM',
    'domain_guid': '11111111-2222-3333-4444-555555555555', 'domain_sid': 'S-1-5-21-111-222-333',
    'dc_hostname': 'synthetic-dc.sosnadmin.local', 'dc_address': '192.0.2.1'}
PASSWORD = 'Aa9!' + 'b'*64


def api():
    from alt_deploy import setup_recovery_native
    return setup_recovery_native


def metadata_dump(meta=META):
    return '''    SOSNADM: struct secrets_domain_infoB
        version                  : SECRETS_DOMAIN_INFO_VERSION_1 (1)
        reserved                 : 0x00000000 (0)
        info                     : union secrets_domain_infoU(case 1)
        info1                    : *
            info1                    : struct secrets_domain_info1
                computer_name            : 'ALT-A1-PC3'
                account_name             : 'ALT-A1-PC3$'
                secure_channel_type      : SEC_CHAN_WKSTA (2)
                domain_info              : struct lsa_DnsDomainInfo
                    name                     : struct lsa_StringLarge
                        string                   : *
                            string                   : 'SOSNADM'
                    dns_domain               : struct lsa_StringLarge
                        string                   : *
                            string                   : 'sosnadmin.local'
                    dns_forest               : struct lsa_StringLarge
                        string                   : *
                            string                   : 'sosnadmin.local'
                    domain_guid              : 11111111-2222-3333-4444-555555555555
                    sid                      : *
                        sid                      : S-1-5-21-111-222-333
                salt_principal           : *
                    salt_principal           : 'host/alt-a1-pc3.sosnadmin.local@SOSNADMIN.LOCAL'
                next_change              : NULL
                password                 : *
                    password                 : struct secrets_domain_info1_password
                        cleartext_blob           : DATA_BLOB length=136
'''


def keytab_dump(kvno=-1):
    lines = ['Vno  Type                                        Principal']
    for principal in ('ALT-A1-PC3$@SOSNADMIN.LOCAL', 'host/alt-a1-pc3.sosnadmin.local@SOSNADMIN.LOCAL'):
        for kind in ('AES-256 CTS mode with 96-bit SHA-1 HMAC', 'AES-128 CTS mode with 96-bit SHA-1 HMAC'):
            lines.append(f' {kvno:2}  {kind:43} {principal}')
    return '\n'.join(lines)+'\n'


@pytest.mark.parametrize('field', list(META))
def test_bad_or_injected_metadata_is_refused(field):
    meta = dict(META); meta[field] = '--option=include=/etc/private'
    with pytest.raises(ValueError): api().validate_metadata(meta)


def test_fixed_configuration_and_sandbox_exclude_live_auth_and_host_sockets(tmp_path):
    module = api(); tmp_path.chmod(0o700)
    config = module.sandbox_config(META)
    assert 'include' not in config and 'sync machine password to keytab = disabled' in config
    assert 'sync machine password script =\n' in config
    for name in ('private dir', 'state directory', 'cache directory', 'lock directory', 'pid directory',
                 'log file', 'ncalrpc dir', 'winbindd socket directory', 'passdb backend'):
        assert name in config
    command = module.sandbox_command(tmp_path, META, 'compose', owner=os.geteuid())
    assert '--unshare-net' in command and '--unshare-user' in command and '--unshare-pid' in command
    assert command.count('--bind') == 1 and command[command.index('--bind')+2] == '/work'
    assert '--clearenv' in command and '--cap-drop' in command
    assert '/etc/samba' not in command and '/run' not in command and '/var/lib/samba' not in command
    assert 'provision' not in command and 'reuse' not in command and 'join' not in command
    assert PASSWORD not in str(command)


def test_metadata_parser_requires_exact_current_domain_and_no_pending_change():
    assert api().validate_native_metadata(metadata_dump(), META) is True


@pytest.mark.parametrize('changed', ['account', 'domain', 'guid', 'sid', 'salt', 'pending', 'duplicate', 'trailing'])
def test_mismatched_native_metadata_is_refused(changed):
    text = metadata_dump()
    if changed == 'account': text = text.replace("'ALT-A1-PC3$'", "'ALT-A1-PC4$'")
    elif changed == 'domain': text = text.replace("'sosnadmin.local'", "'other.invalid'")
    elif changed == 'guid': text = text.replace(META['domain_guid'], 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    elif changed == 'sid': text = text.replace(META['domain_sid'], 'S-1-5-21-444-555-666')
    elif changed == 'salt': text = text.replace('host/alt-a1-pc3.', 'host/alt-a1-pc4.')
    elif changed == 'pending': text = text.replace('next_change              : NULL', 'next_change              : *')
    elif changed == 'duplicate': text += "                account_name             : 'ALT-A1-PC3$'\n"
    elif changed == 'trailing': text = text.replace("'ALT-A1-PC3$'", "'ALT-A1-PC3$' extra")
    with pytest.raises(ValueError): api().validate_native_metadata(text, META)


def test_rehearsal_keytab_does_not_prove_real_kvno():
    assert api().validate_rehearsal_keytab(keytab_dump(), META) is True
    with pytest.raises(ValueError): api().validate_domain_keytab(keytab_dump(), META, 3)
    assert api().validate_domain_keytab(keytab_dump(3), META, 3) is True


@pytest.mark.parametrize('changed', ['kvno', 'principal', 'aes', 'duplicate', 'extra', 'garbage'])
def test_invalid_domain_keytab_is_refused(changed):
    text = keytab_dump(3)
    if changed == 'kvno': text = text.replace('  3 ', '  4 ', 1)
    elif changed == 'principal': text = text.replace('ALT-A1-PC3$', 'ALT-A1-PC4$')
    elif changed == 'aes': text = text.replace('AES-256 CTS mode with 96-bit SHA-1 HMAC', 'ArcFour with HMAC/md5')
    elif changed == 'duplicate': text += text.splitlines()[-1]+'\n'
    elif changed == 'extra': text += '  3  AES-128 CTS mode with 96-bit SHA-1 HMAC     other@SOSNADMIN.LOCAL\n'
    else: text += 'SYNTHETIC_SECRET_DIAGNOSTIC\n'
    with pytest.raises(ValueError): api().validate_domain_keytab(text, META, 3)


def test_installed_samba_flag_indent_and_safe_password_banner():
    text = metadata_dump().replace('                salt_principal',
        '                trust_flags              : 0x0000001a (26)\n'
        '                       1: NETR_TRUST_FLAG_PRIMARY  \n'
        '                salt_principal', 1)
    text += 'The password values are only included using -f flag.\n'
    assert api().validate_native_metadata(text, META)
    with pytest.raises(ValueError):
        api().validate_native_metadata(text.replace('NETR_TRUST_FLAG_PRIMARY', 'account_name'), META)


def test_native_uppercase_dns_domain_is_the_same_domain():
    text = metadata_dump().replace("'sosnadmin.local'", "'SOSNADMIN.LOCAL'")
    assert api().validate_native_metadata(text, META)


def test_sandbox_refuses_linked_directory_and_unknown_operation(tmp_path):
    tmp_path.chmod(0o700)
    link = tmp_path / 'linked'; link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError): api().sandbox_command(link, META, 'compose', owner=os.geteuid())
    with pytest.raises(ValueError): api().sandbox_command(tmp_path, META, 'join', owner=os.geteuid())


def test_read_only_password_check_uses_fixed_tdb_and_stdin(tmp_path):
    tmp_path.chmod(0o700)
    command = api().sandbox_command(tmp_path, META, 'password_check', owner=os.geteuid())
    assert '-I' in command and '-B' in command and PASSWORD not in str(command)
    assert "flags=os.O_RDONLY" in command[-1]
    assert 'sys.stdin.buffer.read(69)' in command[-1]
    assert "password+b'\\0'" in command[-1]


def test_previous_placeholder_requires_complete_aes_entries():
    text = keytab_dump(-1) + keytab_dump(-2).split('\n', 1)[1]
    assert api().validate_rehearsal_keytab(text, META)
    with pytest.raises(ValueError): api().validate_domain_keytab(text, META, 3)
    with pytest.raises(ValueError):
        api().validate_rehearsal_keytab(text.replace(text.splitlines()[-1]+'\n', ''), META)
