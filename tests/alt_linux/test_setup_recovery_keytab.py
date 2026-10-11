from __future__ import annotations

import struct

import pytest

from alt_deploy import setup_recovery_native as native
from test_setup_recovery_native import META


def entry(components,kind,version=0xffffffff,*,realm='SOSNADMIN.LOCAL',extension=True,padding=b''):
    def text(value):
        raw=value.encode('ascii');return struct.pack('>H',len(raw))+raw
    principal=struct.pack('>H',len(components))+text(realm)+b''.join(text(value) for value in components)
    key=bytes([kind])*({17:16,18:32,23:16}.get(kind,16))
    data=principal+struct.pack('>IIBHH',1,1700000000,version&255,kind,len(key))+key
    if extension:data+=struct.pack('>I',version)
    data+=padding
    return struct.pack('>i',len(data))+data


def fixture(*,previous=False,rc4=False):
    raw=b'\x05\x02'
    for version in ((0xffffffff,0xfffffffe) if previous else (0xffffffff,)):
        for components in (('ALT-A1-PC3$',),('host','alt-a1-pc3.sosnadmin.local')):
            for kind in ((17,18,23) if rc4 else (17,18)):raw+=entry(components,kind,version)
    return raw


def api():
    from alt_deploy.setup_recovery_keytab import bind_offline_keytab
    return bind_offline_keytab


@pytest.mark.parametrize('kvno',[1,255,256,65537,2147483647])
@pytest.mark.parametrize('previous',[False,True])
def test_only_current_offline_keys_are_bound_to_positive_directory_kvno(kvno,previous):
    source=fixture(previous=previous,rc4=True)
    output=api()(source,META,kvno,native=native)
    expected=b'\x05\x02'
    for components in (('ALT-A1-PC3$',),('host','alt-a1-pc3.sosnadmin.local')):
        for kind in (17,18,23):expected+=entry(components,kind,kvno)
    assert output==expected
    assert source==fixture(previous=previous,rc4=True)


@pytest.mark.parametrize('changed',['version','truncated','length','foreign','duplicate','missing_aes',
                                   'unsupported','extension','current_kvno','previous_only','padding','hole'])
def test_unreviewed_or_incomplete_keytab_is_refused(changed):
    raw=fixture()
    if changed=='version':raw=b'\x05\x01'+raw[2:]
    elif changed=='truncated':raw=raw[:-1]
    elif changed=='length':raw=raw[:2]+struct.pack('>i',1000000)+raw[6:]
    elif changed=='foreign':raw+=entry(('OTHER$',),17)
    elif changed=='duplicate':raw+=entry(('ALT-A1-PC3$',),17)
    elif changed=='missing_aes':raw=b'\x05\x02'+entry(('ALT-A1-PC3$',),17)
    elif changed=='unsupported':raw+=entry(('ALT-A1-PC3$',),3)
    elif changed=='extension':raw=b'\x05\x02'+entry(('ALT-A1-PC3$',),17,extension=False)
    elif changed=='current_kvno':raw=b'\x05\x02'+entry(('ALT-A1-PC3$',),17,version=1)
    elif changed=='previous_only':raw=fixture().replace(b'\xff\xff\xff\xff',b'\xff\xff\xff\xfe')
    elif changed=='padding':raw+=entry(('ALT-A1-PC3$',),17,padding=b'SECRET')
    else:raw+=struct.pack('>i',-4)+b'bad!'
    with pytest.raises(ValueError) as error:api()(raw,META,5,native=native)
    assert 'SECRET' not in str(error.value)


@pytest.mark.parametrize('kvno',[True,0,-1,2147483648,'3'])
def test_invalid_or_unverified_directory_version_is_refused(kvno):
    with pytest.raises(ValueError):api()(fixture(),META,kvno,native=native)


def test_zero_filled_native_holes_and_padding_do_not_retain_previous_keys():
    raw=b'\x05\x02'+struct.pack('>i',-4)+b'\0'*4
    for components in (('ALT-A1-PC3$',),('host','alt-a1-pc3.sosnadmin.local')):
        for kind in (17,18):raw+=entry(components,kind,padding=b'\0'*4)
    assert api()(raw,META,7,native=native)==fixture_for_version(7)


def fixture_for_version(kvno):
    return b'\x05\x02'+b''.join(entry(components,kind,kvno)
        for components in (('ALT-A1-PC3$',),('host','alt-a1-pc3.sosnadmin.local')) for kind in (17,18))
