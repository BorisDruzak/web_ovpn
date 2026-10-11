"""Bind fresh offline FILE-v2 keys to a verified directory KVNO in memory.

No files, services or directory are touched. The future fixed importer must
supply its verified one-write result, install privately and prove real trust.
This transformation alone is not a domain-acceptance receipt.
"""
from __future__ import annotations

import struct

MAX_BYTES=16384
_CURRENT=0xffffffff
_PREVIOUS=0xfffffffe
_KEY_LENGTHS={17:16,18:32,23:16}


def _entry(raw,meta):
    position=0
    def take(length):
        nonlocal position
        if length<0 or position+length>len(raw):raise ValueError
        value=raw[position:position+length];position+=length
        return value
    def number(fmt):return struct.unpack(fmt,take(struct.calcsize(fmt)))[0]
    def text():return take(number('>H')).decode('ascii')
    count=number('>H')
    if count not in (1,2):raise ValueError
    realm=text();components=tuple(text() for _ in range(count))
    expected={(meta['hostname'].upper()+'$',),('host',meta['hostname']+'.'+meta['realm'])}
    if realm!=meta['realm'].upper() or components not in expected:raise ValueError
    if number('>I') not in (1,2):raise ValueError
    number('>I') # Preserve the original timestamp.
    short_offset=position;short=number('>B')
    kind=number('>H');length=number('>H')
    if kind not in _KEY_LENGTHS or length!=_KEY_LENGTHS[kind]:raise ValueError
    take(length);key_end=position
    version=number('>I')
    if version not in (_CURRENT,_PREVIOUS) or short!=version&255 or any(take(len(raw)-position)):raise ValueError
    return components,kind,version,short_offset,key_end


def bind_offline_keytab(raw,metadata,kvno,*,native):
    try:
        meta=native.validate_metadata(metadata)
        if type(kvno) is not int or not 1<=kvno<=2147483647:raise ValueError
        if not isinstance(raw,bytes) or not 2<len(raw)<=MAX_BYTES or raw[:2]!=b'\x05\x02':raise ValueError
        position=2;records=0;entries=set();versions=set();current=[]
        while position<len(raw):
            if position+4>len(raw):raise ValueError
            size=struct.unpack('>i',raw[position:position+4])[0];position+=4;records+=1
            if records>24 or position+abs(size)>len(raw):raise ValueError
            if size==0:
                if position!=len(raw):raise ValueError
                break
            record=raw[position:position+abs(size)];position+=abs(size)
            if size<0:
                if any(record):raise ValueError
                continue
            principal,kind,version,short_offset,key_end=_entry(record,meta)
            identity=(principal,kind,version)
            if identity in entries or len(entries)>=12:raise ValueError
            entries.add(identity);versions.add(version)
            if version==_CURRENT:
                updated=bytearray(record[:key_end]);updated[short_offset]=kvno&255
                updated.extend(struct.pack('>I',kvno))
                current.append(struct.pack('>i',len(updated))+updated)
        if _CURRENT not in versions:raise ValueError
        principals={(meta['hostname'].upper()+'$',),('host',meta['hostname']+'.'+meta['realm'])}
        if any((principal,kind,version) not in entries for principal in principals
               for kind in (17,18) for version in versions):raise ValueError
        result=b'\x05\x02'+b''.join(current)
        if len(result)>MAX_BYTES:raise ValueError
        return result
    except Exception:
        raise ValueError('Invalid offline keytab binding') from None
