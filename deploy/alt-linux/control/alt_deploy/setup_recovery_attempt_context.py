"""Explicit protected successor context; never reroute legacy attempt paths."""
from __future__ import annotations
import hashlib,re
import copy
from dataclasses import is_dataclass,replace
from .ad_directory import fail
from .setup_plans import digest,private_read,private_read_bytes,canonical

def predecessor_inventory(state_root,pair):
    from .setup_recovery import _pair
    pair=_pair(**pair);root=state_root/'setup-recovery-attempts';prefix=digest(pair)
    paths=sorted(root.glob(prefix+'.*'))
    if not 1<=len(paths)<=96:raise ValueError('Invalid predecessor inventory')
    return {path.name:hashlib.sha256(private_read_bytes(path)).hexdigest() for path in paths}

def validate_envelopes(state_root,envelopes):
    locations={'operator':('setup-recovery-operator-plans','recovery-operator-'),'recovery':('setup-recovery-plans','recovery-'),
        'startup':('setup-recovery-startup-plans','recovery-startup-'),'terminal':('setup-recovery-terminal-plans','recovery-terminal-')}
    if not isinstance(envelopes,dict) or set(envelopes)!=set(locations):raise ValueError
    for kind,(directory,prefix) in locations.items():
        ref=envelopes[kind]
        if (not isinstance(ref,dict) or set(ref)!={'plan_id','sha256','raw_sha256'}
                or any(not isinstance(ref[key],str) or not re.fullmatch('[0-9a-f]{64}',ref[key]) for key in ('sha256','raw_sha256'))
                or ref['plan_id']!=prefix+ref['sha256']):raise ValueError
        raw=private_read_bytes(state_root/directory/(ref['plan_id']+'.json'))
        if hashlib.sha256(raw).hexdigest()!=ref['raw_sha256']:raise ValueError('Predecessor envelope changed')

def validate_context(state_root,reference,pair=None):
    try:
        from .setup_recovery import _pair
        fields={'attempt_id','admission_sha256','failed_run_id','computer_guid'}
        if (not isinstance(reference,dict) or set(reference)!=fields
                or not isinstance(reference['attempt_id'],str) or not re.fullmatch('successor-[0-9a-f]{64}',reference['attempt_id'])
                or not isinstance(reference['admission_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',reference['admission_sha256'])):raise ValueError
        selected=_pair(reference['failed_run_id'],reference['computer_guid'])
        if pair is not None and _pair(**pair)!=selected:raise ValueError
        relation=private_read(state_root/'setup-recovery-successor-relations'/(digest(selected)+'.json'))
        document=private_read(state_root/'setup-recovery-successor-admissions'/(reference['attempt_id']+'.json'))
        if (canonical(relation)!=canonical(reference) or digest(document)!=reference['admission_sha256']
                or set(document)!={'schema_version','status','attempt_id','pair','predecessor_sha256','predecessor_files','proof'}
                or type(document['schema_version']) is not int or document['schema_version']!=1
                or document['status']!='admitted_prewrite_successor' or document['pair']!=selected
                or document['attempt_id']!=reference['attempt_id']
                or not isinstance(document['predecessor_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',document['predecessor_sha256'])
                or canonical(predecessor_inventory(state_root,selected))!=canonical(document['predecessor_files'])):raise ValueError
        validate_envelopes(state_root,document['proof']['envelopes'])
        return document
    except Exception:
        raise fail('recovery_successor_context_invalid','Explicit successor context and all predecessor evidence must remain unchanged') from None

def with_context(settings,reference):
    validate_context(settings.state_root,reference)
    current=getattr(settings,'recovery_attempt_context',None)
    if current is not None and current!=reference:
        raise fail('recovery_attempt_context_mismatch','A composed attempt cannot switch to another context')
    if is_dataclass(settings):return replace(settings,recovery_attempt_context=dict(reference))
    # Trusted constructor fixtures use SimpleNamespace; production uses Settings.
    selected=copy.copy(settings);selected.recovery_attempt_context=dict(reference)
    return selected
