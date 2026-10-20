"""Build a fixed root diagnostic receiver and its original invocation binding."""
import hashlib
from pathlib import Path

from .component_catalog import _regular
from .setup_plans import digest
from .wallet_codes import WALLET_CODES
from .krfb_program import TARGET_CODES
from .final_dns_policy import CODES as DNS_CODES


CODES={'desktop.kwallet_repair':WALLET_CODES,'remote.krfb':TARGET_CODES,'network.final_dns':DNS_CODES}
UNAVAILABLE='workflow_helper_diagnostic_unavailable'


def program():
    path=Path(__file__).with_name('helper_diagnostic_target.py');_regular(path)
    source=path.read_text(encoding='utf-8')
    value='import sys\n'+source+'''\ntry:
    if os.geteuid()!=0 or len(sys.argv)!=2 or len(sys.argv[1].encode())>4096:raise ValueError
    scope=json.loads(sys.argv[1],object_pairs_hook=_unique)
    value=read_diagnostic(scope,'''+repr({k:tuple(sorted(v)) for k,v in CODES.items()})+''')
    print(json.dumps(value))
except Exception:
    print('{"schema_version":1,"status":"blocked","code":"workflow_helper_diagnostic_unavailable"}')
    raise SystemExit(4)
'''
    if len(value.encode())>=65536:raise ValueError
    return value


def binding(job,component,context,helper_sha256):
    if component not in CODES:raise ValueError
    scope={'schema_version':1,'component_id':component,'job_id':job.job_id,'machine_uuid':job.machine_uuid,
        'plan_sha256':job.status['plan_sha256'],'operation_sha256':context.get('claim_sha256',context.get('operation_sha256')),
        'context_sha256':digest(context),'helper_sha256':helper_sha256}
    reader=program()
    return {'scope':scope,'reader_sha256':hashlib.sha256(reader.encode()).hexdigest(),'program':reader}


def callback_bindings(values):
    return {key:{k:value[k] for k in ('scope','reader_sha256')} for key,value in values.items()}
