"""Fixed DNS source, policy digest and public diagnostic allowlist only."""
import hashlib
import json
from pathlib import Path
import sys

from ansible.errors import AnsibleFilterError

control=Path(__file__).resolve().parents[2]/'control'
sys.path.insert(0,str(control if (control/'alt_deploy').is_dir() else Path('/opt/alt-deploy-control')))
from alt_deploy.final_dns_policy import validate,CODES
from alt_deploy.final_dns_program import target_program


def program(role_path):
    try:return target_program(Path(role_path).parents[1])
    except Exception:raise AnsibleFilterError('Published final DNS source is unavailable') from None


def policy_sha256(servers):
    try:return hashlib.sha256(json.dumps(validate(servers),sort_keys=True,separators=(',',':')).encode()).hexdigest()
    except Exception:raise AnsibleFilterError('Protected final DNS policy is unavailable') from None


class FilterModule:
    def filters(self):return {'alt_final_dns_program':program,'alt_final_dns_policy_sha256':policy_sha256,
        'alt_final_dns_safe_code':lambda v:v if isinstance(v,str) and v in CODES else 'final_dns_outcome_unverified'}
