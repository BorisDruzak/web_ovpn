"""Only published source assets and fixed diagnostic codes enter wallet tasks."""
from pathlib import Path
import sys

from ansible.errors import AnsibleFilterError

control=Path(__file__).resolve().parents[2]/'control'
sys.path.insert(0,str(control if (control/'alt_deploy').is_dir() else Path('/opt/alt-deploy-control')))

from alt_deploy.kwallet_program import target_program
from alt_deploy.wallet_codes import WALLET_CODES


def program(role_path):
    try:return target_program(Path(role_path).parents[1])
    except Exception:raise AnsibleFilterError('Published wallet helper source is unavailable') from None


def safe_code(value):
    return value if isinstance(value,str) and value in WALLET_CODES else 'kwallet_repair_outcome_unverified'


class FilterModule:
    def filters(self):return {'alt_wallet_program':program,'alt_wallet_safe_code':safe_code}
