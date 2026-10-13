"""Selection comes only from the published, strictly validated Setup registry."""
from pathlib import Path
import sys

from ansible.errors import AnsibleFilterError

source_control = Path(__file__).resolve().parents[2]/'control'
sys.path.insert(0, str(source_control if (source_control/'alt_deploy').is_dir() else Path('/opt/alt-deploy-control')))

from alt_deploy.component_catalog import ComponentCatalog
from alt_deploy.setup_execution import catalog_selection


def selection(document, profile='base', component_id=''):
    try:
        return catalog_selection(ComponentCatalog(Path(__file__).resolve().parents[1], document),
                                 profile=profile, component_id=component_id)
    except Exception as exc:
        raise AnsibleFilterError('Published Setup component catalog is invalid') from exc


class FilterModule:
    def filters(self):
        return {'alt_setup_selection': selection}
