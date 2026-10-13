"""Carry the operator's explicit KRFB assertion with its exact confirmed plan."""
from contextlib import contextmanager
import os

from .configure import KRFB_NETWORK_CONFIRMATION_VARIABLE


@contextmanager
def confirmed_network(plan):
    payload = plan['payload']
    selected = (payload.get('component', {}).get('id') == 'remote.krfb'
                or payload.get('request', {}).get('remote_access_profile') == 'krfb')
    if not selected or payload.get('network_restriction_confirmed') is not True:
        yield
        return
    previous = os.environ.get(KRFB_NETWORK_CONFIRMATION_VARIABLE)
    os.environ[KRFB_NETWORK_CONFIRMATION_VARIABLE] = 'true'
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(KRFB_NETWORK_CONFIRMATION_VARIABLE, None)
        else:
            os.environ[KRFB_NETWORK_CONFIRMATION_VARIABLE] = previous
