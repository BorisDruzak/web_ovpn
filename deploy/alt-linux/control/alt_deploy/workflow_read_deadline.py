"""A contextual wall deadline for independent read-only phase proof."""
from contextlib import contextmanager
from contextvars import ContextVar
import time

from .errors import ControlError

_deadline=ContextVar('workflow_read_deadline',default=None)


def read_timeout(seconds):
    deadline=_deadline.get()
    if deadline is None:return seconds
    remaining=deadline-time.monotonic()
    if remaining<=0:
        raise ControlError('workflow_readiness_unverified','Independent read-only proof exceeded its deadline',4,
            {'readiness_stage':'deadline'})
    return min(seconds,remaining)


@contextmanager
def read_deadline(seconds):
    previous=_deadline.get();deadline=time.monotonic()+seconds
    token=_deadline.set(deadline if previous is None else min(previous,deadline))
    try:yield
    finally:_deadline.reset(token)
