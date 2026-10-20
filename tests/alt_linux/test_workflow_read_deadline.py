"""Post-effect verification has a shared deadline, never an execution retry."""
import pytest

from alt_deploy.errors import ControlError


def test_nested_read_deadlines_cannot_extend_and_reset_on_error(monkeypatch):
    from alt_deploy import workflow_read_deadline as module
    now=[100.0];monkeypatch.setattr(module.time,'monotonic',lambda:now[0])
    assert module.read_timeout(180)==180
    with pytest.raises(ControlError) as caught:
        with module.read_deadline(30):
            assert module.read_timeout(90)==30
            now[0]+=5
            with module.read_deadline(100):assert module.read_timeout(90)==25
            with module.read_deadline(3):assert module.read_timeout(90)==3
            assert module.read_timeout(90)==25
            now[0]+=26;module.read_timeout(1)
    assert caught.value.code=='workflow_readiness_unverified'
    assert caught.value.details=={'readiness_stage':'deadline'}
    assert module.read_timeout(90)==90


def test_existing_bounded_transport_consumes_shared_remaining_budget(monkeypatch):
    import io
    from alt_deploy import ad_transport,workflow_read_deadline as module
    now=[100.0];monkeypatch.setattr(module.time,'monotonic',lambda:now[0])
    waits=[]
    class ReadProcess:
        returncode=0
        def __init__(self,*args,**kwargs):self.stdout=io.BytesIO(b'{}');self.stderr=io.BytesIO(b'')
        def wait(self,*,timeout):waits.append(timeout)
    monkeypatch.setattr(ad_transport.subprocess,'Popen',ReadProcess)
    with module.read_deadline(12):
        now[0]+=7
        assert ad_transport.bounded_run(['fixed-read'],environment={},timeout=180)==(0,'{}','')
    assert waits==[5]


def test_deadline_also_bounds_blocked_large_stdin():
    import sys,time
    from alt_deploy.ad_transport import bounded_run
    from alt_deploy.workflow_read_deadline import read_deadline
    started=time.monotonic()
    with pytest.raises(ControlError):
        with read_deadline(0.1):
            bounded_run([sys.executable,'-c','import time; time.sleep(1)'],
                environment={},input_text='x'*(1024*1024),timeout=30)
    assert time.monotonic()-started<0.8
