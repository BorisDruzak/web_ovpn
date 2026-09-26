import json
import subprocess
import sys
from pathlib import Path

import pytest
from netctl.db import connect
from netctl.host_snapshot import refresh_host_snapshot


def make_snapshot(tmp_path, count):
    path = tmp_path / 'snapshot.sqlite'
    conn = connect(f'sqlite:///{path.as_posix()}')
    conn.executemany("INSERT INTO network_hosts (ip,category,status,last_seen_at,tags_json) VALUES (?,'unknown','seen','2026-09-26T10:00:00Z','{}')", [(f'10.0.{n//256}.{n%256}',) for n in range(count)])
    conn.commit()
    refresh_host_snapshot(conn, now='2026-09-26T10:00:00Z')
    return conn, path


def cli(path, *args, projection=None):
    return subprocess.run([sys.executable,'-m','netctl.cli','--json','--db',f'sqlite:///{path.as_posix()}','hosts','export','--status=all',*args], input=json.dumps(projection) if projection else None, text=True,capture_output=True,timeout=20)


def test_full_export_actual_cli_beyond_public_page_no_writes(tmp_path):
    conn,path = make_snapshot(tmp_path,300)
    conn.close()
    before=path.read_bytes()
    result=cli(path)
    assert result.returncode == 0, result.stdout+result.stderr
    data=json.loads(result.stdout)
    assert data['total']==len(data['hosts'])==300
    assert data['snapshot']['snapshot_id']==1
    assert data['inventory_projection_revision'] is None
    assert path.read_bytes()==before
    listed=subprocess.run([sys.executable,'-m','netctl.cli','--json','--db',f'sqlite:///{path.as_posix()}','hosts','list','--status=all','--limit=10000'],text=True,capture_output=True,timeout=20)
    assert len(json.loads(listed.stdout)['hosts'])==250


def test_export_projection_filters_before_full_result(tmp_path):
    conn,path=make_snapshot(tmp_path,300)
    conn.execute("UPDATE network_hosts SET device_key='mac:02:00:00:00:00:99' WHERE ip='10.0.1.43'")
    conn.commit(); refresh_host_snapshot(conn,now='2026-09-26T10:00:00Z'); conn.close()
    projection={'schema_version':1,'revision':37,'states':{'mac:02:00:00:00:00:99':'linked'}}
    result=cli(path,'--inventory-link=linked','--inventory-projection-stdin',projection=projection)
    assert result.returncode==0,result.stdout+result.stderr
    data=json.loads(result.stdout)
    assert data['total']==1 and data['hosts'][0]['ip']=='10.0.1.43'
    assert data['inventory_projection_revision']==37


def test_export_rejects_absent_snapshot_without_creating_database(tmp_path):
    path=tmp_path/'absent.sqlite'
    result=cli(path)
    assert result.returncode!=0
    assert json.loads(result.stdout)['message']=='host_snapshot_absent'
    assert not path.exists()


def test_export_row_budget_rejects_without_partial_result(tmp_path):
    conn,path=make_snapshot(tmp_path,10001); conn.close()
    result=cli(path)
    assert result.returncode!=0
    assert json.loads(result.stdout)=={'status':'error','message':'host_export_row_budget'}


def test_export_byte_budget_rejects_before_decoding_oversized_payload(tmp_path,monkeypatch):
    from netctl import host_snapshot
    conn,path=make_snapshot(tmp_path,1)
    conn.execute("UPDATE network_host_current_state SET payload_json=?",('x'*2000,));conn.commit()
    monkeypatch.setattr(host_snapshot,'HOST_EXPORT_MAX_BYTES',1024)
    with pytest.raises(ValueError,match='host_export_byte_budget'):
        host_snapshot.export_host_snapshot(conn,{'status':'all'})
    assert not conn.in_transaction
    conn.close()


def test_export_holds_old_snapshot_when_writer_publishes_after_metadata(tmp_path,monkeypatch):
    from netctl import host_snapshot
    from netctl.db import connect_read_only
    writer,path=make_snapshot(tmp_path,300)
    reader=connect_read_only(f'sqlite:///{path.as_posix()}')
    original=host_snapshot.snapshot_status
    invoked=False
    def publish_after_read(conn,**kwargs):
        nonlocal invoked
        metadata=original(conn,**kwargs)
        if conn is reader and not invoked:
            invoked=True
            writer.execute("DELETE FROM network_hosts WHERE ip!='10.0.0.0'");writer.commit()
            refresh_host_snapshot(writer,now='2026-09-26T10:01:00Z')
        return metadata
    monkeypatch.setattr(host_snapshot,'snapshot_status',publish_after_read)
    result=host_snapshot.export_host_snapshot(reader,{'status':'all'},now='2026-09-26T10:02:00Z')
    assert result['snapshot']['snapshot_id']==1
    assert result['total']==len(result['hosts'])==300
    assert original(writer).snapshot_id==2
    assert not reader.in_transaction
    reader.close();writer.close()


@pytest.mark.parametrize('filters',[
    {'q':'10.0.1.'},{'network':'10.0.1.0/24'},{'source':'all'},
    {'has_mac':'no'},{'has_hostname':'no'},{'category':'unknown'},
    {'seen_within':'1h'},{'status':'seen'},
])
def test_export_matches_list_filters_including_empty_selection(tmp_path,filters):
    from netctl.host_snapshot import export_host_snapshot,list_host_snapshot
    conn,path=make_snapshot(tmp_path,300)
    selected={'status':'all',**filters}
    result=export_host_snapshot(conn,selected,now='2026-09-26T10:02:00Z')
    page=list_host_snapshot(conn,selected,1,250,now='2026-09-26T10:02:00Z')
    assert result['total']==page['total']==len(result['hosts'])
    assert result['hosts'][:250]==page['hosts']
    conn.close()


def test_export_final_envelope_budget_and_empty_stale_snapshot(tmp_path,monkeypatch):
    from netctl import host_snapshot
    conn,path=make_snapshot(tmp_path,1)
    empty=host_snapshot.export_host_snapshot(conn,{'status':'all','q':'no-match'},now='2026-09-27T10:00:00Z')
    assert empty['total']==0 and empty['hosts']==[] and empty['snapshot']['stale'] is True
    payload_bytes=conn.execute('SELECT length(cast(payload_json AS BLOB)) FROM network_host_current_state').fetchone()[0]
    monkeypatch.setattr(host_snapshot,'HOST_EXPORT_MAX_BYTES',payload_bytes+1)
    with pytest.raises(ValueError,match='host_export_byte_budget'):
        host_snapshot.export_host_snapshot(conn,{'status':'all'})
    conn.close()


def test_export_read_only_connection_sql_trace(tmp_path):
    from netctl.db import connect_read_only
    from netctl.host_snapshot import export_host_snapshot
    writer,path=make_snapshot(tmp_path,1);writer.close()
    reader=connect_read_only(f'sqlite:///{path.as_posix()}')
    statements=[];reader.set_trace_callback(statements.append)
    assert export_host_snapshot(reader,{'status':'all'})['total']==1
    assert all(s.lstrip().upper().startswith(('SELECT','SAVEPOINT','RELEASE SAVEPOINT')) for s in statements)
    reader.close()


def test_export_cli_unicode_output_has_portable_exact_byte_bound(tmp_path):
    conn,path=make_snapshot(tmp_path,1)
    conn.execute('UPDATE network_hosts SET hostname=?',('Кириллица 🙂',));conn.commit();refresh_host_snapshot(conn,now='2026-09-26T10:00:00Z');conn.close()
    result=cli(path)
    assert result.returncode==0,result.stderr
    assert json.loads(result.stdout)['hosts'][0]['hostname']=='Кириллица 🙂'
    assert len(result.stdout.encode('ascii')) <= 16*1024*1024
