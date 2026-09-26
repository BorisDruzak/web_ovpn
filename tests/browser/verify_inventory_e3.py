"""Validate only a synthetic E3 fixture and its browser-downloaded workbooks."""
import argparse
import json
import sqlite3
from pathlib import Path
from openpyxl import load_workbook


def verify(fixture: Path, artifacts: Path):
    if not (fixture / 'fixture.json').is_file() or fixture.name[:2] != 'e3':
        raise ValueError('Synthetic E3 fixture directory required')
    database = sqlite3.connect(f'file:{(fixture / "synthetic.sqlite").resolve().as_posix()}?mode=ro', uri=True)
    database.row_factory = sqlite3.Row
    network = sqlite3.connect(f'file:{(fixture / "synthetic-network.sqlite").resolve().as_posix()}?mode=ro', uri=True)
    results = {}
    try:
        for label, mac in [('available','02:00:00:00:00:24'),('unavailable','02:00:00:00:01:24')]:
            name = 'Synthetic E3 '+label+' '
            pc = database.execute('SELECT * FROM inventory_assets WHERE custom_name=?',(name+'PC edited',)).fetchone()
            assert pc is not None and pc['deleted_at'] is None
            children = [database.execute('SELECT * FROM inventory_assets WHERE custom_name=?',(name+kind,)).fetchone() for kind in ('MONITOR','UPS')]
            assert all(child is not None and child['deleted_at'] is None and child['location_id']==pc['location_id'] for child in children)
            for child in children:
                relations = database.execute('SELECT ended_at FROM inventory_asset_relations WHERE parent_asset_id=? AND child_asset_id=?',(pc['id'],child['id'])).fetchall()
                assert relations and all(row['ended_at'] is not None for row in relations)
            bindings = database.execute('SELECT * FROM inventory_netctl_bindings WHERE asset_id=?',(pc['id'],)).fetchall()
            assert sum(row['ended_at'] is None and row['status']=='confirmed' for row in bindings)==1
            assert any(row['ended_at'] is not None for row in bindings)
            assert network.execute('SELECT count(*) FROM network_hosts WHERE mac=?',(mac,)).fetchone()[0]==1
            workbook = load_workbook(artifacts/(label+'.xlsx'),data_only=False)
            values = [value for sheet in workbook for row in sheet.values for value in row]
            for suffix in ('PC edited','MONITOR','UPS'): assert name+suffix in values
            assert workbook.sheetnames==['Устройства','Связи рабочего места','Сетевые привязки','Идентификаторы','Проверки','Фото','Наблюдения','Параметры']
            assert workbook.worksheets[1].max_column==13
            assert workbook.worksheets[2].max_column==35
            # Browser export precedes deletion: all three exact IDs must already be in it.
            for row in [pc,*children]: assert row['id'] in values
            assert label in values  # available/unavailable source metadata
            assert not any(cell.data_type=='f' for sheet in workbook for row in sheet for cell in row)
            results[label]={'asset_id':pc['id'],'peripheral_ids':[child['id'] for child in children],
                'source_retained':True,'relations_ended':True,'explicit_relink':True,
                'workbook_sheets':len(workbook.sheetnames),'relation_columns':13,'binding_columns':35,'exact_ids_exported':True,'no_formulas':True}
        runs = database.execute('SELECT snapshot_id,status,started_at FROM inventory_identifier_sync_runs ORDER BY started_at DESC,id DESC').fetchall()
        assert runs[0]['status']=='success'
        assert sum(row['status']=='success' and row['snapshot_id']==1 for row in runs)==1
        assert any(row['status']=='failed' and row['started_at']<runs[0]['started_at'] for row in runs)
        results['source_recovery']={'latest_attempt':'success','one_success_per_snapshot':True,'failed_attempt_retained':True}
        return results
    finally:
        database.close(); network.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--fixture',type=Path,required=True);parser.add_argument('--artifacts',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(verify(args.fixture,args.artifacts),ensure_ascii=False,indent=2))
