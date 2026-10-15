from __future__ import annotations

import pytest
from sqlalchemy import Column, Integer, Table, create_engine, inspect, text

from app.db import Base
from app.inventory import models as inventory_models


def test_schema_is_additive_idempotent_and_never_repairs_other_domains(tmp_path):
    from app.workstations import models, schema
    engine = create_engine('sqlite:///' + str(tmp_path / 'schema.sqlite'))
    old_tables = [table for name, table in Base.metadata.tables.items() if not name.startswith('workstation_')]
    Base.metadata.create_all(engine, tables=old_tables)
    unrelated = Table('unrelated_workstation_probe', Base.metadata, Column('id', Integer, primary_key=True))
    try:
        schema.ensure_schema(engine)
        schema.ensure_schema(engine)
        schema.check_schema(engine)
        names = set(inspect(engine).get_table_names())
        assert 'unrelated_workstation_probe' not in names
        assert set(schema.TABLE_NAMES) <= names
        assert len(schema.TABLE_NAMES) == 6
    finally:
        Base.metadata.remove(unrelated)
        engine.dispose()


def test_unknown_schema_version_fails_closed(tmp_path):
    from app.workstations import schema
    engine = create_engine('sqlite:///' + str(tmp_path / 'schema.sqlite'))
    schema.ensure_schema(engine)
    with engine.begin() as connection:
        connection.execute(text('UPDATE workstation_schema SET version=2'))
    with pytest.raises(schema.WorkstationsSchemaError):
        schema.ensure_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT version FROM workstation_schema')) == 2


def test_schema_readiness_does_not_create_missing_tables(tmp_path):
    from app.workstations import schema
    engine = create_engine('sqlite:///' + str(tmp_path / 'schema.sqlite'))
    with pytest.raises(schema.WorkstationsSchemaError):
        schema.check_schema(engine)
    assert inspect(engine).get_table_names() == []
