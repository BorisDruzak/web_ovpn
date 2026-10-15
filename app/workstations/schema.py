"""Targeted additive feature schema; never invokes inventory/whole-app repair."""
from sqlalchemy import inspect, select

from .models import TABLES, SchemaVersion

TABLE_NAMES = tuple(table.name for table in TABLES)


class WorkstationsSchemaError(Exception):
    pass


def _existing(engine):
    inspection = inspect(engine)
    names = set(inspection.get_table_names())
    for table in TABLES:
        if table.name in names:
            actual = {column['name'] for column in inspection.get_columns(table.name)}
            if actual != set(table.columns.keys()):
                raise WorkstationsSchemaError('Workstation schema differs; an explicit migration is required')
    if SchemaVersion.__tablename__ in names:
        with engine.connect() as connection:
            rows = connection.execute(select(SchemaVersion.__table__)).all()
        if rows and (len(rows) != 1 or rows[0].id != 1 or rows[0].version != 1):
            raise WorkstationsSchemaError('Unsupported workstation schema version')
    return names


def ensure_schema(engine):
    _existing(engine)
    from ..db import Base
    from ..inventory import models as inventory_models
    Base.metadata.create_all(engine, tables=list(TABLES))
    with engine.begin() as connection:
        if connection.scalar(select(SchemaVersion.version).where(SchemaVersion.id == 1)) is None:
            connection.execute(SchemaVersion.__table__.insert().values(id=1, version=1))
    check_schema(engine)


def check_schema(engine):
    if not set(TABLE_NAMES) <= _existing(engine):
        raise WorkstationsSchemaError('Workstation schema is not installed')
    with engine.connect() as connection:
        if connection.scalar(select(SchemaVersion.version).where(SchemaVersion.id == 1)) != 1:
            raise WorkstationsSchemaError('Workstation schema is not initialized')
    inspection = inspect(engine)
    for table in TABLES:
        indexes = {row['name']: row for row in inspection.get_indexes(table.name)}
        for expected in table.indexes:
            found = indexes.get(expected.name)
            if found is None or bool(found['unique']) != bool(expected.unique) or found['column_names'] != [c.name for c in expected.columns]:
                raise WorkstationsSchemaError('Workstation schema indexes require an explicit migration')
