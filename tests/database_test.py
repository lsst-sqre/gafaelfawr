"""Tests for the Gafaelfawr database schema."""

from __future__ import annotations

import os
import subprocess

import pytest
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency

from .support.constants import CURRENT_SCHEMA
from .support.database import create_old_database, drop_database


@pytest.mark.asyncio
async def test_schema(config: Config, engine: AsyncEngine) -> None:
    """Test for any unmanaged schema changes.

    Compare the current database schema in its SQLAlchemy ORM form against a
    dump of the SQL generated from the last known Alembic migration and ensure
    that Alembic doesn't detect any schema changes.
    """
    await drop_database(engine)
    await create_old_database(config, engine, CURRENT_SCHEMA)
    alembic_config = AlembicConfig("alembic.ini")
    alembic_scripts = ScriptDirectory.from_config(alembic_config)
    current_head = alembic_scripts.get_current_head()
    assert current_head

    def set_version(connection: Connection) -> None:
        context = MigrationContext.configure(connection)
        context.stamp(alembic_scripts, current_head)

    async with engine.begin() as connection:
        await connection.run_sync(set_version)
    env = {
        **os.environ,
        "GAFAELFAWR_CONFIG_PATH": str(config_dependency.config_path),
    }
    subprocess.run(["alembic", "check"], check=True, env=env)
