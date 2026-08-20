"""Tests for web application startup."""

import os
import subprocess

import pytest
from asgi_lifespan import LifespanManager
from safir.database import drop_database
from safir.testing.data import Data
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.exceptions import DatabaseSchemaError
from gafaelfawr.main import create_app
from gafaelfawr.schema import SchemaBase

from .support.database import create_old_database


@pytest.mark.asyncio
async def test_out_of_date_schema(
    config: Config, data: Data, engine: AsyncEngine
) -> None:
    await drop_database(engine, SchemaBase.metadata)
    await create_old_database(config, data, engine, version="9.6.1")

    app = create_app()
    with pytest.raises(DatabaseSchemaError):
        async with LifespanManager(app):
            pass

    # Don't leave the old schema around with now-defunct tables, since that
    # may interfere with future tests. Finish upgrading the schema so that it
    # will be dropped properly.
    env = {
        **os.environ,
        "GAFAELFAWR_CONFIG_PATH": str(config_dependency.config_path),
    }
    subprocess.run(["alembic", "stamp", "5c28ed7092c2"], check=True, env=env)
    subprocess.run(["alembic", "upgrade", "head"], check=True, env=env)
