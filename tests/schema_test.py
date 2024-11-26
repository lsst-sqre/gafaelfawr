"""Tests for the Gafaelfawr database schema."""

from __future__ import annotations

import os
import subprocess

import pytest
from safir.database import drop_database
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.schema import SchemaBase


@pytest.mark.asyncio
async def test_schema(config: Config, engine: AsyncEngine) -> None:
    await drop_database(engine, SchemaBase.metadata)
    env = {
        **os.environ,
        "GAFAELFAWR_CONFIG_PATH": str(config_dependency.config_path),
    }
    subprocess.run(["alembic", "upgrade", "head"], check=True, env=env)
    subprocess.run(["alembic", "check"], check=True, env=env)
