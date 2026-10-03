"""Alembic migration environment."""

from alembic import context
from safir.database import run_migrations_offline
from safir.logging import configure_alembic_logging

from gafaelfawr.database import run_migrations_online
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.schema import SchemaBase

# Load the Gafaelfawr configuration, which as a side effect also configures
# logging using structlog.
config = config_dependency.config()

# Run the migrations.
configure_alembic_logging()
if context.is_offline_mode():
    run_migrations_offline(SchemaBase.metadata, config.database.mock_url)
else:
    run_migrations_online(SchemaBase.metadata, config.database)
