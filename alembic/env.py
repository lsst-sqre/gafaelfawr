"""Alembic migration environment."""

from alembic import context
from safir.database import run_migrations_offline, run_migrations_online
from safir.logging import configure_alembic_logging

from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.schema import SchemaBase

# Load the Gafaelfawr configuration, which as a side effect also configures
# logging using structlog.
config = config_dependency.config()

# Run the migrations.
configure_alembic_logging()
if context.is_offline_mode():
    run_migrations_offline(SchemaBase.metadata, config.database_url)
else:
    run_migrations_online(
        SchemaBase.metadata,
        config.database_url,
        config.database_password,
    )
