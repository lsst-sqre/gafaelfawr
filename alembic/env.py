"""Alembic migration environment."""

import asyncio
import logging
from urllib.parse import quote, urlparse

import structlog
from alembic import context
from safir.database import create_database_engine
from safir.logging import LogLevel, add_log_severity
from sqlalchemy.engine import Connection

from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.schema import Base

# This is the Alembic Config object, which provides access to the values
# within the .ini file in use.
config = context.config

# Load the Gafaelfawr configuration, which as a side effect also configures
# logging using structlog.
gafaelfawr_config = config_dependency.config()

# Define the SQLAlchemy schema, which enables autogenerate support.
target_metadata = Base.metadata


def build_database_url(
    url: str, password: str | None, *, is_async: bool
) -> str:
    """Build the authenticated URL for the database.

    Parameters
    ----------
    url
        Database connection URL, not including the password.
    password
        Database connection password.
    is_async
        Whether the resulting URL should be async or not.

    Returns
    -------
    url
        The URL including the password.

    Raises
    ------
    ValueError
        A password was provided but the connection URL has no username.

    Notes
    -----
    This is duplicated from safir.database and should be replaced with an
    exported Safir function once Safir provides one.
    """
    if is_async or password:
        parsed_url = urlparse(url)
        if is_async and parsed_url.scheme == "postgresql":
            parsed_url = parsed_url._replace(scheme="postgresql+asyncpg")
        if password:
            if not parsed_url.username:
                raise ValueError(f"No username in database URL {url}")
            password = quote(password, safe="")

            # The username portion of the parsed URL does not appear to decode
            # URL escaping of the username, so we should not quote it again or
            # we will get double-quoting.
            netloc = f"{parsed_url.username}:{password}@{parsed_url.hostname}"
            if parsed_url.port:
                netloc = f"{netloc}:{parsed_url.port}"
            parsed_url = parsed_url._replace(netloc=netloc)
        url = parsed_url.geturl()
    return url


def configure_alembic_logging(
    log_level: LogLevel | str = LogLevel.INFO,
) -> None:
    """Set up logging for Alembic.

    This configures Alembic to use structlog for output formatting so that its
    logs are also in JSON. This helps Google's Cloud Logging system understand
    the logs.

    Parameters
    ----------
    log_level
        The Python log level. May be given as a `LogLevel` enum (preferred)
        or a case-insensitive string.
    """
    if not isinstance(log_level, LogLevel):
        log_level = LogLevel[log_level.upper()]

    processors = [
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ]
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "json": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processors": processors,
                    "foreign_pre_chain": [add_log_severity],
                },
            },
            "handlers": {
                "alembic": {
                    "level": log_level.value,
                    "class": "logging.StreamHandler",
                    "formatter": "json",
                    "stream": "ext://sys.stdout",
                },
            },
            "loggers": {
                "alembic": {
                    "handlers": ["alembic"],
                    "level": log_level.value,
                    "propagate": False,
                },
            },
        }
    )


def run_migrations_offline() -> None:
    """Run migrations in offline mode.

    This configures the context with just a URL and not an Engine, though an
    Engine is acceptable here as well. By skipping the Engine creation we
    don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the script
    output.
    """
    url = build_database_url(
        gafaelfawr_config.database_url,
        gafaelfawr_config.database_password,
        is_async=False,
    )
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run database migrations with a connection."""
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in online mode with an async engine.

    In this scenario we need to create an Engine and associate a connection
    with the context.
    """
    engine = create_database_engine(
        gafaelfawr_config.database_url, gafaelfawr_config.database_password
    )

    async with engine.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await engine.dispose()


def run_migrations_online() -> None:
    """Run database migrations.

    This must be called outside of an event loop.
    """
    asyncio.run(run_async_migrations())


configure_alembic_logging()
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
