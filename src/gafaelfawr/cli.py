"""Administrative command-line interface."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import click
import structlog
import uvicorn
from cryptography.fernet import Fernet
from safir.asyncio import run_with_asyncio
from safir.click import display_help
from safir.database import (
    create_database_engine,
    is_database_current,
    stamp_database,
)
from safir.slack.blockkit import SlackMessage
from sqlalchemy import text

from .database import (
    generate_schema_sql,
    initialize_gafaelfawr_database,
    is_database_initialized,
)
from .dependencies.config import config_dependency
from .events import StateEvents
from .factory import Factory
from .keypair import RSAKeyPair
from .main import create_openapi
from .models.token import Token
from .schema import Base

__all__ = [
    "audit",
    "delete_all_data",
    "generate_key",
    "generate_schema",
    "generate_token",
    "help",
    "init",
    "main",
    "maintenance",
    "openapi_schema",
    "run",
]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(message="%(version)s")
def main() -> None:
    """Administrative command-line interface for gafaelfawr."""


@main.command()
@click.argument("topic", default=None, required=False, nargs=1)
@click.pass_context
def help(ctx: click.Context, topic: str | None) -> None:
    """Show help for any command."""
    display_help(main, ctx, topic)


@main.command()
@click.option(
    "--fix", default=False, is_flag=True, help="Fix issues found, if possible"
)
@click.option(
    "--config-path",
    envvar="GAFAELFAWR_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=None,
    help="Application configuration file.",
)
@run_with_asyncio
async def audit(*, fix: bool, config_path: Path | None) -> None:
    """Check data stores for consistency.

    Any problems found will be reported to Slack.
    """
    if config_path:
        config_dependency.set_config_path(config_path)
    config = await config_dependency()
    logger = structlog.get_logger("gafaelfawr")
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    if not await is_database_current(engine, logger):
        raise click.ClickException("Database schema is not current")
    logger.debug("Starting audit")
    async with Factory.standalone(config, engine) as factory:
        slack = factory.create_slack_client()
        if not slack:
            msg = "Slack alerting required for audit but not configured"
            raise click.UsageError(msg)
        token_service = factory.create_token_service()
        async with factory.session.begin():
            alerts = await token_service.audit(fix=fix)
        if alerts:
            message = (
                "Gafaelfawr data inconsistencies found:\n• "
                + "\n• ".join(alerts)
            )
            await slack.post(SlackMessage(message=message))
    await engine.dispose()
    logger.debug("Finished audit")


@main.command()
@click.option(
    "--config-path",
    envvar="GAFAELFAWR_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=None,
    help="Application configuration file.",
)
@run_with_asyncio
async def delete_all_data(*, config_path: Path | None) -> None:
    """Delete all data from Redis and the database.

    Intended for destructive upgrades, such as when switching from one
    upstream authentication provider to another when all of the usernames will
    change.  This does not delete or reset UID and GID assignments from
    Firestore.
    """
    if config_path:
        config_dependency.set_config_path(config_path)
    config = await config_dependency()
    logger = structlog.get_logger("gafaelfawr")
    logger.debug("Starting to delete all data")
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    tables = (t.name for t in Base.metadata.sorted_tables)
    async with Factory.standalone(config, engine) as factory:
        admin_service = factory.create_admin_service()
        async with factory.session.begin():
            stmt = text(f'TRUNCATE TABLE {", ".join(tables)}')
            logger.info("Truncating all tables")
            await factory.session.execute(stmt)
            await admin_service.add_initial_admins(config.initial_admins)
        token_service = factory.create_token_service()
        logger.info("Deleting all tokens from Redis")
        await token_service.delete_all_tokens()
        if config.oidc_server:
            oidc_service = factory.create_oidc_service()
            logger.info("Deleting all OpenID Connect codes from Redis")
            await oidc_service.delete_all_codes()
    await engine.dispose()
    logger.debug("Finished deleting all data")


@main.command()
def generate_key() -> None:
    """Generate a new RSA key pair.

    The output will be the private key of the newly-generated key pair, from
    which the public key can be recovered.
    """
    keypair = RSAKeyPair.generate()
    sys.stdout.write(keypair.private_key_as_pem().decode())


@main.command()
@click.option(
    "--config-path",
    envvar="GAFAELFAWR_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=None,
    help="Application configuration file.",
)
@click.option(
    "--output",
    default=None,
    type=click.Path(path_type=Path),
    help="Output path (output to stdout if not given).",
)
def generate_schema(*, config_path: Path | None, output: Path | None) -> None:
    """Generate SQL to create the Gafaelfawr database schema."""
    if config_path:
        config_dependency.set_config_path(config_path)
    config = config_dependency.config()
    schema = generate_schema_sql(config)
    if output:
        output.write_text(schema)
    else:
        sys.stdout.write(schema)


@main.command()
def generate_session_secret() -> None:
    """Generate a new Gafaelfawr session secret."""
    sys.stdout.write(Fernet.generate_key().decode() + "\n")


@main.command()
def generate_token() -> None:
    """Generate an encoded token.

    The generated token will be syntactically valid, but will not be created
    in the database. It is suitable for use as a Gafaelfawr bootstrap token.
    """
    sys.stdout.write(str(Token()) + "\n")


@main.command()
@click.option(
    "--config-path",
    envvar="GAFAELFAWR_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=None,
    help="Application configuration file.",
)
@click.option(
    "--alembic-config-path",
    envvar="GAFAELFAWR_ALEMBIC_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=Path("/app/alembic.ini"),
    help="Alembic configuration file.",
)
def init(*, config_path: Path | None, alembic_config_path: Path) -> None:
    """Initialize the database storage."""
    if config_path:
        config_dependency.set_config_path(config_path)
    config = config_dependency.config()
    logger = structlog.get_logger("gafaelfawr")
    logger.debug("Initializing database")
    asyncio.run(initialize_gafaelfawr_database(config, logger))
    stamp_database(alembic_config_path)
    logger.debug("Finished initializing data stores")


@main.command()
@click.option(
    "--config-path",
    envvar="GAFAELFAWR_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=None,
    help="Application configuration file.",
)
@run_with_asyncio
async def maintenance(*, config_path: Path | None) -> None:
    """Perform background maintenance."""
    if config_path:
        config_dependency.set_config_path(config_path)
    config = await config_dependency()
    logger = structlog.get_logger("gafaelfawr")
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    if not await is_database_current(engine, logger):
        raise click.ClickException("Database schema is not current")
    logger.debug("Starting background maintenance")
    async with Factory.standalone(config, engine, check_db=True) as factory:
        token_service = factory.create_token_service()
        async with factory.session.begin():
            logger.info("Marking expired tokens in database")
            await token_service.expire_tokens()
            logger.info("Truncating token history")
            await token_service.truncate_history()
        event_manager = config.metrics.make_manager()
        await event_manager.initialize()
        events = StateEvents()
        await events.initialize(event_manager)
        async with factory.session.begin():
            await token_service.gather_state_metrics(events)
    await engine.dispose()
    logger.debug("Finished background maintenance")


@main.command()
@click.option(
    "--add-back-link",
    default=False,
    is_flag=True,
    help="Add back link (used when generating application documentation).",
)
@click.option(
    "--output",
    default=None,
    type=click.Path(path_type=Path),
    help="Output path (output to stdout if not given).",
)
def openapi_schema(*, add_back_link: bool, output: Path | None) -> None:
    """Generate the OpenAPI schema."""
    schema = create_openapi(add_back_link=add_back_link)
    if output:
        output.parent.mkdir(exist_ok=True)
        output.write_text(schema)
    else:
        sys.stdout.write(schema)


@main.command()
@click.option(
    "--port", default=8080, type=int, help="Port to run the application on."
)
def run(*, port: int) -> None:
    """Run the application (for testing only)."""
    uvicorn.run(
        "gafaelfawr.main:create_app",
        factory=True,
        port=port,
        reload=True,
        reload_dirs=["src"],
    )


@main.command()
@click.option(
    "--config-path",
    envvar="GAFAELFAWR_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=None,
    help="Application configuration file.",
)
@click.option(
    "--alembic-config-path",
    envvar="GAFAELFAWR_ALEMBIC_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=Path("/app/alembic.ini"),
    help="Alembic configuration file.",
)
def update_schema(
    *, config_path: Path | None, alembic_config_path: Path
) -> None:
    """Initialize the database or update the schema.

    If the database schema has not yet been initialized, create it. Then, run
    Alembic to perform any necessary migrations.
    """
    if config_path:
        config_dependency.set_config_path(config_path)
        env = {**os.environ, "GAFAELFAWR_CONFIG_PATH": str(config_path)}
    else:
        env = None
    config = config_dependency.config()
    logger = structlog.get_logger("gafaelfawr")
    if not asyncio.run(is_database_initialized(config, logger)):
        logger.debug("Initializing database")
        asyncio.run(initialize_gafaelfawr_database(config, logger))
        stamp_database(alembic_config_path)
        logger.debug("Finished initializing data stores")
        return
    subprocess.run(["alembic", "upgrade", "head"], check=True, env=env)


@main.command()
@click.option(
    "--config-path",
    envvar="GAFAELFAWR_CONFIG_PATH",
    type=click.Path(path_type=Path),
    default=None,
    help="Application configuration file.",
)
@run_with_asyncio
async def validate_schema(*, config_path: Path | None) -> None:
    """Validate that the database schema is current."""
    if config_path:
        config_dependency.set_config_path(config_path)
    config = config_dependency.config()
    logger = structlog.get_logger("gafaelfawr")
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    if not await is_database_initialized(config, logger, engine):
        raise click.ClickException("Database has not been initialized")
    if not await is_database_current(engine, logger):
        raise click.ClickException("Database schema is not current")
