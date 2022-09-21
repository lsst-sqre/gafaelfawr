"""Administrative command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional, Union

import click
import structlog
import uvicorn
from cryptography.fernet import Fernet
from fastapi.openapi.utils import get_openapi
from kubernetes_asyncio.client import ApiClient
from safir.asyncio import run_with_asyncio
from safir.database import create_database_engine, initialize_database
from safir.kubernetes import initialize_kubernetes
from sqlalchemy import text

from .dependencies.config import config_dependency
from .exceptions import KubernetesError
from .factory import Factory
from .keypair import RSAKeyPair
from .main import create_app
from .models.token import Token
from .schema import Base
from .slack import SlackAlertClient

__all__ = [
    "delete_all_data",
    "generate_key",
    "generate_token",
    "help",
    "init",
    "kubernetes_controller",
    "main",
    "maintenance",
    "openapi_schema",
    "run",
    "update_service_tokens",
]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(message="%(version)s")
def main() -> None:
    """Gafaelfawr main.

    Administrative command-line interface for gafaelfawr.
    """
    pass


@main.command()
@click.argument("topic", default=None, required=False, nargs=1)
@click.pass_context
def help(ctx: click.Context, topic: Union[None, str]) -> None:
    """Show help for any command."""
    # The help command implementation is taken from
    # https://www.burgundywall.com/post/having-click-help-subcommand
    if topic:
        if topic in main.commands:
            click.echo(main.commands[topic].get_help(ctx))
        else:
            raise click.UsageError(f"Unknown help topic {topic}", ctx)
    else:
        assert ctx.parent
        click.echo(ctx.parent.get_help())


@main.command()
@click.option(
    "--settings",
    envvar="GAFAELFAWR_SETTINGS_PATH",
    type=str,
    default=None,
    help="Application settings file.",
)
@run_with_asyncio
async def audit(settings: Optional[str]) -> None:
    """Run a consistency check on Gafaelfawr's data stores.

    Any problems found will be reported to Slack.
    """
    if settings:
        config_dependency.set_settings_path(settings)
    config = await config_dependency()
    if not config.slack_webhook:
        msg = "Slack alerting required for audit but not configured"
        raise click.UsageError(msg)
    logger = structlog.get_logger("gafaelfawr")
    logger.debug("Starting audit")
    slack = SlackAlertClient(config.slack_webhook, "Gafaelfawr", logger)
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    async with Factory.standalone(config, engine) as factory:
        token_service = factory.create_token_service()
        async with factory.session.begin():
            alerts = await token_service.audit()
        if alerts:
            message = (
                "Gafaelfawr data inconsistencies found:\n• "
                + "\n• ".join(alerts)
                + "\n"
            )
            await slack.message(message)
    await engine.dispose()
    logger.debug("Finished audit")


@main.command()
@click.option(
    "--settings",
    envvar="GAFAELFAWR_SETTINGS_PATH",
    type=str,
    default=None,
    help="Application settings file.",
)
@run_with_asyncio
async def delete_all_data(settings: Optional[str]) -> None:
    """Delete all data from Redis and the database.

    Intended for destructive upgrades, such as when switching from one
    upstream authentication provider to another when all of the usernames will
    change.  This does not delete or reset UID and GID assignments from
    Firestore.
    """
    if settings:
        config_dependency.set_settings_path(settings)
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
    """Generate a new RSA key pair and print the private key."""
    keypair = RSAKeyPair.generate()
    print(keypair.private_key_as_pem())


@main.command()
def generate_session_secret() -> None:
    """Generate a new Gafaelfawr session secret."""
    print(Fernet.generate_key().decode())


@main.command()
def generate_token() -> None:
    """Generate an encoded token (such as the bootstrap token)."""
    print(str(Token()))


@main.command()
@click.option(
    "--settings",
    envvar="GAFAELFAWR_SETTINGS_PATH",
    type=str,
    default=None,
    help="Application settings file.",
)
@run_with_asyncio
async def init(settings: Optional[str]) -> None:
    """Initialize the database storage."""
    if settings:
        config_dependency.set_settings_path(settings)
    config = await config_dependency()
    logger = structlog.get_logger("gafaelfawr")
    logger.debug("Initializing database")
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    await initialize_database(engine, logger, schema=Base.metadata)
    async with Factory.standalone(config, engine) as factory:
        admin_service = factory.create_admin_service()
        logger.debug("Adding initial administrators")
        async with factory.session.begin():
            await admin_service.add_initial_admins(config.initial_admins)
        if config.firestore:
            firestore = factory.create_firestore_storage()
            logger.debug("Initializing Firestore")
            await firestore.initialize()
    await engine.dispose()
    logger.debug("Finished initializing data stores")


@main.command()
@click.option(
    "--settings",
    envvar="GAFAELFAWR_SETTINGS_PATH",
    type=str,
    default=None,
    help="Application settings file.",
)
@run_with_asyncio
async def kubernetes_controller(settings: Optional[str]) -> None:
    """Run forever, watching service token objects and creating secrets."""
    if settings:
        config_dependency.set_settings_path(settings)
    config = await config_dependency()
    logger = structlog.get_logger("gafaelfawr")
    logger.debug("Starting Kubernetes controller")
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    async with Factory.standalone(config, engine, check_db=True) as factory:
        await initialize_kubernetes()
        async with ApiClient() as api_client:
            kubernetes_service = factory.create_kubernetes_service(api_client)
            logger.debug("Updating all service tokens")
            await kubernetes_service.update_service_tokens()
            logger.debug("Starting Kubernetes watcher")
            queue = await kubernetes_service.start_watcher()
            logger.debug("Starting continuous processing")
            await kubernetes_service.update_service_tokens_from_queue(queue)
    await engine.dispose()


@main.command()
@click.option(
    "--settings",
    envvar="GAFAELFAWR_SETTINGS_PATH",
    type=str,
    default=None,
    help="Application settings file.",
)
@run_with_asyncio
async def maintenance(settings: Optional[str]) -> None:
    """Perform background maintenance."""
    if settings:
        config_dependency.set_settings_path(settings)
    config = await config_dependency()
    logger = structlog.get_logger("gafaelfawr")
    logger.debug("Starting background maintenance")
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    async with Factory.standalone(config, engine, check_db=True) as factory:
        token_service = factory.create_token_service()
        async with factory.session.begin():
            logger.info("Marking expired tokens in database")
            await token_service.expire_tokens()
            logger.info("Truncating token history")
            await token_service.truncate_history()
    await engine.dispose()
    logger.debug("Finished background maintenance")


@main.command()
@click.option(
    "--add-back-link",
    default=False,
    is_flag=True,
    help="Add back link (used when generating application documentation)",
)
@click.option(
    "--output",
    default=None,
    type=click.Path(path_type=Path),
    help="Output path (output to stdout if not given).",
)
def openapi_schema(add_back_link: bool, output: Optional[Path]) -> None:
    """Generate the OpenAPI schema."""
    app = create_app(load_config=False)
    description = app.description
    if add_back_link:
        description += "\n\n[Return to Gafaelfawr documentation](index.html)."
    schema = get_openapi(
        title=app.title,
        description=description,
        version=app.version,
        routes=app.routes,
    )
    if output:
        with output.open("w") as f:
            json.dump(schema, f)
    else:
        json.dump(schema, sys.stdout)


@main.command()
@click.option(
    "--port", default=8080, type=int, help="Port to run the application on."
)
def run(port: int) -> None:
    """Run the application (for testing only)."""
    uvicorn.run(
        "gafaelfawr.main:app", port=port, reload=True, reload_dirs=["src"]
    )


@main.command()
@click.option(
    "--settings",
    envvar="GAFAELFAWR_SETTINGS_PATH",
    type=str,
    default=None,
    help="Application settings file.",
)
@run_with_asyncio
async def update_service_tokens(settings: Optional[str]) -> None:
    """Update service tokens stored in Kubernetes secrets."""
    if settings:
        config_dependency.set_settings_path(settings)
    config = await config_dependency()
    logger = structlog.get_logger("gafaelfawr")
    logger.debug("Starting update of all service tokens")
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    async with Factory.standalone(config, engine, check_db=True) as factory:
        await initialize_kubernetes()
        async with ApiClient() as api_client:
            kubernetes_service = factory.create_kubernetes_service(api_client)
            try:
                await kubernetes_service.update_service_tokens()
            except KubernetesError as e:
                msg = "Failed to update service token secrets"
                logger.error(msg, error=str(e))
                sys.exit(1)
    await engine.dispose()
    logger.debug("Finished update of service tokens")
