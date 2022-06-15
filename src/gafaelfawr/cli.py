"""Administrative command-line interface."""

from __future__ import annotations

import json
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Optional, Union

import click
import structlog
import uvicorn
from fastapi.openapi.utils import get_openapi
from kubernetes_asyncio.client import ApiClient
from safir.asyncio import run_with_asyncio
from safir.database import create_database_engine, initialize_database
from safir.kubernetes import initialize_kubernetes
from sqlalchemy import text

from .dependencies.config import config_dependency
from .exceptions import KubernetesError, NotConfiguredError
from .factory import Factory
from .keypair import RSAKeyPair
from .main import create_app
from .models.token import Token
from .schema import Base

__all__ = [
    "delete_all_data",
    "fix_home_ownership",
    "generate_key",
    "generate_token",
    "help",
    "init",
    "kubernetes_controller",
    "main",
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
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    tables = (t.name for t in Base.metadata.sorted_tables)
    async with Factory.standalone(config, engine) as factory:
        admin_service = factory.create_admin_service()
        async with factory.session.begin():
            stmt = text(f'TRUNCATE TABLE {", ".join(tables)}')
            await factory.session.execute(stmt)
            await admin_service.add_initial_admins(config.initial_admins)
        token_service = factory.create_token_service()
        await token_service.delete_all_tokens()
        if config.oidc_server:
            oidc_service = factory.create_oidc_service()
            await oidc_service.delete_all_codes()


@main.command()
@click.option(
    "--settings",
    envvar="GAFAELFAWR_SETTINGS_PATH",
    type=str,
    default=None,
    help="Application settings file.",
)
@click.argument(
    "path",
    required=True,
    type=click.Path(
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        path_type=Path,
    ),
)
@run_with_asyncio
async def fix_home_ownership(settings: Optional[str], path: Path) -> None:
    """Fix ownership of home directories.

    For each directory under the provided path, assume the name of the
    directory is the username of a user.  Look up (and create if necessary) a
    UID for that user in Firestore, and then change the ownership of that
    directory and everything under it (with ``chown -R``) to that UID.  The
    GID will be set to match the UID.
    """
    if settings:
        config_dependency.set_settings_path(settings)
    config = await config_dependency()
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    async with Factory.standalone(config, engine) as factory:
        try:
            firestore = factory.create_firestore_service()
        except NotConfiguredError:
            raise click.UsageError("Firestore is not configured")
        await firestore.fix_home_ownership(path)


@main.command()
def generate_key() -> None:
    """Generate a new RSA key pair and print the private key."""
    keypair = RSAKeyPair.generate()
    print(keypair.private_key_as_pem())


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
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    await initialize_database(engine, logger, schema=Base.metadata)
    async with Factory.standalone(config, engine) as factory:
        admin_service = factory.create_admin_service()
        async with factory.session.begin():
            await admin_service.add_initial_admins(config.initial_admins)
        if config.firestore:
            firestore = factory.create_firestore_storage()
            await firestore.initialize()
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
async def kubernetes_controller(settings: Optional[str]) -> None:
    """Run forever, watching service token objects and creating secrets."""
    if settings:
        config_dependency.set_settings_path(settings)
    config = await config_dependency()
    logger = structlog.get_logger("gafaelfawr")
    logger.debug("Starting")
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


@main.command()
@click.option(
    "--output",
    default=None,
    type=click.Path(path_type=Path),
    help="Output path (output to stdout if not given).",
)
def openapi_schema(output: Optional[Path]) -> None:
    app = create_app(load_config=False)
    schema = get_openapi(
        title="Gafaelfawr",
        description=(
            "Gafaelfawr is a FastAPI application for the authorization and"
            " management of tokens, including their issuance and revocation."
        ),
        version=version("gafaelfawr"),
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
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    async with Factory.standalone(config, engine, check_db=True) as factory:
        await initialize_kubernetes()
        async with ApiClient() as api_client:
            kubernetes_service = factory.create_kubernetes_service(api_client)
            try:
                logger.debug("Updating all service tokens")
                await kubernetes_service.update_service_tokens()
            except KubernetesError as e:
                msg = "Failed to update service token secrets"
                logger.error(msg, error=str(e))
                sys.exit(1)
