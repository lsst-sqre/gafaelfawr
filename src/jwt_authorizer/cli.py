"""Administrative command-line interface."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import click
from aiohttp.web import run_app

from jwt_authorizer.app import create_app
from jwt_authorizer.keypair import RSAKeyPair

if TYPE_CHECKING:
    from typing import Union

__all__ = ["main", "generate_key", "help", "run"]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(message="%(version)s")
def main() -> None:
    """jwt_authorizer main.

    Administrative command-line interface for jwt_authorizer.
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
    "--port", default=8080, type=int, help="Port to run the application on."
)
@click.option(
    "--settings",
    envvar="SETTINGS_PATH",
    type=str,
    default="/etc/jwt-authorizer/authorizer.yaml",
    help="Application settings file.",
)
def run(port: int, settings: str) -> None:
    """Run the application (for production)."""
    app = create_app(settings_path=settings)
    run_app(app, port=port)


@main.command()
def generate_key() -> None:
    """Generate a new RSA key pair."""
    keypair = RSAKeyPair.generate()
    print(keypair.private_key_as_pem().decode())
    print(keypair.public_key_as_pem().decode())
    print(json.dumps(keypair.public_key_as_jwks(), indent=4))
