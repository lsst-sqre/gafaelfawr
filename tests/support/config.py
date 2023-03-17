"""Build test configuration for Gafaelfawr."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from safir.logging import Profile, configure_logging

from gafaelfawr.config import Config, OIDCClient
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.context import context_dependency
from gafaelfawr.factory import Factory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.models.token import Token

from .constants import TEST_DATABASE_URL

_ISSUER_KEY = RSAKeyPair.generate()
"""RSA key pair for JWT issuance and verification.

Generating this takes a surprisingly long time when summed across every test,
so generate one statically at import time for each test run and use it for
every configuration file.
"""

__all__ = [
    "build_config",
    "config_path",
    "configure",
    "reconfigure",
    "store_secret",
]


def store_secret(tmp_path: Path, name: str, secret: bytes) -> Path:
    """Store a secret in a temporary path.

    Parameters
    ----------
    tmp_path
        The root of the temporary area.
    name
        The name of the secret to construct nice file names.
    secret
        The value of the secret.
    """
    secret_path = tmp_path / name
    secret_path.write_bytes(secret)
    return secret_path


def _build_config_file(
    tmp_path: Path, template: str, **kwargs: str | Path
) -> Path:
    """Construct a configuration file from a format template.

    Parameters
    ----------
    tmp_path
        The root of the temporary area.
    template
        Name of the configuration template to use.
    **kwargs
        The values to substitute into the template.

    Returns
    -------
    Path
        The path to the newly-constructed configuration file.
    """
    template = config_path(template + ".yaml.in").read_text()
    config = template.format(**kwargs)
    path = tmp_path / "gafaelfawr.yaml"
    path.write_text(config)
    return path


def build_config(
    tmp_path: Path,
    template: str,
    *,
    oidc_clients: Optional[list[OIDCClient]] = None,
    **settings: str,
) -> Path:
    """Generate a test Gafaelfawr configuration file with secrets.

    Parameters
    ----------
    tmp_path
        The root of the temporary area.
    template
        Settings template to use.
    oidc_clients
        Configuration information for clients of the OpenID Connect server.
    **settings
        Any additional settings to add to the configuration file.

    Returns
    -------
    Path
        The path of the configuration file.
    """
    bootstrap_token = str(Token()).encode()
    bootstrap_token_file = store_secret(tmp_path, "bootstrap", bootstrap_token)
    session_secret = Fernet.generate_key()
    session_secret_file = store_secret(tmp_path, "session", session_secret)
    issuer_key = _ISSUER_KEY.private_key_as_pem()
    issuer_key_file = store_secret(tmp_path, "issuer", issuer_key)
    github_secret_file = store_secret(tmp_path, "github", b"github-secret")
    oidc_secret_file = store_secret(tmp_path, "oidc", b"oidc-secret")
    slack_webhook_file = store_secret(
        tmp_path, "slack-webhook", b"https://slack.example.com/webhook"
    )
    forgerock_password_file = store_secret(tmp_path, "forgerock", b"password")

    oidc_path = tmp_path / "oidc.json"
    if oidc_clients:
        clients_data = [
            {"id": c.client_id, "secret": c.client_secret}
            for c in oidc_clients
        ]
        oidc_path.write_text(json.dumps(clients_data))

    config_path = _build_config_file(
        tmp_path,
        template,
        database_url=TEST_DATABASE_URL,
        bootstrap_token_file=bootstrap_token_file,
        session_secret_file=session_secret_file,
        issuer_key_file=issuer_key_file,
        github_secret_file=github_secret_file,
        oidc_secret_file=oidc_secret_file,
        oidc_server_secrets_file=oidc_path if oidc_clients else "",
        slack_webhook_file=slack_webhook_file,
        forgerock_password_file=forgerock_password_file,
    )

    if settings:
        with config_path.open("a") as f:
            for key, value in settings.items():
                f.write(f"{key}: {value}\n")

    return config_path


def config_path(filename: str) -> Path:
    """Return the path to a test configuration file.

    Parameters
    ----------
    filename
        The base name of a test configuration file or template.

    Returns
    -------
    Path
        The path to that file.
    """
    return Path(__file__).parent.parent / "data" / "config" / filename


def configure(
    tmp_path: Path,
    template: str,
    *,
    oidc_clients: Optional[list[OIDCClient]] = None,
    **settings: str,
) -> Config:
    """Change the test application configuration.

    This cannot be used to change the database URL because sessions will not
    be recreated or the database reinitialized.

    Parameters
    ----------
    tmp_path
        Root of the test temporary directory, used to write the configuration
        file.
    template
        Configuration template to use.
    oidc_clients
        Configuration information for clients of the OpenID Connect server.
    **settings
        Any additional settings to add to the configuration file.

    Returns
    -------
    Config
        The new configuration.

    Notes
    -----
    This is used for tests that cannot be async, so itself must not be async.
    """
    config_path = build_config(
        tmp_path,
        template,
        oidc_clients=oidc_clients,
        **settings,
    )
    config_dependency.set_config_path(config_path)
    config = config_dependency.config()

    # Pick up any change to the log level.
    configure_logging(
        profile=Profile.production,
        log_level=config.loglevel,
        name="gafaelfawr",
        add_timestamp=True,
    )

    return config


async def reconfigure(
    tmp_path: Path,
    template: str,
    factory: Optional[Factory] = None,
    *,
    oidc_clients: Optional[list[OIDCClient]] = None,
    **settings: str,
) -> Config:
    """Change the test application configuration.

    This cannot be used to change the database URL because sessions will not
    be recreated or the database reinitialized.

    Parameters
    ----------
    tmp_path
        Root of the test temporary directory, used to write the configuration
        file.
    template
        Configuration template to use.
    factory
        The factory to reconfigure.
    oidc_clients
        Configuration information for clients of the OpenID Connect server.
    **settings
        Any additional settings to add to the configuration file.

    Returns
    -------
    Config
        The new configuration.
    """
    config = configure(
        tmp_path, template, oidc_clients=oidc_clients, **settings
    )
    await context_dependency.initialize(config)
    if factory:
        factory.set_context(context_dependency.process_context)
    return config
