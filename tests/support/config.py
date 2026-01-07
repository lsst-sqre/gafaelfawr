"""Build test configuration for Gafaelfawr."""

import json
from pathlib import Path

import pytest
from pydantic import SecretStr

from gafaelfawr.config import Config, OIDCClient
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.context import context_dependency
from gafaelfawr.factory import Factory

__all__ = [
    "build_oidc_client",
    "config_path",
    "configure",
    "reconfigure",
]


def build_oidc_client(
    id: str, secret: str | SecretStr, return_uri: str
) -> OIDCClient:
    """Construct the configuration object for one OpenID Connect client.

    Pydantic makes it a little difficult to build this object, so this wrapper
    function streamlines it.

    Parameters
    ----------
    id
        Client identifier.
    secret
        Client secret.
    return_uri
        Return URI for this client.

    Returns
    -------
    OIDCConfig
        Configuration for the client.
    """
    if isinstance(secret, SecretStr):
        secret = secret.get_secret_value()
    return OIDCClient.model_validate(
        {"id": id, "secret": secret, "return_uri": return_uri}
    )


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
    return (
        Path(__file__).parent.parent / "data" / "config" / (filename + ".yaml")
    )


def configure(
    filename: str,
    monkeypatch: pytest.MonkeyPatch | None = None,
    *,
    oidc_clients: list[OIDCClient] | None = None,
) -> Config:
    """Change the test application configuration.

    This cannot be used to change the database URL because sessions will not
    be recreated or the database reinitialized.

    Parameters
    ----------
    filename
        Configuration file to use.
    monkeypatch
        pytest monkeypatch object to set environment variables. Must be
        provided if ``oidc_clients`` is set.
    oidc_clients
        Configuration information for clients of the OpenID Connect server.

    Returns
    -------
    Config
        The new configuration.

    Notes
    -----
    This is used for tests that cannot be async, so itself must not be async.
    """
    if oidc_clients:
        assert monkeypatch
        clients = [
            {
                "id": c.id,
                "secret": c.secret.get_secret_value(),
                "return_uri": str(c.return_uri),
            }
            for c in oidc_clients
        ]
        clients_json = json.dumps(clients)
        monkeypatch.setenv("GAFAELFAWR_OIDC_SERVER_CLIENTS", clients_json)

    config_dependency.set_config_path(config_path(filename))
    return config_dependency.config()


async def reconfigure(
    filename: str,
    factory: Factory | None = None,
    monkeypatch: pytest.MonkeyPatch | None = None,
    *,
    oidc_clients: list[OIDCClient] | None = None,
) -> Config:
    """Change the test application configuration.

    This cannot be used to change the database URL because the database will
    not be reinitialized.

    Parameters
    ----------
    filename
        Configuration template to use.
    factory
        The factory to reconfigure.
    monkeypatch
        pytest monkeypatch object to set environment variables. Must be
        provided if ``oidc_clients`` is set.
    oidc_clients
        Configuration information for clients of the OpenID Connect server.

    Returns
    -------
    Config
        The new configuration.
    """
    await context_dependency.aclose()
    config = configure(filename, monkeypatch, oidc_clients=oidc_clients)
    event_manager = config.metrics.make_manager()
    await event_manager.initialize()
    await context_dependency.initialize(config, event_manager)
    if factory:
        factory.set_context(context_dependency.process_context)
    return config
