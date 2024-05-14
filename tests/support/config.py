"""Build test configuration for Gafaelfawr."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gafaelfawr.config import Config, OIDCClient
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.context import context_dependency
from gafaelfawr.factory import Factory

__all__ = [
    "config_path",
    "configure",
    "reconfigure",
]


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
                "return_uri": c.return_uri,
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

    This cannot be used to change the database URL because sessions will not
    be recreated or the database reinitialized.

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
    config = configure(filename, monkeypatch, oidc_clients=oidc_clients)
    await context_dependency.initialize(config)
    if factory:
        factory.set_context(context_dependency.process_context)
    return config
