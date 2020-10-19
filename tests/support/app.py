"""Create and configure the test aiohttp application."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import mockaioredis
from cryptography.fernet import Fernet
from httpx import AsyncClient

from gafaelfawr.app import create_app
from gafaelfawr.fastapi.dependencies import config, key_cache, redis
from gafaelfawr.fastapi.main import app
from gafaelfawr.keypair import RSAKeyPair

if TYPE_CHECKING:
    from typing import Any, AsyncIterator, List, Optional

    from aiohttp import web
    from fastapi import FastAPI

    from gafaelfawr.config import OIDCClient

__all__ = ["create_fastapi_test_app", "create_test_app", "create_test_client"]


def build_settings(tmp_path: Path, template_name: str, **kwargs: Path) -> Path:
    """Construct a configuration file from a format template.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    template_name : `str`
        Name of the configuration template to use.
    **kwargs : `str`
        The values to substitute into the template.

    Returns
    -------
    settings_path : `pathlib.Path`
        The path to the newly-constructed configuration file.
    """
    template_file = template_name + ".yaml.in"
    template_path = Path(__file__).parent.parent / "settings" / template_file
    template = template_path.read_text()
    settings = template.format(**kwargs)
    settings_path = tmp_path / "gafaelfawr.yaml"
    settings_path.write_text(settings)
    return settings_path


def store_secret(tmp_path: Path, name: str, secret: bytes) -> Path:
    """Store a secret in a temporary path.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    name : `str`
        The name of the secret to construct nice file names.
    secret : `bytes`
        The value of the secret.
    """
    secret_path = tmp_path / name
    secret_path.write_bytes(secret)
    return secret_path


def build_config(
    tmp_path: Path,
    environment: str,
    oidc_clients: Optional[List[OIDCClient]] = None,
    **settings: str,
) -> Path:
    """Generate a test Gafaelfawr configuration.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    environment : `str`
        Settings template to use.

    Returns
    -------
    config_path : `pathlib.Path`
        The path of the configuration file.
    """
    session_secret = Fernet.generate_key()
    session_secret_file = store_secret(tmp_path, "session", session_secret)
    issuer_key = RSAKeyPair.generate().private_key_as_pem()
    issuer_key_file = store_secret(tmp_path, "issuer", issuer_key)
    influxdb_secret_file = store_secret(tmp_path, "influxdb", b"influx-secret")
    github_secret_file = store_secret(tmp_path, "github", b"github-secret")
    oidc_secret_file = store_secret(tmp_path, "oidc", b"oidc-secret")

    settings_path = build_settings(
        tmp_path,
        environment,
        session_secret_file=session_secret_file,
        issuer_key_file=issuer_key_file,
        github_secret_file=github_secret_file,
        oidc_secret_file=oidc_secret_file,
        influxdb_secret_file=influxdb_secret_file,
    )

    if oidc_clients:
        oidc_path = tmp_path / "oidc.json"
        clients_data = [
            {"id": c.client_id, "secret": c.client_secret}
            for c in oidc_clients
        ]
        oidc_path.write_text(json.dumps(clients_data))
        with settings_path.open("a") as f:
            f.write(f'oidc_server_secrets_file: "{str(oidc_path)}"\n')

    if settings:
        with settings_path.open("a") as f:
            for key, value in settings.items():
                f.write(f"{key}: {value}\n")

    return settings_path


async def create_fastapi_test_app(
    tmp_path: Path,
    *,
    environment: str = "github",
    oidc_clients: Optional[List[OIDCClient]] = None,
    **settings: str,
) -> FastAPI:
    """Create a test FastAPI application.

    Returns the FastAPI Gafaelfawr application, but only after configuring it
    to use a test configuration and a mock Redis pool.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The root of the temporary area.
    environment : `str`, optional
        Settings template to use.

    Returns
    -------
    app : `fastapi.FastAPI`
        The configured test application.
    """
    config_path = build_config(tmp_path, environment, oidc_clients, **settings)
    config.set_config_path(str(config_path))
    redis.use_mock(True)
    key_cache().clear()
    return app


async def create_test_app(
    tmp_path: Path,
    *,
    environment: str = "github",
    oidc_clients: Optional[List[OIDCClient]] = None,
    **settings: Any,
) -> web.Application:
    """Configured aiohttp Application for testing.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        Temporary directory in which to store secrets.
    environment : `str`, optional
        Settings template to use.
    oidc_clients : List[`gafaelfawr.config.OIDCClient`], optional
        If present, serialize the provided OpenID Connect clients into a
        secret and include its path in the configuration.
    **settings : Any
        Settings that override settings read from the configuration file.

    Returns
    -------
    app : `aiohttp.web.Application`
        The configured test application.
    """
    settings_path = build_config(tmp_path, environment)

    if oidc_clients:
        oidc_path = tmp_path / "oidc.json"
        clients_data = [
            {"id": c.client_id, "secret": c.client_secret}
            for c in oidc_clients
        ]
        oidc_path.write_text(json.dumps(clients_data))
        settings["oidc_server_secrets_file"] = str(oidc_path)

    app = await create_app(
        settings_path=str(settings_path),
        redis_pool=await mockaioredis.create_redis_pool(""),
        **settings,
    )

    return app


@asynccontextmanager
async def create_test_client(
    app: FastAPI, hostname: str = "example.com"
) -> AsyncIterator[AsyncClient]:
    """Creates and returns a client for the given application.

    Parameters
    ----------
    app : `fastapi.FastAPI`
        The ASGI application to test.
    hostname : `str`, optional
        The hostname to which test queries will apparently be sent.  Defaults
        to ``example.com``.

    Returns
    -------
    client : `httpx.AsyncClient`
        A client to make queries to that application.
    """
    async with AsyncClient(app=app, base_url="https://" + hostname) as client:
        yield client
