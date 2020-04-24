"""Create and configure the test aiohttp application."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import mockaioredis
from cryptography.fernet import Fernet

from gafaelfawr.app import create_app
from gafaelfawr.keypair import RSAKeyPair
from tests.support.http_session import MockClientSession

if TYPE_CHECKING:
    from aiohttp import web
    from pathlib import Path

__all__ = [
    "create_test_app",
    "store_secret",
]


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
    with secret_path.open(mode="wb") as f:
        f.write(secret)
    return secret_path


async def create_test_app(
    tmp_path: Path, *, environment: str = "testing"
) -> web.Application:
    """Configured aiohttp Application for testing.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        Temporary directory in which to store secrets.
    environment : `str`, optional
        Settings environment to use.  Choose from an environment defined in
        ``settings.yaml`` in the same directory as this module.

    Returns
    -------
    app : `aiohttp.web.Application`
        The configured test application.
    """
    settings = {}

    session_secret = Fernet.generate_key()
    session_secret_file = store_secret(tmp_path, "session", session_secret)
    settings["SESSION_SECRET_FILE"] = str(session_secret_file)

    issuer_key = RSAKeyPair.generate().private_key_as_pem()
    issuer_key_file = store_secret(tmp_path, "issuer", issuer_key)
    settings["ISSUER.KEY_FILE"] = str(issuer_key_file)

    github_secret_file = store_secret(tmp_path, "github", b"github-secret")
    settings["GITHUB.CLIENT_SECRET_FILE"] = str(github_secret_file)

    oidc_secret_file = store_secret(tmp_path, "oidc", b"oidc-secret")
    settings["OIDC.CLIENT_SECRET_FILE"] = str(oidc_secret_file)

    settings_path = os.path.join(os.path.dirname(__file__), "settings.yaml")
    redis_pool = await mockaioredis.create_redis_pool("")
    http_session = MockClientSession()
    app = await create_app(
        settings_path=settings_path,
        redis_pool=redis_pool,
        http_session=http_session,
        FORCE_ENV_FOR_DYNACONF=environment,
        **settings,
    )
    http_session.set_config(app["gafaelfawr/config"])

    return app
