"""Create objects used for testing."""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING

import mockaioredis
from cryptography.fernet import Fernet

from jwt_authorizer.app import create_app
from jwt_authorizer.keypair import RSAKeyPair
from tests.support.config import ConfigForTests
from tests.support.http_session import MockClientSession

if TYPE_CHECKING:
    from aiohttp import web
    from jwt_authorizer.config import Config
    from pathlib import Path
    from typing import Any

__all__ = ["create_test_app", "get_test_config", "store_secret"]


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


async def create_test_app(tmp_path: Path, **kwargs: Any) -> web.Application:
    """Configured aiohttp Application for testing."""
    session_secret = Fernet.generate_key()
    session_secret_path = store_secret(tmp_path, "session", session_secret)
    kwargs["SESSION_SECRET_FILE"] = str(session_secret_path)

    keypair = RSAKeyPair.generate()
    issuer_key = keypair.private_key_as_pem()
    issuer_key_file = store_secret(tmp_path, "issuer", issuer_key)
    kwargs["OAUTH2_JWT.KEY_FILE"] = str(issuer_key_file)

    key = os.urandom(16)
    key_b64 = base64.urlsafe_b64encode(key)
    key_file = store_secret(tmp_path, "session-key", key_b64)
    kwargs["OAUTH2_STORE_SESSION.OAUTH2_PROXY_SECRET_FILE"] = str(key_file)

    test_config = ConfigForTests(
        keypair=keypair,
        session_key=key,
        internal_issuer_url="https://test.example.com/",
        upstream_issuer_url="https://upstream.example.com/",
    )

    redis_pool = await mockaioredis.create_redis_pool("")
    kwargs["OAUTH2_STORE_SESSION.REDIS_URL"] = "dummy"

    app = await create_app(
        redis_pool=redis_pool,
        http_session=MockClientSession(test_config),
        FORCE_ENV_FOR_DYNACONF="testing",
        **kwargs,
    )
    app["jwt_authorizer/test_config"] = test_config

    app_config: Config = app["jwt_authorizer/config"]
    test_config.github = app_config.github
    test_config.oidc = app_config.oidc

    return app


def get_test_config(app: web.Application) -> ConfigForTests:
    """Return the test configuration for a test application."""
    return app["jwt_authorizer/test_config"]
