"""Create and configure the test aiohttp application."""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING

import mockaioredis
from cryptography.fernet import Fernet

from jwt_authorizer.app import create_app
from jwt_authorizer.keypair import RSAKeyPair
from tests.support.http_session import MockClientSession

if TYPE_CHECKING:
    from aiohttp import web
    from pathlib import Path
    from typing import Any

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

    redis_pool = await mockaioredis.create_redis_pool("")
    kwargs["REDIS_URL"] = "dummy"

    http_session = MockClientSession()
    app = await create_app(
        redis_pool=redis_pool,
        http_session=http_session,
        FORCE_ENV_FOR_DYNACONF="testing",
        **kwargs,
    )
    http_session.set_config(app["jwt_authorizer/config"])

    return app
