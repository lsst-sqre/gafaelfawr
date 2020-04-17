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
    from typing import Any

__all__ = ["create_test_app"]


async def create_test_app(**kwargs: Any) -> web.Application:
    """Configured aiohttp Application for testing."""
    keypair = RSAKeyPair.generate()
    session_key = os.urandom(16)

    kwargs["SESSION_SECRET"] = Fernet.generate_key().decode()
    kwargs["OAUTH2_JWT.KEY"] = keypair.private_key_as_pem().decode()
    session_key_b64 = base64.urlsafe_b64encode(session_key).decode()
    kwargs["OAUTH2_STORE_SESSION.OAUTH2_PROXY_SECRET"] = session_key_b64
    kwargs["OAUTH2_STORE_SESSION.REDIS_URL"] = "dummy"

    test_config = ConfigForTests(
        keypair=keypair,
        session_key=session_key,
        internal_issuer_url="https://test.example.com/",
        upstream_issuer_url="https://upstream.example.com/",
    )

    redis_pool = await mockaioredis.create_redis_pool("")
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
