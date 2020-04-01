"""Flask application routes for JWT Authorizer."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import aiohttp_csrf
import aiohttp_jinja2
import aiohttp_session
import aioredis
import jinja2
from aiohttp.web import Application
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography.fernet import Fernet
from dynaconf import LazySettings, Validator
from safir.http import init_http_session
from safir.logging import configure_logging
from safir.metadata import setup_metadata
from safir.middleware import bind_logger
from structlog import get_logger

from jwt_authorizer.config import Config, Configuration
from jwt_authorizer.handlers import init_routes

if TYPE_CHECKING:
    from jwt_authorizer.verify import KeyClient
    from typing import Optional

__all__ = ["create_app"]


async def create_app(
    settings_path: Optional[str] = None,
    redis_pool: Optional[aioredis.ConnectionsPool] = None,
    key_client: Optional[KeyClient] = None,
    **extra: str,
) -> Application:
    """Create and configure the JWT Authorizer application.

    Parameters
    ----------
    settings_path : `str`, optional
        Additional settings file to load.
    redis_pool : `aioredis.ConnectionsPool`, optional
        Redis connection pool.  One will be constructed from the URL in the
        application settings if this is not provided.
    key_client : `jwt_authorizer.verify.KeyClient`, optional
        Class to retrieve a JWKS for an issuer.  A default HTTP-based client
        will be constructed for each request if this is not provided.
    **extra : `str`
        Additional configuration settings for Dynaconf.

    Returns
    -------
    application: `aiohttp.web.Application`
        The constructed application.
    """
    configuration = Configuration()
    configure_logging(
        profile=configuration.profile,
        log_level=configuration.log_level,
        name=configuration.logger_name,
    )

    defaults_file = os.path.join(os.path.dirname(__file__), "defaults.yaml")
    if settings_path:
        settings_files = f"{defaults_file},{settings_path}"
    else:
        settings_files = defaults_file
    settings = LazySettings(SETTINGS_FILE_FOR_DYNACONF=settings_files, **extra)
    settings.validators.register(
        Validator("NO_VERIFY", "NO_AUTHORIZE", is_type_of=bool),
        Validator("GROUP_MAPPING", is_type_of=dict),
    )
    settings.validators.validate()

    config = Config.from_dynaconf(settings)
    logger = get_logger(configuration.logger_name)
    config.log_settings(logger)

    if not redis_pool:
        redis_url = config.session_store.redis_url
        redis_pool = await aioredis.create_redis_pool(redis_url)

    app = Application()
    app["safir/config"] = configuration
    app["jwt_authorizer/config"] = config
    app["jwt_authorizer/redis"] = redis_pool
    setup_metadata(package_name="jwt_authorizer", app=app)
    setup_middleware(app)
    app.cleanup_ctx.append(init_http_session)
    app.add_routes(init_routes())

    if key_client:
        app["jwt_authorizer/key_client"] = key_client

    return app


def setup_middleware(app: Application) -> None:
    """Add middleware to the application."""
    app.middlewares.append(bind_logger)

    # Use an ephemeral key for the session, since we only store flash messages
    # in it.  This should switch to a shared key eventually.
    secret = Fernet.generate_key().decode()
    session_storage = EncryptedCookieStorage(secret, cookie_name="jwts")
    aiohttp_session.setup(app, session_storage)

    # Configure global CSRF protection using session storage.
    csrf_policy = aiohttp_csrf.policy.FormPolicy("_csrf")
    csrf_storage = aiohttp_csrf.storage.SessionStorage("csrf")
    aiohttp_csrf.setup(app, policy=csrf_policy, storage=csrf_storage)

    templates_path = os.path.join(os.path.dirname(__file__), "templates")
    aiohttp_jinja2.setup(
        app, loader=jinja2.FileSystemLoader(templates_path),
    )


async def on_shutdown(app: Application) -> None:
    """Cleanly shut down the application."""
    redis_client = app["jwt_authorizer/redis"]
    redis_client.close()
    await redis_client.wait_closed()
