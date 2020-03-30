"""Flask application routes for JWT Authorizer."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import aiohttp_csrf
import aiohttp_jinja2
import aiohttp_session
import jinja2
import redis
from aiohttp.web import Application
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cryptography.fernet import Fernet
from dynaconf import LazySettings, Validator
from safir.logging import configure_logging
from safir.metadata import setup_metadata
from safir.middleware import bind_logger
from structlog import get_logger

from jwt_authorizer.config import Config, Configuration
from jwt_authorizer.handlers import init_routes

if TYPE_CHECKING:
    from typing import Optional

__all__ = ["create_app"]


class RedisManager:
    """Create Redis clients as needed.

    This class creates a Redis connection pool and returns clients from that
    pool.  It exists primarily so that it can be replaced by a FakeRedis
    instance for testing.
    """

    def __init__(self, redis_url: str) -> None:
        self._pool = redis.ConnectionPool.from_url(url=redis_url)

    def get_redis_client(self) -> redis.Redis:
        """Return a Redis client."""
        return redis.Redis(connection_pool=self._pool)


async def create_app(
    settings_path: Optional[str] = None,
    redis_manager: Optional[RedisManager] = None,
    **extra: str,
) -> Application:
    """Create and configure the JWT Authorizer application.

    Parameters
    ----------
    settings_path : `str`, optional
        Additional settings file to load.
    redis_manager : `RedisManager`, optional
        Class that provides Redis clients.  One will be constructed from the
        URL in the application settings if this is not provided.
    **extra : `str`
        Additional configuration settings for Dynaconf.

    Returns
    -------
    application: `Application`
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

    if not redis_manager:
        redis_manager = RedisManager(settings["REDIS_URL"])

    app = Application()
    app["safir/config"] = configuration
    app["jwt_authorizer/config"] = config
    app["jwt_authorizer/redis"] = redis_manager
    setup_metadata(package_name="jwt_authorizer", app=app)
    setup_middleware(app)
    app.add_routes(init_routes())

    return app


def setup_middleware(app: Application) -> None:
    """Add middleware to the application."""
    app.middlewares.append(bind_logger)

    # Use an ephemeral key for the session, since we only store flash messages
    # in it.  This should probably switch to Redis at some point, since it
    # won't work if there are multiple copies of jwt_authorizer running.
    secret = Fernet.generate_key().decode()
    aiohttp_session.setup(app, EncryptedCookieStorage(secret))

    # Configure global CSRF protection using session storage.
    csrf_policy = aiohttp_csrf.policy.FormPolicy("_csrf")
    csrf_storage = aiohttp_csrf.storage.SessionStorage("csrf")
    aiohttp_csrf.setup(app, policy=csrf_policy, storage=csrf_storage)

    templates_path = os.path.join(os.path.dirname(__file__), "templates")
    aiohttp_jinja2.setup(
        app, loader=jinja2.FileSystemLoader(templates_path),
    )
