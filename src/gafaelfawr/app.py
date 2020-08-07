"""Application setup for Gafaelfawr."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import aiohttp_csrf
import aiohttp_jinja2
import aiohttp_remotes
import aiohttp_session
import aioredis
import jinja2
from aiohttp import web
from aiohttp.web import Application
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cachetools import TTLCache
from safir.http import init_http_session
from safir.logging import configure_logging, response_logger
from safir.metadata import setup_metadata
from safir.middleware import bind_logger
from structlog import get_logger

from gafaelfawr.config import Config
from gafaelfawr.handlers import init_routes
from gafaelfawr.x_forwarded import XForwardedFiltered

if TYPE_CHECKING:
    from typing import Any, Awaitable, Callable, Optional

    from aioredis import Redis
    from structlog import BoundLogger

    Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]

__all__ = ["create_app"]


async def create_app(
    settings_path: str, redis_pool: Optional[Redis] = None, **settings: Any,
) -> Application:
    """Create and configure the Gafaelfawr application.

    Parameters
    ----------
    settings_path : `str`
        Settings file to load.
    redis_pool : `aioredis.Redis`, optional
        Redis connection pool.  One will be constructed from the URL in the
        application settings if this is not provided.
    **settings : `typing.Any`
        Settings that override settings read from the configuration file.

    Returns
    -------
    application: `aiohttp.web.Application`
        The constructed application.
    """
    config = Config.from_file(settings_path, **settings)

    configure_logging(
        profile=config.safir.profile,
        log_level=config.safir.log_level,
        name=config.safir.logger_name,
    )

    logger = get_logger(config.safir.logger_name)
    config.log_settings(logger)

    key_cache = TTLCache(maxsize=16, ttl=600)
    if not redis_pool:
        redis_pool = await aioredis.create_redis_pool(
            config.redis_url, password=config.redis_password
        )

    app = Application()
    app["safir/config"] = config.safir
    app["gafaelfawr/config"] = config
    app["gafaelfawr/key_cache"] = key_cache
    app["gafaelfawr/redis"] = redis_pool
    setup_metadata(package_name="gafaelfawr", app=app)
    await setup_middleware(app, config)
    app.on_cleanup.append(on_shutdown)
    app.add_routes(init_routes())
    app.cleanup_ctx.append(init_http_session)

    logger.info("Starting")
    return app


async def setup_middleware(app: Application, config: Config) -> None:
    """Add middleware to the application."""
    config = app["gafaelfawr/config"]

    # Replace request information with details from X-Forwarded-For and
    # related headers, since this application is designed to run behind an
    # NGINX ingress.
    await aiohttp_remotes.setup(app, XForwardedFiltered(config.proxies))

    # Create a custom logger for each request with request information bound.
    app.middlewares.append(bind_logger)
    app.middlewares.append(bind_logging_context)

    # Set up encrypted session storage via a cookie.
    session_storage = EncryptedCookieStorage(
        config.session_secret, cookie_name="gafaelfawr"
    )
    aiohttp_session.setup(app, session_storage)

    # Configure global CSRF protection using session storage.
    csrf_policy = aiohttp_csrf.policy.FormPolicy("_csrf")
    csrf_storage = aiohttp_csrf.storage.SessionStorage("csrf")
    aiohttp_csrf.setup(app, policy=csrf_policy, storage=csrf_storage)

    # Configure Jinja2 templating of responses.
    templates_path = os.path.join(os.path.dirname(__file__), "templates")
    aiohttp_jinja2.setup(
        app, loader=jinja2.FileSystemLoader(templates_path),
    )


@web.middleware
async def bind_logging_context(
    request: web.Request, handler: Handler
) -> web.StreamResponse:
    """Bind additional context to the context-local structlog logger.

    Parameters
    ----------
    request
        The aiohttp.web request.
    handler
        The application's request handler.

    Returns
    -------
    response
        The response with a new ``logger`` key attached to it.

    Notes
    -----
    This adds the following additional context fields to the structlog logger:

    ``remote``
        The IP address of the originating client.

    ``user_agent``
        The User-Agent header of the incoming request.

    Eventually this context should be incorporated into Safir.
    """
    logger: BoundLogger = request["safir/logger"]

    logger = logger.bind(remote=request.remote)
    user_agent = request.headers.get("User-Agent")
    if user_agent:
        logger = logger.bind(user_agent=user_agent)

    request["safir/logger"] = logger
    response_logger.set(logger)

    response = await handler(request)
    return response


async def on_shutdown(app: Application) -> None:
    """Cleanly shut down the application."""
    redis_client = app["gafaelfawr/redis"]
    redis_client.close()
    await redis_client.wait_closed()


async def create_dev_app() -> Application:
    """Wrapper around create_app for development testing.

    Invoked by the ``run`` test environment to create a local server for
    testing.  Loads configuration from ``gafaelfawr-dev.yaml`` in the current
    directory.
    """
    config_path = os.path.join(os.getcwd(), "examples", "gafaelfawr-dev.yaml")
    return await create_app(config_path)
