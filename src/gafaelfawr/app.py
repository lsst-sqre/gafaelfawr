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
from aiohttp_remotes.exceptions import RemoteError
from aiohttp_remotes.x_forwarded import XForwardedBase
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cachetools import TTLCache
from safir.http import init_http_session
from safir.logging import configure_logging, response_logger
from safir.metadata import setup_metadata
from safir.middleware import bind_logger
from structlog import get_logger

from gafaelfawr.config import Config
from gafaelfawr.handlers import init_routes

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from aioredis import Redis
    from ipaddress import _BaseNetwork
    from structlog import BoundLogger
    from typing import Any, Awaitable, Callable, Dict, Optional, Sequence

    Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]

__all__ = ["create_app"]


async def create_app(
    settings_path: str,
    redis_pool: Optional[Redis] = None,
    http_session: Optional[ClientSession] = None,
    **settings: Any,
) -> Application:
    """Create and configure the Gafaelfawr application.

    Parameters
    ----------
    settings_path : `str`
        Settings file to load.
    redis_pool : `aioredis.Redis`, optional
        Redis connection pool.  One will be constructed from the URL in the
        application settings if this is not provided.
    http_session : `aiohttp.ClientSession`, optional
        Client session to use if provided.  If one is not provided, it will be
        created dynamically by safir.  The provided session is not closed on
        app shutdown.
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
        redis_pool = await aioredis.create_redis_pool(config.redis_url)

    app = Application()
    app["safir/config"] = config.safir
    app["gafaelfawr/config"] = config
    app["gafaelfawr/key_cache"] = key_cache
    app["gafaelfawr/redis"] = redis_pool
    setup_metadata(package_name="gafaelfawr", app=app)
    await setup_middleware(app, config)
    app.on_cleanup.append(on_shutdown)
    app.add_routes(init_routes())

    if http_session:
        app["safir/http_session"] = http_session
    else:
        app.cleanup_ctx.append(init_http_session)

    logger.info("Starting")
    return app


class XForwardedFiltered(XForwardedBase):
    """Middleware to update the request based on ``X-Forwarded-For``.

    The semantics we want aren't supported by either of the
    :py:mod:`aiohttp_remotes` middleware classes, so we implement our own.
    This is similar to `~aiohttp_remotes.XForwardedRelaxed` except that it
    takes the rightmost IP address that is not contained within one of the
    trusted networks.

    Parameters
    ----------
    trusted : Sequence[Union[`ipaddress.IPv4Network`, `ipaddress.IPv6Network`]]
        List of trusted networks that should be skipped over when finding the
        actual client IP address.
    """

    def __init__(self, trusted: Sequence[_BaseNetwork]):
        self._trusted = trusted

    @web.middleware
    async def middleware(
        self, request: web.Request, handler: Handler
    ) -> web.StreamResponse:
        """Replace request information with details from proxy.

        Honor ``X-Forwarded-For`` and related headers.

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
        The remote IP address will be replaced with the right-most IP address
        in ``X-Forwarded-For`` that is not contained within one of the trusted
        networks.  The last entry of ``X-Forwarded-Proto`` and the contents of
        ``X-Forwarded-Host`` will be used unconditionally if they are present
        and ``X-Forwarded-For`` is also present.
        """
        try:
            # https://github.com/python/mypy/issues/8772
            overrides: Dict[str, Any] = {}
            headers = request.headers

            forwarded_for = list(reversed(self.get_forwarded_for(headers)))
            if not forwarded_for:
                return await handler(request)

            for ip in forwarded_for:
                if any((ip in network for network in self._trusted)):
                    continue
                overrides["remote"] = str(ip)
                break

            # If all the IP addresses are from trusted networks, take the
            # left-most.
            if "remote" not in overrides:
                overrides["remote"] = str(forwarded_for[-1])

            proto = self.get_forwarded_proto(headers)
            if proto:
                overrides["scheme"] = proto[-1]

            host = self.get_forwarded_host(headers)
            if host is not None:
                overrides["host"] = host

            request = request.clone(**overrides)
            return await handler(request)

        except RemoteError as exc:
            exc.log(request)
            return await self.raise_error(request)


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
