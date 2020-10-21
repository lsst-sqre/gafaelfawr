"""Global FastAPI dependencies for Gafaelfawr.

These dependencies are made available to all routes and initialized via
:py:func:`gafaelfawr.setup.setup_app`.

Notes
-----
Normally, FastAPI prefers early binding, creating all resources and
dependencies at module load time.  However, this prevents injecting varying
settings and configuration into the app except through environment variables,
which makes testing much harder.

To avoid that problem, we construct dependency callables that only initialize
their values the first time they're called.  The test suite can then override
settings as desired before making its first request.

The downside is that this means errors with initializing dependencies won't
be seen until the first request, but we can work around that by making a
health check request as soon as the application comes up.
"""

import uuid
from dataclasses import dataclass
from typing import AsyncIterator, Optional
from urllib.parse import urlparse

from aioredis import Redis, create_redis_pool
from fastapi import Depends, Form, Header, HTTPException, Request, status
from httpx import AsyncClient
from safir.logging import configure_logging
from structlog import BoundLogger, get_logger

from gafaelfawr.config import Config
from gafaelfawr.constants import CONFIG_PATH
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.util import random_128_bits


class ConfigDependency:
    """Provides the configuration as a dependency.

    We want a production deployment to default to one configuration path, but
    allow that path to be overridden by the test suite and, if the path
    changes, to reload the configuration (which allows sharing the same set of
    global singletons across multiple tests).  Do this by loading the config
    dynamically when it's first requested and reloading it whenever the
    configuration path is changed.
    """

    def __init__(self) -> None:
        self.config_path = CONFIG_PATH
        self.config: Optional[Config] = None

    def __call__(self) -> Config:
        if not self.config:
            self._load_config()
        assert self.config
        return self.config

    def set_config_path(self, path: str) -> None:
        """Change the configuration path and reload the config.

        Parameters
        ----------
        path : `str`
            The new configuration path.
        """
        self.config_path = path
        self._load_config()

    def _load_config(self) -> None:
        self.config = Config.from_file(self.config_path)


config = ConfigDependency()


class LoggerDependency:
    """Provides a structlog logger configured with request information.

    The base logger is configured once, the first time a logger is requested,
    and then never again since repeating the configuration can result in
    multiple registered loggers and duplication of output.

    Parameters
    ----------
    logger : `structlog.BoundLogger`
        A configured logger to use as a basis for the per-request logger.

    Notes
    -----
    This dependency should eventually move into the Safir framework.
    """

    def __init__(self) -> None:
        self.logger: Optional[BoundLogger] = None

    def __call__(
        self, request: Request, config: Config = Depends(config)
    ) -> BoundLogger:
        if not self.logger:
            self._configure_logging(config)
        assert self.logger
        logger = self.logger.new(
            request_id=str(uuid.uuid4()),
            path=request.url.path,
            method=request.method,
            remote=request.client.host,
        )
        user_agent = request.headers.get("User-Agent")
        if user_agent:
            logger = logger.bind(user_agent=user_agent)
        return logger

    def _configure_logging(self, config: Config) -> None:
        configure_logging(
            profile=config.safir.profile,
            log_level=config.safir.log_level,
            name=config.safir.logger_name,
        )
        self.logger = get_logger(config.safir.logger_name)


logger = LoggerDependency()


class RedisDependency:
    """Provides an aioredis pool as a dependency.

    Parameters
    ----------
    redis : `aioredis.Redis`
        The Redis pool to wrap as a dependency.
    """

    def __init__(self) -> None:
        self.redis: Optional[Redis] = None
        self.mock = False

    async def __call__(self, config: Config = Depends(config)) -> Redis:
        if not self.redis:
            await self._create_pool(config)
        assert self.redis
        return self.redis

    async def close(self) -> None:
        if self.redis:
            self.redis.close()
            await self.redis.wait_closed()
            self.redis = None

    def use_mock(self, enable: bool) -> None:
        self.redis = None
        self.mock = enable

    async def _create_pool(self, config: Config) -> None:
        if self.mock:
            import mockaioredis

            self.redis = await mockaioredis.create_redis_pool("")
        else:
            self.redis = await create_redis_pool(
                config.redis_url, password=config.redis_password
            )


redis = RedisDependency()


async def http_client_dependency() -> AsyncIterator[AsyncClient]:
    """Provides an `httpx.AsyncClient` as a dependency.

    Notes
    -----
    This is provided as a function rather than using the class as a callable
    directly so that the session can be explicitly closed and to avoid
    exposing the constructor parameters to FastAPI and possibly confusing it.

    This dependency should eventually move into the Safir framework.
    """
    async with AsyncClient() as client:
        yield client


@dataclass
class RequestContext:
    """Holds the incoming request and its surrounding context.

    The primary reason for the existence of this class is to allow the
    functions involved in request processing to repeated rebind the request
    logger to include more information, without having to pass both the
    request and the logger separately to every function.
    """

    request: Request
    """The incoming request."""

    config: Config
    """Gafaelfawr's configuration."""

    logger: BoundLogger
    """The request logger, rebound with discovered context."""

    redis: Redis
    """Connection pool to use to talk to Redis."""

    http_client: AsyncClient
    """Shared HTTP client."""

    @property
    def factory(self) -> ComponentFactory:
        """A factory for constructing Gafaelfawr components.

        This is constructed on the fly at each reference to ensure that we get
        the latest logger, which may have additional bound context.
        """
        return ComponentFactory(
            config=self.config,
            redis=self.redis,
            http_client=self.http_client,
            logger=self.logger,
        )

    def rebind_logger(self, **values: Optional[str]) -> None:
        """Add the given values to the logging context.

        Also updates the logging context stored in the request object in case
        the request context later needs to be recreated from the request.

        Parameters
        ----------
        **values : `str` or `None`
            Additional values that should be added to the logging context.
        """
        self.logger = self.logger.bind(**values)


def context(
    request: Request,
    config: Config = Depends(config),
    logger: BoundLogger = Depends(logger),
    redis: Redis = Depends(redis),
    http_client: AsyncClient = Depends(http_client_dependency),
) -> RequestContext:
    """Provides a RequestContext as a dependency."""
    return RequestContext(
        request=request,
        config=config,
        logger=logger,
        redis=redis,
        http_client=http_client,
    )


def return_url(
    rd: Optional[str] = None,
    x_forwarded_host: Optional[str] = Header(None),
    context: RequestContext = Depends(context),
) -> Optional[str]:
    """Validate a return URL for use in a redirect.

    Verify that the given URL is at the same host as the current route.

    Parameters
    ----------
    context : `RequestContext`
        The context of the incoming request.
    return_url : `str`
        The URL provided by the client.

    Returns
    -------
    parsed_return_url : `urllib.parse.ParseResult`
        The parsed return URL.

    Raises
    ------
    fastapi.HTTPException
        An appropriate error if the return URL was invalid or missing.
    """
    if not rd:
        return None
    context.rebind_logger(return_url=rd)
    base_host = x_forwarded_host if x_forwarded_host else context.config.realm
    parsed_return_url = urlparse(rd)
    if parsed_return_url.hostname != base_host:
        msg = f"URL is not at {base_host}"
        context.logger.warning("Bad return URL", error=msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "loc": ["query", "rd"],
                "msg": msg,
                "type": "bad_return_url",
            },
        )
    return parsed_return_url.geturl()


def return_url_with_header(
    rd: Optional[str] = None,
    x_auth_request_redirect: Optional[str] = Header(None),
    x_forwarded_host: Optional[str] = Header(None),
    context: RequestContext = Depends(context),
) -> Optional[str]:
    if not rd and x_auth_request_redirect:
        rd = x_auth_request_redirect
    return return_url(rd, x_forwarded_host, context)


def set_csrf(request: Request) -> None:
    if not request.state.cookie.csrf:
        request.state.cookie.csrf = random_128_bits()


def verify_csrf(request: Request, _csrf: str = Form(None)) -> None:
    expected_csrf = request.state.cookie.csrf
    if not expected_csrf:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"msg": "No CSRF in session", "type": "csrf_not_found"},
        )
    if _csrf != expected_csrf:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"msg": "No CSRF token", "type": "csrf_missing"},
        )
