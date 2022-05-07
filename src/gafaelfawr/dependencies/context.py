"""Request context dependency for FastAPI.

This dependency gathers a variety of information into a single object for the
convenience of writing request handlers.  It also provides a place to store a
`structlog.BoundLogger` that can gather additional context during processing,
including from dependencies.
"""

from dataclasses import dataclass
from typing import Any, Optional

from aioredis import Redis
from bonsai.asyncio import AIOConnectionPool
from fastapi import Depends, HTTPException, Request
from httpx import AsyncClient
from safir.dependencies.db_session import db_session_dependency
from safir.dependencies.http_client import http_client_dependency
from safir.dependencies.logger import logger_dependency
from sqlalchemy.ext.asyncio import async_scoped_session
from structlog.stdlib import BoundLogger

from ..config import Config
from ..factory import ComponentFactory
from ..models.state import State
from .cache import (
    IdCache,
    TokenCache,
    id_cache_dependency,
    token_cache_dependency,
)
from .config import config_dependency
from .ldap import ldap_pool_dependency
from .redis import redis_dependency

__all__ = ["RequestContext", "context_dependency"]


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

    ip_address: str
    """IP address of client."""

    config: Config
    """Gafaelfawr's configuration."""

    logger: BoundLogger
    """The request logger, rebound with discovered context."""

    ldap_pool: Optional[AIOConnectionPool]
    """Connection pool to talk to LDAP."""

    redis: Redis
    """Connection pool to use to talk to Redis."""

    session: async_scoped_session
    """The database session."""

    http_client: AsyncClient
    """Shared HTTP client."""

    id_cache: IdCache
    """Shared UID/GID cache."""

    token_cache: TokenCache
    """Shared token cache."""

    @property
    def factory(self) -> ComponentFactory:
        """A factory for constructing Gafaelfawr components.

        This is constructed on the fly at each reference to ensure that we get
        the latest logger, which may have additional bound context.
        """
        return ComponentFactory(
            config=self.config,
            ldap_pool=self.ldap_pool,
            redis=self.redis,
            session=self.session,
            http_client=self.http_client,
            id_cache=self.id_cache,
            token_cache=self.token_cache,
            logger=self.logger,
        )

    @property
    def state(self) -> State:
        """Convenience property to access the cookie state."""
        return self.request.state.cookie

    @state.setter
    def state(self, state: State) -> None:
        """Convenience property to set the cookie state."""
        self.request.state.cookie = state

    def rebind_logger(self, **values: Any) -> None:
        """Add the given values to the logging context.

        Also updates the logging context stored in the request object in case
        the request context later needs to be recreated from the request.

        Parameters
        ----------
        **values : `typing.Any`
            Additional values that should be added to the logging context.
        """
        self.logger = self.logger.bind(**values)


async def context_dependency(
    request: Request,
    config: Config = Depends(config_dependency),
    logger: BoundLogger = Depends(logger_dependency),
    ldap_pool: Optional[AIOConnectionPool] = Depends(ldap_pool_dependency),
    redis: Redis = Depends(redis_dependency),
    session: async_scoped_session = Depends(db_session_dependency),
    http_client: AsyncClient = Depends(http_client_dependency),
    id_cache: IdCache = Depends(id_cache_dependency),
    token_cache: TokenCache = Depends(token_cache_dependency),
) -> RequestContext:
    """Provides a RequestContext as a dependency."""
    if request.client and request.client.host:
        ip_address = request.client.host
    else:
        raise HTTPException(
            status_code=422,
            detail={
                "msg": "No client IP address",
                "type": "missing_client_ip",
            },
        )
    return RequestContext(
        request=request,
        ip_address=ip_address,
        config=config,
        logger=logger,
        ldap_pool=ldap_pool,
        redis=redis,
        session=session,
        http_client=http_client,
        id_cache=id_cache,
        token_cache=token_cache,
    )
