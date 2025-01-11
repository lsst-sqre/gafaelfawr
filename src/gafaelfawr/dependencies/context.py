"""Request context dependency for FastAPI.

This dependency gathers a variety of information into a single object for the
convenience of writing request handlers.  It also provides a place to store a
`structlog.BoundLogger` that can gather additional context during processing,
including from dependencies.
"""

from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from limits.aio.strategies import RateLimiter
from safir.dependencies.db_session import db_session_dependency
from safir.dependencies.logger import logger_dependency
from safir.metrics import EventManager
from sqlalchemy.ext.asyncio import async_scoped_session
from structlog.stdlib import BoundLogger

from ..config import Config
from ..events import FrontendEvents
from ..factory import Factory, ProcessContext
from ..models.state import State

__all__ = [
    "ContextDependency",
    "RequestContext",
    "context_dependency",
]


@dataclass(slots=True)
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

    events: FrontendEvents
    """Frontend events publishers."""

    session: async_scoped_session
    """The database session."""

    rate_limiter: RateLimiter
    """API rate limiter."""

    factory: Factory
    """The component factory."""

    @property
    def state(self) -> State:
        """User cookie state."""
        return self.request.state.cookie

    @state.setter
    def state(self, state: State) -> None:
        """Set the cookie state."""
        self.request.state.cookie = state

    def rebind_logger(self, **values: Any) -> None:
        """Add the given values to the logging context.

        Parameters
        ----------
        **values
            Additional values that should be added to the logging context.
        """
        self.logger = self.logger.bind(**values)
        self.factory.set_logger(self.logger)


class ContextDependency:
    """Provide a per-request context as a FastAPI dependency.

    Each request gets a `RequestContext`.  To save overhead, the portions of
    the context that are shared by all requests are collected into the single
    process-global `~gafaelfawr.factory.ProcessContext` and reused with each
    request.
    """

    def __init__(self) -> None:
        self._config: Config | None = None
        self._events: FrontendEvents | None = None
        self._process_context: ProcessContext | None = None

    async def __call__(
        self,
        *,
        request: Request,
        session: Annotated[
            async_scoped_session, Depends(db_session_dependency)
        ],
        logger: Annotated[BoundLogger, Depends(logger_dependency)],
    ) -> RequestContext:
        """Create a per-request context and return it."""
        if not self._config or not self._process_context or not self._events:
            raise RuntimeError("ContextDependency not initialized")
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
            config=self._config,
            logger=logger,
            events=self._events,
            session=session,
            rate_limiter=self._process_context.rate_limiter,
            factory=Factory(self._process_context, session, logger),
        )

    @property
    def process_context(self) -> ProcessContext:
        """The underlying process context, primarily for use in tests."""
        if not self._process_context:
            raise RuntimeError("ContextDependency not initialized")
        return self._process_context

    async def aclose(self) -> None:
        """Clean up the per-process configuration.

        This also invalidates the events publishers until `initialize` is
        called again.
        """
        if self._process_context:
            await self._process_context.aclose()
        self._config = None
        self._process_context = None

    async def initialize(
        self, config: Config, event_manager: EventManager
    ) -> None:
        """Initialize the process-wide shared context.

        Parameters
        ----------
        config
            Gafaelfawr configuration.
        event_manager
            Global event manager.
        """
        if self._process_context:
            await self._process_context.aclose()
        self._config = config
        self._events = FrontendEvents()
        await self._events.initialize(event_manager)
        self._process_context = await ProcessContext.from_config(config)


context_dependency = ContextDependency()
"""The dependency that will return the per-request context."""
