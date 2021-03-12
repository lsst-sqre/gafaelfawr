"""Logger dependency for FastAPI.

Provides a :py:mod:`structlog` logger as a FastAPI dependency.  The logger
will incorporate information from the request in its bound context.
"""

import uuid
from typing import TYPE_CHECKING

import structlog
from fastapi import Depends, Request
from structlog.stdlib import BoundLogger

from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency

if TYPE_CHECKING:
    from typing import Optional

__all__ = ["LoggerDependency", "get_logger", "logger_dependency"]


class LoggerDependency:
    """Provides a structlog logger configured with request information.

    Notes
    -----
    The base logger is configured once, the first time a logger is requested,
    and then never again since repeating the configuration can result in
    multiple registered loggers and duplication of output.

    This dependency should eventually move into the Safir framework.
    """

    def __init__(self) -> None:
        self.logger: Optional[BoundLogger] = None

    def __call__(
        self, request: Request, config: Config = Depends(config_dependency)
    ) -> BoundLogger:
        """Return a logger bound with request information.

        The following additional information will be included:

        * A UUID for the request
        * The method and path of the request
        * The IP address of the client (as ``remote``)
        * The ``User-Agent`` header of the request, if any.

        Returns
        -------
        logger : `structlog.stdlib.BoundLogger`
            The bound logger.
        """
        if not self.logger:
            self.logger = structlog.get_logger(config.safir.logger_name)
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


logger_dependency = LoggerDependency()
"""The dependency that will return the logger for the current request."""


def get_logger(request: Request) -> BoundLogger:
    """Return a logger bound to a request.

    This is a convenience function that can be used where a dependency isn't
    available, such as in middleware.

    Parameters
    ----------
    request : `fastapi.Request`
        The request to which to bind the logger.

    Returns
    -------
    logger : `structlog.BoundLogger`
         The bound logger.
    """
    config = config_dependency()
    return logger_dependency(request, config)
