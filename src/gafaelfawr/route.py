"""Special route handling for Gafaelfawr."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from starlette.exceptions import HTTPException as StarletteHTTPException

from .dependencies.slack import slack_client_dependency
from .slack import SlackIgnoredException

__all__ = ["SlackRouteErrorHandler"]


class SlackRouteErrorHandler(APIRoute):
    """Custom `fastapi.routing.APIRoute` that reports exceptions to Slack.

    Dynamically wrap FastAPI route handlers in an exception handler that
    reports uncaught exceptions (other than :exc:`fastapi.HTTPException`,
    :exc:`fastapi.exceptions.RequestValidationError`,
    :exc:`starlette.exceptions.HTTPException`, and exceptions inheriting from
    `~gafaelfawr.slack.SlackIgnoredException`) to Slack.

    Examples
    --------
    Specify this class when creating a router.  All uncaught exceptions from
    handlers managed by that router will be reported to Slack, if Slack alerts
    are configured.

    .. code-block:: python

       router = APIRouter(route_class=SlackRouteErrorHandler)

    Notes
    -----
    Based on `this StackOverflow question
    <https://stackoverflow.com/questions/61596911/>`__.
    """

    def get_route_handler(
        self,
    ) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        """Wrap route handler with an exception handler."""
        original_route_handler = super().get_route_handler()

        async def wrapped_route_handler(request: Request) -> Response:
            try:
                return await original_route_handler(request)
            except Exception as e:
                client = await slack_client_dependency()
                if not client:
                    raise
                if isinstance(
                    e,
                    (
                        HTTPException,
                        RequestValidationError,
                        StarletteHTTPException,
                        SlackIgnoredException,
                    ),
                ):
                    raise
                await client.post_uncaught_exception(e)
                raise

        return wrapped_route_handler
