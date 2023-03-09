"""Send alerts to Slack."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any, Optional

from fastapi import HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from safir.datetime import current_datetime
from safir.dependencies.http_client import http_client_dependency
from starlette.exceptions import HTTPException as StarletteHTTPException
from structlog.stdlib import BoundLogger

SLACK_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
"""Date format to use for dates in Slack alerts."""

_slack_alert_client: Optional[SlackAlertClient] = None

__all__ = [
    "SlackAlertClient",
    "SlackIgnoredException",
    "SlackRouteErrorHandler",
    "initialize_slack_alerts",
]


class SlackIgnoredException(Exception):
    """Parent class for exceptions that should not be reported to Slack.

    This exception has no built-in behavior or meaning except to suppress
    Slack notifications if it is thrown uncaught.  Application exceptions that
    should not result in a Slack alert (because, for example, they're intended
    to be caught by exception handlers) should inherit from this class.
    """


class SlackAlertClient:
    """Publish alerts to Slack.

    Use an incoming webhook to publish an alert to a Slack channel.

    Parameters
    ----------
    hook_url
        The URL of the incoming webhook to use to publish the message.
    application
        Name of the application reporting an error.
    logger
        Logger to which to report errors sending messages to Slack.
    """

    def __init__(
        self, hook_url: str, application: str, logger: BoundLogger
    ) -> None:
        self._hook_url = hook_url
        self._application = application
        self._logger = logger

    async def message(self, message: str) -> None:
        """Post a Markdown message to Slack.

        Slack limits the main section of the message to 3000 characters.  It
        will be truncated if longer than that.

        Parameters
        ----------
        message
            The message to post, in Markdown format.
        """
        if len(message) > 3000:
            last_newline = message.rfind("\n", 0, 2950)
            if last_newline == -1:
                message = message[:3000]
            else:
                message = message[:last_newline] + "\n... truncated ...\n"
        alert = {
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message},
                }
            ]
        }
        await self._post(alert)

    async def uncaught_exception(self, exc: Exception) -> None:
        """Post an alert to Slack about an uncaught webapp exception.

        Parameters
        ----------
        exc
            The exception to report.
        """
        date = current_datetime().strftime(SLACK_DATE_FORMAT)
        error = f"{type(exc).__name__}: {str(exc)}"
        alert = {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Uncaught exception in {self._application}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Failed at*\n{date}"}
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Exception*\n```\n{error}\n```",
                        "verbatim": True,
                    },
                },
                {"type": "divider"},
            ]
        }
        await self._post(alert)

    async def _post(self, alert: dict[str, Any]) -> None:
        """Send an alert to Slack."""
        self._logger.debug("Sending alert to Slack")
        try:
            client = await http_client_dependency()
            r = await client.post(self._hook_url, json=alert)
            r.raise_for_status()
        except Exception:
            msg = "Posting Slack alert failed"
            self._logger.exception(msg, alert=alert)


class SlackRouteErrorHandler(APIRoute):
    """Custom `fastapi.routing.APIRoute` that reports exceptions to Slack.

    Dynamically wrap FastAPI route handlers in an exception handler that
    reports uncaught exceptions (other than :exc:`fastapi.HTTPException`,
    :exc:`fastapi.exceptions.RequestValidationError`,
    :exc:`starlette.exceptions.HTTPException`, and exceptions inheriting from
    `SlackIgnoredException`) to Slack.

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
                if not _slack_alert_client:
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
                await _slack_alert_client.uncaught_exception(e)
                raise

        return wrapped_route_handler


def initialize_slack_alerts(
    hook_url: str, application: str, logger: BoundLogger
) -> None:
    """Configure Slack alerting.

    Until this function is called, all Slack alerting will be disabled.

    Parameters
    ----------
    hook_url
        The URL of the incoming webhook to use to publish the message.
    application
        Name of the application reporting an error.
    logger
        Logger to which to report errors sending messages to Slack.
    """
    global _slack_alert_client
    _slack_alert_client = SlackAlertClient(hook_url, application, logger)
