"""Send alerts to Slack."""

from __future__ import annotations

from typing import Any

from safir.datetime import current_datetime
from safir.dependencies.http_client import http_client_dependency
from structlog.stdlib import BoundLogger

_SLACK_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
"""Date format to use for dates in Slack alerts."""

__all__ = [
    "SlackClient",
    "SlackIgnoredException",
]


class SlackIgnoredException(Exception):
    """Parent class for exceptions that should not be reported to Slack.

    This exception has no built-in behavior or meaning except to suppress
    Slack notifications if it is thrown uncaught.  Application exceptions that
    should not result in a Slack alert (because, for example, they're intended
    to be caught by exception handlers) should inherit from this class.
    """


class SlackClient:
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
        date = current_datetime().strftime(_SLACK_DATE_FORMAT)
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
