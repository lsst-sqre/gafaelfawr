"""Client for reporting problems to Slack."""

from typing import Optional

from structlog.stdlib import BoundLogger

from ..slack import SlackClient

__all__ = [
    "SlackClientDependency",
    "slack_client_dependency",
]


class SlackClientDependency:
    """Provide an optional global Slack client for alert reporting.

    This client is available in the request context for individual handlers to
    report problems, and is used by `~gafaelfawr.route.SlackRouteErrorHandler`
    to report uncaught exceptions.
    """

    def __init__(self) -> None:
        self._slack_client: Optional[SlackClient] = None

    async def __call__(self) -> SlackClient | None:
        """Returns the Slack client if one is available."""
        return self._slack_client

    def initialize(
        self, hook_url: str, application: str, logger: BoundLogger
    ) -> None:
        """Configure the Slack client.

        Until this function is called, all Slack messaging will be disabled.

        Parameters
        ----------
        hook_url
            The URL of the incoming webhook to use to publish the message.
        application
            Name of the application sending the Slack message.
        logger
            Logger to which to report errors sending messages to Slack.
        """
        self._slack_client = SlackClient(hook_url, application, logger)


slack_client_dependency = SlackClientDependency()
"""The dependency that caches the Slack client."""
