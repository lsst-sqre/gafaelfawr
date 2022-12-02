"""Mock Slack server for testing alerts."""

from __future__ import annotations

import json
from typing import Any, Dict

import respx
from httpx import Request, Response

__all__ = ["MockSlack", "mock_slack_webhook"]


class MockSlack:
    """Represents a Slack incoming webhook and remembers what was posted.

    Attributes
    ----------
    messages
        The messages that have been posted to the webhook so far.
    """

    def __init__(self) -> None:
        self.messages: list[Dict[str, Any]] = []

    def post_webhook(self, request: Request) -> Response:
        """Callback called whenever a Slack message is posted.

        The provided message is stored in the messages attribute.

        Parameters
        ----------
        request : `httpx.Request`
            Incoming request.

        Returns
        -------
        response : `httpx.Response`
            Always returns a 201 response.
        """
        self.messages.append(json.loads(request.content.decode()))
        return Response(201)


def mock_slack_webhook(hook_url: str, respx_mock: respx.Router) -> MockSlack:
    """Set up a mocked Slack server.

    Parameters
    ----------
    hook_url
        URL for the Slack incoming webhook to mock.
    respx_mock
        The mock router.

    Returns
    -------
    MockSlack
        The mock Slack API object.
    """
    mock = MockSlack()
    respx_mock.post(hook_url).mock(side_effect=mock.post_webhook)
    return mock
