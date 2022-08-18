"""Test Slack alerting."""

from __future__ import annotations

from unittest.mock import ANY

import pytest
from fastapi import APIRouter, FastAPI
from httpx import ASGITransport, AsyncClient

from gafaelfawr.config import Config
from gafaelfawr.slack import SlackRouteErrorHandler

from .support.constants import TEST_HOSTNAME
from .support.slack import MockSlack


@pytest.mark.asyncio
async def test_uncaught_exception(
    app: FastAPI, client: AsyncClient, config: Config, mock_slack: MockSlack
) -> None:
    """Test Slack alerts for uncaught exceptions."""
    router = APIRouter(route_class=SlackRouteErrorHandler)

    @router.get("/exception")
    async def get_exception() -> None:
        raise ValueError("Test exception")

    app.include_router(router)

    # We need a custom httpx configuration to disable raising server
    # exceptions so that we can inspect the resulting error handling.
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    base_url = f"https://{TEST_HOSTNAME}"
    async with AsyncClient(transport=transport, base_url=base_url) as client:
        r = await client.get("/exception")
        assert r.status_code == 500

    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "Uncaught exception in Gafaelfawr",
                    },
                },
                {
                    "type": "section",
                    "fields": [{"type": "mrkdwn", "text": ANY}],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*Exception*\n```\n"
                            "ValueError: Test exception\n```"
                        ),
                        "verbatim": True,
                    },
                },
                {"type": "divider"},
            ]
        }
    ]
    assert mock_slack.messages[0]["blocks"][1]["fields"][0]["text"].startswith(
        "*Failed at*\n"
    )
