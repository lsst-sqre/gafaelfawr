"""Tests multiple simultaneous /auth requests.

These tests are intended to catch problems with excessive database load or
deadlocking when processing numerous requests that require subtokens or some
other potentially expensive or coordinated action.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from gafaelfawr.models.token import Token

if TYPE_CHECKING:
    from httpx import AsyncClient

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_notebook(client: AsyncClient, setup: SetupTest) -> None:
    data = await setup.create_session_token(scopes=["exec:test", "read:all"])
    await setup.login(client, data.token)

    request_awaits = []
    for _ in range(100):
        request_awaits.append(
            client.get(
                "/auth", params={"scope": "exec:test", "notebook": "true"}
            )
        )
    responses = await asyncio.gather(*request_awaits)
    assert responses[0].status_code == 200
    token = Token.from_str(responses[0].headers["X-Auth-Request-Token"])
    for r in responses:
        assert r.status_code == 200
        assert Token.from_str(r.headers["X-Auth-Request-Token"]) == token


@pytest.mark.asyncio
async def test_internal(client: AsyncClient, setup: SetupTest) -> None:
    data = await setup.create_session_token(scopes=["exec:test", "read:all"])
    await setup.login(client, data.token)

    request_awaits = []
    for _ in range(100):
        request_awaits.append(
            client.get(
                "/auth",
                params={
                    "scope": "exec:test",
                    "delegate_to": "a-service",
                    "delegate_scope": "read:all",
                },
            )
        )
    responses = await asyncio.gather(*request_awaits)
    assert responses[0].status_code == 200
    token = Token.from_str(responses[0].headers["X-Auth-Request-Token"])
    for r in responses:
        assert r.status_code == 200
        assert Token.from_str(r.headers["X-Auth-Request-Token"]) == token

    request_awaits = []
    for _ in range(100):
        request_awaits.append(
            client.get(
                "/auth",
                params={
                    "scope": "exec:test",
                    "delegate_to": "a-service",
                    "delegate_scope": "exec:test",
                },
            )
        )
    responses = await asyncio.gather(*request_awaits)
    assert responses[0].status_code == 200
    new_token = Token.from_str(responses[0].headers["X-Auth-Request-Token"])
    assert new_token != token
    for r in responses:
        assert r.status_code == 200
        assert Token.from_str(r.headers["X-Auth-Request-Token"]) == new_token
