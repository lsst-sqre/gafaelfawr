"""Tests multiple simultaneous /auth requests.

These tests are intended to catch problems with excessive database load or
deadlocking when processing numerous requests that require subtokens or some
other potentially expensive or coordinated action.
"""

from __future__ import annotations

import asyncio

import pytest
from httpx import AsyncClient

from gafaelfawr.factory import Factory
from gafaelfawr.models.token import Token

from ..support.cookies import set_session_cookie
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_notebook(client: AsyncClient, factory: Factory) -> None:
    data = await create_session_token(
        factory, scopes=["exec:test", "read:all"]
    )
    await set_session_cookie(client, data.token)

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
async def test_internal(client: AsyncClient, factory: Factory) -> None:
    data = await create_session_token(
        factory, scopes=["exec:test", "read:all"]
    )
    await set_session_cookie(client, data.token)

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
