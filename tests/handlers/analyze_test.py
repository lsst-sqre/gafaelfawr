"""Tests for the ``/auth/analyze`` route."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import urlparse

import pytest

from gafaelfawr.models.token import Token
from tests.support.headers import query_from_url

if TYPE_CHECKING:
    from httpx import AsyncClient

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_analyze_no_auth(client: AsyncClient, setup: SetupTest) -> None:
    r = await client.get("/auth/analyze")
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert not url.scheme
    assert not url.netloc
    assert url.path == "/login"
    assert query_from_url(r.headers["Location"]) == {
        "rd": ["https://example.com/auth/analyze"]
    }


@pytest.mark.asyncio
async def test_analyze_session(client: AsyncClient, setup: SetupTest) -> None:
    token_data = await setup.create_session_token(
        group_names=["foo", "bar"], scopes=["read:all"]
    )
    assert token_data.expires
    assert token_data.groups
    await setup.login(client, token_data.token)

    r = await client.get("/auth/analyze")
    assert r.status_code == 200

    # Check that the result is formatted for humans.
    assert "    " in r.text
    assert '": "' in r.text

    assert r.json() == {
        "token": {
            "data": {
                "exp": int(token_data.expires.timestamp()),
                "iat": int(token_data.created.timestamp()),
                "isMemberOf": [g.dict() for g in token_data.groups],
                "name": token_data.name,
                "scope": "read:all",
                "sub": token_data.username,
                "uid": token_data.username,
                "uidNumber": str(token_data.uid),
            },
            "valid": True,
        }
    }


@pytest.mark.asyncio
async def test_invalid_token(client: AsyncClient, setup: SetupTest) -> None:
    r = await client.post("/auth/analyze", data={"token": "some-token"})
    assert r.status_code == 200
    assert r.json() == {"token": {"errors": [ANY], "valid": False}}


@pytest.mark.asyncio
async def test_analyze_token(client: AsyncClient, setup: SetupTest) -> None:
    token = Token()

    # Handle with no session.
    r = await client.post("/auth/analyze", data={"token": str(token)})
    assert r.status_code == 200
    assert r.json() == {
        "handle": token.dict(),
        "token": {"errors": ["Invalid token"], "valid": False},
    }

    # Valid token.
    token_data = await setup.create_session_token(
        group_names=["foo", "bar"], scopes=["admin:token", "read:all"]
    )
    assert token_data.expires
    assert token_data.groups
    token = token_data.token
    r = await client.post("/auth/analyze", data={"token": str(token)})

    # Check that the results from /analyze include the token components and
    # the token information.
    assert r.status_code == 200
    assert r.json() == {
        "handle": token.dict(),
        "token": {
            "data": {
                "exp": int(token_data.expires.timestamp()),
                "iat": int(token_data.created.timestamp()),
                "isMemberOf": [g.dict() for g in token_data.groups],
                "name": token_data.name,
                "scope": "admin:token read:all",
                "sub": token_data.username,
                "uid": token_data.username,
                "uidNumber": str(token_data.uid),
            },
            "valid": True,
        },
    }

    # Create a session token with minimum data.
    token_data.name = None
    token_data.uid = None
    token_data.groups = None
    token_service = setup.factory.create_token_service()
    user_token = await token_service.create_user_token(
        token_data,
        token_data.username,
        token_name="foo",
        scopes=[],
        expires=None,
        ip_address="127.0.0.1",
    )
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data

    # Check that the correct fields are omitted and nothing odd happens.
    r = await client.post("/auth/analyze", data={"token": str(user_token)})
    assert r.status_code == 200
    assert r.json() == {
        "handle": user_token.dict(),
        "token": {
            "data": {
                "iat": int(user_token_data.created.timestamp()),
                "scope": "",
                "sub": user_token_data.username,
                "uid": user_token_data.username,
            },
            "valid": True,
        },
    }
