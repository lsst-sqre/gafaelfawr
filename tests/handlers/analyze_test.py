"""Tests for the ``/auth/analyze`` route."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

import pytest
from fastapi.encoders import jsonable_encoder

from gafaelfawr.models.token import Token
from tests.support.headers import query_from_url

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_analyze_no_auth(setup: SetupTest) -> None:
    r = await setup.client.get("/auth/analyze", allow_redirects=False)
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert not url.scheme
    assert not url.netloc
    assert url.path == "/login"
    assert query_from_url(r.headers["Location"]) == {
        "rd": ["https://example.com/auth/analyze"]
    }


@pytest.mark.asyncio
async def test_analyze_session(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    await setup.login(token_data.token)

    r = await setup.client.get("/auth/analyze")
    assert r.status_code == 200

    # Check that the result is formatted for humans.
    assert "    " in r.text
    assert '": "' in r.text

    assert r.json() == {
        "data": jsonable_encoder(token_data.dict()),
        "valid": True,
    }


@pytest.mark.asyncio
async def test_analyze_token(setup: SetupTest) -> None:
    token = Token()

    # Handle with no session.
    r = await setup.client.post("/auth/analyze", data={"token": str(token)})
    assert r.status_code == 200
    assert r.json() == {
        "data": {"token": token.dict()},
        "errors": ["Invalid token"],
        "valid": False,
    }

    # Valid token.
    token_data = await setup.create_session_token()
    token = token_data.token
    r = await setup.client.post("/auth/analyze", data={"token": str(token)})

    # Check that the results from /analyze include the handle, the session,
    # and the token information.
    assert r.status_code == 200
    analysis = r.json()
    assert analysis == {
        "data": jsonable_encoder(token_data.dict()),
        "valid": True,
    }
