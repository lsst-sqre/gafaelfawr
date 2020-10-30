"""Tests for the ``/auth/analyze`` route."""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import urlparse

import jwt
import pytest

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.session import Session, SessionHandle
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
    token = setup.create_token()
    await setup.login(token)

    r = await setup.client.get("/auth/analyze")
    assert r.status_code == 200

    # Check that the result is formatted for humans.
    assert "    " in r.text
    assert '": "' in r.text

    assert r.json() == {
        "handle": {"key": ANY, "secret": ANY},
        "session": {
            "email": token.email,
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {
                "alg": ALGORITHM,
                "typ": "JWT",
                "kid": setup.config.issuer.kid,
            },
            "data": token.claims,
            "valid": True,
        },
    }


@pytest.mark.asyncio
async def test_analyze_handle(setup: SetupTest) -> None:
    handle = SessionHandle()

    # Handle with no session.
    r = await setup.client.post(
        "/auth/analyze", data={"token": handle.encode()}
    )
    assert r.status_code == 200
    assert r.json() == {
        "handle": {"key": handle.key, "secret": handle.secret},
        "errors": [f"No session found for {handle.encode()}"],
    }

    # Valid session handle.
    token = setup.create_token(groups=["admin"], jti=handle.key)
    session = Session.create(handle, token)
    session_store = setup.factory.create_session_store()
    await session_store.store_session(session)
    r = await setup.client.post(
        "/auth/analyze", data={"token": handle.encode()}
    )

    # Check that the results from /analyze include the handle, the session,
    # and the token information.
    assert r.status_code == 200
    analysis = r.json()
    assert analysis == {
        "handle": {"key": handle.key, "secret": handle.secret},
        "session": {
            "email": token.email,
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {
                "alg": ALGORITHM,
                "typ": "JWT",
                "kid": setup.config.issuer.kid,
            },
            "data": token.claims,
            "valid": True,
        },
    }
    created_at = datetime.strptime(
        analysis["session"]["created_at"], "%Y-%m-%d %H:%M:%S %z"
    )
    expires_on = datetime.strptime(
        analysis["session"]["expires_on"], "%Y-%m-%d %H:%M:%S %z"
    )

    now = time.time()
    assert now - 5 <= created_at.timestamp() <= now + 5
    assert int(expires_on.timestamp()) == analysis["token"]["data"]["exp"]


@pytest.mark.asyncio
async def test_analyze_token(setup: SetupTest) -> None:
    token = setup.create_token()
    r = await setup.client.post("/auth/analyze", data={"token": token.encoded})
    assert r.status_code == 200
    assert r.json() == {
        "token": {
            "header": jwt.get_unverified_header(token.encoded),
            "data": token.claims,
            "valid": True,
        },
    }
