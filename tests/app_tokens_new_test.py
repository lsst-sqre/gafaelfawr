"""Tests for the /auth/tokens/new route."""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING
from unittest.mock import ANY, patch

import jwt

from jwt_authorizer import config
from jwt_authorizer.session import SessionStore, Ticket
from jwt_authorizer.tokens import TokenStore
from tests.util import RSAKeyPair, create_test_app, create_test_token

if TYPE_CHECKING:
    import redis


def test_tokens_new_no_auth() -> None:
    app = create_test_app()

    with app.test_client() as client:
        r = client.get(
            "/auth/tokens/new", headers={"X-Auth-Request-Token": "foo"}
        )
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"]


def test_tokens_new_form() -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["admin"])
    app = create_test_app(keypair)

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            r = client.get(
                "/auth/tokens/new", headers={"X-Auth-Request-Token": token}
            )
        assert r.status_code == 200
        assert b"exec:admin" in r.data
        assert b"read:all" in r.data
        assert b"admin description" in r.data
        assert b"can read everything" in r.data


def test_tokens_new_create(redis_client: redis.Redis) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["admin"])
    session_secret = os.urandom(16)
    app = create_test_app(keypair, session_secret)

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            r = client.post(
                "/auth/tokens/new",
                headers={"X-Auth-Request-Token": token},
                data={"read:all": "y"},
                follow_redirects=True,
            )
        assert r.status_code == 200
        body = r.data.decode()
        assert "read:all" in body
        match = re.search(r"Token: (\S+)", body)
        assert match
        encoded_ticket = match.group(1)

    token_store = TokenStore(redis_client, "uidNumber")
    tokens = token_store.get_tokens("1000")
    assert len(tokens) == 1
    assert tokens[0] == {
        "aud": "https://example.com/",
        "email": "some-user@example.com",
        "exp": ANY,
        "iat": ANY,
        "iss": "https://test.example.com/",
        "jti": ANY,
        "scope": "read:all",
        "uid": "some-user",
        "uidNumber": "1000",
    }

    # The new token should also appear on the list we were redirected to.
    assert tokens[0]["jti"].encode() in r.data

    session_store = SessionStore("oauth2_proxy", session_secret, redis_client)
    ticket = Ticket.from_str("oauth2_proxy", encoded_ticket)
    session = session_store.get_session(ticket)
    assert session
    assert session.email == "some-user@example.com"
    assert session.user == "some-user@example.com"
    assert int(session.expires_on.timestamp()) == tokens[0]["exp"]

    token = jwt.decode(
        session.token,
        keypair.public_key_as_pem(),
        algorithms=config.ALGORITHM,
        audience="https://example.com/",
    )
    assert tokens[0] == token
