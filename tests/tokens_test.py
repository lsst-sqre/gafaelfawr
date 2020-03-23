"""Tests for the jwt_authorizer.tokens package."""

from __future__ import annotations

import base64
import os
import time
from unittest.mock import ANY

import fakeredis
import jwt

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.session import SessionStore, Ticket
from jwt_authorizer.tokens import issue_token
from tests.util import RSAKeyPair, create_test_app


def test_issue_token() -> None:
    payload = {
        "aud": "https://test.example.com/",
        "email": "some-user@example.com",
        "iss": "https://orig.example.com/",
        "jti": "some-unique-id",
        "sub": "some-user",
        "uidNumber": "1000",
    }
    ticket = Ticket()
    keypair = RSAKeyPair()
    session_secret = os.urandom(16)
    app = create_test_app(
        OAUTH2_JWT={
            "ISS": "https://test.example.com/",
            "KEY": keypair.private_key_as_pem(),
            "KEY_ID": "1",
        },
        OAUTH2_STORE_SESSION={
            "OAUTH2_PROXY_SECRET": base64.urlsafe_b64encode(session_secret),
            "TICKET_PREFIX": "oauth2_proxy",
        },
    )
    redis = fakeredis.FakeRedis()

    with app.app_context():
        token = issue_token(
            payload, "https://example.com/", False, ticket, redis
        )

    assert jwt.get_unverified_header(token) == {
        "alg": ALGORITHM,
        "typ": "JWT",
        "kid": "1",
    }

    decoded_token = jwt.decode(
        token,
        keypair.public_key_as_pem(),
        algorithms=ALGORITHM,
        audience="https://example.com/",
    )
    assert decoded_token
    assert decoded_token == {
        "act": {
            "aud": "https://test.example.com/",
            "iss": "https://orig.example.com/",
            "jti": "some-unique-id",
        },
        "aud": "https://example.com/",
        "email": "some-user@example.com",
        "exp": ANY,
        "iat": ANY,
        "iss": "https://test.example.com/",
        "jti": ticket.as_handle("oauth2_proxy"),
        "sub": "some-user",
        "uidNumber": "1000",
    }
    now = time.time()
    expected_exp = now + app.config["OAUTH2_JWT_EXP"] * 60
    assert expected_exp - 5 <= decoded_token["exp"] <= expected_exp + 5
    assert now - 5 <= decoded_token["iat"] <= now + 5

    session_store = SessionStore("oauth2_proxy", session_secret, redis)
    session = session_store.get_session(ticket)
    assert session
    assert session.token == token
    assert session.email == "some-user@example.com"
    assert session.user == "some-user@example.com"
    assert now - 5 <= session.created_at.timestamp() <= now + 5
    assert session.expires_on.timestamp() == decoded_token["exp"]
