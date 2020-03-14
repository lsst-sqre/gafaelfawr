"""Tests for the /analyze route."""

from __future__ import annotations

import base64
import os
import time
from datetime import datetime
from unittest.mock import ANY, call, patch

import fakeredis
import jwt

from jwt_authorizer.tokens import ALGORITHM, Ticket, issue_token
from tests.util import RSAKeyPair, create_test_app


def test_analyze_ticket() -> None:
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
        ISSUERS={
            "https://test.example.com/": {
                "audience": "https://example.com/",
                "issuer_key_ids": ["some-kid"],
            },
        },
        OAUTH2_JWT={
            "ISS": "https://test.example.com/",
            "KEY": keypair.private_key_as_pem(),
            "KEY_ID": "some-kid",
        },
        OAUTH2_STORE_SESSION={
            "OAUTH2_PROXY_SECRET": base64.urlsafe_b64encode(session_secret),
            "TICKET_PREFIX": "oauth2_proxy",
        },
    )
    redis = fakeredis.FakeRedis()

    # To test, we need a valid ticket.  The existing code path that creates
    # one is the code path that reissues a JWT based on one from an external
    # authentication source.  Run that code path, replacing Redis with our
    # fakeredis instance and intercepting the call that attempts to retrieve
    # the public key from a remote server (while checking that it was called
    # correctly).
    #
    # Then, post the resulting ticket to the /analyze endpoint.
    with app.app_context():
        issue_token(payload, "https://example.com/", False, ticket, redis)
        with patch(
            "jwt_authorizer.tokens.get_key_as_pem"
        ) as get_key_as_pem, patch(
            "jwt_authorizer.tokens.get_redis_client"
        ) as get_redis_client:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            get_redis_client.return_value = redis
            with app.test_client() as client:
                response = client.post(
                    "/auth/analyze",
                    data={"token": ticket.encode("oauth2_proxy")},
                )
            assert get_key_as_pem.call_args_list == [
                call("https://test.example.com/", "some-kid")
            ]

    # Check that the results from /analyze include the ticket, the session,
    # and the token information.
    assert response.status_code == 200
    analysis = response.get_json()
    assert analysis == {
        "ticket": {
            "ticket_id": ticket.ticket_id,
            "secret": base64.urlsafe_b64encode(ticket.secret).decode(),
        },
        "session": {
            "email": "some-user@example.com",
            "user": "some-user@example.com",
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {"alg": ALGORITHM, "typ": "JWT", "kid": "some-kid"},
            "data": {
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
            },
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
    assert expires_on.timestamp() == analysis["token"]["data"]["exp"]


def test_analyze_token() -> None:
    payload = {
        "aud": "https://test.example.com/",
        "email": "some-user@example.com",
        "iss": "https://orig.example.com/",
        "jti": "some-unique-id",
        "sub": "some-user",
        "uidNumber": "1000",
    }
    keypair = RSAKeyPair()
    app = create_test_app(
        ISSUERS={
            "https://orig.example.com/": {
                "audience": "https://test.example.com/",
                "issuer_key_ids": ["some-kid"],
            },
        },
        OAUTH2_STORE_SESSION={"TICKET_PREFIX": "oauth2_proxy"},
    )

    # Generate a token that we can analyze.
    token = jwt.encode(
        payload,
        keypair.private_key_as_pem(),
        algorithm=ALGORITHM,
        headers={"kid": "some-kid"},
    )

    # Analyze it, patching out the call to retrieve the public key from a
    # remote web site (but making sure that it was called correctly).
    with app.app_context():
        with patch("jwt_authorizer.tokens.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            with app.test_client() as client:
                response = client.post("/auth/analyze", data={"token": token})
            assert get_key_as_pem.call_args_list == [
                call("https://orig.example.com/", "some-kid")
            ]

    assert response.status_code == 200
    assert response.get_json() == {
        "token": {
            "header": jwt.get_unverified_header(token),
            "data": payload,
            "valid": True,
        },
    }
