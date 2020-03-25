"""Tests for the /auth/tokens/<handle> route."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import jwt

from jwt_authorizer import config
from jwt_authorizer.session import Session, SessionStore, Ticket
from jwt_authorizer.tokens import TokenStore
from tests.util import (
    RSAKeyPair,
    create_test_app,
    create_test_token,
    create_test_token_payload,
)

if TYPE_CHECKING:
    import redis


def test_tokens_handle_no_auth() -> None:
    app = create_test_app()

    with app.test_client() as client:
        r = client.get(
            "/auth/tokens/blah", headers={"X-Auth-Request-Token": "foo"}
        )
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"]


def test_tokens_handle_get_delete(redis_client: redis.Redis) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair)
    session_secret = os.urandom(16)
    app = create_test_app(keypair, session_secret)

    ticket = Ticket()
    scoped_token_payload = create_test_token_payload(
        scope="exec:test", jti=ticket.as_handle("oauth2_proxy")
    )
    scoped_token = jwt.encode(
        scoped_token_payload,
        keypair.private_key_as_pem(),
        algorithm=config.ALGORITHM,
        headers={"kid": "some-kid"},
    ).decode()
    session = Session(
        token=scoped_token,
        email="some-user@example.com",
        user="some-user@example.com",
        created_at=datetime.now(timezone.utc),
        expires_on=datetime.now(timezone.utc) + timedelta(days=1),
    )

    session_store = SessionStore("oauth2_proxy", session_secret, redis_client)
    token_store = TokenStore(redis_client, "uidNumber")
    with redis_client.pipeline() as pipeline:
        session_store.store_session(ticket, session, pipeline)
        token_store.store_token(scoped_token_payload, pipeline)
        pipeline.execute()

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            handle = ticket.as_handle("oauth2_proxy")
            r = client.get(
                f"/auth/tokens/{handle}",
                headers={"X-Auth-Request-Token": token},
            )
            assert r.status_code == 200
            assert handle.encode() in r.data

            r = client.post(
                f"/auth/tokens/{handle}",
                headers={"X-Auth-Request-Token": token},
                data={"method_": "DELETE"},
                follow_redirects=True,
            )
            assert r.status_code == 200
            msg = f"token with the ticket_id {handle} was deleted"
            assert msg.encode() in r.data

    assert token_store.get_tokens("1000") == []
