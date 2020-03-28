"""Tests for the /auth/tokens route."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

from jwt_authorizer.tokens import TokenStore
from tests.util import (
    RSAKeyPair,
    create_test_app,
    create_test_token,
    create_test_token_payload,
)

if TYPE_CHECKING:
    import redis


def test_tokens_no_auth() -> None:
    app = create_test_app()

    with app.test_client() as client:
        r = client.get("/auth/tokens", headers={"X-Auth-Request-Token": "foo"})
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"]


def test_tokens_empty_list(redis_client: redis.Redis) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair)
    app = create_test_app(keypair)

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            r = client.get(
                "/auth/tokens", headers={"X-Auth-Request-Token": token}
            )
        assert r.status_code == 200
        assert b"Generate new token" in r.data


def test_tokens(redis_client: redis.Redis) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair)
    scoped_token_payload = create_test_token_payload(
        scope="exec:test", jti="other-token"
    )
    app = create_test_app(keypair)
    token_store = TokenStore(redis_client, "uidNumber")
    with redis_client.pipeline() as pipeline:
        token_store.store_token(scoped_token_payload, pipeline)
        pipeline.execute()

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            r = client.get(
                "/auth/tokens", headers={"X-Auth-Request-Token": token}
            )
        assert r.status_code == 200
        assert b"other-token" in r.data
        assert b"exec:test" in r.data
