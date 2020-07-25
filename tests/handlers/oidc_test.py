"""Tests for the /auth/openid routes."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

from gafaelfawr.config import OIDCClient
from gafaelfawr.providers.github import GitHubUserInfo
from gafaelfawr.session import SessionHandle
from gafaelfawr.tokens import Token

if TYPE_CHECKING:
    from tests.setup import SetupTestCallable


async def test_login(create_test_setup: SetupTestCallable) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    setup = await create_test_setup(oidc_clients=clients)
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[],
    )
    await setup.github_login(userinfo)

    # Log in
    return_url = f"https://{setup.client.host}:4444/foo?a=bar&b=baz"
    r = await setup.client.get(
        "/auth/openid/login",
        params={
            "response_type": "code",
            "scope": "openid",
            "client_id": "some-id",
            "state": "random-state",
            "redirect_uri": return_url,
        },
        allow_redirects=False,
    )
    assert r.status == 302
    url = urlparse(r.headers["Location"])
    assert url.scheme == "https"
    assert url.netloc == f"{setup.client.host}:4444"
    assert url.path == "/foo"
    assert url.query
    query = parse_qs(url.query)
    assert query == {
        "a": ["bar"],
        "b": ["baz"],
        "code": [ANY],
        "state": ["random-state"],
    }
    code = query["code"][0]

    # Redeem the code for a token and check the result.
    r = await setup.client.post(
        "/auth/openid/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "some-id",
            "client_secret": "some-secret",
            "code": code,
            "redirect_uri": return_url,
        },
    )
    assert r.status == 200
    data = await r.json()
    assert data == {
        "access_token": ANY,
        "token_type": "Bearer",
        "expires_in": ANY,
        "id_token": ANY,
    }
    assert data["access_token"] == data["id_token"]
    verifier = setup.factory.create_token_verifier()
    token = verifier.verify_internal_token(Token(encoded=data["id_token"]))
    expected_claims = {
        "act": {
            "aud": setup.config.issuer.aud,
            "iss": setup.config.issuer.iss,
            "jti": ANY,
        },
        "aud": setup.config.issuer.aud_internal,
        "email": "githubuser@example.com",
        "exp": ANY,
        "iat": ANY,
        "iss": setup.config.issuer.iss,
        "jti": SessionHandle.from_str(code).key,
        "name": "GitHub User",
        "scope": "openid",
        "sub": "githubuser",
        "uid": "githubuser",
        "uidNumber": "123456",
    }
    assert token.claims == expected_claims
    now = time.time()
    expected_exp = now + setup.config.issuer.exp_minutes * 60
    assert expected_exp - 5 <= token.claims["exp"] <= expected_exp
    assert now - 5 <= token.claims["iat"] <= now

    # Test the user information endpoint.
    r = await setup.client.get(
        "/auth/openid/userinfo",
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 200
    data = await r.json()
    assert data == expected_claims
