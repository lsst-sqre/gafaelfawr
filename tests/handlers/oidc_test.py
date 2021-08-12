"""Tests for the /auth/openid routes."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from gafaelfawr.auth import AuthError, AuthErrorChallenge, AuthType
from gafaelfawr.config import OIDCClient
from gafaelfawr.constants import ALGORITHM
from gafaelfawr.models.oidc import OIDCAuthorizationCode, OIDCToken
from gafaelfawr.util import number_to_base64
from tests.support.constants import TEST_HOSTNAME
from tests.support.headers import parse_www_authenticate, query_from_url
from tests.support.logging import parse_log

if TYPE_CHECKING:
    from typing import Dict

    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_login(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    await setup.configure(oidc_clients=clients)
    token_data = await setup.create_session_token()
    await setup.login(token_data.token)
    return_url = f"https://{TEST_HOSTNAME}:4444/foo?a=bar&b=baz"

    # Log in
    caplog.clear()
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
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert url.scheme == "https"
    assert url.netloc == f"{TEST_HOSTNAME}:4444"
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

    assert parse_log(caplog) == [
        {
            "event": "Returned OpenID Connect authorization code",
            "level": "info",
            "method": "GET",
            "path": "/auth/openid/login",
            "remote": "127.0.0.1",
            "return_url": return_url,
            "scope": "user:token",
            "token": token_data.token.key,
            "token_source": "cookie",
            "user": token_data.username,
        }
    ]

    # Redeem the code for a token and check the result.
    caplog.clear()
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
    assert r.status_code == 200
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["Pragma"] == "no-cache"
    data = r.json()
    assert data == {
        "access_token": ANY,
        "token_type": "Bearer",
        "expires_in": ANY,
        "id_token": ANY,
    }
    assert isinstance(data["expires_in"], int)
    exp_seconds = setup.config.issuer.exp_minutes * 60
    assert exp_seconds - 5 <= data["expires_in"] <= exp_seconds

    assert data["access_token"] == data["id_token"]
    verifier = setup.factory.create_token_verifier()
    token = verifier.verify_internal_token(OIDCToken(encoded=data["id_token"]))
    assert token.claims == {
        "aud": setup.config.issuer.aud,
        "exp": ANY,
        "iat": ANY,
        "iss": setup.config.issuer.iss,
        "jti": OIDCAuthorizationCode.from_str(code).key,
        "name": token_data.name,
        "preferred_username": token_data.username,
        "scope": "openid",
        "sub": token_data.username,
        setup.config.issuer.username_claim: token_data.username,
        setup.config.issuer.uid_claim: token_data.uid,
    }
    now = time.time()
    expected_exp = now + setup.config.issuer.exp_minutes * 60
    assert expected_exp - 5 <= token.claims["exp"] <= expected_exp
    assert now - 5 <= token.claims["iat"] <= now

    username = token_data.username
    assert parse_log(caplog) == [
        {
            "event": f"Retrieved token for user {username} via OpenID Connect",
            "level": "info",
            "method": "POST",
            "path": "/auth/openid/token",
            "remote": "127.0.0.1",
            "token": OIDCAuthorizationCode.from_str(code).key,
            "user": username,
        }
    ]


@pytest.mark.asyncio
async def test_unauthenticated(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    await setup.configure(oidc_clients=clients)
    return_url = f"https://{TEST_HOSTNAME}:4444/foo?a=bar&b=baz"
    login_params = {
        "response_type": "code",
        "scope": "openid",
        "client_id": "some-id",
        "state": "random-state",
        "redirect_uri": return_url,
    }

    caplog.clear()
    r = await setup.client.get(
        "/auth/openid/login", params=login_params, allow_redirects=False
    )

    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert not url.scheme
    assert not url.netloc
    assert url.path == "/login"
    params = urlencode(login_params)
    expected_url = f"https://{TEST_HOSTNAME}/auth/openid/login?{params}"
    assert query_from_url(r.headers["Location"]) == {"rd": [str(expected_url)]}

    assert parse_log(caplog) == [
        {
            "event": "Redirecting user for authentication",
            "level": "info",
            "method": "GET",
            "path": "/auth/openid/login",
            "remote": "127.0.0.1",
            "return_url": return_url,
        }
    ]


@pytest.mark.asyncio
async def test_login_errors(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    await setup.configure(oidc_clients=clients)
    token_data = await setup.create_session_token()
    await setup.login(token_data.token)

    # No parameters at all.
    r = await setup.client.get("/auth/openid/login", allow_redirects=False)
    assert r.status_code == 422

    # Good client ID but missing redirect_uri.
    login_params = {"client_id": "some-id"}
    r = await setup.client.get(
        "/auth/openid/login", params=login_params, allow_redirects=False
    )
    assert r.status_code == 422

    # Bad client ID.
    caplog.clear()
    login_params = {
        "client_id": "bad-client",
        "redirect_uri": f"https://{TEST_HOSTNAME}/",
    }
    r = await setup.client.get(
        "/auth/openid/login", params=login_params, allow_redirects=False
    )
    assert r.status_code == 400
    assert "Unknown client_id bad-client" in r.text

    assert parse_log(caplog) == [
        {
            "error": "Unknown client_id bad-client in OpenID Connect request",
            "event": "Invalid request",
            "level": "warning",
            "method": "GET",
            "path": "/auth/openid/login",
            "remote": "127.0.0.1",
            "return_url": f"https://{TEST_HOSTNAME}/",
            "scope": "user:token",
            "token": ANY,
            "token_source": "cookie",
            "user": token_data.username,
        }
    ]

    # Bad redirect_uri.
    login_params["client_id"] = "some-id"
    login_params["redirect_uri"] = "https://foo.example.com/"
    r = await setup.client.get(
        "/auth/openid/login", params=login_params, allow_redirects=False
    )
    assert r.status_code == 422
    assert "URL is not at" in r.text

    # Valid redirect_uri but missing response_type.
    login_params["redirect_uri"] = f"https://{TEST_HOSTNAME}/app"
    caplog.clear()
    r = await setup.client.get(
        "/auth/openid/login", params=login_params, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert url.scheme == "https"
    assert url.netloc == TEST_HOSTNAME
    assert url.path == "/app"
    assert url.query
    query = parse_qs(url.query)
    assert query == {
        "error": ["invalid_request"],
        "error_description": ["Missing response_type parameter"],
    }

    assert parse_log(caplog) == [
        {
            "error": "Missing response_type parameter",
            "event": "Invalid request",
            "level": "warning",
            "method": "GET",
            "path": "/auth/openid/login",
            "remote": "127.0.0.1",
            "return_url": login_params["redirect_uri"],
            "scope": "user:token",
            "token": ANY,
            "token_source": "cookie",
            "user": token_data.username,
        }
    ]

    # Invalid response_type.
    login_params["response_type"] = "bogus"
    r = await setup.client.get(
        "/auth/openid/login", params=login_params, allow_redirects=False
    )
    assert r.status_code == 307
    assert query_from_url(r.headers["Location"]) == {
        "error": ["invalid_request"],
        "error_description": ["code is the only supported response_type"],
    }

    # Valid response_type but missing scope.
    login_params["response_type"] = "code"
    r = await setup.client.get(
        "/auth/openid/login", params=login_params, allow_redirects=False
    )
    assert r.status_code == 307
    assert query_from_url(r.headers["Location"]) == {
        "error": ["invalid_request"],
        "error_description": ["Missing scope parameter"],
    }

    # Invalid scope.
    login_params["scope"] = "user:email"
    r = await setup.client.get(
        "/auth/openid/login", params=login_params, allow_redirects=False
    )
    assert r.status_code == 307
    assert query_from_url(r.headers["Location"]) == {
        "error": ["invalid_request"],
        "error_description": ["openid is the only supported scope"],
    }


@pytest.mark.asyncio
async def test_token_errors(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    clients = [
        OIDCClient(client_id="some-id", client_secret="some-secret"),
        OIDCClient(client_id="other-id", client_secret="other-secret"),
    ]
    await setup.configure(oidc_clients=clients)
    token_data = await setup.create_session_token()
    token = token_data.token
    oidc_service = setup.factory.create_oidc_service()
    redirect_uri = f"https://{TEST_HOSTNAME}/app"
    code = await oidc_service.issue_code("some-id", redirect_uri, token)

    # Missing parameters.
    request: Dict[str, str] = {}
    caplog.clear()
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_request",
        "error_description": "Invalid token request",
    }

    assert parse_log(caplog) == [
        {
            "error": "Invalid token request",
            "event": "Invalid request",
            "level": "warning",
            "method": "POST",
            "path": "/auth/openid/token",
            "remote": "127.0.0.1",
        }
    ]

    # Invalid grant type.
    request = {
        "grant_type": "bogus",
        "client_id": "other-client",
        "code": "nonsense",
        "redirect_uri": f"https://{TEST_HOSTNAME}/",
    }
    caplog.clear()
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "unsupported_grant_type",
        "error_description": "Invalid grant type bogus",
    }

    assert parse_log(caplog) == [
        {
            "error": "Invalid grant type bogus",
            "event": "Unsupported grant type",
            "level": "warning",
            "method": "POST",
            "path": "/auth/openid/token",
            "remote": "127.0.0.1",
        }
    ]

    # Invalid code.
    request["grant_type"] = "authorization_code"
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # No client_secret.
    request["code"] = str(OIDCAuthorizationCode())
    caplog.clear()
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_client",
        "error_description": "No client_secret provided",
    }

    assert parse_log(caplog) == [
        {
            "error": "No client_secret provided",
            "event": "Unauthorized client",
            "level": "warning",
            "method": "POST",
            "path": "/auth/openid/token",
            "remote": "127.0.0.1",
        }
    ]

    # Incorrect client_id.
    request["client_secret"] = "other-secret"
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_client",
        "error_description": "Unknown client ID other-client",
    }

    # Incorrect client_secret.
    request["client_id"] = "some-id"
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_client",
        "error_description": "Invalid secret for some-id",
    }

    # No stored data.
    request["client_secret"] = "some-secret"
    bogus_code = OIDCAuthorizationCode()
    request["code"] = str(bogus_code)
    caplog.clear()
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }
    log = json.loads(caplog.record_tuples[0][2])
    assert log["event"] == "Invalid authorization code"
    assert log["error"] == f"Unknown authorization code {bogus_code.key}"

    # Corrupt stored data.
    await setup.redis.set(bogus_code.key, "XXXXXXX")
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # Correct code, but invalid client_id for that code.
    bogus_code = await oidc_service.issue_code("other-id", redirect_uri, token)
    request["code"] = str(bogus_code)
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # Correct code and client_id but invalid redirect_uri.
    request["code"] = str(code)
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # Delete the underlying token.
    token_service = setup.factory.create_token_service()
    await token_service.delete_token(
        token.key, token_data, token_data.username, ip_address="127.0.0.1"
    )
    request["redirect_uri"] = redirect_uri
    r = await setup.client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }


@pytest.mark.asyncio
async def test_userinfo(setup: SetupTest) -> None:
    token_data = await setup.create_session_token()
    issuer = setup.factory.create_token_issuer()
    oidc_token = issuer.issue_token(token_data, jti="some-jti")

    r = await setup.client.get(
        "/auth/userinfo",
        headers={"Authorization": f"Bearer {oidc_token.encoded}"},
    )

    assert r.status_code == 200
    assert r.json() == oidc_token.claims


@pytest.mark.asyncio
async def test_no_auth(setup: SetupTest) -> None:
    r = await setup.client.get("/auth/userinfo")

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm


@pytest.mark.asyncio
async def test_invalid(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    token_data = await setup.create_session_token()
    issuer = setup.factory.create_token_issuer()
    oidc_token = issuer.issue_token(token_data, jti="some-jti")

    caplog.clear()
    r = await setup.client.get(
        "/auth/userinfo",
        headers={"Authorization": f"token {oidc_token.encoded}"},
    )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request
    assert authenticate.error_description == "Unknown Authorization type token"

    assert parse_log(caplog) == [
        {
            "error": "Unknown Authorization type token",
            "event": "Invalid request",
            "level": "warning",
            "method": "GET",
            "path": "/auth/userinfo",
            "remote": "127.0.0.1",
        }
    ]

    r = await setup.client.get(
        "/auth/userinfo",
        headers={"Authorization": f"bearer{oidc_token.encoded}"},
    )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request
    assert authenticate.error_description == "Malformed Authorization header"

    caplog.clear()
    r = await setup.client.get(
        "/auth/userinfo",
        headers={"Authorization": f"bearer XXX{oidc_token.encoded}"},
    )

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_token
    assert authenticate.error_description

    assert parse_log(caplog) == [
        {
            "error": ANY,
            "event": "Invalid token",
            "level": "warning",
            "method": "GET",
            "path": "/auth/userinfo",
            "remote": "127.0.0.1",
            "token_source": "bearer",
        }
    ]


@pytest.mark.asyncio
async def test_well_known_jwks(setup: SetupTest) -> None:
    r = await setup.client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    result = r.json()

    keypair = setup.config.issuer.keypair
    assert result == {
        "keys": [
            {
                "alg": ALGORITHM,
                "kty": "RSA",
                "use": "sig",
                "n": number_to_base64(keypair.public_numbers().n).decode(),
                "e": number_to_base64(keypair.public_numbers().e).decode(),
                "kid": "some-kid",
            }
        ],
    }

    # Ensure that we didn't add padding to the key components.  Stripping the
    # padding is required by RFC 7515 and 7518.
    assert "=" not in result["keys"][0]["n"]
    assert "=" not in result["keys"][0]["e"]


@pytest.mark.asyncio
async def test_well_known_oidc(setup: SetupTest) -> None:
    r = await setup.client.get("/.well-known/openid-configuration")
    assert r.status_code == 200

    base_url = setup.config.issuer.iss
    assert r.json() == {
        "issuer": setup.config.issuer.iss,
        "authorization_endpoint": base_url + "/auth/openid/login",
        "token_endpoint": base_url + "/auth/openid/token",
        "userinfo_endpoint": base_url + "/auth/openid/userinfo",
        "jwks_uri": base_url + "/.well-known/jwks.json",
        "scopes_supported": ["openid"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ALGORITHM],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }
