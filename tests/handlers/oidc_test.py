"""Tests for the /auth/openid routes."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict
from unittest.mock import ANY
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from _pytest.logging import LogCaptureFixture
from httpx import AsyncClient

from gafaelfawr.auth import AuthError, AuthErrorChallenge, AuthType
from gafaelfawr.config import Config, OIDCClient
from gafaelfawr.constants import ALGORITHM
from gafaelfawr.factory import Factory
from gafaelfawr.models.oidc import OIDCAuthorizationCode, OIDCToken
from gafaelfawr.util import number_to_base64

from ..support.constants import TEST_HOSTNAME
from ..support.cookies import set_session_cookie
from ..support.headers import (
    assert_unauthorized_is_correct,
    parse_www_authenticate,
    query_from_url,
)
from ..support.logging import parse_log
from ..support.settings import reconfigure
from ..support.slack import MockSlack
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_login(
    tmp_path: Path,
    client: AsyncClient,
    factory: Factory,
    caplog: LogCaptureFixture,
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    config = await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    assert config.oidc_server
    token_data = await create_session_token(factory)
    await set_session_cookie(client, token_data.token)
    return_url = f"https://{TEST_HOSTNAME}:4444/foo?a=bar&b=baz"

    # Log in
    caplog.clear()
    r = await client.get(
        "/auth/openid/login",
        params={
            "response_type": "code",
            "scope": "openid",
            "client_id": "some-id",
            "state": "random-state",
            "redirect_uri": return_url,
        },
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
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "scopes": ["user:token"],
            "severity": "info",
            "token": token_data.token.key,
            "token_source": "cookie",
            "user": token_data.username,
        }
    ]

    # Redeem the code for a token and check the result.
    caplog.clear()
    r = await client.post(
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
    exp_seconds = config.oidc_server.lifetime.total_seconds()
    assert exp_seconds - 5 <= data["expires_in"] <= exp_seconds

    assert data["access_token"] == data["id_token"]
    oidc_service = factory.create_oidc_service()
    token = oidc_service.verify_token(OIDCToken(encoded=data["id_token"]))
    assert token.claims == {
        "aud": config.oidc_server.audience,
        "exp": ANY,
        "iat": ANY,
        "iss": config.oidc_server.issuer,
        "jti": OIDCAuthorizationCode.from_str(code).key,
        "name": token_data.name,
        "preferred_username": token_data.username,
        "scope": "openid",
        "sub": token_data.username,
        "uid_number": token_data.uid,
    }
    now = time.time()
    expected_exp = now + config.oidc_server.lifetime.total_seconds()
    assert expected_exp - 5 <= token.claims["exp"] <= expected_exp
    assert now - 5 <= token.claims["iat"] <= now

    username = token_data.username
    assert parse_log(caplog) == [
        {
            "event": f"Retrieved token for user {username} via OpenID Connect",
            "httpRequest": {
                "requestMethod": "POST",
                "requestUrl": f"https://{TEST_HOSTNAME}/auth/openid/token",
                "remoteIp": "127.0.0.1",
            },
            "severity": "info",
            "token": OIDCAuthorizationCode.from_str(code).key,
            "user": username,
        }
    ]

    r = await client.get(
        "/auth/openid/userinfo",
        headers={"Authorization": f"Bearer {token.encoded}"},
    )

    assert r.status_code == 200
    assert r.json() == token.claims


@pytest.mark.asyncio
async def test_unauthenticated(
    tmp_path: Path, client: AsyncClient, caplog: LogCaptureFixture
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    await reconfigure(tmp_path, "github-oidc-server", oidc_clients=clients)
    return_url = f"https://{TEST_HOSTNAME}:4444/foo?a=bar&b=baz"
    login_params = {
        "response_type": "code",
        "scope": "openid",
        "client_id": "some-id",
        "state": "random-state",
        "redirect_uri": return_url,
    }

    caplog.clear()
    r = await client.get("/auth/openid/login", params=login_params)

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
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
        }
    ]


@pytest.mark.asyncio
async def test_login_errors(
    tmp_path: Path,
    client: AsyncClient,
    factory: Factory,
    caplog: LogCaptureFixture,
    mock_slack: MockSlack,
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    token_data = await create_session_token(factory)
    await set_session_cookie(client, token_data.token)

    # No parameters at all.
    r = await client.get("/auth/openid/login")
    assert r.status_code == 422

    # Good client ID but missing redirect_uri.
    login_params = {"client_id": "some-id"}
    r = await client.get("/auth/openid/login", params=login_params)
    assert r.status_code == 422

    # Bad client ID.
    caplog.clear()
    login_params = {
        "client_id": "bad-client",
        "redirect_uri": f"https://{TEST_HOSTNAME}/",
    }
    r = await client.get("/auth/openid/login", params=login_params)
    assert r.status_code == 400
    data = r.json()
    assert data["detail"][0]["type"] == "invalid_client"
    assert "Unknown client_id bad-client" in data["detail"][0]["msg"]

    assert parse_log(caplog) == [
        {
            "error": "Unknown client_id bad-client in OpenID Connect request",
            "event": "Invalid request",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": f"https://{TEST_HOSTNAME}/",
            "scopes": ["user:token"],
            "severity": "warning",
            "token": ANY,
            "token_source": "cookie",
            "user": token_data.username,
        }
    ]

    # Bad redirect_uri.
    login_params["client_id"] = "some-id"
    login_params["redirect_uri"] = "https://foo.example.com/"
    r = await client.get("/auth/openid/login", params=login_params)
    assert r.status_code == 422
    assert "URL is not at" in r.text

    # Valid redirect_uri but missing response_type.
    login_params["redirect_uri"] = f"https://{TEST_HOSTNAME}/app"
    caplog.clear()
    r = await client.get("/auth/openid/login", params=login_params)
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
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": login_params["redirect_uri"],
            "scopes": ["user:token"],
            "severity": "warning",
            "token": ANY,
            "token_source": "cookie",
            "user": token_data.username,
        }
    ]

    # Invalid response_type.
    login_params["response_type"] = "bogus"
    r = await client.get("/auth/openid/login", params=login_params)
    assert r.status_code == 307
    assert query_from_url(r.headers["Location"]) == {
        "error": ["invalid_request"],
        "error_description": ["code is the only supported response_type"],
    }

    # Valid response_type but missing scope.
    login_params["response_type"] = "code"
    r = await client.get("/auth/openid/login", params=login_params)
    assert r.status_code == 307
    assert query_from_url(r.headers["Location"]) == {
        "error": ["invalid_request"],
        "error_description": ["Missing scope parameter"],
    }

    # Invalid scope.
    login_params["scope"] = "user:email"
    r = await client.get("/auth/openid/login", params=login_params)
    assert r.status_code == 307
    assert query_from_url(r.headers["Location"]) == {
        "error": ["invalid_request"],
        "error_description": ["openid is the only supported scope"],
    }

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_token_errors(
    tmp_path: Path,
    client: AsyncClient,
    factory: Factory,
    caplog: LogCaptureFixture,
    mock_slack: MockSlack,
) -> None:
    clients = [
        OIDCClient(client_id="some-id", client_secret="some-secret"),
        OIDCClient(client_id="other-id", client_secret="other-secret"),
    ]
    await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    token_data = await create_session_token(factory)
    token = token_data.token
    oidc_service = factory.create_oidc_service()
    redirect_uri = f"https://{TEST_HOSTNAME}/app"
    code = await oidc_service.issue_code("some-id", redirect_uri, token)

    # Missing parameters.
    request: Dict[str, str] = {}
    caplog.clear()
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_request",
        "error_description": "Invalid token request",
    }

    assert parse_log(caplog) == [
        {
            "error": "Invalid token request",
            "event": "Invalid request",
            "httpRequest": {
                "requestMethod": "POST",
                "requestUrl": f"https://{TEST_HOSTNAME}/auth/openid/token",
                "remoteIp": "127.0.0.1",
            },
            "severity": "warning",
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
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "unsupported_grant_type",
        "error_description": "Invalid grant type bogus",
    }

    assert parse_log(caplog) == [
        {
            "error": "Invalid grant type bogus",
            "event": "Unsupported grant type",
            "httpRequest": {
                "requestMethod": "POST",
                "requestUrl": f"https://{TEST_HOSTNAME}/auth/openid/token",
                "remoteIp": "127.0.0.1",
            },
            "severity": "warning",
        }
    ]

    # Invalid code.
    request["grant_type"] = "authorization_code"
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # No client_secret.
    request["code"] = str(OIDCAuthorizationCode())
    caplog.clear()
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_client",
        "error_description": "No client_secret provided",
    }

    assert parse_log(caplog) == [
        {
            "error": "No client_secret provided",
            "event": "Unauthorized client",
            "httpRequest": {
                "requestMethod": "POST",
                "requestUrl": f"https://{TEST_HOSTNAME}/auth/openid/token",
                "remoteIp": "127.0.0.1",
            },
            "severity": "warning",
        }
    ]

    # Incorrect client_id.
    request["client_secret"] = "other-secret"
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_client",
        "error_description": "Unknown client ID other-client",
    }

    # Incorrect client_secret.
    request["client_id"] = "some-id"
    r = await client.post("/auth/openid/token", data=request)
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
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }
    log = json.loads(caplog.record_tuples[0][2])
    assert log["event"] == "Invalid authorization code"
    assert log["error"] == f"Unknown authorization code {bogus_code.key}"

    # Corrupt stored data.
    await factory.redis.set(bogus_code.key, "XXXXXXX")
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # Correct code, but invalid client_id for that code.
    bogus_code = await oidc_service.issue_code("other-id", redirect_uri, token)
    request["code"] = str(bogus_code)
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # Correct code and client_id but invalid redirect_uri.
    request["code"] = str(code)
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # Delete the underlying token.
    token_service = factory.create_token_service()
    async with factory.session.begin():
        await token_service.delete_token(
            token.key, token_data, token_data.username, ip_address="127.0.0.1"
        )
    request["redirect_uri"] = redirect_uri
    r = await client.post("/auth/openid/token", data=request)
    assert r.status_code == 400
    assert r.json() == {
        "error": "invalid_grant",
        "error_description": "Invalid authorization code",
    }

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_no_auth(
    client: AsyncClient, config: Config, mock_slack: MockSlack
) -> None:
    r = await client.get("/auth/openid/userinfo")
    assert_unauthorized_is_correct(r, config)

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_invalid(
    tmp_path: Path,
    client: AsyncClient,
    factory: Factory,
    caplog: LogCaptureFixture,
    mock_slack: MockSlack,
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    config = await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    token_data = await create_session_token(factory)
    oidc_service = factory.create_oidc_service()
    oidc_token = oidc_service.issue_token(token_data, jti="some-jti")

    caplog.clear()
    r = await client.get(
        "/auth/openid/userinfo",
        headers={"Authorization": f"token {oidc_token.encoded}"},
    )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.invalid_request
    assert authenticate.error_description == "Unknown Authorization type token"

    assert parse_log(caplog) == [
        {
            "error": "Unknown Authorization type token",
            "event": "Invalid request",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": f"https://{TEST_HOSTNAME}/auth/openid/userinfo",
                "remoteIp": "127.0.0.1",
            },
            "severity": "warning",
        }
    ]

    r = await client.get(
        "/auth/openid/userinfo",
        headers={"Authorization": f"bearer{oidc_token.encoded}"},
    )

    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.invalid_request
    assert authenticate.error_description == "Malformed Authorization header"

    caplog.clear()
    r = await client.get(
        "/auth/openid/userinfo",
        headers={"Authorization": f"bearer XXX{oidc_token.encoded}"},
    )

    assert r.status_code == 401
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == config.realm
    assert authenticate.error == AuthError.invalid_token
    assert authenticate.error_description

    assert parse_log(caplog) == [
        {
            "error": ANY,
            "event": "Invalid token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": f"https://{TEST_HOSTNAME}/auth/openid/userinfo",
                "remoteIp": "127.0.0.1",
            },
            "severity": "warning",
            "token_source": "bearer",
        }
    ]

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_well_known_jwks(
    tmp_path: Path, client: AsyncClient, config: Config
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    config = await reconfigure(
        tmp_path, "github-oidc-server", oidc_clients=clients
    )
    assert config.oidc_server
    r = await client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    result = r.json()

    keypair = config.oidc_server.keypair
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
async def test_well_known_oidc(
    tmp_path: Path, client: AsyncClient, config: Config
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    config = await reconfigure(
        tmp_path, "github-oidc-server", oidc_clients=clients
    )
    assert config.oidc_server
    r = await client.get("/.well-known/openid-configuration")
    assert r.status_code == 200

    base_url = config.oidc_server.issuer
    assert r.json() == {
        "issuer": base_url,
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
