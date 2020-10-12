"""Tests for the /auth/openid routes."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlencode, urlparse

from aiohttp import ClientSession

from gafaelfawr.config import OIDCClient
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.fastapi.dependencies import config, key_cache, redis
from gafaelfawr.providers.github import GitHubUserInfo
from gafaelfawr.session import Session, SessionHandle
from gafaelfawr.tokens import Token
from tests.setup import SetupFastAPITest
from tests.support.app import create_fastapi_test_app, create_test_client
from tests.support.headers import query_from_url
from tests.support.tokens import create_test_token

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Dict

    from _pytest.logging import LogCaptureFixture
    from aioresponses import aioresponses


async def test_login(
    tmp_path: Path, responses: aioresponses, caplog: LogCaptureFixture
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    app = await create_fastapi_test_app(tmp_path, oidc_clients=clients)
    setup = SetupFastAPITest(tmp_path, responses)
    factory = ComponentFactory(
        config=config(),
        redis=await redis(),
        key_cache=key_cache(),
        http_session=ClientSession(),
    )

    async with create_test_client(app) as client:
        userinfo = GitHubUserInfo(
            name="GitHub User",
            username="githubuser",
            uid=123456,
            email="githubuser@example.com",
            teams=[],
        )
        await setup.github_login(client, userinfo)

        # Log in
        return_url = "https://example.com:4444/foo?a=bar&b=baz"
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
            allow_redirects=False,
        )
        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        assert url.scheme == "https"
        assert url.netloc == "example.com:4444"
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

        log = json.loads(caplog.record_tuples[0][2])
        assert log == {
            "event": "Returned OpenID Connect authorization code",
            "level": "info",
            "logger": "gafaelfawr",
            "method": "GET",
            "path": "/auth/openid/login",
            "remote": "127.0.0.1",
            "request_id": ANY,
            "return_url": return_url,
            "scope": "",
            "token": ANY,
            "token_source": "cookie",
            "user": "githubuser",
            "user_agent": ANY,
        }

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
        exp_seconds = setup.config.issuer.exp_minutes * 60
        assert exp_seconds - 5 <= data["expires_in"] <= exp_seconds

        assert data["access_token"] == data["id_token"]
        verifier = factory.create_token_verifier()
        token = verifier.verify_internal_token(Token(encoded=data["id_token"]))
        assert token.claims == {
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
        now = time.time()
        expected_exp = now + setup.config.issuer.exp_minutes * 60
        assert expected_exp - 5 <= token.claims["exp"] <= expected_exp
        assert now - 5 <= token.claims["iat"] <= now

        log = json.loads(caplog.record_tuples[0][2])
        assert log == {
            "event": "Retrieved token for user githubuser via OpenID Connect",
            "level": "info",
            "logger": "gafaelfawr",
            "method": "POST",
            "path": "/auth/openid/token",
            "remote": "127.0.0.1",
            "request_id": ANY,
            "scope": "openid",
            "token": SessionHandle.from_str(code).key,
            "user": "githubuser",
            "user_agent": ANY,
        }


async def test_unauthenticated(
    tmp_path: Path, responses: aioresponses, caplog: LogCaptureFixture
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    app = await create_fastapi_test_app(tmp_path, oidc_clients=clients)

    async with create_test_client(app) as client:
        return_url = "https://example.com:4444/foo?a=bar&b=baz"
        login_params = {
            "response_type": "code",
            "scope": "openid",
            "client_id": "some-id",
            "state": "random-state",
            "redirect_uri": return_url,
        }
        caplog.clear()
        r = await client.get(
            "/auth/openid/login", params=login_params, allow_redirects=False
        )

        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        assert not url.scheme
        assert not url.netloc
        assert url.path == "/login"
        expected_url = "https://example.com/auth/openid/login?" + urlencode(
            login_params
        )
        assert query_from_url(r.headers["Location"]) == {
            "rd": [str(expected_url)]
        }

        log = json.loads(caplog.record_tuples[0][2])
        assert log == {
            "event": "Redirecting user for authentication",
            "level": "info",
            "logger": "gafaelfawr",
            "method": "GET",
            "path": "/auth/openid/login",
            "remote": "127.0.0.1",
            "request_id": ANY,
            "return_url": return_url,
            "user_agent": ANY,
        }


async def test_login_errors(
    tmp_path: Path, responses: aioresponses, caplog: LogCaptureFixture
) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    app = await create_fastapi_test_app(tmp_path, oidc_clients=clients)
    setup = SetupFastAPITest(tmp_path, responses)

    async with create_test_client(app) as client:
        userinfo = GitHubUserInfo(
            name="GitHub User",
            username="githubuser",
            uid=123456,
            email="githubuser@example.com",
            teams=[],
        )
        await setup.github_login(client, userinfo)

        # No parameters at all.
        caplog.clear()
        r = await client.get("/auth/openid/login", allow_redirects=False)
        assert r.status_code == 422

        # Good client ID but missing redirect_uri.
        login_params = {"client_id": "some-id"}
        caplog.clear()
        r = await client.get(
            "/auth/openid/login", params=login_params, allow_redirects=False
        )
        assert r.status_code == 422

        # Bad client ID.
        caplog.clear()
        login_params = {
            "client_id": "bad-client",
            "redirect_uri": "https://example.com/",
        }
        r = await client.get(
            "/auth/openid/login", params=login_params, allow_redirects=False
        )
        assert r.status_code == 400
        assert "Unknown client_id bad-client" in r.text

        log = json.loads(caplog.record_tuples[0][2])
        assert log == {
            "error": "Unknown client_id bad-client in OpenID Connect request",
            "event": "Invalid request",
            "level": "warning",
            "logger": "gafaelfawr",
            "method": "GET",
            "path": "/auth/openid/login",
            "remote": "127.0.0.1",
            "request_id": ANY,
            "return_url": "https://example.com/",
            "scope": "",
            "token": ANY,
            "token_source": "cookie",
            "user": "githubuser",
            "user_agent": ANY,
        }

        # Bad redirect_uri.
        login_params["client_id"] = "some-id"
        login_params["redirect_uri"] = "https://foo.example.com/"
        r = await client.get(
            "/auth/openid/login", params=login_params, allow_redirects=False
        )
        assert r.status_code == 400
        assert "URL is not at" in r.text

        # Valid redirect_uri but missing response_type.
        login_params["redirect_uri"] = "https://example.com/app"
        caplog.clear()
        r = await client.get(
            "/auth/openid/login", params=login_params, allow_redirects=False
        )
        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        assert url.scheme == "https"
        assert url.netloc == "example.com"
        assert url.path == "/app"
        assert url.query
        query = parse_qs(url.query)
        assert query == {
            "error": ["invalid_request"],
            "error_description": ["Missing response_type parameter"],
        }

        log = json.loads(caplog.record_tuples[0][2])
        assert log == {
            "error": "Missing response_type parameter",
            "event": "Invalid request",
            "level": "warning",
            "logger": "gafaelfawr",
            "method": "GET",
            "path": "/auth/openid/login",
            "remote": "127.0.0.1",
            "request_id": ANY,
            "return_url": login_params["redirect_uri"],
            "scope": "",
            "token": ANY,
            "token_source": "cookie",
            "user": "githubuser",
            "user_agent": ANY,
        }

        # Invalid response_type.
        login_params["response_type"] = "bogus"
        r = await client.get(
            "/auth/openid/login", params=login_params, allow_redirects=False
        )
        assert r.status_code == 307
        assert query_from_url(r.headers["Location"]) == {
            "error": ["invalid_request"],
            "error_description": ["code is the only supported response_type"],
        }

        # Valid response_type but missing scope.
        login_params["response_type"] = "code"
        r = await client.get(
            "/auth/openid/login", params=login_params, allow_redirects=False
        )
        assert r.status_code == 307
        assert query_from_url(r.headers["Location"]) == {
            "error": ["invalid_request"],
            "error_description": ["Missing scope parameter"],
        }

        # Invalid scope.
        login_params["scope"] = "user:email"
        r = await client.get(
            "/auth/openid/login", params=login_params, allow_redirects=False
        )
        assert r.status_code == 307
        assert query_from_url(r.headers["Location"]) == {
            "error": ["invalid_request"],
            "error_description": ["openid is the only supported scope"],
        }


async def test_token_errors(
    tmp_path: Path, responses: aioresponses, caplog: LogCaptureFixture
) -> None:
    clients = [
        OIDCClient(client_id="some-id", client_secret="some-secret"),
        OIDCClient(client_id="other-id", client_secret="other-secret"),
    ]
    app = await create_fastapi_test_app(tmp_path, oidc_clients=clients)
    factory = ComponentFactory(
        config=config(),
        redis=await redis(),
        key_cache=key_cache(),
        http_session=ClientSession(),
    )
    handle = SessionHandle()
    token = create_test_token(config(), jti=handle.key)
    session = Session.create(handle, token)
    session_store = factory.create_session_store()
    await session_store.store_session(session)
    oidc_server = factory.create_oidc_server()
    redirect_uri = "https://example.com/app"
    code = await oidc_server.issue_code("some-id", redirect_uri, handle)

    async with create_test_client(app) as client:
        caplog.clear()

        # Missing parameters.
        request: Dict[str, str] = {}
        r = await client.post("/auth/openid/token", data=request)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_request",
            "error_description": "Invalid token request",
        }

        log = json.loads(caplog.record_tuples[0][2])
        assert log == {
            "error": "Invalid token request",
            "event": "Invalid request",
            "level": "warning",
            "logger": "gafaelfawr",
            "method": "POST",
            "path": "/auth/openid/token",
            "remote": "127.0.0.1",
            "request_id": ANY,
            "user_agent": ANY,
        }

        # Invalid grant type.
        request = {
            "grant_type": "bogus",
            "client_id": "other-client",
            "code": "nonsense",
            "redirect_uri": "https://example.com/",
        }
        caplog.clear()
        r = await client.post("/auth/openid/token", data=request)
        assert r.status_code == 400
        assert r.json() == {
            "error": "unsupported_grant_type",
            "error_description": "Invalid grant type bogus",
        }

        log = json.loads(caplog.record_tuples[0][2])
        assert log == {
            "error": "Invalid grant type bogus",
            "event": "Unsupported grant type",
            "level": "warning",
            "logger": "gafaelfawr",
            "method": "POST",
            "path": "/auth/openid/token",
            "remote": "127.0.0.1",
            "request_id": ANY,
            "user_agent": ANY,
        }

        # Invalid code.
        request["grant_type"] = "authorization_code"
        r = await client.post("/auth/openid/token", data=request)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_grant",
            "error_description": "Invalid authorization code",
        }

        # No client_secret.
        request["code"] = SessionHandle().encode()
        caplog.clear()
        r = await client.post("/auth/openid/token", data=request)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_client",
            "error_description": "No client_secret provided",
        }

        log = json.loads(caplog.record_tuples[0][2])
        assert log == {
            "error": "No client_secret provided",
            "event": "Unauthorized client",
            "level": "warning",
            "logger": "gafaelfawr",
            "method": "POST",
            "path": "/auth/openid/token",
            "remote": "127.0.0.1",
            "request_id": ANY,
            "user_agent": ANY,
        }

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
        bogus_code = SessionHandle()
        request["code"] = bogus_code.encode()
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
        redis_client = await redis()
        await redis_client.set(bogus_code.key, "XXXXXXX")
        r = await client.post("/auth/openid/token", data=request)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_grant",
            "error_description": "Invalid authorization code",
        }

        # Correct code, but invalid client_id for that code.
        bogus_code = await oidc_server.issue_code(
            "other-id", redirect_uri, handle
        )
        request["code"] = bogus_code.encode()
        r = await client.post("/auth/openid/token", data=request)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_grant",
            "error_description": "Invalid authorization code",
        }

        # Correct code and client_id but invalid redirect_uri.
        request["code"] = code.encode()
        r = await client.post("/auth/openid/token", data=request)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_grant",
            "error_description": "Invalid authorization code",
        }

        # Delete the underlying session.
        session_store = factory.create_session_store()
        redis_client = await redis()
        pipeline = redis_client.pipeline()
        await session_store.delete_session(handle.key, pipeline)
        await pipeline.execute()
        request["redirect_uri"] = redirect_uri
        r = await client.post("/auth/openid/token", data=request)
        assert r.status_code == 400
        assert r.json() == {
            "error": "invalid_grant",
            "error_description": "Invalid authorization code",
        }
