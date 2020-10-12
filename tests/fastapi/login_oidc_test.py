"""Tests for the /login route with OpenID Connect."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

from gafaelfawr.constants import ALGORITHM
from tests.setup import SetupFastAPITest
from tests.support.app import create_fastapi_test_app, create_test_client

if TYPE_CHECKING:
    from pathlib import Path

    from _pytest.logging import LogCaptureFixture
    from aioresponses import aioresponses


async def test_login(
    tmp_path: Path, responses: aioresponses, caplog: LogCaptureFixture
) -> None:
    app = await create_fastapi_test_app(tmp_path, environment="oidc")
    setup = SetupFastAPITest(tmp_path, responses)
    token = setup.create_oidc_token(groups=["admin"])
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)
    assert setup.config.oidc

    async with create_test_client(app) as client:
        return_url = "https://example.com:4444/foo?a=bar&b=baz"
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        assert r.status_code == 307
        assert r.headers["Location"].startswith(setup.config.oidc.login_url)
        url = urlparse(r.headers["Location"])
        assert url.query
        query = parse_qs(url.query)
        login_params = {
            p: [v] for p, v in setup.config.oidc.login_params.items()
        }
        assert query == {
            "client_id": [setup.config.oidc.client_id],
            "redirect_uri": [setup.config.oidc.redirect_url],
            "response_type": ["code"],
            "scope": ["openid " + " ".join(setup.config.oidc.scopes)],
            "state": [ANY],
            **login_params,
        }

        # Verify the logging.
        data = json.loads(caplog.record_tuples[-1][2])
        login_url = setup.config.oidc.login_url
        assert data == {
            "event": f"Redirecting user to {login_url} for authentication",
            "level": "info",
            "logger": "gafaelfawr",
            "method": "GET",
            "path": "/login",
            "return_url": return_url,
            "remote": "127.0.0.1",
            "request_id": ANY,
            "user_agent": ANY,
        }

        # Simulate the return from the provider.
        r = await client.get(
            "/login",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 307
        assert r.headers["Location"] == return_url

        # Verify the logging.
        expected_scopes_set = setup.config.issuer.group_mapping["admin"]
        expected_scopes = " ".join(sorted(expected_scopes_set))
        data = json.loads(caplog.record_tuples[-1][2])
        event = (
            f"Successfully authenticated user {token.username} ({token.uid})"
        )
        assert data == {
            "event": event,
            "level": "info",
            "logger": "gafaelfawr",
            "method": "GET",
            "path": "/login",
            "return_url": return_url,
            "remote": "127.0.0.1",
            "request_id": ANY,
            "scope": expected_scopes,
            "token": ANY,
            "user": token.username,
            "user_agent": ANY,
        }

        # Check that the /auth route works and finds our token.
        r = await client.get("/auth", params={"scope": "exec:admin"})
        assert r.status_code == 200
        assert r.headers["X-Auth-Request-Token-Scopes"] == expected_scopes
        assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
        assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
        assert r.headers["X-Auth-Request-Email"] == token.email
        assert r.headers["X-Auth-Request-User"] == token.username
        assert r.headers["X-Auth-Request-Uid"] == token.uid
        assert r.headers["X-Auth-Request-Groups"] == "admin"
        assert r.headers["X-Auth-Request-Token"]

        # Now ask for the session handle in the encrypted session to be
        # analyzed, and verify the internals of the session handle from OpenID
        # Connect authentication.
        r = await client.get("/auth/analyze")
        assert r.status_code == 200
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
                "data": {
                    "act": {
                        "aud": setup.config.oidc.audience,
                        "iss": setup.config.oidc.issuer,
                        "jti": token.jti,
                    },
                    "aud": setup.config.issuer.aud,
                    "email": token.email,
                    "exp": ANY,
                    "iat": ANY,
                    "isMemberOf": [{"name": "admin"}],
                    "iss": setup.config.issuer.iss,
                    "jti": ANY,
                    "scope": expected_scopes,
                    "sub": token.username,
                    "uid": token.username,
                    "uidNumber": token.uid,
                },
                "valid": True,
            },
        }


async def test_login_redirect_header(
    tmp_path: Path, responses: aioresponses
) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    app = await create_fastapi_test_app(tmp_path, environment="oidc")
    setup = SetupFastAPITest(tmp_path, responses)
    token = setup.create_oidc_token(groups=["admin"])
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)

    async with create_test_client(app) as client:
        return_url = "https://example.com/foo?a=bar&b=baz"
        r = await client.get(
            "/login",
            headers={"X-Auth-Request-Redirect": return_url},
            allow_redirects=False,
        )
        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        query = parse_qs(url.query)

        # Simulate the return from the OpenID Connect provider.
        r = await client.get(
            "/login",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 307
        assert r.headers["Location"] == return_url


async def test_oauth2_callback(
    tmp_path: Path, responses: aioresponses
) -> None:
    """Test the compatibility /oauth2/callback route."""
    app = await create_fastapi_test_app(tmp_path, environment="oidc")
    setup = SetupFastAPITest(tmp_path, responses)
    token = setup.create_oidc_token(groups=["admin"])
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)
    assert setup.config.oidc

    async with create_test_client(app) as client:
        return_url = "https://example.com/foo"
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        query = parse_qs(url.query)
        assert query["redirect_uri"][0] == setup.config.oidc.redirect_url

        # Simulate the return from the OpenID Connect provider.
        r = await client.get(
            "/oauth2/callback",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 307
        assert r.headers["Location"] == return_url


async def test_callback_error(
    tmp_path: Path, responses: aioresponses, caplog: LogCaptureFixture
) -> None:
    """Test an error return from the OIDC token endpoint."""
    app = await create_fastapi_test_app(tmp_path, environment="oidc")
    setup = SetupFastAPITest(tmp_path, responses)
    assert setup.config.oidc

    async with create_test_client(app) as client:
        return_url = "https://example.com/foo"
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        query = parse_qs(url.query)

        # Build an error response to return from the OIDC token URL and
        # register it as a result.
        response = {
            "error": "error_code",
            "error_description": "description",
        }
        setup.responses.post(
            setup.config.oidc.token_url, payload=response, status=400
        )

        # Simulate the return from the OpenID Connect provider.
        caplog.clear()
        r = await client.get(
            "/oauth2/callback",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 500
        assert "error_code: description" in r.text
        data = json.loads(caplog.record_tuples[-1][2])
        assert data == {
            "error": "error_code: description",
            "event": "Provider authentication failed",
            "level": "warning",
            "logger": "gafaelfawr",
            "method": "GET",
            "path": "/oauth2/callback",
            "return_url": return_url,
            "remote": "127.0.0.1",
            "request_id": ANY,
            "user_agent": ANY,
        }

        # Change the mock error response to not contain an error.  We should
        # then internally raise the exception for the return status, which
        # should translate into an internal server error.
        setup.responses.post(
            setup.config.oidc.token_url, payload={"foo": "bar"}, status=400
        )
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        query = parse_qs(urlparse(r.headers["Location"]).query)
        r = await client.get(
            "/oauth2/callback",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 500
        assert "Cannot contact authentication provider" in r.text

        # Now try a reply that returns 200 but doesn't have the field we
        # need.
        setup.responses.post(
            setup.config.oidc.token_url, payload={"foo": "bar"}, status=200
        )
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        query = parse_qs(urlparse(r.headers["Location"]).query)
        r = await client.get(
            "/oauth2/callback",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 500
        assert "No id_token in token reply" in r.text

        # Return invalid JSON, which should raise an error during JSON
        # decoding.
        setup.responses.post(
            setup.config.oidc.token_url, body="foo", status=200
        )
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        query = parse_qs(urlparse(r.headers["Location"]).query)
        r = await client.get(
            "/oauth2/callback",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 500
        assert "not valid JSON" in r.text

        # Finally, return invalid JSON and an error reply.
        setup.responses.post(
            setup.config.oidc.token_url, body="foo", status=400
        )
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        query = parse_qs(urlparse(r.headers["Location"]).query)
        r = await client.get(
            "/oauth2/callback",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 500
        assert "Cannot contact authentication provider" in r.text


async def test_connection_error(
    tmp_path: Path, responses: aioresponses
) -> None:
    app = await create_fastapi_test_app(tmp_path, environment="oidc")
    setup = SetupFastAPITest(tmp_path, responses)
    assert setup.config.oidc

    async with create_test_client(app) as client:
        return_url = "https://example.com/foo"
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        query = parse_qs(url.query)

        # Do not register a response for the callback request to the OIDC
        # provider and check that an appropriate error is shown to the user.
        r = await client.get(
            "/login",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 500
        assert "Connection refused" in r.text


async def test_verify_error(tmp_path: Path, responses: aioresponses) -> None:
    app = await create_fastapi_test_app(tmp_path, environment="oidc")
    setup = SetupFastAPITest(tmp_path, responses)
    token = setup.create_oidc_token(groups=["admin"])
    setup.set_oidc_token_response("some-code", token)
    assert setup.config.oidc

    async with create_test_client(app) as client:
        return_url = "https://example.com/foo"
        r = await client.get(
            "/login", params={"rd": return_url}, allow_redirects=False
        )
        assert r.status_code == 307
        url = urlparse(r.headers["Location"])
        query = parse_qs(url.query)

        # Returning from OpenID Connect login should fail because we haven't
        # registered the signing key, and therefore attempting to retrieve it
        # will fail, causing a token verification error.
        r = await client.get(
            "/login",
            params={"code": "some-code", "state": query["state"][0]},
            allow_redirects=False,
        )
        assert r.status_code == 500
        assert "token verification failed" in r.text
