"""Tests for the /login route with OpenID Connect."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

import pytest

from tests.support.logging import parse_log

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_login(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    setup.configure("oidc")
    token = setup.create_upstream_oidc_token(
        groups=["admin"], name="Some Person", email="person@example.com"
    )
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)
    assert setup.config.oidc
    return_url = "https://example.com:4444/foo?a=bar&b=baz"

    caplog.clear()
    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    assert r.headers["Location"].startswith(setup.config.oidc.login_url)
    url = urlparse(r.headers["Location"])
    assert url.query
    query = parse_qs(url.query)
    login_params = {p: [v] for p, v in setup.config.oidc.login_params.items()}
    assert query == {
        "client_id": [setup.config.oidc.client_id],
        "redirect_uri": [setup.config.oidc.redirect_url],
        "response_type": ["code"],
        "scope": ["openid " + " ".join(setup.config.oidc.scopes)],
        "state": [ANY],
        **login_params,
    }

    # Verify the logging.
    login_url = setup.config.oidc.login_url
    assert parse_log(caplog) == [
        {
            "event": f"Redirecting user to {login_url} for authentication",
            "level": "info",
            "method": "GET",
            "path": "/login",
            "return_url": return_url,
            "remote": "127.0.0.1",
        }
    ]

    # Simulate the return from the provider.
    caplog.clear()
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url

    # Verify the logging.
    expected_scopes_set = set(setup.config.issuer.group_mapping["admin"])
    expected_scopes_set.add("user:token")
    expected_scopes = " ".join(sorted(expected_scopes_set))
    event = f"Successfully authenticated user {token.username} ({token.uid})"
    assert parse_log(caplog) == [
        {
            "event": f"Retrieving ID token from {setup.config.oidc.token_url}",
            "level": "info",
            "method": "GET",
            "path": "/login",
            "remote": "127.0.0.1",
            "return_url": return_url,
        },
        {
            "event": event,
            "level": "info",
            "method": "GET",
            "path": "/login",
            "return_url": return_url,
            "remote": "127.0.0.1",
            "scope": expected_scopes,
            "token": ANY,
            "user": token.username,
        },
    ]

    # Check that the /auth route works and finds our token.
    r = await setup.client.get("/auth", params={"scope": "exec:admin"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == expected_scopes
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-User"] == token.username
    assert r.headers["X-Auth-Request-Name"] == "Some Person"
    assert r.headers["X-Auth-Request-Email"] == "person@example.com"
    assert r.headers["X-Auth-Request-Uid"] == str(token.uid)
    assert r.headers["X-Auth-Request-Groups"] == "admin"


@pytest.mark.asyncio
async def test_login_redirect_header(setup: SetupTest) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    setup.configure("oidc")
    token = setup.create_upstream_oidc_token(groups=["admin"])
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)
    return_url = "https://example.com/foo?a=bar&b=baz"

    r = await setup.client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": return_url},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url


@pytest.mark.asyncio
async def test_oauth2_callback(setup: SetupTest) -> None:
    """Test the compatibility /oauth2/callback route."""
    setup.configure("oidc")
    token = setup.create_upstream_oidc_token(groups=["admin"])
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)
    assert setup.config.oidc
    return_url = "https://example.com/foo"

    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)
    assert query["redirect_uri"][0] == setup.config.oidc.redirect_url

    # Simulate the return from the OpenID Connect provider.
    r = await setup.client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url


@pytest.mark.asyncio
async def test_callback_error(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    """Test an error return from the OIDC token endpoint."""
    setup.configure("oidc")
    assert setup.config.oidc
    return_url = "https://example.com/foo"

    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Build an error response to return from the OIDC token URL and register
    # it as a result.
    response = {
        "error": "error_code",
        "error_description": "description",
    }
    setup.httpx_mock.add_response(
        url=setup.config.oidc.token_url,
        method="POST",
        json=response,
        status_code=400,
    )

    # Simulate the return from the OpenID Connect provider.
    caplog.clear()
    r = await setup.client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 500
    assert "error_code: description" in r.text
    assert parse_log(caplog) == [
        {
            "event": f"Retrieving ID token from {setup.config.oidc.token_url}",
            "level": "info",
            "method": "GET",
            "path": "/oauth2/callback",
            "remote": "127.0.0.1",
            "return_url": return_url,
        },
        {
            "error": "error_code: description",
            "event": "Provider authentication failed",
            "level": "warning",
            "method": "GET",
            "path": "/oauth2/callback",
            "return_url": return_url,
            "remote": "127.0.0.1",
        },
    ]

    # Change the mock error response to not contain an error.  We should then
    # internally raise the exception for the return status, which should
    # translate into an internal server error.
    setup.httpx_mock.add_response(
        url=setup.config.oidc.token_url,
        method="POST",
        json={"foo": "bar"},
        status_code=400,
    )
    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await setup.client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 500
    assert "Cannot contact authentication provider" in r.text

    # Now try a reply that returns 200 but doesn't have the field we
    # need.
    setup.httpx_mock.add_response(
        url=setup.config.oidc.token_url,
        method="POST",
        json={"foo": "bar"},
        status_code=200,
    )
    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await setup.client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 500
    assert "No id_token in token reply" in r.text

    # Return invalid JSON, which should raise an error during JSON decoding.
    setup.httpx_mock.add_response(
        url=setup.config.oidc.token_url,
        method="POST",
        data="foo",
        status_code=200,
    )
    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await setup.client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 500
    assert "not valid JSON" in r.text

    # Finally, return invalid JSON and an error reply.
    setup.httpx_mock.add_response(
        url=setup.config.oidc.token_url,
        method="POST",
        data="foo",
        status_code=400,
    )
    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await setup.client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 500
    assert "Cannot contact authentication provider" in r.text


@pytest.mark.asyncio
async def test_connection_error(setup: SetupTest) -> None:
    setup.configure("oidc")
    assert setup.config.oidc
    return_url = "https://example.com/foo"

    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Do not register a response for the callback request to the OIDC provider
    # and check that an appropriate error is shown to the user.
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 500
    assert r.json()["detail"][0]["type"] == "provider_connect_failed"


@pytest.mark.asyncio
async def test_verify_error(setup: SetupTest) -> None:
    setup.configure("oidc")
    token = setup.create_upstream_oidc_token(groups=["admin"])
    setup.set_oidc_token_response("some-code", token)
    assert setup.config.oidc
    return_url = "https://example.com/foo"

    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Returning from OpenID Connect login should fail because we haven't
    # registered the signing key, and therefore attempting to retrieve it will
    # fail, causing a token verification error.
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 500
    assert "token verification failed" in r.text


@pytest.mark.asyncio
async def test_invalid_username(setup: SetupTest) -> None:
    setup.configure("oidc")
    token = setup.create_upstream_oidc_token(
        sub="invalid@user", uid="invalid@user"
    )
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)
    assert setup.config.oidc
    return_url = "https://example.com/foo"

    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 403
    assert r.json() == {
        "detail": [
            {
                "msg": "Invalid username: invalid@user",
                "type": "permission_denied",
            }
        ]
    }


@pytest.mark.asyncio
async def test_invalid_group_syntax(setup: SetupTest) -> None:
    setup.configure("oidc")
    token = setup.create_upstream_oidc_token(
        isMemberOf=[{"name": "foo", "id": ["bar"]}]
    )
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)
    assert setup.config.oidc
    return_url = "https://example.com/foo"

    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 500
    assert r.json() == {
        "detail": [
            {
                "msg": ANY,
                "type": "provider_failed",
            }
        ]
    }


@pytest.mark.asyncio
async def test_invalid_groups(setup: SetupTest) -> None:
    setup.configure("oidc")
    token = setup.create_upstream_oidc_token(
        isMemberOf=[
            {"name": "foo"},
            {"group": "bar", "id": 4567},
            {"name": "valid", "id": "7889"},
            {"name": "admin", "id": 2371, "extra": "blah"},
            {"name": "bad:group:name", "id": 5723},
            {"name": "", "id": 1482},
            {"name": "21341", "id": 41233},
        ]
    )
    setup.set_oidc_token_response("some-code", token)
    setup.set_oidc_configuration_response(setup.config.issuer.keypair)
    assert setup.config.oidc
    return_url = "https://example.com/foo"

    r = await setup.client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url

    r = await setup.client.get("/auth", params={"scope": "exec:admin"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Groups"] == "valid,admin"
