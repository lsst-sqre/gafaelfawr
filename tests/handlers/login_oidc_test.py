"""Tests for the /login route with OpenID Connect."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urljoin, urlparse

import pytest
from httpx import ConnectError

from tests.support.logging import parse_log
from tests.support.oidc import (
    mock_oidc_provider_config,
    mock_oidc_provider_token,
)
from tests.support.settings import configure
from tests.support.tokens import create_upstream_oidc_token

if TYPE_CHECKING:
    from pathlib import Path

    import respx
    from _pytest.logging import LogCaptureFixture
    from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    caplog: LogCaptureFixture,
) -> None:
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(
        groups=["admin"], name="Some Person", email="person@example.com"
    )
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    assert config.oidc
    return_url = "https://example.com:4444/foo?a=bar&b=baz"

    caplog.clear()
    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    assert r.headers["Location"].startswith(config.oidc.login_url)
    url = urlparse(r.headers["Location"])
    assert url.query
    query = parse_qs(url.query)
    login_params = {p: [v] for p, v in config.oidc.login_params.items()}
    assert query == {
        "client_id": [config.oidc.client_id],
        "redirect_uri": [config.oidc.redirect_url],
        "response_type": ["code"],
        "scope": ["openid " + " ".join(config.oidc.scopes)],
        "state": [ANY],
        **login_params,
    }

    # Verify the logging.
    login_url = config.oidc.login_url
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
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url

    # Verify the logging.
    expected_scopes_set = set(config.issuer.group_mapping["admin"])
    expected_scopes_set.add("user:token")
    expected_scopes = " ".join(sorted(expected_scopes_set))
    event = f"Successfully authenticated user {token.username} ({token.uid})"
    assert parse_log(caplog) == [
        {
            "event": f"Retrieving ID token from {config.oidc.token_url}",
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
    r = await client.get("/auth", params={"scope": "exec:admin"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == expected_scopes
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-User"] == token.username
    assert r.headers["X-Auth-Request-Email"] == "person@example.com"
    assert r.headers["X-Auth-Request-Uid"] == str(token.uid)
    assert r.headers["X-Auth-Request-Groups"] == "admin"


@pytest.mark.asyncio
async def test_login_redirect_header(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(groups=["admin"])
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo?a=bar&b=baz"

    r = await client.get(
        "/login", headers={"X-Auth-Request-Redirect": return_url}
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url


@pytest.mark.asyncio
async def test_oauth2_callback(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Test the compatibility /oauth2/callback route."""
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(groups=["admin"])
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    assert config.oidc
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)
    assert query["redirect_uri"][0] == config.oidc.redirect_url

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url


@pytest.mark.asyncio
async def test_claim_names(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Uses an alternate settings environment with non-default claims."""
    config = await configure(
        tmp_path, "oidc", username_claim="username", uid_claim="numeric_uid"
    )
    assert config.oidc
    token = await create_upstream_oidc_token(
        groups=["admin"], username="alt-username", numeric_uid=7890
    )
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)
    assert query["redirect_uri"][0] == config.oidc.redirect_url

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url

    # Check that the /auth route works and sets the headers correctly.  uid
    # will be set to some-user and uidNumber will be set to 1000, so we'll
    # know if we read the alternate claim names correctly instead.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "alt-username"
    assert r.headers["X-Auth-Request-Uid"] == "7890"


@pytest.mark.asyncio
async def test_callback_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    caplog: LogCaptureFixture,
) -> None:
    """Test an error return from the OIDC token endpoint."""
    config = await configure(tmp_path, "oidc")
    assert config.oidc
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Build an error response to return from the OIDC token URL and register
    # it as a result.
    response = {
        "error": "error_code",
        "error_description": "description",
    }
    respx_mock.post(config.oidc.token_url).respond(400, json=response)

    # Simulate the return from the OpenID Connect provider.
    caplog.clear()
    r = await client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
    )
    assert r.status_code == 403
    assert "error_code: description" in r.text
    assert parse_log(caplog) == [
        {
            "event": f"Retrieving ID token from {config.oidc.token_url}",
            "level": "info",
            "method": "GET",
            "path": "/oauth2/callback",
            "remote": "127.0.0.1",
            "return_url": return_url,
        },
        {
            "error": "error_code: description",
            "event": "Authentication provider failed",
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
    respx_mock.post(config.oidc.token_url).respond(400, json={"foo": "bar"})
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
    )
    assert r.status_code == 403
    assert "Cannot contact authentication provider" in r.text

    # Now try a reply that returns 200 but doesn't have the field we
    # need.
    respx_mock.post(config.oidc.token_url).respond(json={"foo": "bar"})
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
    )
    assert r.status_code == 403
    assert "No id_token in token reply" in r.text

    # Return invalid JSON, which should raise an error during JSON decoding.
    respx_mock.post(config.oidc.token_url).respond(content=b"foo")
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
    )
    assert r.status_code == 403
    assert "not valid JSON" in r.text

    # Finally, return invalid JSON and an error reply.
    respx_mock.post(config.oidc.token_url).respond(400, content=b"foo")
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
    )
    assert r.status_code == 403
    assert "Cannot contact authentication provider" in r.text


@pytest.mark.asyncio
async def test_connection_error(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    config = await configure(tmp_path, "oidc")
    assert config.oidc
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Register a connection error for the callback request to the OIDC
    # provider and check that an appropriate error is shown to the user.
    token_url = config.oidc.token_url
    respx_mock.post(token_url).mock(side_effect=ConnectError)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "Cannot contact authentication provider" in r.text


@pytest.mark.asyncio
async def test_verify_error(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(groups=["admin"])
    assert config.oidc
    issuer = config.oidc.issuer
    config_url = urljoin(issuer, "/.well-known/openid-configuration")
    jwks_url = urljoin(issuer, "/.well-known/jwks.json")
    respx_mock.get(config_url).respond(404)
    respx_mock.get(jwks_url).respond(404)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Returning from OpenID Connect login should fail because we haven't
    # registered the signing key, and therefore attempting to retrieve it will
    # fail, causing a token verification error.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "token verification failed" in r.text


@pytest.mark.asyncio
async def test_invalid_username(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(
        groups=["admin"], sub="invalid@user", uid="invalid@user"
    )
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "Invalid username: invalid@user" in r.text


@pytest.mark.asyncio
async def test_invalid_group_syntax(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(
        isMemberOf=[{"name": "foo", "id": ["bar"]}]
    )
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "isMemberOf claim is invalid" in r.text


@pytest.mark.asyncio
async def test_invalid_groups(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(
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
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url

    r = await client.get("/auth", params={"scope": "exec:admin"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Groups"] == "valid,admin"


@pytest.mark.asyncio
async def test_no_valid_groups(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(groups=[])
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo?a=bar&b=baz"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    expected = f"{token.username} is not a member of any authorized groups"
    assert expected in r.text
    assert "Some <strong>error instructions</strong> with HTML." in r.text

    # The user should not be logged in.
    r = await client.get("/auth", params={"scope": "user:token"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_unicode_name(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    config = await configure(tmp_path, "oidc")
    token = await create_upstream_oidc_token(name="名字", groups=["admin"])
    await mock_oidc_provider_config(respx_mock, config.issuer.keypair)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url

    # Check that the name as returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": token.username,
        "name": "名字",
        "email": token.claims["email"],
        "uid": token.uid,
        "groups": [{"name": "admin", "id": 1000}],
    }
