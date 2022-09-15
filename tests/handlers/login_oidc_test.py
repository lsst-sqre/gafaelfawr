"""Tests for the /login route with OpenID Connect."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import ANY
from urllib.parse import parse_qs, urljoin, urlparse

import pytest
import respx
from _pytest.logging import LogCaptureFixture
from httpx import AsyncClient, ConnectError

from gafaelfawr.constants import GID_MIN, UID_BOT_MIN, UID_USER_MIN
from gafaelfawr.factory import Factory

from ..support.firestore import MockFirestore
from ..support.jwt import create_upstream_oidc_jwt
from ..support.logging import parse_log
from ..support.oidc import mock_oidc_provider_token, simulate_oidc_login
from ..support.settings import reconfigure
from ..support.slack import MockSlack


@pytest.mark.asyncio
async def test_login(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    caplog: LogCaptureFixture,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.oidc
    token = create_upstream_oidc_jwt(
        groups=["admin"], name="Some Person", email="person@example.com"
    )
    return_url = "https://example.com:4444/foo?a=bar&b=baz"

    # Perform a successful login.
    caplog.clear()
    r = await simulate_oidc_login(
        client, respx_mock, token, return_url=return_url
    )
    assert r.status_code == 307

    # Verify the logging.
    login_url = config.oidc.login_url
    expected_scopes = set(config.group_mapping["admin"])
    expected_scopes.add("user:token")
    username = token.claims[config.oidc.username_claim]
    uid = int(token.claims[config.oidc.uid_claim])
    event = f"Successfully authenticated user {username} ({uid})"
    assert parse_log(caplog) == [
        {
            "event": f"Redirecting user to {login_url} for authentication",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
        },
        {
            "event": f"Retrieving ID token from {config.oidc.token_url}",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
        },
        {
            "event": event,
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "scopes": sorted(expected_scopes),
            "severity": "info",
            "token": ANY,
            "user": username,
        },
    ]

    # Check that the /auth route works and finds our token.
    r = await client.get("/auth", params={"scope": "exec:admin"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == " ".join(
        sorted(expected_scopes)
    )
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-User"] == username
    assert r.headers["X-Auth-Request-Email"] == "person@example.com"
    assert r.headers["X-Auth-Request-Uid"] == str(uid)
    assert r.headers["X-Auth-Request-Groups"] == "admin"

    # Also check the information retrieved via the API.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": username,
        "name": "Some Person",
        "email": "person@example.com",
        "uid": uid,
        "groups": [{"name": "admin", "id": 1000}],
    }


@pytest.mark.asyncio
async def test_login_redirect_header(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(groups=["admin"])
    return_url = "https://example.com/foo?a=bar&b=baz"

    r = await simulate_oidc_login(
        client,
        respx_mock,
        token,
        return_url=return_url,
        use_redirect_header=True,
    )
    assert r.status_code == 307


@pytest.mark.asyncio
async def test_claim_names(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Uses an alternate settings environment with non-default claims."""
    config = await reconfigure(tmp_path, "oidc-claims")
    assert config.oidc
    claims = {
        config.oidc.username_claim: "alt-username",
        config.oidc.uid_claim: 7890,
        config.oidc.groups_claim: [{"name": "admin", "id": "1000"}],
    }
    token = create_upstream_oidc_jwt(kid="orig-kid", groups=["test"], **claims)

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the /auth route works and sets the headers correctly.  uid
    # will be set to some-user, uidNumber will be set to 1000, and isMemberOf
    # will include just the test group, so we'll know if we read the alternate
    # claim names correctly instead.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "alt-username"
    assert r.headers["X-Auth-Request-Uid"] == "7890"
    assert r.headers["X-Auth-Request-Groups"] == "admin"


@pytest.mark.asyncio
async def test_callback_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    caplog: LogCaptureFixture,
    mock_slack: MockSlack,
) -> None:
    """Test an error return from the OIDC token endpoint."""
    config = await reconfigure(tmp_path, "oidc")
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
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "error_code: description" in r.text
    assert parse_log(caplog) == [
        {
            "event": f"Retrieving ID token from {config.oidc.token_url}",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
        },
        {
            "error": "error_code: description",
            "event": "Authentication provider failed",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "warning",
        },
    ]

    # Change the mock error response to not contain an error.  We should then
    # internally raise the exception for the return status, which should
    # translate into an internal server error.
    respx_mock.post(config.oidc.token_url).respond(400, json={"foo": "bar"})
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "Cannot contact authentication provider" in r.text

    # Now try a reply that returns 200 but doesn't have the field we need.
    respx_mock.post(config.oidc.token_url).respond(json={"foo": "bar"})
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "No id_token in token reply" in r.text

    # Return invalid JSON, which should raise an error during JSON decoding.
    respx_mock.post(config.oidc.token_url).respond(content=b"foo")
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "not valid JSON" in r.text

    # Finally, return invalid JSON and an error reply.
    respx_mock.post(config.oidc.token_url).respond(400, content=b"foo")
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 403
    assert "Cannot contact authentication provider" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_connection_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlack,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
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

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_verify_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlack,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(groups=["admin"])
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

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_invalid_username(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlack,
) -> None:
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(
        groups=["admin"], sub="invalid@user", uid="invalid@user"
    )

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert "Invalid username: invalid@user" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_invalid_group_syntax(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlack,
) -> None:
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(isMemberOf=47)

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert "isMemberOf claim has invalid format" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_invalid_groups(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(
        isMemberOf=[
            {"name": "test"},
            {"group": "bar", "id": 4567},
            {"name": "valid", "id": "7889"},
            {"name": "admin", "id": 2371, "extra": "blah"},
            {"name": "bad:group:name", "id": 5723},
            {"name": "", "id": 1482},
            {"name": "21341", "id": 41233},
            {"name": "foo", "id": ["bar"]},
        ]
    )

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # test counts as a valid group despite not having a GID, and should
    # contribute to scopes.
    r = await client.get("/auth", params={"scope": "exec:admin"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Groups"] == "test,valid,admin"
    expected_scopes = "exec:admin exec:test read:all user:token"
    assert r.headers["X-Auth-Request-Token-Scopes"] == expected_scopes

    # Check the group membership via the user-info endpoint.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": token.claims["uid"],
        "email": token.claims["email"],
        "uid": int(token.claims["uidNumber"]),
        "groups": [
            {"name": "test"},
            {"name": "valid", "id": 7889},
            {"name": "admin", "id": 2371},
        ],
    }


@pytest.mark.asyncio
async def test_no_valid_groups(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlack,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.oidc
    token = create_upstream_oidc_jwt(groups=[])

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    username = token.claims[config.oidc.username_claim]
    expected = f"{username} is not a member of any authorized groups"
    assert expected in r.text
    assert "Some <strong>error instructions</strong> with HTML." in r.text

    # The user should not be logged in.
    r = await client.get("/auth", params={"scope": "user:token"})
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_unicode_name(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.oidc
    token = create_upstream_oidc_jwt(name="名字", groups=["admin"])

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the name as returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": token.claims[config.oidc.username_claim],
        "name": "名字",
        "email": token.claims["email"],
        "uid": int(token.claims[config.oidc.uid_claim]),
        "groups": [{"name": "admin", "id": 1000}],
    }


@pytest.mark.asyncio
async def test_firestore(
    tmp_path: Path,
    factory: Factory,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_firestore: MockFirestore,
) -> None:
    config = await reconfigure(tmp_path, "oidc-firestore", factory)
    assert config.oidc
    firestore_storage = factory.create_firestore_storage()
    await firestore_storage.initialize()
    token = create_upstream_oidc_jwt(groups=["admin", "foo"])

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check the allocated UID and GIDs.
    username = token.claims[config.oidc.username_claim]
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": username,
        "email": token.claims["email"],
        "uid": UID_USER_MIN,
        "groups": [
            {"name": "admin", "id": GID_MIN},
            {"name": "foo", "id": GID_MIN + 1},
        ],
    }

    # Delete the user document and reauthenticate.  We should still get the
    # same UID due to the internal cache.  The below is not a valid use of the
    # Firestore API; it only works with our mock implementation.
    transaction = mock_firestore.transaction()
    transaction.delete(mock_firestore.collection("users").document(username))
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": username,
        "email": token.claims["email"],
        "uid": UID_USER_MIN,
        "groups": [
            {"name": "admin", "id": GID_MIN},
            {"name": "foo", "id": GID_MIN + 1},
        ],
    }

    # Authenticate as a different user.
    claims = {config.oidc.username_claim: "other-user", "sub": "other-user"}
    token = create_upstream_oidc_jwt(groups=["foo", "group-1"], **claims)
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "other-user",
        "email": token.claims["email"],
        "uid": UID_USER_MIN + 1,
        "groups": [
            {"name": "foo", "id": GID_MIN + 1},
            {"name": "group-1", "id": GID_MIN + 2},
        ],
    }

    # Authenticate as a bot user, which should use a different UID space.
    claims = {config.oidc.username_claim: "bot-foo", "sub": "bot-foo"}
    token = create_upstream_oidc_jwt(groups=["foo", "group-2"], **claims)
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "bot-foo",
        "email": token.claims["email"],
        "uid": UID_BOT_MIN,
        "groups": [
            {"name": "foo", "id": GID_MIN + 1},
            {"name": "group-2", "id": GID_MIN + 3},
        ],
    }


@pytest.mark.asyncio
async def test_enrollment_url(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
) -> None:
    await reconfigure(tmp_path, "oidc-enrollment")
    token = create_upstream_oidc_jwt(groups=["admin"])

    r = await simulate_oidc_login(
        client, respx_mock, token, expect_enrollment=True
    )
    assert r.status_code == 307


@pytest.mark.asyncio
async def test_no_enrollment_url(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlack,
) -> None:
    """Test a missing username claim in the ID token but no enrollment URL."""
    await reconfigure(tmp_path, "oidc-claims")
    token = create_upstream_oidc_jwt(groups=["admin"])

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    assert "User is not enrolled" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_gid(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlack,
) -> None:
    """Test getting the primary GID from the OIDC claims."""
    await reconfigure(tmp_path, "oidc-gid")
    token = create_upstream_oidc_jwt(groups=["admin"], gid_number="1671")

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Get the user information and check that the GID was set.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": token.claims["sub"],
        "email": token.claims["email"],
        "uid": 1000,
        "gid": 1671,
        "groups": [{"name": "admin", "id": 1000}],
    }


@pytest.mark.asyncio
async def test_group_list(
    tmp_path: Path, client: AsyncClient, respx_mock: respx.Router
) -> None:
    """Test a simple list of groups instead of a complex structure."""
    config = await reconfigure(tmp_path, "oidc-claims")
    assert config.oidc
    claims = {
        config.oidc.username_claim: "alt-username",
        config.oidc.uid_claim: 7890,
        config.oidc.groups_claim: ["foo", "admin"],
    }
    token = create_upstream_oidc_jwt(kid="orig-kid", groups=["test"], **claims)

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Groups"] == "foo,admin"

    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "alt-username",
        "email": token.claims["email"],
        "uid": 7890,
        "groups": [{"name": "foo"}, {"name": "admin"}],
    }
