"""Tests for OpenID Connect auth."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import ANY
from urllib.parse import parse_qs, urljoin, urlparse

import pytest
import respx
from httpx import AsyncClient, ConnectError
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.constants import GID_MIN, UID_USER_MIN
from gafaelfawr.factory import Factory
from gafaelfawr.models.userinfo import Group, UserInfo

from ..support.config import reconfigure
from ..support.firestore import MockFirestore
from ..support.jwt import create_upstream_oidc_jwt
from ..support.ldap import MockLDAP
from ..support.logging import parse_log
from ..support.oidc import mock_oidc_provider_token, simulate_oidc_login


@pytest.mark.asyncio
async def test_login(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    caplog: pytest.LogCaptureFixture,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.ldap
    assert config.oidc
    token = create_upstream_oidc_jwt("ldap-user")
    return_url = "https://example.com:4444/foo?a=bar&b=baz"

    # Test invalid and duplicate entries that should be accepted with at most
    # a logged warning.
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [
            {
                "displayName": ["LDAP User", "Other user name"],
                "mail": ["ldap-user@example.com", "foo@example.com"],
                "uidNumber": ["2000", "1000"],
                "gidNumber": ["1045", "4000"],
            }
        ],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "ldap-user",
        [
            {"cn": ["foo"], "gidNumber": ["1222"]},
            {"cn": ["group-1"], "gidNumber": ["123123"]},
            {"cn": ["group-2"], "gidNumber": ["123442"]},
            {"cn": ["invalid!group"], "gidNumber": ["123443"]},
            {"cn": ["invalid-gid"], "gidNumber": ["bob"]},
        ],
    )

    caplog.clear()
    r = await simulate_oidc_login(
        client, respx_mock, token, return_url=return_url
    )
    assert r.status_code == 307

    # Verify the logging.
    expected_scopes = set(config.group_mapping["foo"])
    expected_scopes.add("user:token")
    username = token.claims[config.oidc.username_claim]
    assert parse_log(caplog, ignore_debug=True) == [
        {
            "event": "Redirecting user for authentication",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "login_url": config.oidc.login_url,
            "return_url": return_url,
            "severity": "info",
        },
        {
            "event": "Retrieving ID token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
            "token_url": config.oidc.token_url,
        },
        {
            "event": "LDAP group invalid!group invalid, ignoring",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "ldap_search": "(&(objectClass=posixGroup)(member=ldap-user))",
            "ldap_url": config.ldap.url,
            "return_url": return_url,
            "severity": "warning",
            "user": "ldap-user",
        },
        {
            "event": f"Successfully authenticated user {username}",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
            "token_key": ANY,
            "token_username": username,
            "token_expires": ANY,
            "token_scopes": sorted(expected_scopes),
            "token_userinfo": {},
        },
    ]

    # Check that the data returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "ldap-user",
        "name": "LDAP User",
        "email": "ldap-user@example.com",
        "uid": 2000,
        "gid": 1045,
        "groups": [
            {"name": "foo", "id": 1222},
            {"name": "group-1", "id": 123123},
            {"name": "group-2", "id": 123442},
        ],
    }

    # Check that the headers returned by the auth endpoint are also correct.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "ldap-user"
    assert r.headers["X-Auth-Request-Email"] == "ldap-user@example.com"


@pytest.mark.asyncio
async def test_login_redirect_header(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt("some-user")
    return_url = "https://example.com/foo?a=bar&b=baz"
    mock_ldap.add_test_user(UserInfo(username="some-user"))
    mock_ldap.add_test_group_membership(
        "some-user", [Group(name="foo", id=1222)]
    )

    r = await simulate_oidc_login(
        client,
        respx_mock,
        token,
        return_url=return_url,
        use_redirect_header=True,
    )
    assert r.status_code == 307


@pytest.mark.asyncio
async def test_firestore(
    tmp_path: Path,
    factory: Factory,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
    mock_firestore: MockFirestore,
) -> None:
    config = await reconfigure(tmp_path, "oidc-firestore", factory)
    assert config.oidc
    firestore_storage = factory.create_firestore_storage()
    await firestore_storage.initialize()
    token = create_upstream_oidc_jwt("ldap-user")
    mock_ldap.add_test_user(
        UserInfo(
            username="ldap-user",
            name="LDAP User",
            email="ldap-user@example.com",
        )
    )
    mock_ldap.add_test_user(UserInfo(username="other-user"))

    # Add group memberships without GIDs to test that we don't fail.
    assert config.ldap
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "ldap-user",
        [{"cn": ["foo"]}, {"cn": ["group-1"]}, {"cn": ["group-2"]}],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "other-user",
        [{"cn": ["foo"]}, {"cn": ["group-1"]}],
    )

    # Simulate the OIDC login.
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the data returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    expected = {
        "username": "ldap-user",
        "name": "LDAP User",
        "email": "ldap-user@example.com",
        "uid": UID_USER_MIN,
        "gid": UID_USER_MIN,
        "groups": [
            {"name": "foo", "id": GID_MIN},
            {"name": "group-1", "id": GID_MIN + 1},
            {"name": "group-2", "id": GID_MIN + 2},
            {"name": "ldap-user", "id": UID_USER_MIN},
        ],
    }
    assert r.json() == expected

    # Check that the headers returned by the auth endpoint are also correct.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "ldap-user"
    assert r.headers["X-Auth-Request-Email"] == "ldap-user@example.com"

    # Delete the user document and reauthenticate.  We should still get the
    # same UID due to the internal cache.  The below is not a valid use of the
    # Firestore API; it only works with our mock implementation.
    transaction = mock_firestore.transaction()
    transaction.delete(
        mock_firestore.collection("users").document("ldap-user")
    )
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == expected

    # Authenticate as a different user.
    token = create_upstream_oidc_jwt("other-user")
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "other-user",
        "uid": UID_USER_MIN + 1,
        "gid": UID_USER_MIN + 1,
        "groups": [
            {"name": "foo", "id": GID_MIN},
            {"name": "group-1", "id": GID_MIN + 1},
            {"name": "other-user", "id": UID_USER_MIN + 1},
        ],
    }


@pytest.mark.asyncio
async def test_gid_group_lookup(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    """Test separate lookup of the primary group."""
    config = await reconfigure(tmp_path, "oidc")
    assert config.ldap
    token = create_upstream_oidc_jwt("ldap-user")
    mock_ldap.add_test_user(UserInfo(username="ldap-user", uid=2000, gid=1045))
    mock_ldap.add_test_group_membership(
        "ldap-user", [Group(name="group-1", id=123123)]
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "gidNumber",
        "1045",
        [{"cn": ["invalid!name"]}, {"cn": ["foo"]}],
    )
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the data returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "ldap-user",
        "uid": 2000,
        "gid": 1045,
        "groups": [
            {"name": "foo", "id": 1045},
            {"name": "group-1", "id": 123123},
        ],
    }


@pytest.mark.asyncio
async def test_missing_attrs(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt("ldap-user")
    mock_ldap.add_test_user(UserInfo(username="ldap-user", uid=2000))
    mock_ldap.add_test_group_membership(
        "ldap-user", [Group(name="foo", id=1222)]
    )

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the data returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "ldap-user",
        "uid": 2000,
        "groups": [{"name": "foo", "id": 1222}],
    }

    # Check that the headers returned by the auth endpoint are also correct.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "ldap-user"
    assert "X-Auth-Request-Email" not in r.headers


@pytest.mark.asyncio
async def test_invalidate_cache(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    await reconfigure(tmp_path, "oidc")
    mock_ldap.add_test_user(UserInfo(username="ldap-user", uid=2000))
    token = create_upstream_oidc_jwt("ldap-user")

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403

    # Add the group entry and try again. This should immediately succeed
    # because the cache is invalidated. If the cache were not invalidated, it
    # would fail again.
    mock_ldap.add_test_group_membership(
        "ldap-user", [Group(name="foo", id=1222)]
    )
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307


@pytest.mark.asyncio
async def test_member_dn(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    """Test group membership attributes containing full user DNs."""
    config = await reconfigure(tmp_path, "oidc-memberdn")
    assert config.ldap
    assert config.ldap.group_search_by_dn
    token = create_upstream_oidc_jwt("ldap-user")
    mock_ldap.add_test_user(UserInfo(username="ldap-user", uid=2000, gid=1222))
    mock_ldap.add_test_group_membership(
        "ldap-user",
        [
            Group(name="foo", id=1222),
            Group(name="group-1", id=123123),
            Group(name="group-2", id=123442),
        ],
    )
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the data returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "ldap-user",
        "uid": 2000,
        "gid": 1222,
        "groups": [
            {"name": "foo", "id": 1222},
            {"name": "group-1", "id": 123123},
            {"name": "group-2", "id": 123442},
        ],
    }


@pytest.mark.asyncio
async def test_username_claim(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    """Uses an alternate configuration file with non-default claims."""
    config = await reconfigure(tmp_path, "oidc-claims")
    assert config.oidc
    assert config.oidc.username_claim != "uid"
    mock_ldap.add_test_user(
        UserInfo(username="alt-username", uid=2000, gid=1222)
    )
    mock_ldap.add_test_group_membership(
        "alt-username", [Group(name="foo", id=1222)]
    )
    claims = {config.oidc.username_claim: "alt-username"}
    token = create_upstream_oidc_jwt(**claims)

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the /auth/api/v1/user-info and /auth routes works and return
    # the correct information.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "alt-username"

    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "alt-username",
        "uid": 2000,
        "gid": 1222,
        "groups": [{"name": "foo", "id": 1222}],
    }


@pytest.mark.asyncio
async def test_unicode_name(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.ldap
    assert config.oidc
    token = create_upstream_oidc_jwt("some-user")
    mock_ldap.add_test_user(UserInfo(username="some-user", name="名字"))
    mock_ldap.add_test_group_membership(
        "some-user", [Group(name="foo", id=1222)]
    )

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the name as returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "some-user",
        "name": "名字",
        "groups": [{"name": "foo", "id": 1222}],
    }


@pytest.mark.asyncio
async def test_callback_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    caplog: pytest.LogCaptureFixture,
    mock_slack: MockSlackWebhook,
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
    assert r.status_code == 500
    assert "error_code: description" in r.text
    assert parse_log(caplog, ignore_debug=True) == [
        {
            "event": "Retrieving ID token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
            "token_url": config.oidc.token_url,
        },
        {
            "error": "Error retrieving ID token: error_code: description",
            "event": "Authentication provider failed",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "error",
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
    assert r.status_code == 500
    assert "Cannot contact authentication provider" in r.text

    # Now try a reply that returns 200 but doesn't have the field we need.
    respx_mock.post(config.oidc.token_url).respond(json={"foo": "bar"})
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert "No id_token in token reply" in r.text

    # Return invalid JSON, which should raise an error during JSON decoding.
    respx_mock.post(config.oidc.token_url).respond(content=b"foo")
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert "not valid JSON" in r.text

    # Finally, return invalid JSON and an error reply.
    respx_mock.post(config.oidc.token_url).respond(400, content=b"foo")
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert f"Response from {config.oidc.token_url} not valid JSON" in r.text

    # Most of these errors should be reported to Slack.
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Error retrieving ID token:"
                            " error_code: description"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Status 400 from POST "
                            "https://upstream.example.com/token"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCWebError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*URL*\nPOST https://upstream.example.com/token"
                        ),
                        "verbatim": True,
                    },
                },
            ],
            "attachments": [
                {
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": '*Response*\n```\n{"foo": "bar"}\n```',
                                "verbatim": True,
                            },
                        },
                    ]
                }
            ],
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: No id_token in token reply"
                            " from https://upstream.example.com/token"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Response from "
                            "https://upstream.example.com/token not valid JSON"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Response from "
                            "https://upstream.example.com/token not valid JSON"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
    ]


@pytest.mark.asyncio
async def test_connection_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
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
    assert r.status_code == 500
    assert "Cannot contact authentication provider" in r.text

    # This error should be reported to Slack.
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: ConnectError: Mock Error"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCWebError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*URL*\nPOST https://upstream.example.com/token"
                        ),
                        "verbatim": True,
                    },
                },
                {"type": "divider"},
            ]
        },
    ]


@pytest.mark.asyncio
async def test_verify_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.oidc
    token = create_upstream_oidc_jwt("some-user")
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
    assert r.status_code == 500
    assert "Cannot contact authentication provider" in r.text

    # This error should be reported to Slack.
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Status 404 from GET "
                            "https://upstream.example.com/.well-known"
                            "/jwks.json"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCWebError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*URL*\n"
                            "GET https://upstream.example.com/.well-known"
                            "/jwks.json"
                        ),
                        "verbatim": True,
                    },
                },
                {"type": "divider"},
            ]
        },
    ]


@pytest.mark.asyncio
async def test_invalid_username(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt("invalid@user")

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert "Invalid username in uid claim in token: invalid@user" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_double_username(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
    mock_slack: MockSlackWebhook,
) -> None:
    """Test error handling of a multivalued ``uid`` attribute."""
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(["one", "two"])

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 500
    assert "token verification failed" in r.text

    # This error should be reported to Slack.
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: OpenID Connect token"
                            " verification failed: Invalid uid claim in"
                            " token: ['one', 'two']"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
    ]


@pytest.mark.asyncio
async def test_no_valid_groups(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt("some-user")

    # Try authenticating with no LDAP entry and thus no valid groups.
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, no-store"
    assert r.headers["Content-Type"] == "text/html; charset=utf-8"
    assert "some-user is not a member of any authorized groups" in r.text
    assert config.error_footer
    assert config.error_footer in r.text

    # The user should not be logged in.
    r = await client.get("/auth", params={"scope": "user:token"})
    assert r.status_code == 401

    # Do the same with a valid LDAP entry but no groups.
    mock_ldap.add_test_user(UserInfo(username="some-user", uid=1222, gid=1234))
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert "some-user is not a member of any authorized groups" in r.text
    r = await client.get("/auth", params={"scope": "user:token"})
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_enrollment_url(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
) -> None:
    await reconfigure(tmp_path, "oidc-enrollment")
    token = create_upstream_oidc_jwt(None)

    r = await simulate_oidc_login(
        client, respx_mock, token, expect_enrollment=True
    )
    assert r.status_code == 307
    assert r.headers["Cache-Control"] == "no-cache, no-store"


@pytest.mark.asyncio
async def test_missing_username(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    """Test a missing username claim in the ID token but no enrollment URL."""
    await reconfigure(tmp_path, "oidc-claims")
    token = create_upstream_oidc_jwt(None)

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, no-store"
    assert "User is not enrolled" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []
