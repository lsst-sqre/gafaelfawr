"""Tests for LDAP and Firestore with OpenID Connect auth."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import ANY

import pytest
import respx
from httpx import AsyncClient

from gafaelfawr.constants import GID_MIN, UID_USER_MIN
from gafaelfawr.factory import Factory

from ..support.config import reconfigure
from ..support.firestore import MockFirestore
from ..support.jwt import create_upstream_oidc_jwt
from ..support.ldap import MockLDAP
from ..support.logging import parse_log
from ..support.oidc import simulate_oidc_login


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
    token = create_upstream_oidc_jwt(uid="ldap-user")
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [
            {
                "displayName": ["LDAP User"],
                "mail": ["ldap-user@example.com", "foo@example.com"],
                "uidNumber": ["2000"],
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
    return_url = "https://example.com:4444/foo?a=bar&b=baz"

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
    config = await reconfigure(tmp_path, "oidc")
    assert config.ldap
    token = create_upstream_oidc_jwt()
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        token.claims["uid"],
        [{"uidNumber": ["2000"], "gidNumber": ["2001"]}],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        token.claims["uid"],
        [{"cn": ["foo"], "gidNumber": ["1222"]}],
    )
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
async def test_firestore(
    tmp_path: Path,
    factory: Factory,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
    mock_firestore: MockFirestore,
) -> None:
    config = await reconfigure(tmp_path, "oidc-firestore", factory)
    assert config.ldap
    assert config.oidc
    firestore_storage = factory.create_firestore_storage()
    await firestore_storage.initialize()
    token = create_upstream_oidc_jwt(uid="ldap-user")
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [{"displayName": ["LDAP User"], "mail": ["ldap-user@example.com"]}],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "other-user",
        [{"displayName": ["Other User"]}],
    )
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
    claims = {config.oidc.username_claim: "other-user"}
    token = create_upstream_oidc_jwt(**claims)
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "other-user",
        "name": "Other User",
        "uid": UID_USER_MIN + 1,
        "gid": UID_USER_MIN + 1,
        "groups": [
            {"name": "foo", "id": GID_MIN},
            {"name": "group-1", "id": GID_MIN + 1},
            {"name": "other-user", "id": UID_USER_MIN + 1},
        ],
    }


@pytest.mark.asyncio
async def test_no_name_email(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.ldap
    token = create_upstream_oidc_jwt(uid="ldap-user", groups=["admin"])
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [{"uidNumber": ["2000"]}],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "ldap-user",
        [{"cn": ["foo"], "gidNumber": ["1222"]}],
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
async def test_gid(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc-gid")
    assert config.ldap
    token = create_upstream_oidc_jwt(uid="ldap-user", groups=["admin"])
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [
            {
                "displayName": ["LDAP User"],
                "mail": ["ldap-user@example.com"],
                "uidNumber": ["2000"],
                "gidNumber": ["1045"],
            }
        ],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "ldap-user",
        [
            {"cn": ["foo"], "gidNumber": ["1045"]},
            {"cn": ["group-1"], "gidNumber": ["123123"]},
            {"cn": ["group-2"], "gidNumber": ["123442"]},
        ],
    )
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

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
            {"name": "foo", "id": 1045},
            {"name": "group-1", "id": 123123},
            {"name": "group-2", "id": 123442},
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
    config = await reconfigure(tmp_path, "oidc-gid")
    assert config.ldap
    token = create_upstream_oidc_jwt(uid="ldap-user", groups=["admin"])
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [
            {
                "displayName": ["LDAP User"],
                "mail": ["ldap-user@example.com"],
                "uidNumber": ["2000"],
                "gidNumber": ["1045"],
            }
        ],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "ldap-user",
        [{"cn": ["group-1"], "gidNumber": ["123123"]}],
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
        "name": "LDAP User",
        "email": "ldap-user@example.com",
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
    config = await reconfigure(tmp_path, "oidc")
    assert config.ldap
    token = create_upstream_oidc_jwt(
        uid="ldap-user", email=None, groups=["admin"]
    )
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [{"uidNumber": ["2000"]}],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "ldap-user",
        [{"cn": ["foo"], "gidNumber": ["1222"]}],
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
    config = await reconfigure(tmp_path, "oidc")
    assert config.ldap
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [{"uidNumber": ["2000"]}],
    )
    token = create_upstream_oidc_jwt(uid="ldap-user")

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403

    # Add the group entry.  This should immediately succeed because the cache
    # is invalidated.  If the cache were not invalidated, it would fail again.
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "ldap-user",
        [{"cn": ["foo"], "gidNumber": ["1222"]}],
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
    token = create_upstream_oidc_jwt(uid="ldap-user", groups=["admin"])
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [
            {
                "displayName": ["LDAP User"],
                "mail": ["ldap-user@example.com"],
                "uidNumber": ["2000"],
                "gidNumber": ["1222"],
            }
        ],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        f"{config.ldap.user_search_attr}=ldap-user,{config.ldap.user_base_dn}",
        [
            {"cn": ["foo"], "gidNumber": ["1222"]},
            {"cn": ["group-1"], "gidNumber": ["123123"]},
            {"cn": ["group-2"], "gidNumber": ["123442"]},
        ],
    )
    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the data returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "ldap-user",
        "name": "LDAP User",
        "email": "ldap-user@example.com",
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
    assert config.ldap
    assert config.oidc
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "alt-username",
        [
            {
                "displayName": ["LDAP User"],
                "mail": ["ldap-user@example.com"],
                "uidNumber": ["2000"],
                "gidNumber": ["1222"],
            }
        ],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "alt-username",
        [{"cn": ["foo"], "gidNumber": ["1222"]}],
    )
    claims = {config.oidc.username_claim: "alt-username"}
    token = create_upstream_oidc_jwt(**claims)

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the /auth/api/v1/user-info and /auth routes works and return
    # the correct information.  uid will be set to some-user, uidNumber will
    # be set to 1000, and isMemberOf will include just the test group, so
    # we'll know if we read the alternate claim names correctly instead.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "alt-username"

    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": "alt-username",
        "name": "LDAP User",
        "email": "ldap-user@example.com",
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
    token = create_upstream_oidc_jwt()
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        token.claims[config.oidc.username_claim],
        [
            {
                "displayName": ["名字"],
                "uidNumber": ["2000"],
                "gidNumber": ["1222"],
            }
        ],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        token.claims[config.oidc.username_claim],
        [{"cn": ["foo"], "gidNumber": ["1222"]}],
    )

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 307

    # Check that the name as returned from the user-info API is correct.
    r = await client.get("/auth/api/v1/user-info")
    assert r.status_code == 200
    assert r.json() == {
        "username": token.claims[config.oidc.username_claim],
        "name": "名字",
        "uid": 2000,
        "gid": 1222,
        "groups": [{"name": "foo", "id": 1222}],
    }
