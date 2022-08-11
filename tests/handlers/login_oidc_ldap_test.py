"""Tests for LDAP and Firestore with OpenID Connect auth."""

from __future__ import annotations

from pathlib import Path

import pytest
import respx
from httpx import AsyncClient

from ..support.jwt import create_upstream_oidc_jwt
from ..support.ldap import MockLDAP
from ..support.oidc import simulate_oidc_login
from ..support.settings import reconfigure


@pytest.mark.asyncio
async def test_ldap(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc-ldap")
    assert config.ldap
    assert config.ldap.user_base_dn
    token = create_upstream_oidc_jwt(uid="ldap-user", groups=["admin"])
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
    assert r.headers["X-Auth-Request-Uid"] == "2000"
    assert r.headers["X-Auth-Request-Groups"] == "foo,group-1,group-2"


@pytest.mark.asyncio
async def test_no_name_email(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc-ldap-uid")
    assert config.ldap
    assert config.ldap.user_base_dn
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
        "email": token.claims["email"],
        "uid": 2000,
        "gid": 2000,
        "groups": [
            {"name": "foo", "id": 1222},
            {"name": "ldap-user", "id": 2000},
        ],
    }

    # Check that the headers returned by the auth endpoint are also correct.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "ldap-user"
    assert r.headers["X-Auth-Request-Email"] == token.claims["email"]
    assert r.headers["X-Auth-Request-Uid"] == "2000"
    assert r.headers["X-Auth-Request-Groups"] == "foo,ldap-user"


@pytest.mark.asyncio
async def test_gid(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc-ldap-gid")
    assert config.ldap
    assert config.ldap.user_base_dn
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
async def test_only_groups(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc-ldap-groups")
    assert config.ldap
    token = create_upstream_oidc_jwt(
        name="Some User", uid="ldap-user", groups=["admin"]
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
        "name": token.claims["name"],
        "email": token.claims["email"],
        "uid": int(token.claims["uidNumber"]),
        "groups": [{"name": "foo", "id": 1222}],
    }

    # Check that the headers returned by the auth endpoint are also correct.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "ldap-user"
    assert r.headers["X-Auth-Request-Email"] == token.claims["email"]
    assert r.headers["X-Auth-Request-Uid"] == token.claims["uidNumber"]
    assert r.headers["X-Auth-Request-Groups"] == "foo"


@pytest.mark.asyncio
async def test_missing_attrs(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc-ldap")
    assert config.ldap
    assert config.ldap.user_base_dn
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
    assert r.headers["X-Auth-Request-Uid"] == "2000"
    assert r.headers["X-Auth-Request-Groups"] == "foo"
