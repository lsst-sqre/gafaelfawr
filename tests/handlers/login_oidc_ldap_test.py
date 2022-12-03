"""Tests for LDAP and Firestore with OpenID Connect auth."""

from __future__ import annotations

from pathlib import Path

import pytest
import respx
from httpx import AsyncClient

from gafaelfawr.constants import GID_MIN, UID_USER_MIN
from gafaelfawr.factory import Factory

from ..support.config import reconfigure
from ..support.firestore import MockFirestore
from ..support.jwt import create_upstream_oidc_jwt
from ..support.ldap import MockLDAP
from ..support.oidc import simulate_oidc_login


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


@pytest.mark.asyncio
async def test_ldap_firestore(
    tmp_path: Path,
    factory: Factory,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
    mock_firestore: MockFirestore,
) -> None:
    config = await reconfigure(tmp_path, "oidc-ldap-firestore", factory)
    assert config.oidc
    assert config.ldap
    assert config.ldap.user_base_dn
    firestore_storage = factory.create_firestore_storage()
    await firestore_storage.initialize()
    token = create_upstream_oidc_jwt(uid="ldap-user", groups=["admin"])
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "ldap-user",
        [{"displayName": ["LDAP User"], "mail": ["ldap-user@example.com"]}],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "ldap-user",
        [{"cn": ["foo"]}, {"cn": ["group-1"]}, {"cn": ["group-2"]}],
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
        "uid": UID_USER_MIN,
        "gid": UID_USER_MIN,
        "groups": [
            {"name": "foo", "id": GID_MIN},
            {"name": "group-1", "id": GID_MIN + 1},
            {"name": "group-2", "id": GID_MIN + 2},
            {"name": "ldap-user", "id": UID_USER_MIN},
        ],
    }

    # Check that the headers returned by the auth endpoint are also correct.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "ldap-user"
    assert r.headers["X-Auth-Request-Email"] == "ldap-user@example.com"


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
async def test_gid_group_lookup(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
) -> None:
    """Test separate lookup of the primary group."""
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
    assert "X-Auth-Request-Email" not in r.headers
