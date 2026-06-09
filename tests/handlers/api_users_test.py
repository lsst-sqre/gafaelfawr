"""Tests for the user information API."""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from safir.testing.data import Data

from gafaelfawr.config import Config
from gafaelfawr.constants import GID_MIN, UID_USER_MIN
from gafaelfawr.factory import Factory
from gafaelfawr.models.token import TokenData
from gafaelfawr.models.userinfo import Group, UserInfo

from ..support.firestore import MockFirestore
from ..support.ldap import MockLDAP
from ..support.tokens import create_session_token


@pytest_asyncio.fixture
async def admin_token(factory: Factory) -> TokenData:
    return await create_session_token(
        factory, username="admin", scopes={"admin:userinfo"}
    )


@pytest.mark.parametrize("config", ["oidc"], indirect=True)
@pytest.mark.asyncio
async def test_list_users(
    *,
    data: Data,
    admin_token: TokenData,
    client: AsyncClient,
    mock_ldap: MockLDAP,
) -> None:
    headers = {"Authorization": f"Bearer {admin_token.token}"}
    mock_ldap.load_test_data(data, "ldap/users")

    r = await client.get("/auth/api/v1/users", headers=headers)
    assert r.status_code == 200
    assert r.json()
    data.assert_json_matches(r.json(), "api/users")


@pytest.mark.parametrize("config", ["oidc-firestore"], indirect=True)
@pytest.mark.asyncio
async def test_list_users_firestore(
    *,
    data: Data,
    admin_token: TokenData,
    client: AsyncClient,
    mock_ldap: MockLDAP,
) -> None:
    headers = {"Authorization": f"Bearer {admin_token.token}"}
    mock_ldap.load_test_data(data, "ldap/users")

    # Initially, there will be GIDs for the explicitly listed groups, but not
    # UIDs or GIDs for any of the users since no entries exist in Firestore.
    r = await client.get("/auth/api/v1/users", headers=headers)
    assert r.status_code == 200
    data.assert_json_matches(r.json(), "api/users-unallocated")

    # Force UID allocation for each of the users.
    for user in data.read_json("api/users-unallocated"):
        username = user["username"]
        r = await client.get(f"/auth/api/v1/users/{username}", headers=headers)
        assert r.status_code == 200

    # Now, there should be UIDs and GIDs for all of the users that have any
    # LDAP attributes.
    r = await client.get("/auth/api/v1/users", headers=headers)
    assert r.status_code == 200
    data.assert_json_matches(r.json(), "api/users-firestore")


@pytest.mark.parametrize("config", ["oidc"], indirect=True)
@pytest.mark.asyncio
async def test_userinfo_basic(
    *,
    config: Config,
    admin_token: TokenData,
    client: AsyncClient,
    factory: Factory,
    mock_ldap: MockLDAP,
) -> None:
    assert config.ldap
    headers = {"Authorization": f"bearer {admin_token.token}"}
    mock_ldap.add_test_user(
        UserInfo(username="some-user", name="Some user", uid=2000, gid=1045)
    )
    mock_ldap.add_test_group_membership(
        "some-user", [Group(name="foo", id=1222)]
    )

    # We should now be able to get user information for that user without
    # having a token for that user, using the admin token.
    r = await client.get("/auth/api/v1/users/some-user", headers=headers)
    assert r.status_code == 200
    assert r.json() == {
        "username": "some-user",
        "name": "Some user",
        "uid": 2000,
        "gid": 1045,
        "groups": [{"id": 1222, "name": "foo"}],
    }

    # Getting the information for the admin user should return just the
    # username since the user doesn't exist in LDAP.
    r = await client.get(
        f"/auth/api/v1/users/{admin_token.username}", headers=headers
    )
    assert r.status_code == 200
    assert r.json() == {"username": admin_token.username}


@pytest.mark.parametrize("config", ["oidc-firestore"], indirect=True)
@pytest.mark.asyncio
async def test_userinfo_firestore(
    *,
    config: Config,
    client: AsyncClient,
    factory: Factory,
    mock_ldap: MockLDAP,
    mock_firestore: MockFirestore,
) -> None:
    assert config.ldap
    firestore_storage = factory.create_firestore_storage()
    await firestore_storage.initialize()

    # Create an admin token and use it to set up quotas via an override, which
    # saves having to add quota details to the test configuration and change a
    # lot of user info output in other tests.
    token_data = await create_session_token(
        factory, username="admin", scopes={"admin:token", "admin:userinfo"}
    )
    headers = {"Authorization": f"bearer {token_data.token}"}
    r = await client.put(
        "/auth/api/v1/quota-overrides",
        json={
            "default": {"api": {"test": 10}},
            "groups": {"foo": {"api": {"test": 5}}},
        },
        headers=headers,
    )
    assert r.status_code == 200

    # some-user will be the user for which we retrieve user information. Add
    # them without UID and GID information.
    mock_ldap.add_test_user(UserInfo(username="some-user", name="Some user"))
    mock_ldap.add_test_group_membership(
        "some-user", [Group(name="foo", id=1111)], omit_gid=True
    )

    # We should now be able to get user information for that user, including
    # Firestore-assigned UID and GID and quota information based on the
    # override.
    r = await client.get("/auth/api/v1/users/some-user", headers=headers)
    assert r.status_code == 200
    assert r.json() == {
        "username": "some-user",
        "name": "Some user",
        "uid": UID_USER_MIN,
        "gid": UID_USER_MIN,
        "groups": [
            {"id": GID_MIN, "name": "foo"},
            {"id": UID_USER_MIN, "name": "some-user"},
        ],
        "quota": {"api": {"test": 15}},
    }

    # Getting the information for the admin user should return just the
    # username and default quota but no other information since the user
    # doesn't exist in LDAP.
    r = await client.get("/auth/api/v1/users/admin", headers=headers)
    assert r.status_code == 200
    assert r.json() == {"username": "admin", "quota": {"api": {"test": 10}}}

    # Likewise for some other random user.
    r = await client.get("/auth/api/v1/users/other-user", headers=headers)
    assert r.status_code == 200
    assert r.json() == {
        "username": "other-user",
        "quota": {"api": {"test": 10}},
    }


@pytest.mark.asyncio
async def test_userinfo_github(
    admin_token: TokenData, client: AsyncClient, factory: Factory
) -> None:
    """Test GitHub handling of user listing endpoints.

    When configured with GitHub, any attempt to access the users endpoint
    directly should fail with 404.
    """
    username = admin_token.username
    headers = {"Authorization": f"bearer {admin_token.token}"}

    r = await client.get("/auth/api/v1/users", headers=headers)
    assert r.status_code == 404

    r = await client.get(f"/auth/api/v1/users/{username}", headers=headers)
    assert r.status_code == 404
