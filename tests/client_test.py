"""Test integration with the Gafaelfawr client.

These tests access the Gafaelfawr API via the Gafaelfawr client to test
interoperability between the client and the server.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import ANY

import pytest
import respx
from httpx import AsyncClient
from rubin.repertoire import (
    Discovery,
    DiscoveryClient,
    register_mock_discovery,
)
from safir.testing.data import Data

from gafaelfawr.factory import Factory
from gafaelfawr.models.token import Token, TokenUserInfo
from rubin.gafaelfawr import GafaelfawrClient, GafaelfawrGroup, create_token

from .support.ldap import MockLDAP


@pytest.fixture
def mock_discovery(
    data: Data, respx_mock: respx.Router, monkeypatch: pytest.MonkeyPatch
) -> Discovery:
    monkeypatch.setenv("REPERTOIRE_BASE_URL", "https://example.com/repertoire")
    return register_mock_discovery(respx_mock, data.path("discovery.json"))


@pytest.fixture
def gafaelfawr_client(
    client: AsyncClient, mock_discovery: Discovery
) -> GafaelfawrClient:
    # Use a separate discovery client with its own AsyncClient because the
    # AsyncClient the Gafaelfawr client is using is bound to a specific
    # FastAPI app.
    discovery = DiscoveryClient()
    return GafaelfawrClient(client, discovery_client=discovery)


@pytest.mark.parametrize("config", ["github-quota"], indirect=True)
@pytest.mark.asyncio
async def test_get_user_info(
    *,
    data: Data,
    client: AsyncClient,
    factory: Factory,
    gafaelfawr_client: GafaelfawrClient,
) -> None:
    user_info = data.read_pydantic(TokenUserInfo, "userinfo/example")
    token_service = factory.create_token_service()
    token = await token_service.create_session_token(
        user_info, scopes={"admin:userinfo"}, ip_address="127.0.0.1"
    )

    result = await gafaelfawr_client.get_user_info(str(token))
    data.assert_pydantic_matches(result, "client/userinfo-example")


@pytest.mark.parametrize("config", ["oidc"], indirect=True)
@pytest.mark.asyncio
async def test_get_user_info_ldap(
    *,
    data: Data,
    client: AsyncClient,
    factory: Factory,
    gafaelfawr_client: GafaelfawrClient,
    mock_ldap: MockLDAP,
) -> None:
    token_service = factory.create_token_service()
    token = await token_service.create_session_token(
        TokenUserInfo(username="example"),
        scopes={"admin:userinfo"},
        ip_address="127.0.0.1",
    )
    mock_ldap.load_data_for_test(data, "ldap/one-user")

    result = await gafaelfawr_client.get_user_info(str(token), "ldap")
    data.assert_pydantic_matches(result, "client/userinfo-ldap")


@pytest.mark.asyncio
async def test_create_service_token(
    client: AsyncClient, factory: Factory, gafaelfawr_client: GafaelfawrClient
) -> None:
    token_service = factory.create_token_service()
    admin_token = await token_service.create_session_token(
        TokenUserInfo(username="example"),
        scopes={"admin:token"},
        ip_address="127.0.0.1",
    )

    expires = datetime.now(tz=UTC) + timedelta(days=1)
    service_token = await gafaelfawr_client.create_service_token(
        str(admin_token),
        "bot-user",
        scopes=["read:all"],
        expires=expires,
        name="Some bot",
        uid=45613,
        gid=45612,
        groups=[GafaelfawrGroup(name="foo", id=12313)],
    )

    r = await client.get(
        "/auth/api/v1/user-info",
        headers={"Authorization": f"bearer {service_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "username": "bot-user",
        "name": "Some bot",
        "uid": 45613,
        "gid": 45612,
        "groups": [{"name": "foo", "id": 12313}],
    }

    r = await client.get(
        "/auth/api/v1/token-info",
        headers={"Authorization": f"bearer {service_token}"},
    )
    assert r.status_code == 200
    assert r.json() == {
        "token": Token.from_str(service_token).key,
        "username": "bot-user",
        "token_type": "service",
        "scopes": ["read:all"],
        "created": ANY,
        "expires": int(expires.timestamp()),
    }


def test_create_token() -> None:
    token = create_token()
    assert str(Token.from_str(token)) == token
