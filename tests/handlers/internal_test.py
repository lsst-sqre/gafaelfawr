"""Tests for the checkerboard.handlers.internal.index module and routes."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory
from gafaelfawr.models.userinfo import Group, UserInfo

from ..support.config import reconfigure
from ..support.constants import TEST_HOSTNAME
from ..support.ldap import MockLDAP
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_get_index(client: AsyncClient, config: Config) -> None:
    r = await client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "gafaelfawr"
    assert isinstance(data["version"], str)
    assert isinstance(data["description"], str)
    assert isinstance(data["repository_url"], str)
    assert isinstance(data["documentation_url"], str)


@pytest.mark.asyncio
async def test_health(
    app: FastAPI, client: AsyncClient, factory: Factory, mock_ldap: MockLDAP
) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "healthy"}

    # Create a session token so that Redis will also be tested.
    token = await create_session_token(factory)
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "healthy"}

    # Configure LDAP so that we'll also do LDAP lookups. The test should still
    # pass because successful LDAP lookups are optional as long as the LDAP
    # server is responding.
    await reconfigure("oidc")
    token_service = factory.create_token_service()
    await token_service.delete_token(
        token.token.key, token, token.username, ip_address="127.0.0.1"
    )
    token = await create_session_token(factory)
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "healthy"}

    # Add the entries for the test user and try again.
    mock_ldap.add_test_user(
        UserInfo(username=token.username, uid=2000, gid=1222)
    )
    mock_ldap.add_test_group_membership(
        token.username, [Group(name="foo", id=1222)]
    )
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "healthy"}

    # Finally, force a health check failure by dropping the tokens table,
    # which should produce database errors.
    async with factory.session.begin():
        await factory.session.execute(text("DROP TABLE token CASCADE"))
    base_url = f"https://{TEST_HOSTNAME}"
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url=base_url) as c:
        r = await c.get("/health")
    assert r.status_code == 500
