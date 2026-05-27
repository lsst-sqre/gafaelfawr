"""Tests for the IVOA GMS protocol."""

import pytest
from httpx import AsyncClient

from gafaelfawr.factory import Factory
from gafaelfawr.models.token import TokenUserInfo
from gafaelfawr.models.userinfo import Group

from ..support.cookies import set_session_cookie


@pytest.mark.asyncio
async def test_gms(client: AsyncClient, factory: Factory) -> None:
    user_info = TokenUserInfo(
        username="example",
        uid=1234,
        groups=[Group(name="foo", id=1111), Group(name="foobar", id=1112)],
    )
    token_service = factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=set(), ip_address="127.0.0.1"
    )

    r = await client.get(
        "/auth/gms", headers={"Authorization": f"Bearer {session_token}"}
    )
    assert r.status_code == 200
    assert r.text == "foo\nfoobar\n"

    r = await client.get(
        "/auth/gms",
        params=(("group", "foo"), ("group", "foobar")),
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert r.status_code == 200
    assert r.text == "foo\nfoobar\n"

    # Remaining tests are done using cookie authentication.
    await set_session_cookie(client, session_token)

    r = await client.get(
        "/auth/gms", params=(("group", "foo"), ("group", "bar"))
    )
    assert r.status_code == 200
    assert r.text == "foo\n"

    r = await client.get("/auth/gms", params={"group": "bar"})
    assert r.status_code == 200
    assert r.text == ""


@pytest.mark.asyncio
async def test_no_groups(client: AsyncClient, factory: Factory) -> None:
    user_info = TokenUserInfo(username="example", uid=1234)
    token_service = factory.create_token_service()
    session_token = await token_service.create_session_token(
        user_info, scopes=set(), ip_address="127.0.0.1"
    )

    r = await client.get(
        "/auth/gms", headers={"Authorization": f"Bearer {session_token}"}
    )
    assert r.status_code == 200
    assert r.text == ""

    r = await client.get(
        "/auth/gms",
        params={"group": "foo"},
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert r.status_code == 200
    assert r.text == ""


@pytest.mark.asyncio
async def test_auth_required(client: AsyncClient) -> None:
    r = await client.get("/auth/gms")
    assert r.status_code == 401
