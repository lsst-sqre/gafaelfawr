"""Tets for the ``/auth/cadc`` routes."""

from __future__ import annotations

from datetime import timedelta

import pytest
from httpx import AsyncClient
from safir.datetime import current_datetime

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory
from gafaelfawr.models.enums import TokenType
from gafaelfawr.models.token import AdminTokenRequest, Token, TokenData


@pytest.mark.asyncio
async def test_userinfo(
    config: Config, client: AsyncClient, factory: Factory
) -> None:
    expires = current_datetime() + timedelta(days=7)
    request = AdminTokenRequest(
        username="bot-example",
        token_type=TokenType.service,
        uid=45613,
        expires=expires,
    )
    token_service = factory.create_token_service()
    token = await token_service.create_token_from_admin_request(
        request, TokenData.internal_token(), ip_address=None
    )

    r = await client.get(
        "/auth/cadc/userinfo", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == {
        "exp": int(expires.timestamp()),
        "preferred_username": "bot-example",
        "sub": "bot-example",
    }


@pytest.mark.asyncio
async def test_userinfo_errors(
    config: Config, client: AsyncClient, factory: Factory
) -> None:
    r = await client.get("/auth/cadc/userinfo")
    assert r.status_code == 401
    r = await client.get(
        "/auth/cadc/userinfo", headers={"Authorization": f"bearer {Token()!s}"}
    )
    assert r.status_code == 401
    r = await client.get(
        "/auth/cadc/userinfo", headers={"Authorization": "bearer blahblah"}
    )
    assert r.status_code == 401
