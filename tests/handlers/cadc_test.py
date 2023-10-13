"""Tets for the ``/auth/cadc`` routes."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from uuid import uuid5

import pytest
from httpx import AsyncClient
from safir.datetime import current_datetime

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenType,
)

from ..support.config import reconfigure


@pytest.mark.asyncio
async def test_userinfo(
    config: Config, client: AsyncClient, factory: Factory
) -> None:
    assert config.cadc_base_uuid
    expires = current_datetime() + timedelta(days=7)
    request = AdminTokenRequest(
        username="bot-example",
        token_type=TokenType.service,
        uid=45613,
        expires=expires,
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
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
        "sub": str(uuid5(config.cadc_base_uuid, "45613")),
    }


@pytest.mark.asyncio
async def test_userinfo_errors(
    config: Config, client: AsyncClient, factory: Factory, tmp_path: Path
) -> None:
    assert config.cadc_base_uuid

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

    # Create a token that doesn't have a UID. We cannot generate a UUID for
    # these, so they will produce an error.
    request = AdminTokenRequest(
        username="bot-example", token_type=TokenType.service
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_token_from_admin_request(
            request, TokenData.internal_token(), ip_address=None
        )
    r = await client.get(
        "/auth/cadc/userinfo", headers={"Authorization": f"bearer {token!s}"}
    )
    assert r.status_code == 403

    # Switch to a configuration that doesn't have CADC auth configuration.
    await reconfigure(tmp_path, "github-quota", factory)
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_token_from_admin_request(
            request, TokenData.internal_token(), ip_address=None
        )
    r = await client.get(
        "/auth/cadc/userinfo", headers={"Authorization": f"bearer {token!s}"}
    )
    assert r.status_code == 404
