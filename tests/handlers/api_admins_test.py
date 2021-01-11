"""Tests for the ``/auth/api/v1/admins`` routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_admins(setup: SetupTest) -> None:
    r = await setup.client.get("/auth/api/v1/admins")
    assert r.status_code == 401

    token_data = await setup.create_session_token()
    r = await setup.client.get(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == {
        "msg": "Token does not have required scope admin:token",
        "type": "permission_denied",
    }

    token_data = await setup.create_session_token(scopes=["admin:token"])
    r = await setup.client.get(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert r.json() == [{"username": "admin"}]

    admin_service = setup.factory.create_admin_service()
    admin_service.add_admin("example", actor="admin", ip_address="127.0.0.1")

    r = await setup.client.get(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert r.json() == [{"username": "admin"}, {"username": "example"}]
