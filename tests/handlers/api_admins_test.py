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


@pytest.mark.asyncio
async def test_add_delete(setup: SetupTest) -> None:
    r = await setup.client.post(
        "/auth/api/v1/admins", json={"username": "some-user"}
    )
    assert r.status_code == 401
    r = await setup.client.delete("/auth/api/v1/admins/admin")
    assert r.status_code == 401

    token_data = await setup.create_session_token(username="admin")
    csrf = await setup.login(token_data.token)
    r = await setup.client.post(
        "/auth/api/v1/admins",
        headers={"X-CSRF-Token": csrf},
        json={"username": "new-admin"},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == {
        "msg": "Token does not have required scope admin:token",
        "type": "permission_denied",
    }
    r = await setup.client.delete(
        "/auth/api/v1/admins/admin", headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 403
    assert r.json()["detail"] == {
        "msg": "Token does not have required scope admin:token",
        "type": "permission_denied",
    }

    token_data = await setup.create_session_token(
        username="admin", scopes=["admin:token"]
    )
    csrf = await setup.login(token_data.token)
    r = await setup.client.post(
        "/auth/api/v1/admins", json={"username": "new-admin"}
    )
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "invalid_csrf"
    r = await setup.client.post(
        "/auth/api/v1/admins",
        headers={"X-CSRF-Token": csrf},
        json={"username": "new-admin"},
    )
    assert r.status_code == 204
    r = await setup.client.get("/auth/api/v1/admins")
    assert r.status_code == 200
    assert r.json() == [{"username": "admin"}, {"username": "new-admin"}]
    r = await setup.client.delete("/auth/api/v1/admins/admin")
    assert r.status_code == 403
    assert r.json()["detail"]["type"] == "invalid_csrf"
    r = await setup.client.delete(
        "/auth/api/v1/admins/admin", headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 204
    r = await setup.client.get("/auth/api/v1/admins")
    assert r.json() == [{"username": "new-admin"}]

    # We can still retrieve the list because we have a token with scope
    # admin:token, but since we (admin) were removed as an admin, we should no
    # longer be able to add new admins.
    r = await setup.client.post(
        "/auth/api/v1/admins",
        headers={"X-CSRF-Token": csrf},
        json={"username": "another-admin"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_bootstrap(setup: SetupTest) -> None:
    token = str(setup.config.bootstrap_token)

    r = await setup.client.post(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token}"},
        json={"username": "example"},
    )
    assert r.status_code == 204

    r = await setup.client.get(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json() == [{"username": "admin"}, {"username": "example"}]

    r = await setup.client.delete(
        "/auth/api/v1/admins/admin",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 204
    r = await setup.client.get(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json() == [{"username": "example"}]
