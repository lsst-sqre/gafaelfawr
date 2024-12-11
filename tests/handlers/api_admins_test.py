"""Tests for the ``/auth/api/v1/admins`` routes."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory

from ..support.cookies import set_session_cookie
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_admins(
    client: AsyncClient, factory: Factory, mock_slack: MockSlackWebhook
) -> None:
    r = await client.get("/auth/api/v1/admins")
    assert r.status_code == 401

    token_data = await create_session_token(factory)
    r = await client.get(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 403
    assert r.json()["detail"][0] == {
        "msg": "Token does not have required scope admin:token",
        "type": "permission_denied",
    }

    token_data = await create_session_token(factory, scopes={"admin:token"})
    r = await client.get(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert r.json() == [{"username": "admin"}]

    admin_service = factory.create_admin_service()
    await admin_service.add_admin(
        "example", actor="admin", ip_address="127.0.0.1"
    )

    r = await client.get(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 200
    assert r.json() == [{"username": "admin"}, {"username": "example"}]

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_add_delete(client: AsyncClient, factory: Factory) -> None:
    # Adding or deleting without authentication should fail.
    r = await client.post(
        "/auth/api/v1/admins", json={"username": "some-user"}
    )
    assert r.status_code == 401
    r = await client.delete("/auth/api/v1/admins/admin")
    assert r.status_code == 401

    # Adding or deleting without the appropriate scopes should fail.
    token_data = await create_session_token(factory, username="not-admin")
    csrf = await set_session_cookie(client, token_data.token)
    r = await client.post(
        "/auth/api/v1/admins",
        headers={"X-CSRF-Token": csrf},
        json={"username": "new-admin"},
    )
    assert r.status_code == 403
    assert r.json()["detail"][0] == {
        "msg": "Token does not have required scope admin:token",
        "type": "permission_denied",
    }
    r = await client.delete(
        "/auth/api/v1/admins/admin", headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 403
    assert r.json()["detail"][0] == {
        "msg": "Token does not have required scope admin:token",
        "type": "permission_denied",
    }

    # Adding without the appropriate CSRF token should fail, but with a CSRF
    # token should succeed.
    token_data = await create_session_token(factory, username="admin")
    csrf = await set_session_cookie(client, token_data.token)
    r = await client.post(
        "/auth/api/v1/admins", json={"username": "new-admin"}
    )
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "invalid_csrf"
    r = await client.post(
        "/auth/api/v1/admins",
        headers={"X-CSRF-Token": csrf},
        json={"username": "new-admin"},
    )
    assert r.status_code == 204
    r = await client.get("/auth/api/v1/admins")
    assert r.status_code == 200
    assert r.json() == [{"username": "admin"}, {"username": "new-admin"}]

    # Add the same user again. This should result in a reasonable failure and
    # not an internal server error.
    r = await client.post(
        "/auth/api/v1/admins",
        headers={"X-CSRF-Token": csrf},
        json={"username": "new-admin"},
    )
    assert r.status_code == 409

    # Deleting the user should fail without a CSRF code and should succeed
    # with one.
    r = await client.delete("/auth/api/v1/admins/admin")
    assert r.status_code == 403
    assert r.json()["detail"][0]["type"] == "invalid_csrf"
    r = await client.delete(
        "/auth/api/v1/admins/admin", headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 204
    r = await client.get("/auth/api/v1/admins")
    assert r.json() == [{"username": "new-admin"}]

    # We can still retrieve the list because we have a token with scope
    # admin:token, but since we (admin) were removed as an admin, we should no
    # longer be able to add new admins.
    r = await client.post(
        "/auth/api/v1/admins",
        headers={"X-CSRF-Token": csrf},
        json={"username": "another-admin"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_bootstrap(client: AsyncClient, config: Config) -> None:
    token = config.bootstrap_token.get_secret_value()

    r = await client.post(
        "/auth/api/v1/admins",
        headers={"Authorization": f"bearer {token}"},
        json={"username": "example"},
    )
    assert r.status_code == 204

    r = await client.get(
        "/auth/api/v1/admins", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == [{"username": "admin"}, {"username": "example"}]

    r = await client.delete(
        "/auth/api/v1/admins/admin",
        headers={"Authorization": f"bearer {token}"},
    )
    assert r.status_code == 204
    r = await client.get(
        "/auth/api/v1/admins", headers={"Authorization": f"bearer {token}"}
    )
    assert r.status_code == 200
    assert r.json() == [{"username": "example"}]
