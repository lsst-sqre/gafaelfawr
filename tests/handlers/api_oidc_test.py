"""Tests for managing OpenID Connect clients."""

from datetime import UTC, datetime
from unittest.mock import ANY

import pytest
from httpx import AsyncClient
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.factory import Factory
from gafaelfawr.models.oidc import OIDCClientWithSecret
from gafaelfawr.models.state import State

from ..support.constants import TEST_HOSTNAME
from ..support.cookies import clear_session_cookie, set_session_cookie
from ..support.tokens import create_session_token


@pytest.mark.parametrize("config", ["github-oidc-server"], indirect=True)
@pytest.mark.asyncio
async def test_lifecycle(
    client: AsyncClient, factory: Factory, mock_slack: MockSlackWebhook
) -> None:
    token_data = await create_session_token(factory, scopes={"admin:oidc"})
    headers = {"Authorization": f"Bearer {token_data.token}"}
    return_uri = "https://foo.example.com/service/"
    url_prefix = f"https://{TEST_HOSTNAME}/auth/api/v1/oidc-clients"
    start = datetime.now(tz=UTC).replace(microsecond=0)

    r = await client.post(
        "/auth/api/v1/oidc-clients",
        json={"return_uri": return_uri, "description": "Test client"},
        headers=headers,
    )
    now = datetime.now(tz=UTC)
    assert r.status_code == 201
    client_json = r.json()
    oidc_client = OIDCClientWithSecret.model_validate(client_json)
    expected_url = f"{url_prefix}/{oidc_client.client_id}"
    expected = {
        "client_id": oidc_client.client_id,
        "client_secret": oidc_client.client_secret.get_secret_value(),
        "return_uri": return_uri,
        "description": "Test client",
        "created": ANY,
        "last_modified": client_json["created"],
        "last_modified_by": token_data.username,
        "url": expected_url,
    }
    assert client_json == expected
    assert start <= oidc_client.created <= now
    assert r.headers["Location"] == expected_url

    # Retrieving the client will show the same fields except for the client
    # secret, which can no longer be retrieved since it is stored hashed.
    del expected["client_secret"]
    r = await client.get(expected_url, headers=headers)
    assert r.status_code == 200
    assert r.json() == expected

    r = await client.get("/auth/api/v1/oidc-clients", headers=headers)
    assert r.status_code == 200
    assert r.json() == [expected]

    return_uri = "https://foo.example.com/other-service"
    start = datetime.now(tz=UTC).replace(microsecond=0)
    r = await client.patch(
        expected_url,
        json={
            "return_uri": return_uri,
            "description": "Updated description",
            "notes": "Some random notes\nwhich can contain newlines",
        },
        headers=headers,
    )
    now = datetime.now(tz=UTC)
    assert r.status_code == 200
    client_json = r.json()
    new_expected = {
        "client_id": oidc_client.client_id,
        "return_uri": return_uri,
        "description": "Updated description",
        "notes": "Some random notes\nwhich can contain newlines",
        "created": expected["created"],
        "last_modified": ANY,
        "last_modified_by": token_data.username,
        "url": expected_url,
    }
    assert client_json == new_expected
    last_modified = datetime.fromisoformat(client_json["last_modified"])
    assert start <= last_modified <= now

    r = await client.get(expected_url, headers=headers)
    assert r.status_code == 200
    assert r.json() == new_expected
    r = await client.get("/auth/api/v1/oidc-clients", headers=headers)
    assert r.status_code == 200
    assert r.json() == [new_expected]

    r = await client.delete(expected_url, headers=headers)
    assert r.status_code == 204
    r = await client.get(expected_url, headers=headers)
    assert r.status_code == 404
    r = await client.get("/auth/api/v1/oidc-clients", headers=headers)
    assert r.status_code == 200
    assert r.json() == []

    # No Slack messages logged.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-oidc-server"], indirect=True)
@pytest.mark.asyncio
async def test_auth_required(
    client: AsyncClient, factory: Factory, mock_slack: MockSlackWebhook
) -> None:
    token_data = await create_session_token(factory, scopes={"admin:oidc"})
    token = token_data.token
    csrf = await set_session_cookie(client, token)

    # Create one valid client with cookie authentication.
    r = await client.post(
        "/auth/api/v1/oidc-clients",
        headers={"X-CSRF-Token": csrf},
        json={"return_uri": "https://example.com", "description": "Test"},
    )
    assert r.status_code == 201
    oidc_client_url = r.headers["Location"]

    # Replace the cookie with one containing the CSRF token but not the
    # authentication token.
    clear_session_cookie(client)
    client.cookies[COOKIE_NAME] = State(csrf=csrf).to_cookie()

    r = await client.post(
        "/auth/api/v1/oidc-clients",
        headers={"X-CSRF-Token": csrf},
        json={"return_uri": "https://example.com", "description": "Test"},
    )
    assert r.status_code == 401

    r = await client.get("/auth/api/v1/oidc-clients")
    assert r.status_code == 401
    r = await client.get(oidc_client_url)
    assert r.status_code == 401
    r = await client.patch(
        oidc_client_url,
        headers={"X-CSRF-Token": csrf},
        json={"return_uri": "https://example.org", "description": "Update"},
    )
    assert r.status_code == 401
    r = await client.delete(oidc_client_url, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-oidc-server"], indirect=True)
@pytest.mark.asyncio
async def test_csrf_required(
    client: AsyncClient, factory: Factory, mock_slack: MockSlackWebhook
) -> None:
    token_data = await create_session_token(factory, scopes={"admin:oidc"})
    csrf = await set_session_cookie(client, token_data.token)

    r = await client.post(
        "/auth/api/v1/oidc-clients",
        json={"return_uri": "https://example.com", "description": "Test"},
    )
    assert r.status_code == 403
    r = await client.post(
        "/auth/api/v1/oidc-clients",
        headers={"X-CSRF-Token": f"XXX{csrf}"},
        json={"return_uri": "https://example.com", "description": "Test"},
    )
    assert r.status_code == 403

    # Create a valid client for additional tests.
    r = await client.post(
        "/auth/api/v1/oidc-clients",
        headers={"X-CSRF-Token": csrf},
        json={"return_uri": "https://example.com", "description": "Test"},
    )
    assert r.status_code == 201
    oidc_client_url = r.headers["Location"]

    r = await client.patch(
        oidc_client_url,
        json={"return_uri": "https://example.org", "description": "Update"},
    )
    assert r.status_code == 403
    r = await client.delete(oidc_client_url)
    assert r.status_code == 403

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.parametrize("config", ["github-oidc-server"], indirect=True)
@pytest.mark.asyncio
async def test_unauthorized(
    client: AsyncClient, factory: Factory, mock_slack: MockSlackWebhook
) -> None:
    token_data = await create_session_token(factory)
    admin_data = await create_session_token(factory, scopes={"admin:oidc"})

    r = await client.get(
        "/auth/api/v1/oidc-clients",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 403
    r = await client.post(
        "/auth/api/v1/oidc-clients",
        headers={"Authorization": f"bearer {token_data.token}"},
        json={"return_uri": "https://example.com", "description": "Test"},
    )
    assert r.status_code == 403

    # Create a valid token for testing.
    r = await client.post(
        "/auth/api/v1/oidc-clients",
        headers={"Authorization": f"bearer {admin_data.token}"},
        json={"return_uri": "https://example.com", "description": "Test"},
    )
    assert r.status_code == 201
    oidc_client_url = r.headers["Location"]

    r = await client.patch(
        oidc_client_url,
        headers={"Authorization": f"bearer {token_data.token}"},
        json={"return_uri": "https://example.org", "description": "Update"},
    )
    assert r.status_code == 403
    r = await client.delete(
        oidc_client_url,
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert r.status_code == 403

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []
