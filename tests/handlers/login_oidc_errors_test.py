"""Tests for the /login route with OpenID Connect."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import ANY
from urllib.parse import parse_qs, urljoin, urlparse

import pytest
import respx
from _pytest.logging import LogCaptureFixture
from httpx import AsyncClient, ConnectError
from safir.testing.slack import MockSlackWebhook

from ..support.config import reconfigure
from ..support.jwt import create_upstream_oidc_jwt
from ..support.ldap import MockLDAP
from ..support.logging import parse_log
from ..support.oidc import mock_oidc_provider_token, simulate_oidc_login


@pytest.mark.asyncio
async def test_callback_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    caplog: LogCaptureFixture,
    mock_slack: MockSlackWebhook,
) -> None:
    """Test an error return from the OIDC token endpoint."""
    config = await reconfigure(tmp_path, "oidc")
    assert config.oidc
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Build an error response to return from the OIDC token URL and register
    # it as a result.
    response = {
        "error": "error_code",
        "error_description": "description",
    }
    respx_mock.post(config.oidc.token_url).respond(400, json=response)

    # Simulate the return from the OpenID Connect provider.
    caplog.clear()
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert "error_code: description" in r.text
    assert parse_log(caplog, ignore_debug=True) == [
        {
            "event": "Retrieving ID token",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "info",
            "token_url": config.oidc.token_url,
        },
        {
            "error": "Error retrieving ID token: error_code: description",
            "event": "Authentication provider failed",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": ANY,
                "remoteIp": "127.0.0.1",
            },
            "return_url": return_url,
            "severity": "error",
        },
    ]

    # Change the mock error response to not contain an error.  We should then
    # internally raise the exception for the return status, which should
    # translate into an internal server error.
    respx_mock.post(config.oidc.token_url).respond(400, json={"foo": "bar"})
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert "Cannot contact authentication provider" in r.text

    # Now try a reply that returns 200 but doesn't have the field we need.
    respx_mock.post(config.oidc.token_url).respond(json={"foo": "bar"})
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert "No id_token in token reply" in r.text

    # Return invalid JSON, which should raise an error during JSON decoding.
    respx_mock.post(config.oidc.token_url).respond(content=b"foo")
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert "not valid JSON" in r.text

    # Finally, return invalid JSON and an error reply.
    respx_mock.post(config.oidc.token_url).respond(400, content=b"foo")
    r = await client.get("/login", params={"rd": return_url})
    query = parse_qs(urlparse(r.headers["Location"]).query)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert f"Response from {config.oidc.token_url} not valid JSON" in r.text

    # Most of these errors should be reported to Slack.
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Error retrieving ID token:"
                            " error_code: description"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Status 400 from POST "
                            "https://upstream.example.com/token"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCWebError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*URL*\nPOST https://upstream.example.com/token"
                        ),
                        "verbatim": True,
                    },
                },
            ],
            "attachments": [
                {
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": '*Response*\n```\n{"foo": "bar"}\n```',
                                "verbatim": True,
                            },
                        },
                    ]
                }
            ],
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: No id_token in token reply"
                            " from https://upstream.example.com/token"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Response from "
                            "https://upstream.example.com/token not valid JSON"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Response from "
                            "https://upstream.example.com/token not valid JSON"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
    ]


@pytest.mark.asyncio
async def test_connection_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.oidc
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Register a connection error for the callback request to the OIDC
    # provider and check that an appropriate error is shown to the user.
    token_url = config.oidc.token_url
    respx_mock.post(token_url).mock(side_effect=ConnectError)
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert "Cannot contact authentication provider" in r.text

    # This error should be reported to Slack.
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: ConnectError: Mock Error"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCWebError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*URL*\nPOST https://upstream.example.com/token"
                        ),
                        "verbatim": True,
                    },
                },
                {"type": "divider"},
            ]
        },
    ]


@pytest.mark.asyncio
async def test_verify_error(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(groups=["admin"])
    assert config.oidc
    issuer = config.oidc.issuer
    config_url = urljoin(issuer, "/.well-known/openid-configuration")
    jwks_url = urljoin(issuer, "/.well-known/jwks.json")
    respx_mock.get(config_url).respond(404)
    respx_mock.get(jwks_url).respond(404)
    await mock_oidc_provider_token(respx_mock, "some-code", token)
    return_url = "https://example.com/foo"

    r = await client.get("/login", params={"rd": return_url})
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Returning from OpenID Connect login should fail because we haven't
    # registered the signing key, and therefore attempting to retrieve it will
    # fail, causing a token verification error.
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 500
    assert "Cannot contact authentication provider" in r.text

    # This error should be reported to Slack.
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Status 404 from GET "
                            "https://upstream.example.com/.well-known"
                            "/jwks.json"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCWebError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "*URL*\n"
                            "GET https://upstream.example.com/.well-known"
                            "/jwks.json"
                        ),
                        "verbatim": True,
                    },
                },
                {"type": "divider"},
            ]
        },
    ]


@pytest.mark.asyncio
async def test_invalid_username(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(sub="invalid@user", uid="invalid@user")

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert "Invalid username in uid claim in token: invalid@user" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_double_username(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_ldap: MockLDAP,
    mock_slack: MockSlackWebhook,
) -> None:
    """Test error handling of a multivalued ``uid`` attribute."""
    config = await reconfigure(tmp_path, "oidc")
    token = create_upstream_oidc_jwt(uid=["one", "two"])
    assert config.ldap
    mock_ldap.add_entries_for_test(
        config.ldap.user_base_dn,
        config.ldap.user_search_attr,
        "one",
        [{"uidNumber": ["2000"]}],
    )
    mock_ldap.add_entries_for_test(
        config.ldap.group_base_dn,
        "member",
        "one",
        [{"cn": ["foo"], "gidNumber": ["1222"]}],
    )

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 500
    assert "token verification failed" in r.text

    # This error should be reported to Slack.
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: OpenID Connect token"
                            " verification failed: Invalid uid claim in"
                            " token: ['one', 'two']"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nOIDCError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                    ],
                },
                {"type": "divider"},
            ]
        },
    ]


@pytest.mark.asyncio
async def test_no_valid_groups(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
    mock_ldap: MockLDAP,
) -> None:
    config = await reconfigure(tmp_path, "oidc")
    assert config.oidc
    token = create_upstream_oidc_jwt()

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, no-store"
    assert r.headers["Content-Type"] == "text/html; charset=utf-8"
    username = token.claims[config.oidc.username_claim]
    assert f"{username} is not a member of any authorized groups" in r.text
    assert config.error_footer
    assert config.error_footer in r.text

    # The user should not be logged in.
    r = await client.get("/auth", params={"scope": "user:token"})
    assert r.status_code == 401

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_enrollment_url(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
) -> None:
    await reconfigure(tmp_path, "oidc-enrollment")
    token = create_upstream_oidc_jwt(groups=["admin"])

    r = await simulate_oidc_login(
        client, respx_mock, token, expect_enrollment=True
    )
    assert r.status_code == 307
    assert r.headers["Cache-Control"] == "no-cache, no-store"


@pytest.mark.asyncio
async def test_missing_username(
    tmp_path: Path,
    client: AsyncClient,
    respx_mock: respx.Router,
    mock_slack: MockSlackWebhook,
) -> None:
    """Test a missing username claim in the ID token but no enrollment URL."""
    await reconfigure(tmp_path, "oidc-claims")
    token = create_upstream_oidc_jwt(groups=["admin"])

    r = await simulate_oidc_login(client, respx_mock, token)
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, no-store"
    assert "User is not enrolled" in r.text

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []
