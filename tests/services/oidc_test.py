"""Tests for the OpenID Connect server."""

from __future__ import annotations

import json
import os
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import ANY

import pytest
from cryptography.fernet import Fernet
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.config import OIDCClient
from gafaelfawr.exceptions import (
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
)
from gafaelfawr.factory import Factory
from gafaelfawr.models.oidc import (
    OIDCAuthorization,
    OIDCAuthorizationCode,
    OIDCScope,
)

from ..support.config import reconfigure
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_issue_code(tmp_path: Path, factory: Factory) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    config = await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    oidc_service = factory.create_oidc_service()
    token_data = await create_session_token(factory)
    token = token_data.token
    redirect_uri = "https://example.com/"

    assert config.oidc_server
    assert list(config.oidc_server.clients) == clients

    with pytest.raises(UnauthorizedClientError):
        await oidc_service.issue_code(
            client_id="unknown-client",
            redirect_uri=redirect_uri,
            token=token,
            scopes=[OIDCScope.openid],
        )

    code = await oidc_service.issue_code(
        client_id="some-id",
        redirect_uri=redirect_uri,
        token=token,
        scopes=[OIDCScope.openid, OIDCScope.profile],
    )
    encrypted_code = await factory.redis.get(f"oidc:{code.key}")
    assert encrypted_code
    fernet = Fernet(config.session_secret.encode())
    serialized_code = json.loads(fernet.decrypt(encrypted_code))
    assert serialized_code == {
        "code": {
            "key": code.key,
            "secret": code.secret,
        },
        "client_id": "some-id",
        "redirect_uri": redirect_uri,
        "token": {
            "key": token.key,
            "secret": token.secret,
        },
        "created_at": ANY,
        "scopes": ["openid", "profile"],
        "nonce": None,
    }
    now = time.time()
    assert now - 2 < serialized_code["created_at"] < now


@pytest.mark.asyncio
async def test_redeem_code(tmp_path: Path, factory: Factory) -> None:
    clients = [
        OIDCClient(client_id="client-1", client_secret="client-1-secret"),
        OIDCClient(client_id="client-2", client_secret="client-2-secret"),
    ]
    config = await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    assert config.oidc_server
    oidc_service = factory.create_oidc_service()
    token_data = await create_session_token(factory)
    token = token_data.token
    redirect_uri = "https://example.com/"
    code = await oidc_service.issue_code(
        client_id="client-2",
        redirect_uri=redirect_uri,
        token=token,
        scopes=[OIDCScope.openid, OIDCScope.profile],
    )

    oidc_token = await oidc_service.redeem_code(
        grant_type="authorization_code",
        client_id="client-2",
        client_secret="client-2-secret",
        redirect_uri=redirect_uri,
        code=str(code),
    )
    assert oidc_token.claims == {
        "aud": "client-2",
        "iat": ANY,
        "exp": ANY,
        "iss": config.oidc_server.issuer,
        "jti": code.key,
        "name": token_data.name,
        "preferred_username": token_data.username,
        "scope": "openid profile",
        "sub": token_data.username,
    }

    assert not await factory.redis.get(f"oidc:{code.key}")


@pytest.mark.asyncio
async def test_redeem_code_errors(
    tmp_path: Path, factory: Factory, mock_slack: MockSlackWebhook
) -> None:
    expires = int(timedelta(minutes=60).total_seconds())
    clients = [
        OIDCClient(client_id="client-1", client_secret="client-1-secret"),
        OIDCClient(client_id="client-2", client_secret="client-2-secret"),
    ]
    config = await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    oidc_service = factory.create_oidc_service()
    token_data = await create_session_token(factory)
    token = token_data.token
    redirect_uri = "https://example.com/"
    code = await oidc_service.issue_code(
        client_id="client-2",
        redirect_uri=redirect_uri,
        token=token,
        scopes=[OIDCScope.openid],
    )

    with pytest.raises(InvalidRequestError):
        await oidc_service.redeem_code(
            grant_type=None,
            client_id="some-client",
            client_secret="some-secret",
            redirect_uri=redirect_uri,
            code=str(code),
        )
    with pytest.raises(UnsupportedGrantTypeError):
        await oidc_service.redeem_code(
            grant_type="something_else",
            client_id="some-client",
            client_secret="some-secret",
            redirect_uri=redirect_uri,
            code=str(code),
        )
    with pytest.raises(InvalidClientError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="some-client",
            client_secret="some-secret",
            redirect_uri=redirect_uri,
            code=str(code),
        )
    with pytest.raises(InvalidClientError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="some-secret",
            redirect_uri=redirect_uri,
            code=str(code),
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri=redirect_uri,
            code=str(OIDCAuthorizationCode()),
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-1",
            client_secret="client-1-secret",
            redirect_uri=redirect_uri,
            code=str(code),
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri="https://foo.example.com/",
            code=str(code),
        )
    with pytest.raises(InvalidGrantError):
        wrong_secret = OIDCAuthorizationCode(key=code.key)
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri="https://foo.example.com/",
            code=str(wrong_secret),
        )
    assert mock_slack.messages == []

    # Malformed data in Redis.
    fernet = Fernet(config.session_secret.encode())
    raw_data = fernet.encrypt(b"malformed json")
    await factory.redis.set(f"oidc:{code.key}", raw_data, ex=expires)
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri=redirect_uri,
            code=str(code),
        )
    assert mock_slack.messages == [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "Error in Gafaelfawr: Cannot deserialize data"
                            f" for key oidc:{code.key}"
                        ),
                        "verbatim": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Exception type*\nDeserializeError",
                            "verbatim": True,
                        },
                        {"type": "mrkdwn", "text": ANY, "verbatim": True},
                        {
                            "type": "mrkdwn",
                            "text": f"*Key*\noidc:{code.key}",
                            "verbatim": True,
                        },
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": ANY, "verbatim": True},
                },
                {"type": "divider"},
            ]
        }
    ]
    messages = mock_slack.messages
    assert "ValidationError" in messages[0]["blocks"][2]["text"]["text"]


@pytest.mark.asyncio
async def test_issue_id_token(tmp_path: Path, factory: Factory) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    config = await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    assert config.oidc_server
    oidc_service = factory.create_oidc_service()

    token_data = await create_session_token(factory)
    authorization = OIDCAuthorization(
        client_id="some-id",
        redirect_uri="https://example.com/",
        token=token_data.token,
        scopes=[OIDCScope.openid, OIDCScope.profile],
        nonce=os.urandom(16).hex(),
    )
    oidc_token = await oidc_service.issue_id_token(authorization)

    assert oidc_token.claims == {
        "aud": "some-id",
        "exp": int(token_data.expires.timestamp()),
        "iat": ANY,
        "iss": config.oidc_server.issuer,
        "jti": authorization.code.key,
        "name": token_data.name,
        "nonce": authorization.nonce,
        "preferred_username": token_data.username,
        "scope": "openid profile",
        "sub": token_data.username,
    }

    now = time.time()
    assert now - 5 <= oidc_token.claims["iat"] <= now + 5
