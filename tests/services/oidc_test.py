"""Tests for the OpenID Connect server."""

from __future__ import annotations

import json
import os
import time
from datetime import timedelta
from unittest.mock import ANY

import pytest
from cryptography.fernet import Fernet
from safir.datetime import current_datetime
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.exceptions import (
    InvalidClientError,
    InvalidClientIdError,
    InvalidGrantError,
    InvalidRequestError,
    UnsupportedGrantTypeError,
)
from gafaelfawr.factory import Factory
from gafaelfawr.models.oidc import (
    OIDCAuthorization,
    OIDCAuthorizationCode,
    OIDCScope,
    OIDCToken,
)
from gafaelfawr.models.token import Token, TokenType

from ..support.config import build_oidc_client, reconfigure
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_issue_code(
    factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_uri = "https://example.com/"
    clients = [build_oidc_client("some-id", "some-secret", redirect_uri)]
    config = await reconfigure(
        "github-oidc-server", factory, monkeypatch, oidc_clients=clients
    )
    oidc_service = factory.create_oidc_service()
    token_data = await create_session_token(factory)
    token = token_data.token

    assert config.oidc_server
    assert list(config.oidc_server.clients) == clients

    with pytest.raises(InvalidClientIdError):
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
    fernet = Fernet(config.session_secret.get_secret_value().encode())
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
async def test_redeem_code(
    factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_uri = "https://example.com/"
    clients = [
        build_oidc_client("client-1", "client-1-secret", redirect_uri),
        build_oidc_client("client-2", "client-2-secret", redirect_uri),
    ]
    config = await reconfigure(
        "github-oidc-server", factory, monkeypatch, oidc_clients=clients
    )
    assert config.oidc_server
    oidc_service = factory.create_oidc_service()
    token_data = await create_session_token(factory)
    assert token_data.expires
    token = token_data.token
    code = await oidc_service.issue_code(
        client_id="client-2",
        redirect_uri=redirect_uri,
        token=token,
        scopes=[OIDCScope.openid, OIDCScope.profile],
    )

    reply = await oidc_service.redeem_code(
        grant_type="authorization_code",
        client_id="client-2",
        client_secret="client-2-secret",
        redirect_uri=redirect_uri,
        code=str(code),
        ip_address="127.0.0.1",
    )
    assert reply.scope == "openid profile"
    assert reply.token_type == "Bearer"
    id_token = oidc_service.verify_token(OIDCToken(encoded=reply.id_token))
    assert id_token.claims == {
        "aud": "client-2",
        "iat": ANY,
        "exp": ANY,
        "iss": str(config.oidc_server.issuer),
        "jti": code.key,
        "name": token_data.name,
        "preferred_username": token_data.username,
        "scope": "openid profile",
        "sub": token_data.username,
    }
    token_service = factory.create_token_service()
    access_token = Token.from_str(reply.access_token)
    access_data = await token_service.get_data(access_token)
    assert access_data
    assert access_data.model_dump() == {
        "token": access_token.model_dump(),
        "username": token_data.username,
        "token_type": TokenType.oidc,
        "service": None,
        "scopes": [],
        "created": ANY,
        "expires": int(token_data.expires.timestamp()),
        "name": token_data.name,
        "email": token_data.email,
        "uid": token_data.uid,
        "gid": token_data.gid,
        "groups": token_data.groups,
    }
    now = current_datetime()
    assert now - timedelta(seconds=2) <= access_data.created <= now

    assert not await factory.redis.get(f"oidc:{code.key}")

    # If the parent session token is revoked, the oidc token returned as an
    # access token should also be revoked.
    await token_service.delete_token(
        token.key, token_data, token_data.username, ip_address="127.0.0.1"
    )
    assert await token_service.get_data(access_token) is None


@pytest.mark.asyncio
async def test_redeem_code_errors(
    factory: Factory,
    monkeypatch: pytest.MonkeyPatch,
    mock_slack: MockSlackWebhook,
) -> None:
    expires = int(timedelta(minutes=60).total_seconds())
    redirect_uri = "https://example.com/"
    clients = [
        build_oidc_client("client-1", "client-1-secret", redirect_uri),
        build_oidc_client("client-2", "client-2-secret", redirect_uri),
    ]
    config = await reconfigure(
        "github-oidc-server", factory, monkeypatch, oidc_clients=clients
    )
    oidc_service = factory.create_oidc_service()
    token_data = await create_session_token(factory)
    token = token_data.token
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
            ip_address="127.0.0.1",
        )
    with pytest.raises(UnsupportedGrantTypeError):
        await oidc_service.redeem_code(
            grant_type="something_else",
            client_id="some-client",
            client_secret="some-secret",
            redirect_uri=redirect_uri,
            code=str(code),
            ip_address="127.0.0.1",
        )
    with pytest.raises(InvalidClientError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="some-client",
            client_secret="some-secret",
            redirect_uri=redirect_uri,
            code=str(code),
            ip_address="127.0.0.1",
        )
    with pytest.raises(InvalidClientError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="some-secret",
            redirect_uri=redirect_uri,
            code=str(code),
            ip_address="127.0.0.1",
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri=redirect_uri,
            code=str(OIDCAuthorizationCode()),
            ip_address="127.0.0.1",
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-1",
            client_secret="client-1-secret",
            redirect_uri=redirect_uri,
            code=str(code),
            ip_address="127.0.0.1",
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri="https://foo.example.com/",
            code=str(code),
            ip_address="127.0.0.1",
        )
    with pytest.raises(InvalidGrantError):
        wrong_secret = OIDCAuthorizationCode(key=code.key)
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri="https://foo.example.com/",
            code=str(wrong_secret),
            ip_address="127.0.0.1",
        )
    assert mock_slack.messages == []

    # Malformed data in Redis.
    fernet = Fernet(config.session_secret.get_secret_value().encode())
    raw_data = fernet.encrypt(b"malformed json")
    await factory.redis.set(f"oidc:{code.key}", raw_data, ex=expires)
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri=redirect_uri,
            code=str(code),
            ip_address="127.0.0.1",
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

    # Underlying access token revoked before code was redeemed.
    token_data = await create_session_token(factory)
    code = await oidc_service.issue_code(
        client_id="client-2",
        redirect_uri=redirect_uri,
        token=token,
        scopes=[OIDCScope.openid],
    )
    token_service = factory.create_token_service()
    await token_service.delete_token(
        token.key, token_data, token_data.username, ip_address="127.0.0.1"
    )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            grant_type="authorization_code",
            client_id="client-2",
            client_secret="client-2-secret",
            redirect_uri=redirect_uri,
            code=str(code),
            ip_address="127.0.0.1",
        )


@pytest.mark.asyncio
async def test_issue_id_token(
    factory: Factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    redirect_uri = "https://example.com/"
    clients = [build_oidc_client("some-id", "some-secret", redirect_uri)]
    config = await reconfigure(
        "github-oidc-server", factory, monkeypatch, oidc_clients=clients
    )
    assert config.oidc_server
    oidc_service = factory.create_oidc_service()

    token_data = await create_session_token(factory)
    assert token_data.expires
    authorization = OIDCAuthorization(
        client_id="some-id",
        redirect_uri=redirect_uri,
        token=token_data.token,
        scopes=[OIDCScope.openid, OIDCScope.profile],
        nonce=os.urandom(16).hex(),
    )
    oidc_token = await oidc_service.issue_id_token(authorization)

    assert oidc_token.claims == {
        "aud": "some-id",
        "exp": int(token_data.expires.timestamp()),
        "iat": ANY,
        "iss": str(config.oidc_server.issuer),
        "jti": authorization.code.key,
        "name": token_data.name,
        "nonce": authorization.nonce,
        "preferred_username": token_data.username,
        "scope": "openid profile",
        "sub": token_data.username,
    }

    now = time.time()
    assert now - 5 <= oidc_token.claims["iat"] <= now + 5
