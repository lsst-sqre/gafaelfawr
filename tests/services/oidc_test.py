"""Tests for the OpenIdServer class."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import ANY

import pytest
from cryptography.fernet import Fernet

from gafaelfawr.config import OIDCClient
from gafaelfawr.exceptions import (
    InvalidClientError,
    InvalidGrantError,
    UnauthorizedClientError,
)
from gafaelfawr.factory import Factory
from gafaelfawr.models.oidc import OIDCAuthorizationCode

from ..support.settings import reconfigure
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
        await oidc_service.issue_code("unknown-client", redirect_uri, token)

    code = await oidc_service.issue_code("some-id", redirect_uri, token)
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
    code = await oidc_service.issue_code("client-2", redirect_uri, token)

    oidc_token = await oidc_service.redeem_code(
        "client-2", "client-2-secret", redirect_uri, code
    )
    assert oidc_token.claims == {
        "aud": config.oidc_server.audience,
        "iat": ANY,
        "exp": ANY,
        "iss": config.oidc_server.issuer,
        "jti": code.key,
        "name": token_data.name,
        "preferred_username": token_data.username,
        "scope": "openid",
        "sub": token_data.username,
        "uid_number": token_data.uid,
    }

    assert not await factory.redis.get(f"oidc:{code.key}")


@pytest.mark.asyncio
async def test_redeem_code_errors(tmp_path: Path, factory: Factory) -> None:
    clients = [
        OIDCClient(client_id="client-1", client_secret="client-1-secret"),
        OIDCClient(client_id="client-2", client_secret="client-2-secret"),
    ]
    await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    oidc_service = factory.create_oidc_service()
    token_data = await create_session_token(factory)
    token = token_data.token
    redirect_uri = "https://example.com/"
    code = await oidc_service.issue_code("client-2", redirect_uri, token)

    with pytest.raises(InvalidClientError):
        await oidc_service.redeem_code(
            "some-client", "some-secret", redirect_uri, code
        )
    with pytest.raises(InvalidClientError):
        await oidc_service.redeem_code(
            "client-2", "some-secret", redirect_uri, code
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            "client-2",
            "client-2-secret",
            redirect_uri,
            OIDCAuthorizationCode(),
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            "client-1", "client-1-secret", redirect_uri, code
        )
    with pytest.raises(InvalidGrantError):
        await oidc_service.redeem_code(
            "client-2", "client-2-secret", "https://foo.example.com/", code
        )


@pytest.mark.asyncio
async def test_issue_token(tmp_path: Path, factory: Factory) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    config = await reconfigure(
        tmp_path, "github-oidc-server", factory, oidc_clients=clients
    )
    assert config.oidc_server
    oidc_service = factory.create_oidc_service()

    token_data = await create_session_token(factory)
    oidc_token = oidc_service.issue_token(
        token_data, jti="new-jti", scope="openid"
    )

    assert oidc_token.claims == {
        "aud": config.oidc_server.audience,
        "exp": ANY,
        "iat": ANY,
        "iss": config.oidc_server.issuer,
        "jti": "new-jti",
        "name": token_data.name,
        "preferred_username": token_data.username,
        "scope": "openid",
        "sub": token_data.username,
        "uid_number": token_data.uid,
    }

    now = time.time()
    assert now - 5 <= oidc_token.claims["iat"] <= now + 5
    expected_exp = now + config.oidc_server.lifetime.total_seconds()
    assert expected_exp - 5 <= oidc_token.claims["exp"] <= expected_exp + 5
