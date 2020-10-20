"""Tests for the OpenIdServer class."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest
from cryptography.fernet import Fernet

from gafaelfawr.config import OIDCClient
from gafaelfawr.exceptions import (
    InvalidClientError,
    InvalidGrantError,
    UnauthorizedClientException,
)
from gafaelfawr.storage.oidc import OIDCAuthorizationCode

if TYPE_CHECKING:
    from tests.setup import SetupTest


async def test_issue_code(setup: SetupTest) -> None:
    clients = [OIDCClient(client_id="some-id", client_secret="some-secret")]
    setup.switch_environment("github", oidc_clients=clients)
    oidc_server = setup.factory.create_oidc_server()
    handle = await setup.create_session()
    redirect_uri = "https://example.com/"

    assert setup.config.oidc_server
    assert list(setup.config.oidc_server.clients) == clients

    with pytest.raises(UnauthorizedClientException):
        await oidc_server.issue_code("unknown-client", redirect_uri, handle)

    code = await oidc_server.issue_code("some-id", redirect_uri, handle)
    encrypted_code = await setup.redis.get(f"oidc:{code.key}")
    assert encrypted_code
    fernet = Fernet(setup.config.session_secret.encode())
    serialized_code = json.loads(fernet.decrypt(encrypted_code))
    assert serialized_code == {
        "code": code.encode(),
        "client_id": "some-id",
        "redirect_uri": redirect_uri,
        "session_handle": handle.encode(),
        "created_at": ANY,
    }
    now = time.time()
    assert now - 2 < serialized_code["created_at"] < now


async def test_redeem_code(setup: SetupTest) -> None:
    clients = [
        OIDCClient(client_id="client-1", client_secret="client-1-secret"),
        OIDCClient(client_id="client-2", client_secret="client-2-secret"),
    ]
    setup.switch_environment("github", oidc_clients=clients)
    oidc_server = setup.factory.create_oidc_server()
    handle = await setup.create_session()
    redirect_uri = "https://example.com/"
    code = await oidc_server.issue_code("client-2", redirect_uri, handle)

    token = await oidc_server.redeem_code(
        "client-2", "client-2-secret", redirect_uri, code
    )
    assert token.claims == {
        "act": {
            "aud": setup.config.issuer.aud,
            "iss": setup.config.issuer.iss,
            "jti": ANY,
        },
        "aud": setup.config.issuer.aud_internal,
        "email": "some-user@example.com",
        "iat": ANY,
        "exp": ANY,
        "iss": setup.config.issuer.iss,
        "jti": code.key,
        "scope": "openid",
        "sub": "some-user",
        "uid": "some-user",
        "uidNumber": "1000",
    }

    assert not await setup.redis.get(f"oidc:{code.key}")


async def test_redeem_code_errors(setup: SetupTest) -> None:
    clients = [
        OIDCClient(client_id="client-1", client_secret="client-1-secret"),
        OIDCClient(client_id="client-2", client_secret="client-2-secret"),
    ]
    setup.switch_environment("github", oidc_clients=clients)
    oidc_server = setup.factory.create_oidc_server()
    handle = await setup.create_session()
    redirect_uri = "https://example.com/"
    code = await oidc_server.issue_code("client-2", redirect_uri, handle)

    with pytest.raises(InvalidClientError):
        await oidc_server.redeem_code(
            "some-client", "some-secret", redirect_uri, code
        )
    with pytest.raises(InvalidClientError):
        await oidc_server.redeem_code(
            "client-2", "some-secret", redirect_uri, code
        )
    with pytest.raises(InvalidGrantError):
        await oidc_server.redeem_code(
            "client-2",
            "client-2-secret",
            redirect_uri,
            OIDCAuthorizationCode(),
        )
    with pytest.raises(InvalidGrantError):
        await oidc_server.redeem_code(
            "client-1", "client-1-secret", redirect_uri, code
        )
    with pytest.raises(InvalidGrantError):
        await oidc_server.redeem_code(
            "client-2", "client-2-secret", "https://foo.example.com/", code
        )
