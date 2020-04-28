"""Tests for the /auth route."""

from __future__ import annotations

import base64
import time
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from gafaelfawr.constants import ALGORITHM

if TYPE_CHECKING:
    from tests.setup import SetupTestCallable


async def test_no_auth(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/auth", params={"scope": "exec:admin"})
    assert r.status == 401
    method, info = r.headers["WWW-Authenticate"].split(" ", 1)
    assert method == "Bearer"
    data = info.split(",")
    assert len(data) == 3
    assert data[0] == f'realm="{setup.config.realm}"'
    assert data[1] == f'error="Unable to find token"'
    assert data[2].startswith("error_description=")

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer"},
    )
    assert r.status == 401
    method, info = r.headers["WWW-Authenticate"].split(" ", 1)
    assert method == "Bearer"
    data = info.split(",")
    assert len(data) == 3
    assert data[0] == f'realm="{setup.config.realm}"'
    assert data[1] == f'error="Unable to find token"'
    assert data[2].startswith("error_description=")


async def test_invalid_auth(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer token"},
    )
    assert r.status == 403


async def test_access_denied(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token()

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 403
    body = await r.text()
    assert "Missing required scope" in body


async def test_satisfy_all(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token(scope="exec:test")

    r = await setup.client.get(
        "/auth",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 403
    body = await r.text()
    assert "Missing required scope" in body


async def test_success(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:admin read:all"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == token.email
    assert r.headers["X-Auth-Request-User"] == token.username
    assert r.headers["X-Auth-Request-Uid"] == token.uid
    assert r.headers["X-Auth-Request-Groups"] == "admin"
    assert r.headers["X-Auth-Request-Token"] == token.encoded


async def test_success_any(create_test_setup: SetupTestCallable) -> None:
    """Test satisfy=any as an /auth parameter.

    Ask for either ``exec:admin`` or ``exec:test`` and pass in credentials
    with only ``exec:test``.  Ensure they are accepted but also the headers
    don't claim the setup.client has ``exec:admin``.
    """
    setup = await create_test_setup()
    token = setup.create_token(groups=["test"], scope="exec:test")

    r = await setup.client.get(
        "/auth",
        params=[
            ("scope", "exec:admin"),
            ("scope", "exec:test"),
            ("satisfy", "any"),
        ],
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:test"
    assert (
        r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin exec:test"
    )
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "any"
    assert r.headers["X-Auth-Request-Groups"] == "test"


async def test_basic(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token(groups=["test"], scope="exec:admin")

    basic = f"{token.encoded}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"

    basic = f"x-oauth-basic:{token.encoded}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"

    # We currently fall back on using the username if x-oauth-basic doesn't
    # appear anywhere in the auth string.
    basic = f"{token.encoded}:something-else".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"


async def test_basic_failure(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    for basic in (b"foo:foo", b"x-oauth-basic:foo", b"foo:x-oauth-basic"):
        basic_b64 = base64.b64encode(basic).decode()
        r = await setup.client.get(
            "/auth",
            params={"scope": "exec:admin"},
            headers={"Authorization": f"Basic {basic_b64}"},
        )
        assert r.status == 403


async def test_handle(create_test_setup: SetupTestCallable) -> None:
    """Test that a session handle can be used in Authorization."""
    setup = await create_test_setup()
    handle = await setup.create_session(groups=["test"], scope="exec:admin")

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {handle.encode()}"},
    )
    assert r.status == 200

    basic = f"{handle.encode()}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200

    basic = f"x-oauth-basic:{handle.encode()}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200

    # We currently fall back on using the username if x-oauth-basic doesn't
    # appear anywhere in the auth string.
    basic = f"{handle.encode()}:something-else".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200


async def test_reissue_internal(create_test_setup: SetupTestCallable) -> None:
    """Test requesting token reissuance to an internal audience."""
    setup = await create_test_setup()
    token = setup.create_token(groups=["admin"], scope="exec:admin")

    r = await setup.client.get(
        "/auth",
        params={
            "scope": "exec:admin",
            "audience": setup.config.issuer.aud_internal,
        },
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 200
    new_encoded_token = r.headers["X-Auth-Request-Token"]
    assert token != new_encoded_token

    assert jwt.get_unverified_header(new_encoded_token) == {
        "alg": ALGORITHM,
        "typ": "JWT",
        "kid": setup.config.issuer.kid,
    }

    decoded_token = jwt.decode(
        new_encoded_token,
        setup.config.issuer.keypair.public_key_as_pem(),
        algorithms=ALGORITHM,
        audience=setup.config.issuer.aud_internal,
    )
    assert decoded_token == {
        "act": {
            "aud": setup.config.issuer.aud,
            "iss": setup.config.issuer.iss,
            "jti": token.jti,
        },
        "aud": setup.config.issuer.aud_internal,
        "email": token.email,
        "exp": ANY,
        "iat": ANY,
        "isMemberOf": [{"name": "admin"}],
        "iss": setup.config.issuer.iss,
        "jti": ANY,
        "scope": " ".join(sorted(setup.config.issuer.group_mapping["admin"])),
        "sub": token.claims["sub"],
        "uid": token.username,
        "uidNumber": token.uid,
    }
    now = time.time()
    expected_exp = now + setup.config.issuer.exp_minutes * 60
    assert expected_exp - 5 <= decoded_token["exp"] <= expected_exp + 5
    assert now - 5 <= decoded_token["iat"] <= now + 5

    # No session should be created for internal tokens.
    assert not await setup.redis.get(f"session:{decoded_token['jti']}")


async def test_ajax_unauthorized(create_test_setup: SetupTestCallable) -> None:
    """Test that AJAX requests without auth get 403, not 401."""
    setup = await create_test_setup()

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r.status == 403
