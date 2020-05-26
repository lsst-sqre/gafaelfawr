"""Tests for the /auth route."""

from __future__ import annotations

import base64
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.handlers.util import AuthChallenge, AuthError, AuthType

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from tests.setup import SetupTestCallable


def parse_www_authenticate(header: str) -> AuthChallenge:
    """Parse a ``WWW-Authenticate`` header into this representation.

    A ``WWW-Authenticate`` header consists of one or mor challenges, each of
    which is an auth type, whitespace, and a series of attributes in the form
    of key="value", separated by a comma and whitespace.

    We only support a single challenge here, since Gafaelfawr only returns a
    single challenge.
    """
    auth_type_name, info = header.split(None, 1)
    auth_type = AuthType[auth_type_name]

    # A half-assed regex parser for the WWW-Authenticate header.
    #
    # Repeatedly match key/value pairs in the form key="value" and iterate
    # on them as matches.  The key will be match group 1 and the value will
    # be match group 2.
    #
    # Each attribute has to either start at the beginning of the portion of
    # the header after the auth type (\A) or follow a previous attribute with
    # a comma and whitespace (,\s*), ensuring there isn't any extraneous junk
    # in the header.
    error = None
    error_description = None
    scope = None
    for attribute in re.finditer(r'(?:\A|,\s*)([^ "=]+)="([^"]+)"', info):
        if attribute.group(1) == "realm":
            realm = attribute.group(2)
        elif attribute.group(1) == "error":
            error = attribute.group(2)
        elif attribute.group(1) == "error_description":
            error_description = attribute.group(2)
        elif attribute.group(1) == "scope":
            scope = attribute.group(2)
        else:
            assert False, f"unexpected attribute {attribute.group(1)}"
    assert realm

    return AuthChallenge(
        auth_type=auth_type,
        realm=realm,
        error=AuthError[error] if error else None,
        error_description=error_description,
        scope=scope,
    )


async def test_no_auth(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/auth", params={"scope": "exec:admin"})
    assert r.status == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert not authenticate.error
    assert not authenticate.scope

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "bearer"}
    )
    assert r.status == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert not authenticate.error
    assert not authenticate.scope

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "bogus"}
    )
    assert r.status == 400

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "basic"}
    )
    assert r.status == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Basic
    assert authenticate.realm == setup.config.realm
    assert not authenticate.error
    assert not authenticate.scope


async def test_invalid_auth(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer"},
    )
    assert r.status == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer token"},
    )
    assert r.status == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_token

    # Create an expired token.
    exp = int((datetime.now(timezone.utc) - timedelta(days=24)).timestamp())
    token = setup.create_token(exp=exp, scope="exec:admin")
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_token


async def test_access_denied(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token()

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin"
    body = await r.text()
    assert "Token missing required scope" in body


async def test_auth_forbidden(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get(
        "/auth/forbidden",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
    )
    assert r.status == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin exec:test"
    body = await r.text()
    assert "Token missing required scope" in body

    r = await setup.client.get(
        "/auth/forbidden",
        params={"scope": "exec:admin", "auth_type": "basic"},
    )
    assert r.status == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Basic
    assert authenticate.realm == setup.config.realm
    assert not authenticate.error
    assert not authenticate.scope
    body = await r.text()
    assert "Token missing required scope" in body


async def test_satisfy_all(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token(scope="exec:test")

    r = await setup.client.get(
        "/auth",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin exec:test"
    body = await r.text()
    assert "Token missing required scope" in body


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
            params={"scope": "exec:admin", "auth_type": "basic"},
            headers={"Authorization": f"Basic {basic_b64}"},
        )
        assert r.status == 401
        authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
        assert authenticate.auth_type == AuthType.Basic
        assert authenticate.realm == setup.config.realm
        assert not authenticate.error
        assert not authenticate.error_description
        assert not authenticate.scope


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
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert not authenticate.error
    assert not authenticate.scope


async def test_logging(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    """These tests also test X-Forwarded-For and friends."""
    setup = await create_test_setup()
    token = setup.create_token(scope="exec:admin")

    # Successful request with X-Forwarded-For.
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Bearer {token.encoded}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status == 200
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == {
        "auth_uri": "/foo",
        "event": "Token authorized",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "192.0.2.1",
        "request_id": ANY,
        "required_scope": "exec:admin",
        "satisfy": "all",
        "scope": "exec:admin",
        "token": token.jti,
        "token_source": "bearer",
        "user": token.username,
        "user_agent": ANY,
    }
    caplog.clear()

    # Authorization failed with chained X-Forwarded-For.
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:test", "satisfy": "any"},
        headers={
            "Authorization": f"Bearer {token.encoded}",
            "X-Original-URL": "https://example.com/foo",
            "X-Forwarded-For": "192.0.2.1, 172.24.0.4",
        },
    )
    assert r.status == 403
    data = json.loads(caplog.record_tuples[0][2])
    assert data == {
        "auth_uri": "https://example.com/foo",
        "event": "Token missing required scope",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "172.24.0.4",
        "request_id": ANY,
        "required_scope": "exec:test",
        "satisfy": "any",
        "scope": "exec:admin",
        "token": token.jti,
        "token_source": "bearer",
        "user": token.username,
        "user_agent": ANY,
    }
    caplog.clear()

    # No token found with chained X-Forwarded-For and trusted proxies.
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "X-Forwarded-For": "2001:db8:85a3:8d3:1319:8a2e:370:734, 10.0.0.1",
            "X-Forwarded-Proto": "https, http",
            "X-Original-URI": "/foo",
            "X-Original-URL": "https://example.com/foo",
        },
    )
    assert r.status == 401
    data = json.loads(caplog.record_tuples[0][2])
    assert data == {
        "auth_uri": "/foo",
        "event": "No token found, returning unauthorized",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "2001:db8:85a3:8d3:1319:8a2e:370:734",
        "request_id": ANY,
        "required_scope": "exec:admin",
        "satisfy": "all",
        "user_agent": ANY,
    }
    caplog.clear()

    # Invalid token with no X-Forwarded-For.
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer blah"},
    )
    assert r.status == 401
    data = json.loads(caplog.record_tuples[0][2])
    assert data == {
        "auth_uri": "NONE",
        "error": "Not enough segments",
        "event": "Invalid token",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "required_scope": "exec:admin",
        "satisfy": "all",
        "token_source": "bearer",
        "user_agent": ANY,
    }
    caplog.clear()

    # Successful request where all IP addresses are proxies.
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Bearer {token.encoded}",
            "X-Original-Uri": "/foo",
            "X-Forwarded-For": "10.255.4.3, 10.0.3.1",
            "X-Forwarded-Proto": "https",
        },
    )
    assert r.status == 200
    data = json.loads(caplog.record_tuples[0][2])
    assert data == {
        "auth_uri": "/foo",
        "event": "Token authorized",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth",
        "remote": "10.255.4.3",
        "request_id": ANY,
        "required_scope": "exec:admin",
        "satisfy": "all",
        "scope": "exec:admin",
        "token": token.jti,
        "token_source": "bearer",
        "user": token.username,
        "user_agent": ANY,
    }
    caplog.clear()
