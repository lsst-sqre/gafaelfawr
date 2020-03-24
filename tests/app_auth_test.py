"""Tests for the /auth route."""

from __future__ import annotations

from unittest.mock import call, patch

from tests.util import RSAKeyPair, create_test_app, create_test_token


def assert_www_authenticate_header_matches(
    header: str, method: str, error: str
) -> None:
    header_method, header_info = header.split(" ", 1)
    assert header_method == method
    if header_method == "Basic":
        assert header_info == 'realm="tokens"'
    else:
        data = header_info.split(",")
        assert data[0] == 'realm="tokens"'
        assert data[1] == f'error="{error}"'
        assert data[2].startswith("error_description=")


def test_authnz_token_no_auth() -> None:
    app = create_test_app()

    with app.test_client() as client:
        r = client.get("/auth?capability=exec:admin")
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"]
        assert_www_authenticate_header_matches(
            r.headers["WWW-Authenticate"], "Bearer", "No Authorization header"
        )

        r = client.get(
            "/auth?capability=exec:admin", headers={"Authorization": "Bearer"}
        )
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"]
        assert_www_authenticate_header_matches(
            r.headers["WWW-Authenticate"], "Bearer", "Unable to find token"
        )

        r = client.get(
            "/auth?capability=exec:admin",
            headers={"Authorization": "Bearer token"},
        )
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"]
        assert_www_authenticate_header_matches(
            r.headers["WWW-Authenticate"], "Bearer", "Invalid Token"
        )


def test_authnz_token_access_denied() -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair)
    app = create_test_app(keypair)

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            r = client.get(
                "/auth?capability=exec:admin",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert get_key_as_pem.call_args_list == [
                call("https://test.example.com/", "some-kid")
            ]

    assert r.status_code == 403
    assert b"No Capability group found in user's `isMemberOf`" in r.data
    assert r.headers["X-Auth-Request-Token-Capabilities"] == ""
    assert r.headers["X-Auth-Request-Capabilities-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "all"


def test_authnz_token_satisfy_all() -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["test"])
    app = create_test_app(keypair)

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            r = client.get(
                "/auth?capability=exec:test&capability=exec:admin",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert get_key_as_pem.call_args_list == [
                call("https://test.example.com/", "some-kid")
            ]

    assert r.status_code == 403
    assert b"No Capability group found in user's `isMemberOf`" in r.data
    assert r.headers["X-Auth-Request-Token-Capabilities"] == "exec:test"
    assert (
        r.headers["X-Auth-Request-Capabilities-Accepted"]
        == "exec:admin exec:test"
    )
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "all"


def test_authnz_token_success() -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["admin"])
    app = create_test_app(keypair)

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            r = client.get(
                "/auth?capability=exec:admin",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert get_key_as_pem.call_args_list == [
                call("https://test.example.com/", "some-kid")
            ]

    assert r.status_code == 200
    assert (
        r.headers["X-Auth-Request-Token-Capabilities"] == "exec:admin read:all"
    )
    assert r.headers["X-Auth-Request-Capabilities-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"
    assert r.headers["X-Auth-Request-User"] == "some-user"
    assert r.headers["X-Auth-Request-Uid"] == "1000"
    assert r.headers["X-Auth-Request-Groups"] == "admin"
    assert r.headers["X-Auth-Request-Token"] == token
    assert r.headers["X-Auth-Request-Token-Ticket"] == ""


def test_authnz_token_success_any() -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["test"])
    app = create_test_app(keypair)

    with app.test_client() as client:
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            r = client.get(
                "/auth?capability=exec:admin&capability=exec:test&satisfy=any",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert get_key_as_pem.call_args_list == [
                call("https://test.example.com/", "some-kid")
            ]

    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Token-Capabilities"] == "exec:test"
    assert (
        r.headers["X-Auth-Request-Capabilities-Accepted"]
        == "exec:admin exec:test"
    )
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "any"
    assert r.headers["X-Auth-Request-Groups"] == "test"
