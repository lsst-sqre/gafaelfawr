"""Tests for the jwt_authorizer.authnz package."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING
from unittest.mock import call, patch

import jwt

from jwt_authorizer.authnz import authenticate, capabilities_from_groups
from jwt_authorizer.tokens import ALGORITHM
from tests.util import RSAKeyPair, create_test_app

if TYPE_CHECKING:
    from typing import Any, Dict


def test_authenticate() -> None:
    payload = {
        "aud": "https://test.example.com/",
        "email": "some-user@example.com",
        "iss": "https://orig.example.com/",
        "jti": "some-unique-id",
        "sub": "some-user",
        "uidNumber": "1000",
    }
    keypair = RSAKeyPair()
    app = create_test_app(
        ISSUERS={
            "https://orig.example.com/": {
                "audience": "https://test.example.com/",
                "issuer_key_ids": ["some-kid"],
            },
        },
        OAUTH2_STORE_SESSION={"TICKET_PREFIX": "oauth2_proxy"},
    )

    # Generate a valid token.
    token = jwt.encode(
        payload,
        keypair.private_key_as_pem(),
        algorithm=ALGORITHM,
        headers={"kid": "some-kid"},
    )

    # Analyze it, patching out the call to retrieve the public key from a
    # remote web site (but making sure that it was called correctly).
    with app.app_context():
        with patch("jwt_authorizer.authnz.get_key_as_pem") as get_key_as_pem:
            get_key_as_pem.return_value = keypair.public_key_as_pem()
            result = authenticate(token.decode())
            assert get_key_as_pem.call_args_list == [
                call("https://orig.example.com/", "some-kid")
            ]

    assert result == payload


def test_capabilities_from_groups() -> None:
    app = create_test_app()
    token: Dict[str, Any] = {
        "sub": "bvan",
        "email": "bvan@gmail.com",
        "isMemberOf": [{"name": "user"}],
    }

    with app.app_context():
        assert capabilities_from_groups(token) == set()

        admin_token = copy.deepcopy(token)
        admin_token["isMemberOf"].append({"name": "admin"})
        assert capabilities_from_groups(admin_token) == {"exec:admin"}
