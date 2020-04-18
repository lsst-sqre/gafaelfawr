"""Tests for the /.well-known/jwks.json route."""

from __future__ import annotations

from typing import TYPE_CHECKING

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.util import number_to_base64
from tests.util import RSAKeyPair, create_test_app

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient


async def test_well_known(aiohttp_client: TestClient) -> None:
    keypair = RSAKeyPair()
    app = await create_test_app(keypair)
    client = await aiohttp_client(app)

    r = await client.get("/.well-known/jwks.json")
    assert r.status == 200
    result = await r.json()

    assert result == {
        "keys": [
            {
                "alg": ALGORITHM,
                "kty": "RSA",
                "use": "sig",
                "n": number_to_base64(keypair.public_numbers().n).decode(),
                "e": number_to_base64(keypair.public_numbers().e).decode(),
                "kid": "some-kid",
            }
        ],
    }
