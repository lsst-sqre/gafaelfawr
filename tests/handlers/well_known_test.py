"""Tests for the /.well-known/jwks.json route."""

from __future__ import annotations

from typing import TYPE_CHECKING

from jwt_authorizer.constants import ALGORITHM
from jwt_authorizer.util import number_to_base64
from tests.support.app import create_test_app, get_test_config

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_well_known(tmp_path: Path, aiohttp_client: TestClient) -> None:
    app = await create_test_app(tmp_path)
    test_config = get_test_config(app)
    keypair = test_config.keypair
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
