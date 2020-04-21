"""Tests for the /.well-known/jwks.json route."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.util import number_to_base64
from tests.setup import SetupTest

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_well_known(tmp_path: Path, aiohttp_client: TestClient) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    r = await client.get("/.well-known/jwks.json")
    assert r.status == 200
    result = await r.json()

    keypair = setup.config.issuer.keypair
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
