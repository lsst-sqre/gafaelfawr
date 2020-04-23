"""Tests for the /.well-known/jwks.json route."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.util import number_to_base64

if TYPE_CHECKING:
    from tests.setup import SetupTestCallable


async def test_well_known(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/.well-known/jwks.json")
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
