"""Test RSA keypair handling."""

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from gafaelfawr.keypair import RSAKeyPair


def test_import() -> None:
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    serialized_key = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    keypair = RSAKeyPair.from_pem(serialized_key)
    assert keypair.public_numbers() == key.public_key().public_numbers()


def test_unsupported_key_type() -> None:
    key = Ed25519PrivateKey.generate()
    serialized_key = key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )

    with pytest.raises(UnsupportedAlgorithm):
        RSAKeyPair.from_pem(serialized_key)
