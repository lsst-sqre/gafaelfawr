"""RSA key pair handling."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.util import number_to_base64

if TYPE_CHECKING:
    from typing import Dict, Optional

__all__ = ["RSAKeyPair"]


class RSAKeyPair:
    """An RSA key pair with some simple helper functions.

    Normally created by calling py:meth:`RSAKeyPair.generate` rather than the
    constructor.

    Parameters
    ----------
    private_key : `rsa.RSAPrivateKeyWithSerialization`
        The private key represented by this class.
    """

    @classmethod
    def generate(cls) -> RSAKeyPair:
        """Generate a new RSA key pair.

        Returns
        -------
        keypair : `RSAKeyPair`
            Newly-generated key pair.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return cls(private_key)

    def __init__(
        self, private_key: rsa.RSAPrivateKeyWithSerialization
    ) -> None:
        self.private_key = private_key

    def private_key_as_pem(self) -> bytes:
        """Return the serialized private key.

        Returns
        -------
        key : `bytes`
            Private key encoded using PKCS#8 with no encryption.
        """
        return self.private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )

    def public_key_as_jwks(self, kid: Optional[str] = None) -> Dict[str, str]:
        """Return the public key in JWKS format.

        Parameters
        ----------
        kid : `str`, optional
            The key ID.  If not included, the kid will be omitted, making the
            result invalid JWKS.

        Returns
        -------
        key : Dict[`str`, `str`]
            The public key in JWKS format.
        """
        public_numbers = self.private_key.public_key().public_numbers()
        jwks = {
            "alg": ALGORITHM,
            "kty": "RSA",
            "use": "sig",
            "n": number_to_base64(public_numbers.n).decode(),
            "e": number_to_base64(public_numbers.e).decode(),
        }
        if kid:
            jwks["kid"] = kid
        return jwks

    def public_key_as_pem(self) -> bytes:
        """Return the PEM-encoded public key.

        Returns
        -------
        public_key : `bytes`
            The public key in PEM encoding and SubjectPublicKeyInfo format.
        """
        return self.private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
        )
