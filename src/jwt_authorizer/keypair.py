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
    load_pem_private_key,
)

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.util import number_to_base64

if TYPE_CHECKING:
    from typing import Dict, Optional

__all__ = ["RSAKeyPair"]


class RSAKeyPair:
    """An RSA key pair with some simple helper functions.

    Notes
    -----
    Created by calling :py:meth:`~RSAKeyPair.generate` or
    :py:meth:`~RSAKeyPair.from_pem` rather than the constructor.
    """

    @classmethod
    def from_pem(cls, pem: bytes) -> RSAKeyPair:
        """Import an RSA key pair from a PEM-encoded private key.

        Parameters
        ----------
        pem : `bytes`
            The PEM-encoded key (must not be password-protected).

        Returns
        -------
        keypair : `RSAKeyPair`
            The corresponding key pair.
        """
        private_key = load_pem_private_key(
            pem, password=None, backend=default_backend()
        )
        return cls(private_key)

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
        public_numbers = self.public_numbers()
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

    def public_numbers(self) -> rsa.RSAPublicNumbers:
        """Return the public numbers for the key pair.

        Returns
        -------
        nums : `cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers`
            The public numbers.
        """
        return self.private_key.public_key().public_numbers()
