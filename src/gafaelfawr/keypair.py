"""RSA key pair handling."""

from typing import Self

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from .constants import ALGORITHM
from .models.oidc import JWK, JWKS
from .util import number_to_base64

__all__ = ["RSAKeyPair"]


class RSAKeyPair:
    """An RSA key pair with some simple helper functions.

    Notes
    -----
    Created by calling :py:meth:`~RSAKeyPair.generate` or
    :py:meth:`~RSAKeyPair.from_pem` rather than the constructor.
    """

    @classmethod
    def from_pem(cls, pem: bytes) -> Self:
        """Import an RSA key pair from a PEM-encoded private key.

        Parameters
        ----------
        pem
            The PEM-encoded key (must not be password-protected).

        Returns
        -------
        RSAKeyPair
            The corresponding key pair.

        Raises
        ------
        cryptography.exceptions.UnsupportedAlgorithm
            Raised if the provided key is not an RSA private key.
        """
        private_key = load_pem_private_key(
            pem, password=None, backend=default_backend()
        )
        if not isinstance(private_key, rsa.RSAPrivateKeyWithSerialization):
            raise UnsupportedAlgorithm("Key is not an RSA private key")
        return cls(private_key)

    @classmethod
    def generate(cls) -> Self:
        """Generate a new RSA key pair.

        Returns
        -------
        RSAKeyPair
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
        self._private_key_as_pem: bytes | None = None
        self._public_key_as_pem: bytes | None = None

    def private_key_as_pem(self) -> bytes:
        """Return the serialized private key.

        Returns
        -------
        bytes
            Private key encoded using PKCS#8 with no encryption.
        """
        if not self._private_key_as_pem:
            self._private_key_as_pem = self.private_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        return self._private_key_as_pem

    def public_key_as_jwks(self, kid: str | None = None) -> JWKS:
        """Return the public key in JWKS format.

        Parameters
        ----------
        kid
            The key ID.  If not included, the kid will be omitted, making the
            result invalid JWKS.

        Returns
        -------
        JWKS
            The public key in JWKS format.
        """
        public_numbers = self.public_numbers()
        jwk = JWK(
            alg=ALGORITHM,
            kid=kid,
            kty="RSA",
            use="sig",
            n=number_to_base64(public_numbers.n).decode(),
            e=number_to_base64(public_numbers.e).decode(),
        )
        return JWKS(keys=[jwk])

    def public_key_as_pem(self) -> bytes:
        """Return the PEM-encoded public key.

        Returns
        -------
        bytes
            The public key in PEM encoding and SubjectPublicKeyInfo format.
        """
        if not self._public_key_as_pem:
            public_key = self.private_key.public_key()
            self._public_key_as_pem = public_key.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
        return self._public_key_as_pem

    def public_numbers(self) -> rsa.RSAPublicNumbers:
        """Return the public numbers for the key pair.

        Returns
        -------
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers
            The public numbers.
        """
        return self.private_key.public_key().public_numbers()
