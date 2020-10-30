"""Session storage for JWT Authorizer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from gafaelfawr.exceptions import InvalidSessionHandleException
from gafaelfawr.util import random_128_bits

if TYPE_CHECKING:
    from gafaelfawr.tokens import VerifiedToken

__all__ = ["Session", "SessionHandle"]


@dataclass
class SessionHandle:
    """A handle for a session, usable instead of a JWT.

    Notes
    -----
    A session handle consists of two parts, a semi-public key that is used as
    the token jti claim and as the Redis key, and a secret that is only
    present in the token returned to the user and the encrypted session in
    Redis.

    The serialized form of a session handle always starts with ``gsh-``, short
    for Gafaelfawr session handle, to make it easier to identify these handles
    in logs.

    The serialized form encodes the secret in URL-safe base64 with the padding
    stripped off (because equal signs can be parsed oddly in cookies).
    """

    key: str = field(default_factory=random_128_bits)
    secret: str = field(default_factory=random_128_bits)

    @classmethod
    def from_str(cls, handle: str) -> SessionHandle:
        """Parse a serialized handle into a `SessionHandle`.

        Parameters
        ----------
        handle : `str`
            The serialized handle.

        Returns
        -------
        decoded_handle : `SessionHandle`
            The decoded SessionHandle.

        Raises
        ------
        gafaelfawr.exceptions.InvalidSessionHandleException
            The provided string is not a valid session handle.
        """
        if not handle.startswith("gsh-"):
            msg = "Session handle does not start with gsh-"
            raise InvalidSessionHandleException(msg)
        trimmed_handle = handle[len("gsh-") :]

        if "." not in trimmed_handle:
            raise InvalidSessionHandleException("Ticket is malformed")
        key, secret = trimmed_handle.split(".", 1)
        if len(key) != 22 or len(secret) != 22:
            raise InvalidSessionHandleException("Ticket is malformed")

        return cls(key=key, secret=secret)

    def encode(self) -> str:
        """Return the encoded session handle."""
        return f"gsh-{self.key}.{self.secret}"


@dataclass
class Session:
    """An authentication session.

    Notes
    -----
    The JWT is the user's authentication credentials and could be used alone.
    However JWTs tend to be long, which causes various problems in practice.
    Therefore, JWTs are stored in authentication sessions, and the session
    handle can be used instead of the JWT.

    The session handle is represented by the `SessionHandle` class.  It
    consists of a key and a secret.  The key corresponds to the Redis key
    under which the session is stored.  The secret must match the
    corresponding secret inside the encrypted Redis session value.  This
    approach prevents someone with access to list the Redis keys from using a
    Redis key directly as a session handle.
    """

    handle: SessionHandle
    """The handle for this session."""

    token: VerifiedToken
    """The authentication token stored in the session."""

    email: str
    """The email address of the user (taken from the token claims)."""

    created_at: datetime
    """When the session was created."""

    expires_on: datetime
    """When the session will expire."""

    @classmethod
    def create(cls, handle: SessionHandle, token: VerifiedToken) -> Session:
        """Create a new session.

        Parameters
        ----------
        handle : `SessionHandle`
            The handle for this session.
        token : `gafaelfawr.tokens.VerifiedToken`
            The token to store in this session.

        Returns
        -------
        session : `Session`
            The newly-created session.
        """
        email: str = token.claims["email"]
        iat: int = token.claims["iat"]
        exp: int = token.claims["exp"]

        return cls(
            handle=handle,
            token=token,
            email=email,
            created_at=datetime.fromtimestamp(iat, tz=timezone.utc),
            expires_on=datetime.fromtimestamp(exp, tz=timezone.utc),
        )
