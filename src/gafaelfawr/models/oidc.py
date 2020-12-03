"""Representation of data for OpenID Connect support."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, validator

from gafaelfawr.exceptions import InvalidGrantError
from gafaelfawr.models.token import Token
from gafaelfawr.util import normalize_datetime, random_128_bits

__all__ = [
    "OIDCAuthorization",
    "OIDCAuthorizationCode",
    "OIDCToken",
    "OIDCVerifiedToken",
]


class OIDCAuthorizationCode(BaseModel):
    """An OpenID Connect authorization code.

    Very similar to a `~gafaelfawr.models.token.Token` in behavior, but with a
    different serialization and a different type.
    """

    key: str = Field(default_factory=random_128_bits)
    secret: str = Field(default_factory=random_128_bits)

    @classmethod
    def from_str(cls, code: str) -> OIDCAuthorizationCode:
        """Parse a serialized token into an `OIDCAuthorizationCode`.

        Parameters
        ----------
        code : `str`
            The serialized code.

        Returns
        -------
        decoded_code : `OIDCAuthorizationCode`
            The decoded `OIDCAuthorizationCode`.

        Raises
        ------
        gafaelfawr.exceptions.InvalidGrantError
            The provided string is not a valid authorization code.
        """
        if not code.startswith("gc-"):
            msg = "Token does not start with gc-"
            raise InvalidGrantError(msg)
        trimmed_code = code[len("gc-") :]

        if "." not in trimmed_code:
            raise InvalidGrantError("Code is malformed")
        key, secret = trimmed_code.split(".", 1)
        if len(key) != 22 or len(secret) != 22:
            raise InvalidGrantError("Code is malformed")

        return cls(key=key, secret=secret)

    def __str__(self) -> str:
        """Return the encoded code."""
        return f"gc-{self.key}.{self.secret}"


class OIDCAuthorization(BaseModel):
    """Represents an authorization for an OpenID Connect client.

    This is the object created during login and stored in Redis.  The returned
    authorization code points to it and allows it to be retrieved so that an
    OpenID Connect client can redeem the code for a JWT.

    Notes
    -----
    The authorization code is represented by the `OIDCAuthorizationCode`
    class, which functions the same as, and has the same security properties
    as, a `~gafaelfawr.models.token.Token`.

    The underlying user data is not stored directly in the entry for the code.
    Instead, it stores the user's token for which the code was issued, and
    from which the user's data can be retrieved.
    """

    code: OIDCAuthorizationCode = Field(
        default_factory=OIDCAuthorizationCode, title="The authorization code"
    )

    client_id: str = Field(
        ..., title="The client that is allowed to use this authorization"
    )

    redirect_uri: str = Field(
        ..., title="The redirect URI for which this authorization is intended"
    )

    token: Token = Field(
        ...,
        title="The underlying authentication token for the user",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        title="When the authorization was created",
    )

    class Config:
        json_encoders = {datetime: lambda v: int(v.timestamp())}

    _normalize_created_at = validator(
        "created_at", allow_reuse=True, pre=True
    )(normalize_datetime)

    @property
    def lifetime(self) -> int:
        """The object lifetime in seconds."""


class OIDCToken(BaseModel):
    """Holds an encoded JWT.

    Notes
    -----
    Tokens come in two forms: the encoded form, with is suitable for passing
    in HTTP calls and includes a signature that may not be validated; and the
    validated and decoded form, which is a dict of claims.

    This class represents a token that we have in at least encoded form, but
    which may not be validated.  The child class OIDCValidatedToken represents
    the other case.
    """

    encoded: str = Field(..., title="The encoded form of a JWT")


class OIDCVerifiedToken(OIDCToken):
    """Holds a verified JWT.

    Holds a JWT whose signature has been checked and whose claims have been
    decoded.
    """

    claims: Dict[str, Any] = Field(
        ..., title="The claims contained in the token"
    )

    username: str = Field(..., title="The value of the username claim")

    uid: int = Field(
        ...,
        title="The value of the claim named by the uid_claim config setting",
    )

    jti: Optional[str] = Field(
        None, title="The jti (JWT ID) claim from the token"
    )
