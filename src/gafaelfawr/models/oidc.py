"""Representation of data for OpenID Connect support."""

from __future__ import annotations

from contextlib import suppress
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, Field, field_serializer, field_validator
from safir.datetime import current_datetime
from safir.pydantic import normalize_datetime

from ..constants import ALGORITHM, OIDC_AUTHORIZATION_LIFETIME
from ..exceptions import InvalidGrantError
from ..util import random_128_bits
from .token import Token

__all__ = [
    "JWK",
    "JWKS",
    "OIDCAuthorization",
    "OIDCAuthorizationCode",
    "OIDCConfig",
    "OIDCScope",
    "OIDCToken",
    "OIDCVerifiedToken",
]


class OIDCScope(StrEnum):
    """A recognized OpenID Connect scope.

    This should not be directly exposed in the model of any endpoint. Instead,
    the `str` scope parameter should be parsed with the `parse_scopes` class
    method to yield a list of `OIDCScope` objects.
    """

    openid = "openid"
    profile = "profile"
    email = "email"

    @classmethod
    def parse_scopes(cls, scopes: str) -> list[Self]:
        """Parse a space-separated list of scopes.

        Any unknown scopes are silently ignored, following the OpenID Connect
        Core specification.

        Parameters
        ----------
        scopes
            Space-separated list of scopes.

        Returns
        -------
        list of OIDCScope
            Corresponding enums of recognized scopes.
        """
        result = []
        for scope in scopes.split(None):
            with suppress(KeyError):
                result.append(cls[scope])
        result.sort()
        return result


class OIDCAuthorizationCode(BaseModel):
    """An OpenID Connect authorization code.

    Very similar to a `~gafaelfawr.models.token.Token` in behavior, but with a
    different serialization and a different type.
    """

    key: str = Field(default_factory=random_128_bits)
    secret: str = Field(default_factory=random_128_bits)

    @classmethod
    def from_str(cls, code: str) -> Self:
        """Parse a serialized token into an `OIDCAuthorizationCode`.

        Parameters
        ----------
        code
            The serialized code.

        Returns
        -------
        OIDCAuthorizationCode
            The decoded `OIDCAuthorizationCode`.

        Raises
        ------
        InvalidGrantError
            Raised if the provided string is not a valid authorization code.
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
        default_factory=current_datetime,
        title="When the authorization was created",
    )

    scopes: list[OIDCScope] = Field(
        [OIDCScope.openid], title="Requested scopes"
    )

    nonce: str | None = Field(
        None,
        title="Client-provided nonce",
        description=(
            "Nonce to include in the issued ID token for either replay"
            " protection or to bind the ID token to a client session"
        ),
    )

    @field_serializer("created_at")
    def _serialize_datetime(self, time: datetime | None) -> int | None:
        return int(time.timestamp()) if time is not None else None

    _normalize_created_at = field_validator("created_at", mode="before")(
        normalize_datetime
    )

    @property
    def lifetime(self) -> int:
        """The object lifetime in seconds."""
        age = (current_datetime() - self.created_at).total_seconds()
        remaining = OIDC_AUTHORIZATION_LIFETIME - age
        return int(remaining) if remaining > 0 else 0


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

    claims: dict[str, Any] = Field(
        ..., title="The claims contained in the token"
    )

    jti: str | None = Field(
        None, title="The jti (JWT ID) claim from the token"
    )


class OIDCTokenReply(BaseModel):
    """A reply to a successful OpenID Connect token request."""

    access_token: str = Field(
        ...,
        title="Authentication token",
        description=(
            "access_token and id_token are the same in this implementation"
        ),
        examples=[
            (
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNvbWUta2lkIn0.e"
                "yJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tLyIsImlhdCI6MTYxNTIzMzc4NC"
                "wiaXNzIjoiaHR0cHM6Ly90ZXN0LmV4YW1wbGUuY29tLyIsImV4cCI6MTYxNTM"
                "yMDE4NCwibmFtZSI6IlNvbWUgVXNlciIsInByZWZlcnJlZF91c2VybmFtZSI6"
                "InNvbWUtdXNlciIsInN1YiI6InNvbWUtdXNlciIsInVpZCI6InNvbWUtdXNlc"
                "iIsInVpZE51bWJlciI6MTAwMCwianRpIjoiN2lDdjZvcHI3Vkp4ZkVDR19yWj"
                "A5dyIsInNjb3BlIjoib3BlbmlkIn0.vfR-J5SDWeydtd_HWBZ8o6RpLbOZcVX"
                "Lvwfh_zpYAKRVN-nZ_H82hOsPjRKD0ujAxaPQJv5kmIAIVYrfDIpQDUcP0IIS"
                "sZ_IuEO-BuotCtZ-MPU-hKMlWGG-B3goc3Ygu_HWlfO56GppTE7A9fksYVMca"
                "Sdi6zVvWZH-PmgZAlPZ4xs4NQ_pXdIUA5yc4NhLAoQ5jBkPCTXsr4tqTBkPKK"
                "XxsNDLUFeS262o58kvOAgSCDLRuFXVVHEUIOw-kGko_UGmG3O5R3o-dC7f7K3"
                "OOUI_UulCldWu1ZgdckUfIS7fyMDmcZ4vNL8EALDEewvmjwyO_OLqquNFnfMe"
                "JdKNPw"
            )
        ],
    )

    id_token: str = Field(
        ...,
        title="Identity token",
        description=(
            "access_token and id_token are the same in this implementation"
        ),
        examples=[
            (
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNvbWUta2lkIn0.e"
                "yJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tLyIsImlhdCI6MTYxNTIzMzc4NC"
                "wiaXNzIjoiaHR0cHM6Ly90ZXN0LmV4YW1wbGUuY29tLyIsImV4cCI6MTYxNTM"
                "yMDE4NCwibmFtZSI6IlNvbWUgVXNlciIsInByZWZlcnJlZF91c2VybmFtZSI6"
                "InNvbWUtdXNlciIsInN1YiI6InNvbWUtdXNlciIsInVpZCI6InNvbWUtdXNlc"
                "iIsInVpZE51bWJlciI6MTAwMCwianRpIjoiN2lDdjZvcHI3Vkp4ZkVDR19yWj"
                "A5dyIsInNjb3BlIjoib3BlbmlkIn0.vfR-J5SDWeydtd_HWBZ8o6RpLbOZcVX"
                "Lvwfh_zpYAKRVN-nZ_H82hOsPjRKD0ujAxaPQJv5kmIAIVYrfDIpQDUcP0IIS"
                "sZ_IuEO-BuotCtZ-MPU-hKMlWGG-B3goc3Ygu_HWlfO56GppTE7A9fksYVMca"
                "Sdi6zVvWZH-PmgZAlPZ4xs4NQ_pXdIUA5yc4NhLAoQ5jBkPCTXsr4tqTBkPKK"
                "XxsNDLUFeS262o58kvOAgSCDLRuFXVVHEUIOw-kGko_UGmG3O5R3o-dC7f7K3"
                "OOUI_UulCldWu1ZgdckUfIS7fyMDmcZ4vNL8EALDEewvmjwyO_OLqquNFnfMe"
                "JdKNPw"
            )
        ],
    )

    expires_in: int = Field(
        ...,
        title="Expiration in seconds",
        examples=[86400],
    )

    scope: str = Field(
        ...,
        title="Scopes of token",
        description=(
            "Scopes of the issued token, with any unrecognized or unauthorized"
            " scopes from the request filtered out"
        ),
        examples=["email openid profile"],
    )

    token_type: str = Field(
        "Bearer",
        title="Type of token",
        description="Will always be `Bearer`",
        examples=["Bearer"],
    )


class OIDCErrorReply(BaseModel):
    """An error from an OpenID Connect token request."""

    error: str = Field(
        ...,
        title="Error code",
        description=(
            "See [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)"
            " for possible codes"
        ),
        examples=["some_code"],
    )

    error_description: str = Field(
        ...,
        title="Error message",
        examples=["Some error message"],
    )


class JWK(BaseModel):
    """The schema for a JSON Web Key (RFCs 7517 and 7518)."""

    alg: str = Field(
        ...,
        title="Algorithm",
        description=f"Will always be `{ALGORITHM}`",
        examples=[ALGORITHM],
    )

    kty: str = Field(
        ...,
        title="Key type",
        description="Will always be `RSA`",
        examples=["RSA"],
    )

    use: str = Field(
        ...,
        title="Key usage",
        description="Will always be `sig` (signatures)",
        examples=["sig"],
    )

    kid: str | None = Field(
        None,
        title="Key ID",
        description=(
            "A name for the key, also used in the header of a JWT signed by"
            " that key. Allows the signer to have multiple valid keys at a"
            " time and thus support key rotation."
        ),
        examples=["some-key-id"],
    )

    n: str = Field(
        ...,
        title="RSA modulus",
        description=(
            "Big-endian modulus component of the RSA public key encoded in"
            " URL-safe base64 without trailing padding"
        ),
        examples=[
            (
                "ANKiIsSRoHb4n9xumf17III4O74-eYEMIb6KgGZmC9g7besYXa8vFi-FyHGhI"
                "9hUkaR0UeGLfsB18NWmdVmfGk1kiHOHVEXVjmr40FH8nGIU9Bh9bUwUlm18BE"
                "adHwoXCoiHW6Tm6cFNX8ANmOO3px99mpL5hd3Z2HFeKC230vpQ7ufbLj_QMIp"
                "Fw3h-UOcJ9Yro_GFQB7tObL34HyrnzR-pS9DaAzQ0oGUwBHx-9b5iw75A2VEO"
                "raDoKgBlTuZgQpfGM8hJHJcEkg9htWceQfTCPAG7kP9p0K_bF3BM-8zXw53eE"
                "7g3Nd8Yz3875PrPIG7JeKWz7mef8YNmv331fXc"
            )
        ],
    )

    e: str = Field(
        ...,
        title="RSA exponent",
        description=(
            "Big-endian exponent component of the RSA public key encoded in"
            " URL-safe base64 without trailing padding"
        ),
        examples=["AQAB"],
    )


class JWKS(BaseModel):
    """Schema for the ``/.well-known/jwks.json`` endpoint."""

    keys: list[JWK] = Field(
        ...,
        title="Signing keys",
        description="Valid signing keys for OpenID Connect JWTs",
    )


class OIDCConfig(BaseModel):
    """Schema for the ``/.well-known/openid-configuration`` endpoint."""

    issuer: str = Field(
        ...,
        title="iss value for JWTs",
        examples=["https://example.com/"],
    )

    authorization_endpoint: str = Field(
        ...,
        title="URL to start login",
        examples=["https://example.com/auth/openid/login"],
    )

    token_endpoint: str = Field(
        ...,
        title="URL to get token",
        examples=["https://example.com/auth/openid/token"],
    )

    userinfo_endpoint: str = Field(
        ...,
        title="URL to get user metadata",
        examples=["https://example.com/auth/openid/userinfo"],
    )

    jwks_uri: str = Field(
        ...,
        title="URL to get signing keys",
        description="Endpoint will return a JWKS",
        examples=["https://example.com/.well-known/jwks.json"],
    )

    scopes_supported: list[str] = Field(
        [s.value for s in OIDCScope],
        title="Supported scopes",
        description="List of supported scopes",
        examples=[["openid", "profile", "email"]],
    )

    response_types_supported: list[str] = Field(
        ["code"],
        title="Supported response types",
        description="`code` is the only supported response type",
        examples=[["code"]],
    )

    response_modes_supported: list[str] = Field(
        ["query"],
        title="Supported response modes",
        description="`query` is the only supported response mode",
        examples=[["query"]],
    )

    grant_types_supported: list[str] = Field(
        ["authorization_code"],
        title="Supported grant types",
        description="`authorization_code` is the only supported grant type",
        examples=[["authorization_code"]],
    )

    subject_types_supported: list[str] = Field(
        ["public"],
        title="Supported subject types",
        description="`public` is the only supported subject type",
        examples=[["public"]],
    )

    id_token_signing_alg_values_supported: list[str] = Field(
        [ALGORITHM],
        title="Supported JWT signing algorithms",
        description=f"`{ALGORITHM}` is the only supported signing algorithm",
        examples=[[ALGORITHM]],
    )

    token_endpoint_auth_methods_supported: list[str] = Field(
        ["client_secret_post"],
        title="Supported client auth methods",
        description="`client_secret_post` is the only supported auth method",
        examples=[["client_secret_post"]],
    )
