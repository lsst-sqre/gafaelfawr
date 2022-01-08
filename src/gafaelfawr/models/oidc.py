"""Representation of data for OpenID Connect support."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

from ..constants import ALGORITHM
from ..exceptions import InvalidGrantError
from ..util import normalize_datetime, random_128_bits
from .token import Token

__all__ = [
    "JWK",
    "JWKS",
    "OIDCAuthorization",
    "OIDCAuthorizationCode",
    "OIDCConfig",
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


class OIDCTokenReply(BaseModel):
    """A reply to a successful OpenID Connect token request."""

    access_token: str = Field(
        ...,
        title="Authentication token",
        description=(
            "access_token and id_token are the same in this implementation"
        ),
        example=(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNvbWUta2lkIn0.eyJhd"
            "WQiOiJodHRwczovL2V4YW1wbGUuY29tLyIsImlhdCI6MTYxNTIzMzc4NCwiaXNzIj"
            "oiaHR0cHM6Ly90ZXN0LmV4YW1wbGUuY29tLyIsImV4cCI6MTYxNTMyMDE4NCwibmF"
            "tZSI6IlNvbWUgVXNlciIsInByZWZlcnJlZF91c2VybmFtZSI6InNvbWUtdXNlciIs"
            "InN1YiI6InNvbWUtdXNlciIsInVpZCI6InNvbWUtdXNlciIsInVpZE51bWJlciI6M"
            "TAwMCwianRpIjoiN2lDdjZvcHI3Vkp4ZkVDR19yWjA5dyIsInNjb3BlIjoib3Blbm"
            "lkIn0.vfR-J5SDWeydtd_HWBZ8o6RpLbOZcVXLvwfh_zpYAKRVN-nZ_H82hOsPjRK"
            "D0ujAxaPQJv5kmIAIVYrfDIpQDUcP0IISsZ_IuEO-BuotCtZ-MPU-hKMlWGG-B3go"
            "c3Ygu_HWlfO56GppTE7A9fksYVMcaSdi6zVvWZH-PmgZAlPZ4xs4NQ_pXdIUA5yc4"
            "NhLAoQ5jBkPCTXsr4tqTBkPKKXxsNDLUFeS262o58kvOAgSCDLRuFXVVHEUIOw-kG"
            "ko_UGmG3O5R3o-dC7f7K3OOUI_UulCldWu1ZgdckUfIS7fyMDmcZ4vNL8EALDEewv"
            "mjwyO_OLqquNFnfMeJdKNPw"
        ),
    )

    id_token: str = Field(
        ...,
        title="Identity token",
        description=(
            "access_token and id_token are the same in this implementation"
        ),
        example=(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InNvbWUta2lkIn0.eyJhd"
            "WQiOiJodHRwczovL2V4YW1wbGUuY29tLyIsImlhdCI6MTYxNTIzMzc4NCwiaXNzIj"
            "oiaHR0cHM6Ly90ZXN0LmV4YW1wbGUuY29tLyIsImV4cCI6MTYxNTMyMDE4NCwibmF"
            "tZSI6IlNvbWUgVXNlciIsInByZWZlcnJlZF91c2VybmFtZSI6InNvbWUtdXNlciIs"
            "InN1YiI6InNvbWUtdXNlciIsInVpZCI6InNvbWUtdXNlciIsInVpZE51bWJlciI6M"
            "TAwMCwianRpIjoiN2lDdjZvcHI3Vkp4ZkVDR19yWjA5dyIsInNjb3BlIjoib3Blbm"
            "lkIn0.vfR-J5SDWeydtd_HWBZ8o6RpLbOZcVXLvwfh_zpYAKRVN-nZ_H82hOsPjRK"
            "D0ujAxaPQJv5kmIAIVYrfDIpQDUcP0IISsZ_IuEO-BuotCtZ-MPU-hKMlWGG-B3go"
            "c3Ygu_HWlfO56GppTE7A9fksYVMcaSdi6zVvWZH-PmgZAlPZ4xs4NQ_pXdIUA5yc4"
            "NhLAoQ5jBkPCTXsr4tqTBkPKKXxsNDLUFeS262o58kvOAgSCDLRuFXVVHEUIOw-kG"
            "ko_UGmG3O5R3o-dC7f7K3OOUI_UulCldWu1ZgdckUfIS7fyMDmcZ4vNL8EALDEewv"
            "mjwyO_OLqquNFnfMeJdKNPw"
        ),
    )

    expires_in: int = Field(
        ...,
        title="Expiration in seconds",
        example=86400,
    )

    token_type: str = Field(
        "Bearer",
        title="Type of token",
        description="Will always be Bearer",
        example="Bearer",
    )


class OIDCErrorReply(BaseModel):
    """An error from an OpenID Connect token request."""

    error: str = Field(
        ...,
        title="Error code",
        description="See RFC 6750 for possible codes",
        example="some_code",
    )

    error_description: str = Field(
        ...,
        title="Error message",
        example="Some error message",
    )


class JWK(BaseModel):
    """The schema for a JSON Web Key (RFCs 7517 and 7518)."""

    alg: str = Field(
        ...,
        title="Algorithm",
        description=f"Will always be {ALGORITHM}",
        example=ALGORITHM,
    )

    kty: str = Field(
        ...,
        title="Key type",
        description="Will always be RSA",
        example="RSA",
    )

    use: str = Field(
        ...,
        title="Key usage",
        description="Will always be sig (signatures)",
        example="sig",
    )

    kid: str = Field(
        None,
        title="Key ID",
        description=(
            "A name for the key, also used in the header of a JWT signed by"
            " that key. Allows the signer to have multiple valid keys at a"
            " time and thus support key rotation."
        ),
        example="some-key-id",
    )

    n: str = Field(
        ...,
        title="RSA modulus",
        description=(
            "Big-endian modulus component of the RSA public key encoded in"
            " URL-safe base64 without trailing padding"
        ),
        example=(
            "ANKiIsSRoHb4n9xumf17III4O74-eYEMIb6KgGZmC9g7besYXa8vFi-FyHGhI9hUk"
            "aR0UeGLfsB18NWmdVmfGk1kiHOHVEXVjmr40FH8nGIU9Bh9bUwUlm18BEadHwoXCo"
            "iHW6Tm6cFNX8ANmOO3px99mpL5hd3Z2HFeKC230vpQ7ufbLj_QMIpFw3h-UOcJ9Yr"
            "o_GFQB7tObL34HyrnzR-pS9DaAzQ0oGUwBHx-9b5iw75A2VEOraDoKgBlTuZgQpfG"
            "M8hJHJcEkg9htWceQfTCPAG7kP9p0K_bF3BM-8zXw53eE7g3Nd8Yz3875PrPIG7Je"
            "KWz7mef8YNmv331fXc"
        ),
    )

    e: str = Field(
        ...,
        title="RSA exponent",
        description=(
            "Big-endian exponent component of the RSA public key encoded in"
            " URL-safe base64 without trailing padding"
        ),
        example="AQAB",
    )


class JWKS(BaseModel):
    """Schema for the ``/.well-known/jwks.json`` endpoint."""

    keys: List[JWK] = Field(
        ...,
        title="Signing keys",
        description="Valid signing keys for OpenID Connect JWTs",
    )


class OIDCConfig(BaseModel):
    """Schema for the ``/.well-known/openid-configuration`` endpoint."""

    issuer: str = Field(
        ...,
        title="iss value for JWTs",
        example="https://example.com/",
    )

    authorization_endpoint: str = Field(
        ...,
        title="URL to start login",
        example="https://example.com/auth/openid/login",
    )

    token_endpoint: str = Field(
        ...,
        title="URL to get token",
        example="https://example.com/auth/openid/token",
    )

    userinfo_endpoint: str = Field(
        ...,
        title="URL to get user metadata",
        example="https://example.com/auth/openid/userinfo",
    )

    jwks_uri: str = Field(
        ...,
        title="URL to get signing keys",
        description="Endpoint will return a JWKS",
        example="https://example.com/.well-known/jwks.json",
    )

    scopes_supported: List[str] = Field(
        ["openid"],
        title="Supported scopes",
        description="openid is the only supported scope",
        example=["openid"],
    )

    response_types_supported: List[str] = Field(
        ["code"],
        title="Supported response types",
        description="code is the only supported response type",
        example=["code"],
    )

    grant_types_supported: List[str] = Field(
        ["authorization_code"],
        title="Supported grant types",
        description="authorization_code is the only supported grant type",
        example=["authorization_code"],
    )

    subject_types_supported: List[str] = Field(
        ["public"],
        title="Supported subject types",
        description="public is the only supported subject type",
        example=["public"],
    )

    id_token_signing_alg_values_supported: List[str] = Field(
        [ALGORITHM],
        title="Supported JWT signing algorithms",
        description=f"{ALGORITHM} is the only supported signing algorithm",
        example=[ALGORITHM],
    )

    token_endpoint_auth_methods_supported: List[str] = Field(
        ["client_secret_post"],
        title="Supported client auth methods",
        description="client_secret_post is the only supported auth method",
        example=["client_secret_post"],
    )
