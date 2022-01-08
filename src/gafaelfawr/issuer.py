"""Token issuer."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt

from gafaelfawr.config import IssuerConfig
from gafaelfawr.constants import ALGORITHM
from gafaelfawr.exceptions import NotConfiguredException
from gafaelfawr.models.oidc import OIDCVerifiedToken
from gafaelfawr.models.token import TokenData, TokenUserInfo

__all__ = ["TokenIssuer"]


class TokenIssuer:
    """Issuing new JWTs.

    This class is responsible for either reissuing internal JWTs based on
    external ones, creating new long-lived JWTs at user request, or minting
    new JWTs from non-JWT authentication sources.

    Parameters
    ----------
    config : `gafaelfawr.config.IssuerConfig`
        Configuration parameters for the issuer.
    """

    def __init__(self, config: IssuerConfig) -> None:
        self._config = config

    def issue_token(
        self, user_info: TokenUserInfo, **claims: str
    ) -> OIDCVerifiedToken:
        """Issue an OpenID Connect token.

        This creates a new OpenID Connect token with data taken from the
        internal Gafaelfawr token.  The scope claim of the new token will be
        based on the group membership in the token unless it is overridden.

        Parameters
        ----------
        user_info : `gafaelfawr.models.token.TokenData`
            The token data on which to base the token.
        **claims : `str`
            Additional claims to add to the token.

        Returns
        -------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The new token.
        """
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=self._config.exp_minutes)
        payload = {
            "aud": self._config.aud,
            "iat": int(now.timestamp()),
            "iss": self._config.iss,
            "exp": int(expires.timestamp()),
            "name": user_info.name,
            "preferred_username": user_info.username,
            "sub": user_info.username,
            self._config.username_claim: user_info.username,
            self._config.uid_claim: user_info.uid,
            **claims,
        }
        return self._encode_token(payload)

    def issue_influxdb_token(self, token_data: TokenData) -> str:
        """Issue an InfluxDB-compatible token.

        InfluxDB requires an HS256 JWT with ``username`` and ``exp`` claims
        using a shared secret.  Issue such a token based on the user's
        Gafaelfawr token.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            The data from the user's authentication token.

        Returns
        -------
        influxdb_token : `str`
            The encoded form of an InfluxDB-compatible token.
        """
        secret = self._config.influxdb_secret
        if not secret:
            raise NotConfiguredException("No InfluxDB issuer configuration")
        if self._config.influxdb_username:
            username = self._config.influxdb_username
        else:
            username = token_data.username
        if token_data.expires:
            expires = token_data.expires
        else:
            now = datetime.now(timezone.utc)
            expires = now + timedelta(minutes=self._config.exp_minutes)
        payload = {
            "exp": int(expires.timestamp()),
            "iat": int(time.time()),
            "username": username,
        }
        return jwt.encode(payload, secret, algorithm="HS256")

    def _encode_token(self, payload: Dict[str, Any]) -> OIDCVerifiedToken:
        """Encode a token.

        Parameters
        ----------
        payload : Dict[`str`, Any]
            The contents of the token.

        Returns
        -------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The encoded token.
        """
        encoded_token = jwt.encode(
            payload,
            self._config.keypair.private_key_as_pem().decode(),
            algorithm=ALGORITHM,
            headers={"kid": self._config.kid},
        )
        return OIDCVerifiedToken(
            encoded=encoded_token,
            claims=payload,
            username=payload[self._config.username_claim],
            uid=payload[self._config.uid_claim],
            jti=payload.get("jti"),
        )
