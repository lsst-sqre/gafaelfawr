"""Token issuer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from jwt_authorizer.constants import ALGORITHM
from jwt_authorizer.tokens import VerifiedToken

if TYPE_CHECKING:
    from jwt_authorizer.config import IssuerConfig
    from jwt_authorizer.tokens import Token
    from typing import Any, Dict, Mapping, Optional, Union

__all__ = ["TokenIssuer"]


class TokenIssuer:
    """Issuing new JWTs.

    This class is responsible for either reissuing internal JWTs based on
    external ones, creating new long-lived JWTs at user request, or minting
    new JWTs from non-JWT authentication sources.

    Parameters
    ----------
    config : `jwt_authorizer.config.IssuerConfig`
        Configuration parameters for the issuer.
    """

    def __init__(self, config: IssuerConfig,) -> None:
        self._config = config

    def issue_token(self, claims: Mapping[str, Any]) -> VerifiedToken:
        """Issue a token containing the provided claims.

        Parameters
        ----------
        claims : Mapping[`str`, Any]
            Claims to include in the token.

        Returns
        -------
        token : `jwt_authorizer.tokens.VerifiedToken`
            The newly-issued token.
        """
        payload = dict(claims)
        payload.update(self._default_attributes())
        return self._encode_token(payload)

    def verify_token(self, token: Token) -> VerifiedToken:
        """Verify a token issued by this issuer.

        Parameters
        ----------
        token : `jwt_authorizer.tokens.Token`
            An encoded token.

        Returns
        -------
        verified_token : `jwt_authorizer.tokens.VerifiedToken`
            The verified token.

        Raises
        ------
        jwt.exceptions.InvalidTokenError
            The issuer of this token is unknown and therefore the token cannot
            be verified.
        """
        audience = [self._config.aud, self._config.aud_internal]
        payload = jwt.decode(
            token.encoded,
            self._config.keypair.public_key_as_pem(),
            algorithms=ALGORITHM,
            audience=audience,
        )
        return VerifiedToken(encoded=token.encoded, claims=payload)

    def reissue_token(
        self,
        token: VerifiedToken,
        *,
        jti: Optional[str] = None,
        scope: Optional[str] = None,
        internal: bool = False,
    ) -> VerifiedToken:
        """Reissue a token.

        This makes a copy of the token, sets the audience, expiration, issuer,
        and issue time as appropriate, and then returns the token in encoded
        form.

        Parameters
        ----------
        token : `jwt_authorizer.tokens.VerifiedToken`
            The token to reissue.
        jti : Optional[`str`], optional
            The jti to use for the new token.
        scope : Optional[`str`], optional
            If provided, set the scope claim of the reissued ticket to this.
        internal : `bool`, optional
            If set to True, issue the token with the internal audience instead
            of the external audience.

        Returns
        -------
        new_token : `jwt_authorizer.tokens.VerifiedToken`
            The new token.
        """
        payload = dict(token.claims)
        payload.update(self._default_attributes(internal=internal))
        if jti:
            payload["jti"] = jti
        if scope:
            payload["scope"] = scope

        if "aud" in token.claims and "iss" in token.claims:
            actor_claim = {
                "aud": token.claims["aud"],
                "iss": token.claims["iss"],
            }
            if "jti" in token.claims:
                actor_claim["jti"] = token.claims["jti"]
            if "act" in token.claims:
                actor_claim["act"] = token.claims["act"]
            payload["act"] = actor_claim

        return self._encode_token(payload)

    def _default_attributes(
        self, *, internal: bool = False
    ) -> Dict[str, Union[str, int]]:
        """Return the standard attributes for any new token.

        Parameters
        ----------
        internal : `bool`, optional
            Whether to issue for an internal audience instead of the default
            audience.

        Returns
        -------
        attributes : Dict[`str`, Union[`str`, `int`]]
            Attributes to add to the token under construction.
        """
        audience = self._config.aud_internal if internal else self._config.aud
        expires = datetime.now(timezone.utc) + timedelta(
            minutes=self._config.exp_minutes
        )
        return {
            "aud": audience,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "iss": self._config.iss,
            "exp": int(expires.timestamp()),
        }

    def _encode_token(self, payload: Dict[str, Any]) -> VerifiedToken:
        """Encode a token.

        Parameters
        ----------
        payload : Dict[`str`, Any]
            The contents of the token.

        Returns
        -------
        token : `jwt_authorizer.tokens.VerifiedToken`
            The encoded token.
        """
        encoded_token = jwt.encode(
            payload,
            self._config.keypair.private_key_as_pem(),
            algorithm=ALGORITHM,
            headers={"kid": self._config.kid},
        ).decode()
        return VerifiedToken(encoded=encoded_token, claims=payload)
