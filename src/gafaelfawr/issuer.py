"""Token issuer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.tokens import VerifiedToken

if TYPE_CHECKING:
    from typing import Any, Dict, List, Mapping, Optional, Set, Union

    from gafaelfawr.config import IssuerConfig

__all__ = ["InvalidTokenClaimsException", "TokenIssuer"]


class InvalidTokenClaimsException(Exception):
    """A token cannot be issued with the provided claims."""


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

    def issue_token(self, claims: Mapping[str, Any]) -> VerifiedToken:
        """Issue a token containing the provided claims.

        A scope claim will be added based on any groups in an isMemberOf
        claim, if a scope claim was not already present.

        Parameters
        ----------
        claims : Mapping[`str`, Any]
            Claims to include in the token.

        Returns
        -------
        token : `gafaelfawr.tokens.VerifiedToken`
            The newly-issued token.
        """
        payload = dict(claims)
        payload.update(self._default_claims())

        if "jti" not in payload:
            raise InvalidTokenClaimsException("No jti claim")

        if "scope" not in payload:
            scope = self._scope_from_groups(claims.get("isMemberOf", []))
            if scope:
                payload["scope"] = scope

        return self._encode_token(payload)

    def issue_user_token(
        self, token: VerifiedToken, *, scope: str, jti: str,
    ) -> VerifiedToken:
        """Issue a new user-issued token.

        Issues a long-lived token intended for programmatic use.  The claims
        of this token will be based on the user's authentication token, but
        only selective claims will be copied over.

        Parameters
        ----------
        token : `gafaelfawr.tokens.VerifiedToken`
            The user's authentication token.
        scope : str
            The scope of the new token.
        jti : str
            The jti (JWT ID) claim for the new token.

        Returns
        -------
        user_token : `gafaelfawr.tokens.VerifiedToken`
            The new user-issued token.
        """
        claims = {
            "scope": scope,
            "jti": jti,
            self._config.username_claim: token.username,
            self._config.uid_claim: token.uid,
        }
        if token.email:
            claims["email"] = token.email
        return self.issue_token(claims)

    def reissue_token(
        self,
        token: VerifiedToken,
        *,
        jti: str,
        scope: Optional[str] = None,
        internal: bool = False,
    ) -> VerifiedToken:
        """Reissue a token.

        This makes a copy of the token, sets the audience, expiration, issuer,
        and issue time as appropriate, and then returns the token in encoded
        form.  The scope claim of the new token will be based on the provided
        scope, if there is one, and otherwise on the group membership in the
        token.  The upstream scope claim will be discarded.

        Parameters
        ----------
        token : `gafaelfawr.tokens.VerifiedToken`
            The token to reissue.
        jti : Optional[`str`], optional
            The jti to use for the new token.
        scope : Optional[`str`], optional
            If provided, set the scope claim of the reissued token to this.
        internal : `bool`, optional
            If set to True, issue the token with the internal audience instead
            of the external audience.

        Returns
        -------
        new_token : `gafaelfawr.tokens.VerifiedToken`
            The new token.
        """
        payload = dict(token.claims)
        payload.pop("scope", None)
        payload.update(self._default_claims(internal=internal))
        payload["jti"] = jti
        if not scope:
            scope = self._scope_from_groups(token.claims.get("isMemberOf", []))
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

    def _default_claims(
        self, *, internal: bool = False
    ) -> Dict[str, Union[str, int]]:
        """Return the standard claims for any new token.

        Parameters
        ----------
        internal : `bool`, optional
            Whether to issue for an internal audience instead of the default
            audience.

        Returns
        -------
        claims : Dict[`str`, Union[`str`, `int`]]
            Attributes to add to the token under construction.
        """
        if internal:
            audience = self._config.aud_internal
        else:
            audience = self._config.aud
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
        token : `gafaelfawr.tokens.VerifiedToken`
            The encoded token.
        """
        encoded_token = jwt.encode(
            payload,
            self._config.keypair.private_key_as_pem(),
            algorithm=ALGORITHM,
            headers={"kid": self._config.kid},
        ).decode()
        return VerifiedToken(
            encoded=encoded_token,
            claims=payload,
            username=payload[self._config.username_claim],
            uid=payload[self._config.uid_claim],
            jti=payload["jti"],
            email=payload.get("email"),
            scope=set(payload.get("scope", "").split()),
        )

    def _scope_from_groups(
        self, groups: List[Dict[str, str]]
    ) -> Optional[str]:
        """Get scopes from a token's groups.

        Used to determine the scope claim of a reissued token.

        Parameters
        ----------
        groups : List[Dict[`str`, `str`]]
            The groups of a token.  (Technically the value may be `int` but
            the value of the ``name`` key is always `str` and that's all we
            look at.)

        Returns
        -------
        scope : str or `None`
            The scope claim generated from the group membership based on the
            group_mapping configuration parameter.
        """
        group_names = [g["name"] for g in groups]
        scopes: Set[str] = set()
        for group in group_names:
            scopes.update(self._config.group_mapping.get(group, set()))
        return " ".join(sorted(scopes))
