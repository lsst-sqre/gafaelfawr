"""Token issuer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from jwt_authorizer.config import ALGORITHM, IssuerConfig
from jwt_authorizer.session import Session, Ticket
from jwt_authorizer.tokens import VerifiedToken

if TYPE_CHECKING:
    from aioredis import Redis
    from jwt_authorizer.session import SessionStore
    from jwt_authorizer.tokens import TokenStore
    from typing import Any, Dict, Mapping, Union

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
    ticket_prefix : `str`
        Prefix to use when converting tickets to strings.
    session_store : `jwt_authorizer.session.SessionStore`
        Storage for oauth2_proxy sessions.
    redis : `aioredis.Redis`
        Redis client.
    """

    def __init__(
        self,
        config: IssuerConfig,
        ticket_prefix: str,
        session_store: SessionStore,
        redis: Redis,
    ) -> None:
        self._config = config
        self._ticket_prefix = ticket_prefix
        self._session_store = session_store
        self._redis = redis

    async def issue_token(
        self, claims: Mapping[str, Any], ticket: Ticket
    ) -> VerifiedToken:
        """Issue a token containing the provided claims.

        Create a token, store it in the session store under the provided
        ticket, and then return the new token.

        Parameters
        ----------
        claims : Mapping[`str`, Any]
            Claims to include in the token.

        Returns
        -------
        ticket : `jwt_authorizer.tokens.VerifiedToken`
            The newly-issued token.
        """
        payload = dict(claims)
        payload.update(self._default_attributes(ticket))

        token = self._encode_token(payload)
        session = self._session_for_token(token)
        await self._session_store.store_session(ticket, session)

        return token

    async def issue_user_token(
        self, attributes: Mapping[str, Any], token_store: TokenStore
    ) -> Ticket:
        """Issue a user token.

        Given a partial payload, fill out the remaining token attributes,
        issue and store a token, create and store an oauth2_proxy session, and
        return the ticket for the new token.

        Parameters
        ----------
        attributes : Mapping[`str`, Any]
            Attributes for the new token.
        token_store : `jwt_authorizer.tokens.TokenStore`
            Store for the list of user tokens.
        session_store : `jwt_authorizer.session.SessionStore`
            Store for new oauth2_proxy session.

        Returns
        -------
        ticket : `jwt_authorizer.session.Ticket`
            The ticket corresponding to the new stored session.
        """
        ticket = Ticket()
        payload = dict(attributes)
        payload.update(self._default_attributes(ticket))

        token = self._encode_token(payload)
        session = self._session_for_token(token)
        pipeline = self._redis.pipeline()
        await self._session_store.store_session(ticket, session, pipeline)
        token_store.store_token(token.claims, pipeline)
        await pipeline.execute()

        return ticket

    async def reissue_token(
        self,
        token: Mapping[str, Any],
        ticket: Ticket,
        *,
        internal: bool = False,
    ) -> VerifiedToken:
        """Reissue a token.

        This makes a copy of the token, sets the audience, expiration, issuer,
        and issue time as appropriate, and then returns the token in encoded
        form. If configured, it will also store the newly issued token a
        oauth2_proxy redis session store.

        Parameters
        ----------
        token : Mapping[`str`, Any]
            The token to reissue.
        ticket : `jwt_authorizer.session.Ticket`
            The Ticket to use as the identifier for the token and to use for
            storing the new token.
        internal : `bool`, optional
            If set to True, issue the token with the internal audience instead
            of the external audience.

        Returns
        -------
        new_token : `str`
            The new token.
        """
        payload = dict(token)
        payload.update(self._default_attributes(ticket, internal=internal))

        if "aud" in token and "iss" in token:
            actor_claim = {"aud": token["aud"], "iss": token["iss"]}
            if "jti" in token:
                actor_claim["jti"] = token["jti"]
            if "act" in token:
                actor_claim["act"] = token["act"]
            payload["act"] = actor_claim

        reissued_token = self._encode_token(payload)
        session = self._session_for_token(reissued_token)
        await self._session_store.store_session(ticket, session)

        return reissued_token

    def _default_attributes(
        self, ticket: Ticket, *, internal: bool = False
    ) -> Dict[str, Union[str, int]]:
        """Return the standard attributes for any new token.

        Parameters
        ----------
        ticket : `jwt_authorizer.session.Ticket`
            The ticket that will be used for this token.
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
            "jti": ticket.as_handle(self._ticket_prefix),
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
            self._config.key,
            algorithm=ALGORITHM,
            headers={"kid": self._config.kid},
        ).decode()
        return VerifiedToken(encoded=encoded_token, claims=payload)

    @staticmethod
    def _session_for_token(token: VerifiedToken) -> Session:
        """Construct a session for a token.

        Parameters
        ----------
        token : `jwt_authorizer.tokens.VerifiedToken`
            The validated token.  The email, iat, and exp claims must be set.

        Returns
        -------
        session : `jwt_authorizer.session.Session`
            An oauth2_proxy session for that token.
        """
        email: str = token.claims["email"]
        iat: int = token.claims["iat"]
        exp: int = token.claims["exp"]

        return Session(
            token=token,
            email=email,
            user=email,
            created_at=datetime.fromtimestamp(iat, tz=timezone.utc),
            expires_on=datetime.fromtimestamp(exp, tz=timezone.utc),
        )
