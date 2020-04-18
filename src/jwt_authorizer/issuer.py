"""Token issuer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import jwt

from jwt_authorizer.config import ALGORITHM, IssuerConfig
from jwt_authorizer.session import Session, Ticket

if TYPE_CHECKING:
    from aioredis import Redis
    from jwt_authorizer.providers import GitHubUserInfo
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

    async def issue_token_from_github(
        self, user_info: GitHubUserInfo
    ) -> Ticket:
        """Issue a user token based on GitHub user data.

        Create a token, issue and store it, create and store an oauth2_proxy
        session, and return the ticket for the new token.

        Parameters
        ----------
        user_info : `jwt_authorizer.providers.GitHubUserInfo`
            User information gathered from GitHub.

        Returns
        -------
        ticket : `jwt_authorizer.session.Ticket`
            The ticket corresponding to the new stored session.
        """
        ticket = Ticket()
        groups = [{"name": t.group_name, "id": t.gid} for t in user_info.teams]
        payload = {
            "name": user_info.name,
            "uid": user_info.username,
            "uidNumber": str(user_info.uid),
            "email": user_info.email,
            "isMemberOf": groups,
        }
        payload.update(self._default_attributes(ticket))

        token = self._encode_token(payload)
        session = self._session_for_token(token, payload)
        await self._session_store.store_session(ticket, session)

        return ticket

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
        token_store : `jwt_authorizer.session.TokenStore`
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
        session = self._session_for_token(token, payload)
        pipeline = self._redis.pipeline()
        await self._session_store.store_session(ticket, session, pipeline)
        token_store.store_token(payload, pipeline)
        await pipeline.execute()

        return ticket

    async def reissue_token(
        self,
        token: Mapping[str, Any],
        ticket: Ticket,
        *,
        internal: bool = False,
    ) -> str:
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
            The new encoded token.
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
        session = self._session_for_token(reissued_token, payload)
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

    def _encode_token(self, payload: Dict[str, Any]) -> str:
        """Encode a token.

        Parameters
        ----------
        payload : Dict[`str`, Any]
            The contents of the token.

        Returns
        -------
        token : `str`
            The encoded token.
        """
        return jwt.encode(
            payload,
            self._config.key,
            algorithm=ALGORITHM,
            headers={"kid": self._config.kid},
        ).decode()

    @staticmethod
    def _session_for_token(token: str, payload: Mapping[str, Any]) -> Session:
        """Construct a session for a token.

        Parameters
        ----------
        token : `str`
            The serialized and encoded token.
        payload : Mapping[`str`, `object`]
            The contents of the token.  The email, iat, and exp attributes
            must be set.

        Returns
        -------
        session : `jwt_authorizer.session.Session`
            An oauth2_proxy session for that token.
        """
        email: str = payload["email"]
        iat: int = payload["iat"]
        exp: int = payload["exp"]

        return Session(
            token=token,
            email=email,
            user=email,
            created_at=datetime.fromtimestamp(iat, tz=timezone.utc),
            expires_on=datetime.fromtimestamp(exp, tz=timezone.utc),
        )
