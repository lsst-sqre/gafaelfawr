"""Storage for OpenID Connect authorizations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from gafaelfawr.constants import OIDC_AUTHORIZATION_LIFETIME
from gafaelfawr.exceptions import DeserializeException
from gafaelfawr.session import SessionHandle
from gafaelfawr.storage.base import Serializable

if TYPE_CHECKING:
    from typing import Optional

    from gafaelfawr.storage.base import RedisStorage

__all__ = [
    "OIDCAuthorization",
    "OIDCAuthorizationCode",
    "OIDCAuthorizationStore",
]


class OIDCAuthorizationCode(SessionHandle):
    """An OpenID Connect authorization code.

    Identical to a session handle in behavior.  This class exists to give it a
    new type for better type checking.
    """


@dataclass
class OIDCAuthorization(Serializable):
    """Represents an authorization for an OpenID Connect client.

    This is the object created during login and stored in Redis.  The returned
    authorization code points to it and allows it to be retrieved so that an
    OpenID Connect client can redeem the code for a token.

    Notes
    -----
    The authorization code is represented by the `OIDCAuthorizationCode`
    class.  It consists of a key and a secret.  The key corresponds to the
    Redis key under which the session is stored.  The combined key and secret
    must match the handle stored inside the encrypted Redis object.  This
    approach prevents someone with access to list the Redis keys from using a
    Redis key directly as an authorization code.

    The corresponding token is not stored directly in this session entry.
    Instead, it stores a handle for the user's underlying authentication
    session, from which a token can be retrieved.
    """

    code: OIDCAuthorizationCode
    """The authorization code."""

    client_id: str
    """The client that is allowed to use this authorization."""

    redirect_uri: str
    """The redirect URI for which this authorization is intended."""

    session_handle: SessionHandle
    """The underlying authentication session for the user."""

    created_at: datetime
    """When the authorization was created."""

    @classmethod
    def create(
        cls, client_id: str, redirect_uri: str, session_handle: SessionHandle
    ) -> OIDCAuthorization:
        """Create a new OpenID Connect authorization.

        Parameters
        ----------
        client_id : `str`
            The client that is allowed to use this authorization.
        redirect_uri : `str`
            The redirect URI for which this authorization is intended.
        session_handle : `gafaelfawr.session.SessionHandle`
            A handle for the underlying authentication session.

        Returns
        -------
        code : `OIDCAuthorization`
            The newly-created session.
        """
        return cls(
            code=OIDCAuthorizationCode(),
            client_id=client_id,
            redirect_uri=redirect_uri,
            session_handle=session_handle,
            created_at=datetime.now(timezone.utc),
        )

    @classmethod
    def from_json(cls, data: str) -> OIDCAuthorization:
        authorization = json.loads(data)
        code = OIDCAuthorizationCode.from_str(authorization["code"])
        return cls(
            code=cast(OIDCAuthorizationCode, code),
            client_id=authorization["client_id"],
            redirect_uri=authorization["redirect_uri"],
            session_handle=SessionHandle.from_str(
                authorization["session_handle"]
            ),
            created_at=datetime.fromtimestamp(
                authorization["created_at"], tz=timezone.utc
            ),
        )

    @property
    def lifetime(self) -> int:
        now = datetime.now(timezone.utc)
        age = int((now - self.created_at).total_seconds())
        return OIDC_AUTHORIZATION_LIFETIME - age

    def to_json(self) -> str:
        data = {
            "code": self.code.encode(),
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "session_handle": self.session_handle.encode(),
            "created_at": int(self.created_at.timestamp()),
        }
        return json.dumps(data)


class OIDCAuthorizationStore:
    """Stores and retrieves OpenID Connect authorizations.

    Parameters
    ----------
    storage : `gafaelfawr.storage.base.RedisStorage`
        The underlying storage for `OIDCAuthorization`.
    """

    def __init__(self, storage: RedisStorage[OIDCAuthorization]) -> None:
        self._storage = storage

    async def create(
        self, client_id: str, redirect_uri: str, session_handle: SessionHandle
    ) -> OIDCAuthorizationCode:
        """Create a new OpenID Connect authorization and return its code.

        Parameters
        ----------
        client_id : `str`
            The client ID with access to this authorization.
        redirect_uri : `str`
            The intended return URI for this authorization.
        session_handle : `gafaelfawr.session.SessionHandle`
            The handle for the underlying authentication session.

        Returns
        -------
        code : `gafaelfawr.session.SessionHandle`
            The code for a newly-created and stored authorization.
        """
        authorization = OIDCAuthorization.create(
            client_id, redirect_uri, session_handle
        )
        key = f"oidc:{authorization.code.key}"
        await self._storage.store(key, authorization)
        return authorization.code

    async def delete(self, code: OIDCAuthorizationCode) -> None:
        """Delete an OpenID Connect authorization.

        Parameters
        ----------
        code : `gafaelfawr.session.SessionHandle`
            The authorization code.
        """
        await self._storage.delete(f"oidc:{code.key}")

    async def get(
        self, code: OIDCAuthorizationCode
    ) -> Optional[OIDCAuthorization]:
        """Retrieve an OpenID Connect authorization.

        Parameters
        ----------
        code : `gafaelfawr.session.SessionHandle`
            The authorization code.

        Returns
        -------
        authorization : `OIDCAuthorization` or `None`
            The corresponding authorization, or `None` if no such
            authorization exists.

        Raises
        ------
        gafaelfawr.exceptions.DeserializeException
            If the authorization exists but cannot be deserialized.
        """
        authorization = await self._storage.get(f"oidc:{code.key}")
        if not authorization:
            return None
        if authorization.code != code:
            msg = "Secret does not match stored authorization"
            raise DeserializeException(msg)
        return authorization
