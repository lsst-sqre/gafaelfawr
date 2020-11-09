"""Storage for OpenID Connect authorizations."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.exceptions import DeserializeException
from gafaelfawr.models.oidc import OIDCAuthorization

if TYPE_CHECKING:
    from typing import Optional

    from gafaelfawr.models.oidc import OIDCAuthorizationCode
    from gafaelfawr.models.token import Token
    from gafaelfawr.storage.base import RedisStorage

__all__ = ["OIDCAuthorizationStore"]


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
        self, client_id: str, redirect_uri: str, token: Token
    ) -> OIDCAuthorizationCode:
        """Create a new OpenID Connect authorization and return its code.

        Parameters
        ----------
        client_id : `str`
            The client ID with access to this authorization.
        redirect_uri : `str`
            The intended return URI for this authorization.
        token : `gafaelfawr.models.token.Token`
            The underlying authentication token.

        Returns
        -------
        code : `gafaelfawr.models.oidc.OIDCAuthorizationCode`
            The code for a newly-created and stored authorization.
        """
        authorization = OIDCAuthorization(
            client_id=client_id, redirect_uri=redirect_uri, token=token
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
