"""Storage for OpenID Connect authorizations."""

from __future__ import annotations

from typing import Optional

from ..constants import OIDC_AUTHORIZATION_LIFETIME
from ..exceptions import DeserializeError
from ..models.oidc import OIDCAuthorization, OIDCAuthorizationCode
from ..models.token import Token
from .base import RedisStorage

__all__ = ["OIDCAuthorizationStore"]


class OIDCAuthorizationStore:
    """Stores and retrieves OpenID Connect authorizations.

    Parameters
    ----------
    storage
        The underlying storage for `~gafaelfawr.models.oidc.OIDCAuthorization`.
    """

    def __init__(self, storage: RedisStorage[OIDCAuthorization]) -> None:
        self._storage = storage

    async def create(
        self, client_id: str, redirect_uri: str, token: Token
    ) -> OIDCAuthorizationCode:
        """Create a new OpenID Connect authorization and return its code.

        Parameters
        ----------
        client_id
            The client ID with access to this authorization.
        redirect_uri
            The intended return URI for this authorization.
        token
            The underlying authentication token.

        Returns
        -------
        OIDCAuthorizationCode
            The code for a newly-created and stored authorization.
        """
        authorization = OIDCAuthorization(
            client_id=client_id, redirect_uri=redirect_uri, token=token
        )
        await self._storage.store(
            f"oidc:{authorization.code.key}",
            authorization,
            OIDC_AUTHORIZATION_LIFETIME,
        )
        return authorization.code

    async def delete(self, code: OIDCAuthorizationCode) -> None:
        """Delete an OpenID Connect authorization.

        Parameters
        ----------
        code
            The authorization code.
        """
        await self._storage.delete(f"oidc:{code.key}")

    async def delete_all(self) -> None:
        """Delete all stored OpenID Connect authorizations."""
        await self._storage.delete_all("oidc:*")

    async def get(
        self, code: OIDCAuthorizationCode
    ) -> Optional[OIDCAuthorization]:
        """Retrieve an OpenID Connect authorization.

        Parameters
        ----------
        code
            The authorization code.

        Returns
        -------
        OIDCAuthorization or None
            The corresponding authorization, or `None` if no such
            authorization exists.

        Raises
        ------
        DeserializeError
            Raised if the authorization exists but cannot be deserialized.
        """
        authorization = await self._storage.get(f"oidc:{code.key}")
        if not authorization:
            return None
        if authorization.code != code:
            msg = "Secret does not match stored authorization"
            raise DeserializeError(msg)
        return authorization
