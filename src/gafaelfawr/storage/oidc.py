"""Storage for OpenID Connect authorizations."""

from __future__ import annotations

from safir.redis import EncryptedPydanticRedisStorage

from ..constants import OIDC_AUTHORIZATION_LIFETIME
from ..exceptions import InvalidGrantError
from ..models.oidc import OIDCAuthorization, OIDCAuthorizationCode

__all__ = ["OIDCAuthorizationStore"]


class OIDCAuthorizationStore:
    """Stores and retrieves OpenID Connect authorizations.

    Parameters
    ----------
    storage
        Underlying storage for `~gafaelfawr.models.oidc.OIDCAuthorization`.
    """

    def __init__(
        self, storage: EncryptedPydanticRedisStorage[OIDCAuthorization]
    ) -> None:
        self._storage = storage

    async def create(self, authorization: OIDCAuthorization) -> None:
        """Create a new OpenID Connect authorization.

        Parameters
        ----------
        authorization
            The authorization to create.
        """
        await self._storage.store(
            authorization.code.key,
            authorization,
            OIDC_AUTHORIZATION_LIFETIME,
        )

    async def delete(self, code: OIDCAuthorizationCode) -> None:
        """Delete an OpenID Connect authorization.

        Parameters
        ----------
        code
            The authorization code.
        """
        await self._storage.delete(code.key)

    async def delete_all(self) -> None:
        """Delete all stored OpenID Connect authorizations."""
        await self._storage.delete_all("*")

    async def get(
        self, code: OIDCAuthorizationCode
    ) -> OIDCAuthorization | None:
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
        safir.redis.DeserializeError
            Raised if the authorization exists but cannot be deserialized.
        InvalidGrantError
            Raised if the provided secret didn't match the authorization code.
        """
        authorization = await self._storage.get(code.key)
        if not authorization:
            return None
        if authorization.code != code:
            msg = f"Invalid authorization code {code.key}"
            raise InvalidGrantError(msg)
        return authorization
