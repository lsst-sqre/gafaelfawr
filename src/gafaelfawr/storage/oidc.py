"""Storage for OpenID Connect authorizations."""

import builtins
import secrets
from datetime import UTC, datetime
from typing import cast

import bcrypt
from pydantic import SecretStr
from safir.database import datetime_to_db
from safir.datetime import format_datetime_for_logging
from safir.redis import EncryptedPydanticRedisStorage
from sqlalchemy import CursorResult, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import OIDCClientConfig
from ..constants import OIDC_AUTHORIZATION_LIFETIME
from ..exceptions import InvalidGrantError
from ..models.oidc import (
    OIDCAuthenticateStatus,
    OIDCAuthorization,
    OIDCAuthorizationCode,
    OIDCClient,
    OIDCClientCreate,
    OIDCClientUpdate,
    OIDCClientWithSecret,
)
from ..schema import OIDCClient as SQLOIDCClient

__all__ = ["OIDCAuthorizationStore", "OIDCClientStore"]


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


class OIDCClientStore:
    """Manage registered OpenID Connect clients.

    Client secrets are stored hashed in the database and are only returned
    during initial creation. After creation, the secret can only be compared
    against a provided password.

    Parameters
    ----------
    session
        The database session.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def authenticate(
        self, client_id: str, client_secret: str
    ) -> OIDCAuthenticateStatus:
        """Check authentication for an OpenID Connect client.

        Parameters
        ----------
        client_id
            Provided client ID.
        client_secret
            Provided client secret.

        Returns
        -------
        OIDCAuthenticateStatus
            Results of the authentication.
        """
        oidc_client = await self._get(client_id)
        if not oidc_client:
            return OIDCAuthenticateStatus.BAD_CLIENT
        hashed = oidc_client.client_secret_hash
        if not bcrypt.checkpw(client_secret.encode(), hashed):
            return OIDCAuthenticateStatus.BAD_SECRET
        return OIDCAuthenticateStatus.VALID

    async def delete(self, client_id: str) -> bool:
        """Delete a registered OpenID Connect client.

        Parameters
        ----------
        client_id
            Identifier of client.

        Returns
        -------
        bool
            `True` if the client was found and deleted, `False` otherwise.
        """
        stmt = delete(SQLOIDCClient).where(
            SQLOIDCClient.client_id == client_id
        )

        # See https://github.com/sqlalchemy/sqlalchemy/issues/9185
        # and https://github.com/sqlalchemy/sqlalchemy/issues/12813
        result = cast("CursorResult", await self._session.execute(stmt))
        return result.rowcount > 0

    async def get(self, client_id: str) -> OIDCClient | None:
        """Retrieve a registered OpenID Connect client.

        Parameters
        ----------
        client_id
            Identifier of client.

        Returns
        -------
        OIDCClient or None
            Corresponding metadata for the OpenID Connect client (without the
            hashed password), or `None` if the client was not found.
        """
        oidc_client = await self._get(client_id)
        if not oidc_client:
            return None
        return OIDCClient.model_validate(oidc_client, from_attributes=True)

    async def list(self) -> builtins.list[OIDCClient]:
        """List all registered OpenID Connect clients.

        Returns
        -------
        list of OIDCClient
            List of registered clients.
        """
        stmt = select(SQLOIDCClient).order_by(SQLOIDCClient.client_id)
        result = await self._session.scalars(stmt)
        return [
            OIDCClient.model_validate(a, from_attributes=True)
            for a in result.all()
        ]

    async def migrate(self, client: OIDCClientConfig) -> None:
        """Migrate an old-style configured client into the database.

        Parameters
        ----------
        config
            Client configuration.
        """
        created = datetime.now(tz=UTC)
        migration_date = format_datetime_for_logging(created)
        description = f"Migrated from secret on {migration_date}"
        secret = client.secret.get_secret_value()
        hashed_secret = bcrypt.hashpw(secret.encode(), bcrypt.gensalt())
        new = SQLOIDCClient(
            client_id=client.id,
            client_secret_hash=hashed_secret,
            return_uri=str(client.return_uri),
            description=description,
            notes=None,
            created=datetime_to_db(created),
            last_modified=datetime_to_db(created),
            last_modified_by="<internal>",
        )
        self._session.add(new)

    async def register(self, create: OIDCClientCreate) -> OIDCClientWithSecret:
        """Register a new OpenID Connect client.

        A secret will be generated and returned in the created client
        information and then stored hashed in the database. The secret is
        (hopefully) then no longer recoverable from the database and can only
        be compared against other hashed passwords.

        Parameters
        ----------
        create
            Parameters for the new client.

        Returns
        -------
        OIDCClientWithSecret
            Newly-registered client with its secret.
        """
        secret = secrets.token_urlsafe()
        hashed_secret = bcrypt.hashpw(secret.encode(), bcrypt.gensalt())
        created = datetime_to_db(datetime.now(tz=UTC))
        new = SQLOIDCClient(
            client_id=create.client_id,
            client_secret_hash=hashed_secret,
            return_uri=create.return_uri,
            description=create.description,
            notes=create.notes,
            created=created,
            last_modified=created,
            last_modified_by=create.last_modified_by,
        )
        self._session.add(new)
        await self._session.flush()
        oidc_client = OIDCClient.model_validate(new, from_attributes=True)
        return OIDCClientWithSecret(
            client_secret=SecretStr(secret),
            **oidc_client.model_dump(mode="json"),
        )

    async def update(
        self, client_id: str, update: OIDCClientUpdate
    ) -> OIDCClient | None:
        """Update a registered OpenID Connect client.

        Parameters
        ----------
        client_id
            Identifier of client.
        update
            Changes to apply.

        Returns
        -------
        OIDCClient or None
            Updated OpenID Connect client metadata or `None` if no such client
            was found.

        Raises
        ------
        NotFoundError
            Raised if the client doesn't exist.
        """
        oidc_client = await self._get(client_id)
        if not oidc_client:
            return None
        oidc_client.return_uri = update.return_uri
        oidc_client.description = update.description
        oidc_client.notes = update.notes
        return OIDCClient.model_validate(oidc_client, from_attributes=True)

    async def _get(self, client_id: str) -> SQLOIDCClient | None:
        """Retrieve a registered OIDC client by ID."""
        stmt = select(SQLOIDCClient).where(
            SQLOIDCClient.client_id == client_id
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()
