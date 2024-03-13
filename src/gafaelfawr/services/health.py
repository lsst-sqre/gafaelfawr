"""Health check for the Gafaelfawr service."""

from __future__ import annotations

from ..models.token import TokenType
from ..storage.ldap import LDAPStorage
from ..storage.token import TokenDatabaseStore, TokenRedisStore

__all__ = ["HealthCheckService"]


class HealthCheckService:
    """Check the health of the Gafaelfawr service.

    Intended to be invoked via a Kubernetes liveness check and test the
    underlying Redis, database, and LDAP connections.

    Parameters
    ----------
    ldap
        LDAP store for user metadata, if LDAP was configured.
    token_db_store
        Database backing store for tokens.
    token_redis_store
        Redis backing store for tokens.
    """

    def __init__(
        self,
        *,
        ldap: LDAPStorage | None,
        token_db_store: TokenDatabaseStore,
        token_redis_store: TokenRedisStore,
    ) -> None:
        self._ldap = ldap
        self._db = token_db_store
        self._redis = token_redis_store

    async def check(self) -> None:
        """Check the health of the underlying database and Redis.

        Raises an exception of some kind if one of the underlying services is
        unavailable.
        """
        tokens = await self._db.list_tokens(
            token_type=TokenType.session, limit=1
        )

        # If we can't find a user session token, we don't have a token key for
        # Redis or a username for LDAP, and thus unfortunately can't test the
        # other backend components. This should not be the case if Gafaelfawr
        # is being used at all, so it should be safe to skip those health
        # checks in this case.
        if not tokens:
            return
        token_info = tokens[0]
        await self._redis.get_data_by_key(token_info.token)
        if self._ldap:
            user_info = await self._ldap.get_data(token_info.username)
            await self._ldap.get_groups(token_info.username, user_info.gid)
