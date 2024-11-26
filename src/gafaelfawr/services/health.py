"""Health check for the Gafaelfawr service."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import async_scoped_session

from ..models.enums import TokenType
from ..storage.token import TokenDatabaseStore, TokenRedisStore
from .userinfo import UserInfoService

__all__ = ["HealthCheckService"]


class HealthCheckService:
    """Check the health of the Gafaelfawr service.

    Intended to be invoked via a Kubernetes liveness check and test the
    underlying Redis, database, and LDAP connections.

    Parameters
    ----------
    token_db_store
        Database backing store for tokens.
    token_redis_store
        Redis backing store for tokens.
    user_info_service
        Service for retrieving user information from LDAP and Firestore.
    session
        Database session.
    """

    def __init__(
        self,
        *,
        token_db_store: TokenDatabaseStore,
        token_redis_store: TokenRedisStore,
        user_info_service: UserInfoService,
        session: async_scoped_session,
    ) -> None:
        self._db = token_db_store
        self._redis = token_redis_store
        self._userinfo = user_info_service
        self._session = session

    async def check(self, *, check_user_info: bool = True) -> None:
        """Check the health of the underlying database and Redis.

        Raises an exception of some kind if one of the underlying services is
        unavailable.

        Parameters
        ----------
        check_user_info
            Whether to check the connections to the user metadata backends.
            This is disabled for the Kubernetes operator, which doesn't need
            access to those.
        """
        async with self._session.begin():
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
        data = await self._redis.get_data_by_key(token_info.token)
        if data and check_user_info:
            await self._userinfo.get_user_info_from_token(data, uncached=True)
