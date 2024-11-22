"""Manage tokens."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from datetime import datetime, timedelta

from safir.datetime import current_datetime, format_datetime_for_logging
from sqlalchemy.ext.asyncio import async_scoped_session
from structlog.stdlib import BoundLogger

from ..config import Config
from ..constants import (
    CHANGE_HISTORY_RETENTION,
    MINIMUM_LIFETIME,
    USERNAME_REGEX,
)
from ..events import (
    ActiveUserSessionsEvent,
    ActiveUserTokensEvent,
    StateEvents,
)
from ..exceptions import (
    InvalidExpiresError,
    InvalidIPAddressError,
    InvalidScopesError,
    PermissionDeniedError,
)
from ..models.history import (
    HistoryCursor,
    PaginatedHistory,
    TokenChange,
    TokenChangeHistoryEntry,
)
from ..models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenInfo,
    TokenType,
    TokenUserInfo,
)
from ..storage.admin import AdminStore
from ..storage.history import TokenChangeHistoryStore
from ..storage.token import TokenDatabaseStore, TokenRedisStore
from ..util import is_bot_user
from .token_cache import TokenCacheService

__all__ = ["TokenService"]


class TokenService:
    """Manage tokens.

    Parameters
    ----------
    config
        Gafaelfawr configuration.
    token_cache
        Cache of internal and notebook tokens.
    token_db_store
        Database backing store for tokens.
    token_redis_store
        Redis backing store for tokens.
    token_change_store
        Backing store for history of changes to tokens.
    admin_store
        Backing store for Gafaelfawr admins.
    session
        Database session.
    logger
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: Config,
        token_cache: TokenCacheService,
        token_db_store: TokenDatabaseStore,
        token_redis_store: TokenRedisStore,
        token_change_store: TokenChangeHistoryStore,
        admin_store: AdminStore,
        session: async_scoped_session,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._token_cache = token_cache
        self._token_db_store = token_db_store
        self._token_redis_store = token_redis_store
        self._token_change_store = token_change_store
        self._admin_store = admin_store
        self._session = session
        self._logger = logger

    async def audit(self, *, fix: bool = False) -> list[str]:
        """Check Gafaelfawr data stores for consistency.

        If any errors are found and Slack is configured, report them to Slack
        in addition to returning them.

        Parameters
        ----------
        fix
            Whether to fix problems that the audit code knows how to fix
            (which is not all alerts).

        Returns
        -------
        list of str
            A list of human-readable alert messages formatted in Markdown.
        """
        alert: str | None
        alerts = []
        now = current_datetime()

        async with self._session.begin():
            db_tokens = {
                t.token: t
                for t in await self._token_db_store.list_with_parents()
            }
        db_token_keys = set(db_tokens.keys())
        redis_tokens = {}
        for key in await self._token_redis_store.list():
            token_data = await self._token_redis_store.get_data_by_key(key)
            if token_data:
                redis_tokens[key] = token_data
        redis_token_keys = set(redis_tokens.keys())

        # Tokens in the database but not in Redis.
        for key in db_token_keys - redis_token_keys:
            expires = db_tokens[key].expires
            if expires and expires <= now:
                continue
            self._logger.warning(
                "Token found in database but not Redis",
                token=key,
                user=db_tokens[key].username,
            )
            alert = (
                f"Token `{key}` for `{db_tokens[key].username}` found in"
                " database but not Redis"
            )
            if fix:
                async with self._session.begin():
                    await self._token_db_store.modify(key, expires=now)
                alert += " (fixed)"
            alerts.append(alert)

        # Tokens in Redis but not in the database.
        for key in redis_token_keys - db_token_keys:
            self._logger.warning(
                "Token found in Redis but not database",
                token=key,
                user=redis_tokens[key].username,
            )
            alert = (
                f"Token `{key}` for `{redis_tokens[key].username}` found in"
                " Redis but not database"
            )
            if fix:
                await self._token_redis_store.delete(key)
                alert += " (fixed)"
            alerts.append(alert)

        # Check that the data matches between the database and Redis. Older
        # versions of Gafaelfawr didn't sort the scopes in Redis, so we have
        # to sort them here or we get false positives with old tokens.
        for key in db_token_keys & redis_token_keys:
            db = db_tokens[key]
            redis = redis_tokens[key]
            parent = db_tokens.get(db.parent) if db.parent else None
            alerts.extend(
                await self._audit_token(key, db, redis, parent, fix=fix)
            )

        # Check for orphaned tokens.
        alerts.extend(await self._audit_orphaned())

        # Check for unknown scopes.
        alerts.extend(self._audit_unknown_scopes(redis_tokens.values()))

        # Return any errors.
        return alerts

    async def create_session_token(
        self, user_info: TokenUserInfo, *, scopes: list[str], ip_address: str
    ) -> Token:
        """Create a new session token.

        Parameters
        ----------
        user_info
            The user information to associate with the token.
        scopes
            The scopes of the token. ``admin:token`` will be added to these
            scopes if the user is an admin.
        ip_address
            The IP address from which the request came.

        Returns
        -------
        Token
            The newly-created token.

        Raises
        ------
        PermissionDeniedError
            Raised if the provided username is invalid.
        """
        self._validate_username(user_info.username)
        token = Token()
        created = current_datetime()
        expires = created + self._config.token_lifetime
        async with self._session.begin():
            admins = await self._admin_store.list()
        if any(user_info.username == a.username for a in admins):
            scopes = sorted({*scopes, "admin:token"})
        else:
            scopes = sorted(scopes)

        data = TokenData(
            token=token,
            token_type=TokenType.session,
            scopes=scopes,
            created=created,
            expires=expires,
            **user_info.model_dump(),
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.session,
            scopes=scopes,
            expires=expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        try:
            async with self._session.begin():
                await self._token_db_store.add(data)
                await self._token_change_store.add(history_entry)
        except Exception:
            await self._token_redis_store.delete(data.token.key)
            raise

        self._logger.info(
            "Successfully authenticated user %s",
            data.username,
            token_key=token.key,
            token_username=data.username,
            token_expires=format_datetime_for_logging(expires),
            token_scopes=scopes,
            token_userinfo=data.to_userinfo_dict(),
        )

        return token

    async def create_oidc_token(
        self, auth_data: TokenData, *, ip_address: str
    ) -> Token:
        """Add a new OpenID Connect access token.

        Parameters
        ----------
        auth_data
            The token data for the parent token used for authentication.
        ip_address
            The IP address from which the request came.

        Returns
        -------
        Token
            A new child token of type ``oidc``.

        Raises
        ------
        InvalidGrantError
            Raised if the underlying authentication token has expired.
        """
        token = Token()
        created = current_datetime()
        if auth_data.expires:
            expires = auth_data.expires
        else:
            expires = created + self._config.token_lifetime
        data = TokenData(
            token=token,
            username=auth_data.username,
            token_type=TokenType.oidc,
            scopes=[],
            created=created,
            expires=expires,
            name=auth_data.name,
            email=auth_data.email,
            uid=auth_data.uid,
            gid=auth_data.gid,
            groups=auth_data.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.oidc,
            scopes=data.scopes,
            expires=data.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=data.created,
        )

        # Store the new token in Redis and the database.
        await self._token_redis_store.store_data(data)
        try:
            parent = auth_data.token.key
            async with self._session.begin():
                await self._token_db_store.add(data, parent=parent)
                await self._token_change_store.add(history_entry)
        except Exception:
            await self._token_redis_store.delete(data.token.key)
            raise

        # Log the token creation and return it.
        self._logger.info(
            "Created new OpenID Connect token",
            token_key=token.key,
            token_expires=format_datetime_for_logging(expires),
            token_scopes=sorted(data.scopes),
            token_userinfo=data.to_userinfo_dict(),
        )
        return token

    async def create_user_token(
        self,
        auth_data: TokenData,
        username: str,
        *,
        token_name: str,
        scopes: list[str],
        expires: datetime | None = None,
        ip_address: str,
    ) -> Token:
        """Add a new user token.

        Parameters
        ----------
        auth_data
            The token data for the authentication token of the user creating
            a user token.
        username
            The username for which to create a token.
        token_name
            The name of the token.
        scopes
            The scopes of the token.
        expires
            When the token should expire.  If not given, defaults to the
            expiration of the authentication token taken from ``data``.
        ip_address
            The IP address from which the request came.

        Returns
        -------
        Token
            The newly-created token.

        Raises
        ------
        DuplicateTokenNameError
            Raised if a token with this name for this user already exists.
        InvalidExpiresError
            Raised if the provided expiration time was invalid.
        PermissionDeniedError
            Raised if the given username didn't match the user information in
            the authentication token, or if the specified username is invalid.

        Notes
        -----
        This can only be used by the user themselves, not by a token
        administrator for a different user, because this API does not provide
        a way to set the additional user information for the token and instead
        always takes it from the authentication token.
        """
        self._check_authorization(username, auth_data, require_same_user=True)
        self._validate_username(username)
        self._validate_expires(expires)
        self._validate_scopes(scopes, auth_data)
        if expires:
            expires = expires.replace(microsecond=0)
        scopes = sorted(scopes)

        token = Token()
        created = current_datetime()
        data = TokenData(
            token=token,
            username=username,
            token_type=TokenType.user,
            scopes=scopes,
            created=created,
            expires=expires,
            name=auth_data.name,
            email=auth_data.email,
            uid=auth_data.uid,
            gid=auth_data.gid,
            groups=auth_data.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name=token_name,
            scopes=scopes,
            expires=expires,
            actor=auth_data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        try:
            async with self._session.begin():
                await self._token_db_store.add(data, token_name=token_name)
                await self._token_change_store.add(history_entry)
        except Exception:
            await self._token_redis_store.delete(data.token.key)
            raise

        self._logger.info(
            "Created new user token",
            token_key=token.key,
            token_expires=format_datetime_for_logging(expires),
            token_name=token_name,
            token_scopes=sorted(data.scopes),
            token_userinfo=data.to_userinfo_dict(),
        )

        return token

    async def create_token_from_admin_request(
        self,
        request: AdminTokenRequest,
        auth_data: TokenData,
        *,
        ip_address: str | None,
    ) -> Token:
        """Create a new service or user token from an admin request.

        Parameters
        ----------
        request
            The incoming request.
        auth_data
            The data for the authenticated user making the request.
        ip_address
            The IP address from which the request came, or `None` for internal
            requests by Gafaelfawr.

        Returns
        -------
        Token
            The newly-created token.

        Raises
        ------
        InvalidExpiresError
            Raised if the provided expiration time is not valid.
        InvalidScopesError
            Raised if the requested scopes are not permitted.
        PermissionDeniedError
            Raised if the provided username is invalid.
        """
        self._check_authorization(
            request.username, auth_data, require_admin=True
        )
        self._validate_username(request.username)
        self._validate_scopes(request.scopes)
        self._validate_expires(request.expires)
        expires = request.expires
        if expires:
            expires = expires.replace(microsecond=0)

        # Service tokens must be for bot users.
        if request.token_type == TokenType.service:
            if not is_bot_user(request.username):
                msg = f'Username "{request.username}" must start with "bot-"'
                raise PermissionDeniedError(msg)

        token = Token()
        created = current_datetime()
        data = TokenData(
            token=token,
            username=request.username,
            token_type=request.token_type,
            scopes=sorted(request.scopes),
            created=created,
            expires=expires,
            name=request.name,
            email=request.email,
            uid=request.uid,
            gid=request.gid,
            groups=request.groups,
        )
        history_entry = TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=data.token_type,
            token_name=request.token_name,
            scopes=data.scopes,
            expires=expires,
            actor=auth_data.username,
            action=TokenChange.create,
            ip_address=ip_address,
            event_time=created,
        )

        await self._token_redis_store.store_data(data)
        try:
            name = request.token_name
            async with self._session.begin():
                await self._token_db_store.add(data, token_name=name)
                await self._token_change_store.add(history_entry)
        except Exception:
            await self._token_redis_store.delete(data.token.key)
            raise

        if data.token_type == TokenType.user:
            self._logger.info(
                "Created new user token as administrator",
                token_key=token.key,
                token_username=request.username,
                token_expires=format_datetime_for_logging(expires),
                token_name=request.token_name,
                token_scopes=data.scopes,
                token_userinfo=data.to_userinfo_dict(),
            )
        else:
            self._logger.info(
                "Created new service token",
                token_key=token.key,
                token_username=request.username,
                token_expires=format_datetime_for_logging(expires),
                token_scopes=data.scopes,
                token_userinfo=data.to_userinfo_dict(),
            )
        return token

    async def delete_all_tokens(self) -> None:
        """Delete all stored tokens.

        This only purges them from Redis, not from the database.  It is
        normally called in combination with truncating all database tables
        (which is much faster than deleting entries line by line).
        """
        await self._token_redis_store.delete_all()

    async def delete_token(
        self,
        key: str,
        auth_data: TokenData,
        username: str,
        *,
        ip_address: str,
    ) -> bool:
        """Delete a token.

        Parameters
        ----------
        key
            The key of the token to delete.
        auth_data
            The token data for the authentication token of the user deleting
            the token.
        username
            Constrain deletions to tokens owned by the given user.
        ip_address
            The IP address from which the request came.

        Returns
        -------
        bool
            `True` if the token has been deleted, `False` if it was not
            found.
        """
        info = await self.get_token_info_unchecked(key, username)
        if not info:
            return False
        self._check_authorization(info.username, auth_data)

        # Recursively delete the children of this token first. Children are
        # returned in breadth-first order, so delete them in reverse order to
        # delete the tokens farthest down in the tree first.  This minimizes
        # the number of orphaned children at any given point.
        async with self._session.begin():
            children = await self._token_db_store.get_children(key)
            children.reverse()
            for child in children:
                await self._delete_one_token(child, auth_data, ip_address)
            return await self._delete_one_token(key, auth_data, ip_address)

    async def expire_tokens(self) -> None:
        """Bookkeeping for expired tokens.

        Token expiration is primarily controlled by the Redis expiration,
        after which the token disappears from Redis and effectively expires
        from an authentication standpoint. However, we want to do some
        additional bookkeeping of expired tokens: remove them from the
        database and add an expiration entry to the token history table.

        This method is meant to be run periodically, outside of any given user
        request.
        """
        async with self._session.begin():
            expired_tokens = await self._token_db_store.delete_expired()
            for info in expired_tokens:
                self._logger.info(
                    "Expired token",
                    user=info.username,
                    token_type=info.token_type.value,
                    token=info.token,
                )
                history_entry = TokenChangeHistoryEntry(
                    token=info.token,
                    username=info.username,
                    token_type=info.token_type,
                    token_name=info.token_name,
                    parent=info.parent,
                    scopes=info.scopes,
                    service=info.service,
                    expires=info.expires,
                    actor="<internal>",
                    action=TokenChange.expire,
                )
                await self._token_change_store.add(history_entry)

    async def gather_state_metrics(self, events: StateEvents) -> None:
        """Gather metrics from the stored state and record them.

        Parameters
        ----------
        events
            Publishers for state events.
        """
        async with self._session.begin():
            session_count = await self._token_db_store.count_unique_sessions()
            await events.active_user_sessions.publish(
                ActiveUserSessionsEvent(count=session_count)
            )
            token_count = await self._token_db_store.count_user_tokens()
            await events.active_user_tokens.publish(
                ActiveUserTokensEvent(count=token_count)
            )

    async def get_change_history(
        self,
        auth_data: TokenData,
        *,
        cursor: str | None = None,
        limit: int | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        username: str | None = None,
        actor: str | None = None,
        key: str | None = None,
        token: str | None = None,
        token_type: TokenType | None = None,
        ip_or_cidr: str | None = None,
    ) -> PaginatedHistory[TokenChangeHistoryEntry]:
        """Retrieve the change history of a token.

        Parameters
        ----------
        auth_data
            Authentication information for the user making the request.
        cursor
            A pagination cursor specifying where to start in the results.
        limit
            Limit the number of returned results.
        since
            Limit the results to events at or after this time.
        until
            Limit the results to events before or at this time.
        username
            Limit the results to tokens owned by this user.
        actor
            Limit the results to actions performed by this user.
        key
            Limit the results to this token and any subtokens of this token.
            Note that this will currently pick up direct subtokens but not
            subtokens of subtokens.
        token
            Limit the results to only this token.
        token_type
            Limit the results to tokens of this type.
        ip_or_cidr
            Limit the results to changes made from this IPv4 or IPv6 address
            or CIDR block.

        Returns
        -------
        PaginatedHistory
            A list of changes matching the search criteria.

        Raises
        ------
        InvalidCursorError
            Raised if the provided cursor was invalid.
        InvalidIPAddressError
            Raised if the provided argument was syntactically invalid for both
            an IP address and a CIDR block.
        """
        self._check_authorization(username, auth_data)
        self._validate_ip_or_cidr(ip_or_cidr)
        async with self._session.begin():
            return await self._token_change_store.list(
                cursor=HistoryCursor.from_str(cursor) if cursor else None,
                limit=limit,
                since=since,
                until=until,
                username=username,
                actor=actor,
                key=key,
                token=token,
                token_type=token_type,
                ip_or_cidr=ip_or_cidr,
            )

    async def get_data(self, token: Token) -> TokenData | None:
        """Retrieve the data for a token from Redis.

        Doubles as a way to check the validity of the token.

        Parameters
        ----------
        token
            The token.

        Returns
        -------
        TokenData or None
            The data underlying the token, or `None` if the token is not found
            or is invalid.
        """
        return await self._token_redis_store.get_data(token)

    async def get_internal_token(
        self,
        token_data: TokenData,
        service: str,
        scopes: list[str],
        *,
        ip_address: str,
        minimum_lifetime: timedelta | None = None,
    ) -> Token:
        """Get or create a new internal token.

        Parameters
        ----------
        token_data
            The authentication data on which to base the new token.
        service
            The internal service to which the token is delegated.
        scopes
            The scopes the new token should have.
        ip_address
            The IP address from which the request came.
        minimum_lifetime
            If set, the minimum required lifetime of the token.

        Returns
        -------
        Token
            The newly-created token.

        Raises
        ------
        PermissionDeniedError
            Raised if the username is invalid.
        """
        self._validate_scopes(scopes, token_data)
        self._validate_username(token_data.username)
        scopes = sorted(scopes)
        return await self._token_cache.get_internal_token(
            token_data,
            service,
            scopes,
            ip_address,
            minimum_lifetime=minimum_lifetime,
        )

    async def get_notebook_token(
        self,
        token_data: TokenData,
        ip_address: str,
        *,
        minimum_lifetime: timedelta | None = None,
    ) -> Token:
        """Get or create a new notebook token.

        Parameters
        ----------
        token_data
            The authentication data on which to base the new token.
        ip_address
            The IP address from which the request came.
        minimum_lifetime
            If set, the minimum required lifetime of the token.

        Returns
        -------
        Token
            The newly-created token.

        Raises
        ------
        PermissionDeniedError
            Raised if the username is invalid.
        """
        self._validate_username(token_data.username)
        return await self._token_cache.get_notebook_token(
            token_data, ip_address, minimum_lifetime=minimum_lifetime
        )

    async def get_token_info(
        self, key: str, auth_data: TokenData, username: str
    ) -> TokenInfo | None:
        """Get information about a token.

        Parameters
        ----------
        key
            The key of the token.
        auth_data
            The authentication data of the person requesting the token
            information, used for authorization checks.
        username
            Constrain the result to tokens from that user and return `None` if
            the token exists but is for a different user.

        Returns
        -------
        TokenInfo or None
            Token information from the database, or `None` if the token was
            not found or username was given and the token was for another
            user.

        Raises
        ------
        PermissionDeniedError
            Raised if the authenticated user doesn't have permission to
            manipulate tokens for that user.
        """
        info = await self.get_token_info_unchecked(key, username)
        if not info:
            return None
        self._check_authorization(info.username, auth_data)
        return info

    async def get_token_info_unchecked(
        self, key: str, username: str | None = None
    ) -> TokenInfo | None:
        """Get information about a token without checking authorization.

        Parameters
        ----------
        key
            The key of the token.
        username
            If set, constrain the result to tokens from that user and return
            `None` if the token exists but is for a different user.

        Returns
        -------
        TokenInfo or None
            Token information from the database, or `None` if the token was
            not found or username was given and the token was for another
            user.
        """
        async with self._session.begin():
            return await self._get_token_info_internal(key, username)

    async def list_tokens(
        self, auth_data: TokenData, username: str | None = None
    ) -> list[TokenInfo]:
        """List tokens.

        Parameters
        ----------
        auth_data
            The token data for the authentication token of the user making
            this modification.
        username
            Limit results to the given username.

        Returns
        -------
        list of TokenInfo
            Information for all matching tokens.

        Raises
        ------
        PermissionDeniedError
            Raised if the user whose tokens are being listed does not match
            the authentication information.
        """
        self._check_authorization(username, auth_data)
        async with self._session.begin():
            return await self._token_db_store.list_tokens(username=username)

    async def modify_token(
        self,
        key: str,
        auth_data: TokenData,
        username: str | None = None,
        *,
        ip_address: str,
        token_name: str | None = None,
        scopes: list[str] | None = None,
        expires: datetime | None = None,
        no_expire: bool = False,
    ) -> TokenInfo | None:
        """Modify a token.

        Token modification is only allowed for token administrators. Users who
        want to modify their own tokens should instead create a new token and
        delete the old one. Arguably, it shouldn't be allowed for token
        administrators either, but it allows them to fix bugs and the code is
        tested and working.

        Parameters
        ----------
        key
            The key of the token to modify.
        auth_data
            The token data for the authentication token of the user making
            this modification.
        username
            If given, constrain modifications to tokens owned by the given
            user.
        ip_address
            The IP address from which the request came.
        token_name
            The new name for the token.
        scopes
            The new scopes for the token.
        expires
            The new expiration time for the token.
        no_expire
            If set, the token should not expire.  This is a separate parameter
            because passing `None` to ``expires`` is ambiguous.

        Returns
        -------
        TokenInfo or None
            Information for the updated token or `None` if the token was not
            found.

        Raises
        ------
        InvalidExpiresError
            Raised if the provided expiration time was invalid.
        DuplicateTokenNameError
            Raised if a token with this name for this user already exists.
        PermissionDeniedError
            Raised if the user modifiying the token is not a token
            administrator.
        """
        info = await self.get_token_info_unchecked(key, username)
        if not info:
            return None
        self._check_authorization(info.username, auth_data, require_admin=True)
        if info.token_type != TokenType.user:
            msg = "Only user tokens can be modified"
            self._logger.warning("Permission denied", error=msg)
            raise PermissionDeniedError(msg)
        if scopes:
            self._validate_scopes(scopes, auth_data)
        self._validate_expires(expires)

        # Determine if the lifetime has decreased, in which case we may have
        # to update subtokens.
        update_subtoken_expires = expires and (
            not info.expires or expires <= info.expires
        )

        history_entry = TokenChangeHistoryEntry(
            token=key,
            username=info.username,
            token_type=TokenType.user,
            token_name=token_name if token_name else info.token_name,
            scopes=sorted(scopes) if scopes is not None else info.scopes,
            expires=info.expires if not (expires or no_expire) else expires,
            actor=auth_data.username,
            action=TokenChange.edit,
            old_token_name=info.token_name if token_name else None,
            old_scopes=info.scopes if scopes is not None else None,
            old_expires=info.expires if (expires or no_expire) else None,
            ip_address=ip_address,
        )

        async with self._session.begin():
            info = await self._token_db_store.modify(
                key,
                token_name=token_name,
                scopes=sorted(scopes) if scopes else scopes,
                expires=expires,
                no_expire=no_expire,
            )
            if not info:
                return None
            await self._token_change_store.add(history_entry)

            # Token names exist only in the database and don't require
            # updating Redis, but scopes and expirations are stored in both
            # places and require rewriting the token data in Redis as well.
            if scopes or no_expire or expires:
                data = await self._token_redis_store.get_data_by_key(key)
                if not data:
                    return None
                data.scopes = info.scopes
                data.expires = info.expires
                await self._token_redis_store.store_data(data)

            # Update subtokens if needed.
            if update_subtoken_expires and info:
                if not expires:
                    msg = "expires not set updating subtoken expires"
                    raise RuntimeError(msg)
                for child in await self._token_db_store.get_children(key):
                    await self._modify_expires(
                        child, auth_data, expires, ip_address
                    )

        self._logger.info(
            "Modified token",
            token_key=key,
            token_expires=format_datetime_for_logging(info.expires),
            token_name=info.token_name,
            token_scopes=sorted(info.scopes),
        )
        return info

    async def truncate_history(self) -> None:
        """Drop history entries older than the cutoff date.

        This method is meant to be run periodically, outside of any given user
        request.
        """
        cutoff = current_datetime() - CHANGE_HISTORY_RETENTION
        async with self._session.begin():
            await self._token_change_store.delete(older_than=cutoff)

    async def _audit_orphaned(self) -> list[str]:
        """Audit for orphaned tokens.

        Returns
        -------
        list of str
            Alerts to report.
        """
        alerts = []
        async with self._session.begin():
            for token in await self._token_db_store.list_orphaned():
                key = token.token
                username = token.username
                msg = "Token has no parent"
                self._logger.warning(msg, token=key, user=username)
                alert = f"Token `{key}` for `{username}` has no parent token"
                alerts.append(alert)
        return alerts

    async def _audit_token(
        self,
        key: str,
        db: TokenInfo,
        redis: TokenData,
        parent: TokenInfo | None,
        *,
        fix: bool = False,
    ) -> list[str]:
        """Audit a single token.

        Compares the Redis data for a token against the database data for a
        token and reports and optionally fixes any issues.

        Parameters
        ----------
        key
            Key of the token.
        db
            Database version of token.
        parent
            Database record of parent of token, if any.
        redis
            Redis version of token.
        fix
            Whether to fix any issues found.

        Returns
        -------
        str or `None`
            List of alerts to report.
        """
        alerts = []
        mismatches = []
        if db.username != redis.username:
            mismatches.append("username")
        if db.token_type != redis.token_type:
            mismatches.append("type")
        if db.scopes != sorted(redis.scopes):
            # There was a bug where Redis wasn't updated when the scopes were
            # changed but the database was. Redis is canonical, so set the
            # database scopes to match.
            if fix:
                async with self._session.begin():
                    await self._token_db_store.modify(key, scopes=redis.scopes)
                mismatches.append("scopes [fixed]")
            else:
                mismatches.append("scopes")
        if db.created != redis.created:
            mismatches.append("created")
        if db.expires != redis.expires:
            mismatches.append("expires")
        if mismatches:
            self._logger.warning(
                "Token does not match between database and Redis",
                token=key,
                user=redis.username,
                mismatches=mismatches,
            )
            alerts.append(
                f"Token `{key}` for `{redis.username}` does not match"
                f' between database and Redis ({", ".join(mismatches)})'
            )
        if parent:
            exp = db.expires
            if parent.expires and (not exp or exp > parent.expires):
                self._logger.warning(
                    "Token expires after its parent",
                    token=key,
                    user=redis.username,
                    expires=exp,
                    parent_expires=parent.expires,
                )
                alerts.append(
                    f"Token `{key}` for `{redis.username}` expires after"
                    " its parent token"
                )
        return alerts

    def _audit_unknown_scopes(self, tokens: Iterable[TokenData]) -> list[str]:
        """Audit Redis tokens for unknown scopes.

        Parameters
        ----------
        tokens
            List of all Redis tokens to audit.

        Returns
        -------
        list of str
            List of alerts to report.
        """
        alerts = []
        for token_data in tokens:
            known_scopes = set(self._config.known_scopes.keys())
            for scope in token_data.scopes:
                if scope not in known_scopes:
                    self._logger.warning(
                        "Token has unknown scope",
                        token=token_data.token.key,
                        user=token_data.username,
                        scope=scope,
                    )
                    alerts.append(
                        f"Token `{token_data.token.key}` for"
                        f" `{token_data.username}` has unknown scope"
                        f" (`{scope}`)"
                    )
        return alerts

    def _check_authorization(
        self,
        username: str | None,
        auth_data: TokenData,
        *,
        require_admin: bool = False,
        require_same_user: bool = False,
    ) -> None:
        """Check authorization for performing an action.

        Arguments
        ---------
        username
            The user whose tokens are being changed, or `None` if listing
            all tokens.
        auth_data
            The authenticated user changing the tokens.
        require_admin
            If set to `True`, require the authenticated user have
            ``admin:token`` scope.
        require_same_user
            If set to `True`, require that ``username`` match the
            authenticated user as specified by ``auth_data`` and do not allow
            token admins.

        Raises
        ------
        PermissionDeniedError
            Raised if the authenticated user doesn't have permission to
            manipulate tokens for that user.
        """
        is_admin = "admin:token" in auth_data.scopes
        if (username is None or require_admin) and not is_admin:
            msg = "Missing required admin:token scope"
            self._logger.warning("Permission denied", error=msg)
            raise PermissionDeniedError(msg)
        if username is not None and username != auth_data.username:
            if require_same_user or not is_admin:
                msg = f"Cannot act on tokens for user {username}"
                self._logger.warning("Permission denied", error=msg)
                raise PermissionDeniedError(msg)
        if not is_admin and "user:token" not in auth_data.scopes:
            msg = "Missing required user:token scope"
            self._logger.warning("Permission denied", error=msg)
            raise PermissionDeniedError(msg)

    async def _delete_one_token(
        self,
        key: str,
        auth_data: TokenData,
        ip_address: str,
    ) -> bool:
        """Delete a single token.

        This does not do cascading delete and assumes authorization has
        already been checked. Must be called from inside a transaction.

        Parameters
        ----------
        key
            The key of the token to delete.
        auth_data
            The token data for the authentication token of the user deleting
            the token.
        ip_address
            The IP address from which the request came.

        Returns
        -------
        bool
            `True` if the token was deleted, `False` if the token was not
            found.
        """
        info = await self._get_token_info_internal(key)
        if not info:
            return False

        history_entry = TokenChangeHistoryEntry(
            token=key,
            username=info.username,
            token_type=info.token_type,
            token_name=info.token_name,
            parent=info.parent,
            scopes=info.scopes,
            service=info.service,
            expires=info.expires,
            actor=auth_data.username,
            action=TokenChange.revoke,
            ip_address=ip_address,
        )

        await self._token_redis_store.delete(key)
        success = await self._token_db_store.delete(key)
        if success:
            await self._token_change_store.add(history_entry)
            self._logger.info(
                "Deleted token", token_key=key, token_username=info.username
            )
        return success

    async def _get_token_info_internal(
        self, key: str, username: str | None = None
    ) -> TokenInfo | None:
        """Get database information about a token.

        This method is used inside transactions and neither opens a
        transaction nor checks authorization.

        Parameters
        ----------
        key
            The key of the token.
        username
            If set, constrain the result to tokens from that user and return
            `None` if the token exists but is for a different user.

        Returns
        -------
        TokenInfo or None
            Token information from the database, or `None` if the token was
            not found or username was given and the token was for another
            user.
        """
        info = await self._token_db_store.get_info(key)
        if not info:
            return None
        if username and info.username != username:
            return None
        return info

    async def _modify_expires(
        self,
        key: str,
        auth_data: TokenData,
        expires: datetime,
        ip_address: str,
    ) -> None:
        """Change the expiration of a token if necessary.

        Used to update the expiration of subtokens when the parent token
        expiration has changed. Must be called within a transaction.

        Parameters
        ----------
        key
            The key of the token to update.
        auth_data
            The token data for the authentication token of the user changing
            the expiration.
        expires
            The new expiration of the parent token.  The expiration of the
            child token will be changed if it's later than this value.
        ip_address
            The IP address from which the request came.
        """
        info = await self._get_token_info_internal(key)
        if not info:
            return
        if info.expires and info.expires <= expires:
            return

        history_entry = TokenChangeHistoryEntry(
            token=key,
            username=info.username,
            token_type=info.token_type,
            token_name=info.token_name,
            parent=info.parent,
            scopes=info.scopes,
            service=info.service,
            expires=expires,
            old_expires=info.expires,
            actor=auth_data.username,
            action=TokenChange.edit,
            ip_address=ip_address,
        )

        await self._token_db_store.modify(key, expires=expires)
        await self._token_change_store.add(history_entry)
        data = await self._token_redis_store.get_data_by_key(key)
        if data:
            data.expires = expires
            await self._token_redis_store.store_data(data)

    def _validate_ip_or_cidr(self, ip_or_cidr: str | None) -> None:
        """Check that an IP address or CIDR block is valid.

        Arguments
        ---------
        ip_address
            `None` or a string representing an IPv4 or IPv6 address or CIDR
            block.

        Raises
        ------
        InvalidIPAddressError
            Raised if the provided argument was syntactically invalid for both
            an IP address and a CIDR block.
        """
        if ip_or_cidr is None:
            return
        try:
            if "/" in ip_or_cidr:
                ipaddress.ip_network(ip_or_cidr)
            else:
                ipaddress.ip_address(ip_or_cidr)
        except ValueError as e:
            raise InvalidIPAddressError(f"Invalid IP address: {e!s}") from e

    def _validate_expires(self, expires: datetime | None) -> None:
        """Check that a provided token expiration is valid.

        Arguments
        ---------
        expires
            The token expiration time.

        Raises
        ------
        InvalidExpiresError
            The provided expiration time is not valid.

        Notes
        -----
        This is not done in the model because we want to be able to return
        whatever expiration time is set in the backing store in replies, even
        if it isn't valid. (It could be done using multiple models, but isn't
        currently.)
        """
        if not expires:
            return
        if expires < current_datetime() + MINIMUM_LIFETIME:
            msg = "Token must be valid for at least five minutes"
            raise InvalidExpiresError(msg)

    def _validate_scopes(
        self,
        scopes: list[str],
        auth_data: TokenData | None = None,
    ) -> None:
        """Check that the requested scopes are valid.

        Arguments
        ---------
        scopes
            The requested scopes.
        auth_data
            Token used to authenticate the operation, if the scopes should be
            checked to ensure they are a subset.

        Raises
        ------
        InvalidScopesError
            Raised if the requested scopes are not permitted.
        """
        if not scopes:
            return
        scopes_set = set(scopes)
        if auth_data and "admin:token" not in auth_data.scopes:
            if not (scopes_set <= set(auth_data.scopes)):
                msg = "Requested scopes are broader than your current scopes"
                raise InvalidScopesError(msg)
        if not (scopes_set <= self._config.known_scopes.keys()):
            msg = "Unknown scopes requested"
            raise InvalidScopesError(msg)

    def _validate_username(self, username: str) -> None:
        """Check that the username is valid.

        If ``auth_data`` is provided, ensure that the authenticated user as
        represented by ``auth_data`` is permitted to manipulate the tokens of
        ``username``.

        Arguments
        ---------
        username
            The user whose tokens are being changed.
        auth_data
            The authenticated user changing the tokens.
        same_user
            Require that ``username`` match the authenticated user as
            specified by ``auth_data`` and do not allow token admins.

        Raises
        ------
        PermissionDeniedError
            Raised if the username is invalid or the authenticated user
            doesn't have permission to manipulate tokens for that user.
        """
        if not re.match(USERNAME_REGEX, username):
            raise PermissionDeniedError(f"Invalid username: {username}")
