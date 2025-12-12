"""Client for the Gafaelfawr authorization and identity service."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import structlog
from cachetools import TTLCache
from httpx import AsyncClient, HTTPError, HTTPStatusError, Timeout
from pydantic import BaseModel, ValidationError
from rubin.repertoire import DiscoveryClient
from structlog.stdlib import BoundLogger

from ._constants import CACHE_LIFETIME, CACHE_SIZE
from ._exceptions import (
    GafaelfawrDiscoveryError,
    GafaelfawrNotFoundError,
    GafaelfawrValidationError,
    GafaelfawrWebError,
)
from ._models import (
    AdminTokenRequest,
    GafaelfawrGroup,
    GafaelfawrUserInfo,
    NewToken,
    TokenType,
)

__all__ = ["GafaelfawrClient"]


class GafaelfawrClient:
    """Client for the Gafaelfawr service API.

    Parameters
    ----------
    http_client
        Existing ``httpx.AsyncClient`` to use instead of creating a new one.
        This allows the caller to reuse an existing client and connection
        pool.
    discovery_client
        If given, Repertoire_ discovery client to use. Otherwise, a new client
        will be created.
    logger
        Logger to use. If not given, the default structlog logger will be
        used.
    timeout
        Timeout for Gafaelfawr operations. If not given, defaults to the
        timeout of the underlying HTTPX_ client.
    userinfo_cache_lifetime
        How long to cache user information for a token.
    userinfo_cache_size
        How many cache entries for the cache of user information by token.
    """

    def __init__(
        self,
        http_client: AsyncClient | None = None,
        *,
        discovery_client: DiscoveryClient | None = None,
        logger: BoundLogger | None = None,
        timeout: timedelta | None = None,
        userinfo_cache_lifetime: timedelta = CACHE_LIFETIME,
        userinfo_cache_size: int = CACHE_SIZE,
    ) -> None:
        self._client = http_client or AsyncClient()
        self._discovery = discovery_client or DiscoveryClient(self._client)
        self._logger = logger or structlog.get_logger()
        self._userinfo_cache_lifetime = userinfo_cache_lifetime
        self._userinfo_cache_size = userinfo_cache_size

        # Whether the HTTP client needs to be explicitly closed because we
        # created it.
        self._close_client = http_client is not None

        # The default timeout is the underlying timeout of the HTTPX client.
        if timeout is not None:
            self._timeout: float | Timeout = timeout.total_seconds()
        else:
            self._timeout = self._client.timeout

        # Maintain two caches of user information, one indexed by token (when
        # requesting user information for the user corresponding to the token)
        # and one indexed by username (when requesting user information with a
        # privileged token). Most users of the client will only make one type
        # of call, but hopefully the overhead is tiny.
        self._userinfo_token_cache: TTLCache[str, GafaelfawrUserInfo]
        self._userinfo_token_cache = TTLCache(
            userinfo_cache_size, userinfo_cache_lifetime.total_seconds()
        )
        self._userinfo_token_lock = asyncio.Lock()
        self._userinfo_username_cache: TTLCache[str, GafaelfawrUserInfo]
        self._userinfo_username_cache = TTLCache(
            userinfo_cache_size, userinfo_cache_lifetime.total_seconds()
        )
        self._userinfo_username_lock = asyncio.Lock()

    async def aclose(self) -> None:
        """Close the HTTP connection pool, if one wasn't provided.

        Only closes the pool if a new one was created. Does nothing if an
        external HTTP connection pool was passed into the constructor. The
        object must not be used after calling this method.
        """
        if self._close_client:
            await self._client.aclose()

    async def clear_cache(self) -> None:
        """Clear all internal caches."""
        async with self._userinfo_token_lock:
            self._userinfo_token_cache = TTLCache(
                self._userinfo_cache_size,
                self._userinfo_cache_lifetime.total_seconds(),
            )
        async with self._userinfo_username_lock:
            self._userinfo_username_cache = TTLCache(
                self._userinfo_cache_size,
                self._userinfo_cache_lifetime.total_seconds(),
            )

    async def create_service_token(
        self,
        token: str,
        username: str,
        *,
        scopes: list[str],
        expires: datetime | None = None,
        name: str | None = None,
        uid: int | None = None,
        gid: int | None = None,
        groups: list[GafaelfawrGroup] | None = None,
    ) -> str:
        """Create a new service token.

        Parameters
        ----------
        token
            Token to use to authenticate to the Gafaelfawr API. This token
            must have the ``admin:token`` scope.
        username
            Username for which to create a token. Must begin with ``bot-``.
        scopes
            List of scopes to grant to the new token.
        expires
            Expiration date of te new token, or `None` to create a token that
            never expires.
        name
            Full name override. If `None`, the full name will be determined
            from LDAP if configured, and otherwise not set.
        uid
            UID override. If `None`, the UID will be determined from Firestore
            or LDAP if configured, and otherwise not set.
        gid
            Primary GID override. If `None`, the primary GID will be
            determined from Firestore or LDAP if configured, and otherwise not
            set.
        groups
            Group membership override. If `None`, the group membership will be
            determined from LDAP if configured, and otherwise not set.

        Returns
        -------
        str
            Newly-created token.

        Raises
        ------
        GafaelfawrValidationError
            Raised if the response from Gafaelfawr is invalid.
        GafaelfawrWebError
            Raised if there is some problem talking to the Gafaelfawr API,
            such as an invalid token or network or service failure.
        rubin.repertoire.RepertoireError
            Raised if there was an error talking to service discovery.
        """
        url = await self._url_for("tokens")
        request = AdminTokenRequest(
            username=username,
            token_type=TokenType.service,
            scopes=scopes,
            expires=expires,
            name=name,
            uid=uid,
            gid=gid,
            groups=groups,
        )
        result = await self._post(url, NewToken, token, body=request)
        return result.token

    async def get_user_info(
        self, token: str, username: str | None = None
    ) -> GafaelfawrUserInfo:
        """Get information about the user, with caching.

        Parameters
        ----------
        token
            Token to use to authenticate to the Gafaelfawr API.
        username
            Username for which to request user information, if given. If not
            given, the user information for the user corresponding to the
            authentication token will be retrieved. This parameter may only be
            provided when authenticating with a token with ``admin:userinfo``
            scope.

        Returns
        -------
        GafaelfawrUserInfo
            User information for the user.

        Raises
        ------
        GafaelfawrNotFoundError
            Raised if no user information for the requested user could be
            found. This will always be the case when the ``username``
            parameter is provided and Gafaelfawr is not configured to use LDAP
            for user information, since in that case user information can only
            be retrieved with a user's token.
        GafaelfawrValidationError
            Raised if the response from Gafaelfawr is invalid.
        GafaelfawrWebError
            Raised if there is some problem talking to the Gafaelfawr API,
            such as an invalid token or network or service failure.
        rubin.repertoire.RepertoireError
            Raised if there was an error talking to service discovery.
        """
        if username is not None:
            if userinfo := self._userinfo_username_cache.get(username):
                return userinfo
            async with self._userinfo_username_lock:
                if userinfo := self._userinfo_username_cache.get(username):
                    return userinfo
                url = await self._url_for(f"users/{username}")
                userinfo = await self._get(url, GafaelfawrUserInfo, token)
                self._userinfo_username_cache[username] = userinfo
                return userinfo
        else:
            if userinfo := self._userinfo_token_cache.get(token):
                return userinfo
            async with self._userinfo_token_lock:
                if userinfo := self._userinfo_token_cache.get(token):
                    return userinfo
                url = await self._url_for("user-info")
                userinfo = await self._get(url, GafaelfawrUserInfo, token)
                self._userinfo_token_cache[token] = userinfo
                return userinfo

    async def _get[T: BaseModel](
        self, url: str, model: type[T], token: str
    ) -> T:
        """Make an HTTP GET request and validate the results.

        Parameters
        ----------
        url
            URL at which to make the request.
        model
            Expected type of the response.
        token
            Gafaelfawr token used for authentication.

        Returns
        -------
        pydantic.BaseModel
            Validated model of the requested type.

        Raises
        ------
        GafaelfawrNotFoundError
            Raised if the requested URL returned a 404 response.
        GafaelfawrValidationError
            Raised if the response from Gafaelfawr is invalid.
        GafaelfawrWebError
            Raised if there is some problem talking to the Gafaelfawr API,
            such as an invalid token or network or service failure.
        """
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r = await self._client.get(
                url, headers=headers, timeout=self._timeout
            )
            r.raise_for_status()
            return model.model_validate(r.json())
        except HTTPError as e:
            if isinstance(e, HTTPStatusError):
                if e.response.status_code == 404:
                    raise GafaelfawrNotFoundError.from_exception(e) from e
            raise GafaelfawrWebError.from_exception(e) from e
        except ValidationError as e:
            raise GafaelfawrValidationError.from_exception(e) from e

    async def _post[T: BaseModel](
        self, url: str, model: type[T], token: str, *, body: BaseModel
    ) -> T:
        """Make an HTTP GET request and validate the results.

        Parameters
        ----------
        url
            URL at which to make the request.
        model
            Expected type of the response.
        token
            Gafaelfawr token used for authentication.
        body
            Pydantic model to send as the POST body.

        Returns
        -------
        pydantic.BaseModel
            Validated model of the requested type.

        Raises
        ------
        GafaelfawrValidationError
            Raised if the response from Gafaelfawr is invalid.
        GafaelfawrWebError
            Raised if there is some problem talking to the Gafaelfawr API,
            such as an invalid token or network or service failure.
        """
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r = await self._client.post(
                url,
                headers=headers,
                json=body.model_dump(mode="json"),
                timeout=self._timeout,
            )
            r.raise_for_status()
            return model.model_validate(r.json())
        except HTTPError as e:
            raise GafaelfawrWebError.from_exception(e) from e
        except ValidationError as e:
            raise GafaelfawrValidationError.from_exception(e) from e

    async def _url_for(self, route: str) -> str:
        """Construct the URL for a Gafaelfawr API route.

        Parameters
        ----------
        route
            Route relative to the Gafaelfawr API base URL. Must not start with
            ``/``.

        Returns
        -------
        str
            Full URL to use.

        Raises
        ------
        GafaelfawrDiscoveryError
            Raised if Gafaelfawr is missing from service discovery.
        rubin.repertoire.RepertoireError
            Raised if there was an error talking to service discovery.
        """
        base_url = await self._discovery.url_for_internal(
            "gafaelfawr", version="v1"
        )
        if not base_url:
            msg = "gafaelfawr (v1) service not found in service discovery"
            raise GafaelfawrDiscoveryError(msg)
        return f"{base_url.rstrip('/')}/{route}"
