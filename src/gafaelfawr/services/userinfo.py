"""Service and caching layer for user metadata."""

from __future__ import annotations

from typing import List, Optional

from structlog.stdlib import BoundLogger

from ..config import Config
from ..exceptions import (
    InvalidTokenClaimsError,
    MissingClaimsError,
    NotConfiguredError,
    ValidationError,
)
from ..models.ldap import LDAPUserData
from ..models.oidc import OIDCVerifiedToken
from ..models.token import TokenData, TokenGroup, TokenUserInfo
from ..services.firestore import FirestoreService
from ..services.ldap import LDAPService

__all__ = ["OIDCUserInfoService", "UserInfoService"]


class UserInfoService:
    """Retrieve user metadata from external systems.

    In some cases, we take user metadata from external systems.  Examples are:

    #. Resolve a unique identifier to a username via LDAP.
    #. Get user group membership from LDAP.
    #. Get UID or GID from LDAP.
    #. Assign and manage UIDs and GIDs via Google Firestore.

    This service manages those interactions.  UID/GID data from Firestore is
    cached.  LDAP data is not cached, since LDAP is supposed to be able to
    handle a very high query load.

    This is the parent class, which is further specialized by authentication
    provider to incorporate some provider-specific logic for extracting user
    information from the upstream authentication details.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    ldap : `gafaelfawr.services.ldap.LDAPService`, optional
        LDAP service for user metadata, if LDAP was configured.
    firestore : `gafaelfawr.services.firestore.FirestoreService`, optional
        Service for Firestore UID/GID lookups, if Firestore was configured.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: Config,
        ldap: Optional[LDAPService],
        firestore: Optional[FirestoreService],
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._ldap = ldap
        self._firestore = firestore
        self._logger = logger

    async def get_user_info_from_token(
        self, token_data: TokenData
    ) -> TokenUserInfo:
        """Get the user information from a token.

        Information stored with the token takes precedence over information
        from LDAP.  If the token information is `None` and LDAP is configured,
        retrieve it dynamically from LDAP.

        Parameters
        ----------
        token_data : `gafaelfawr.models.token.TokenData`
            Data from the authentication token.

        Returns
        -------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            User information for the holder of that token.

        Raises
        ------
        gafaelfawr.exceptions.FirestoreError
            UID/GID allocation using Firestore failed, probably because the UID
            or GID space has been exhausted.
        gafaelfawr.exceptions.LDAPError
            Gafaelfawr was configured to get user groups, username, or numeric
            UID from LDAP, but the attempt failed due to some error.
        """
        username = token_data.username
        uid = token_data.uid
        if uid is None and self._firestore:
            uid = await self._firestore.get_uid(username)

        if self._ldap:
            groups = token_data.groups
            if groups is None:
                if self._firestore:
                    group_names = await self._ldap.get_group_names(username)
                    groups = []
                    for group_name in group_names:
                        gid = await self._firestore.get_gid(group_name)
                        groups.append(TokenGroup(name=group_name, id=gid))
                else:
                    groups = await self._ldap.get_groups(username)
            if not token_data.name or not token_data.email or not uid:
                ldap_data = await self._ldap.get_data(username)
                if not uid:
                    uid = ldap_data.uid
            return TokenUserInfo(
                username=username,
                name=token_data.name or ldap_data.name,
                uid=uid,
                email=token_data.email or ldap_data.email,
                groups=groups,
            )
        else:
            return TokenUserInfo(
                username=token_data.username,
                name=token_data.name,
                uid=uid,
                email=token_data.email,
                groups=token_data.groups,
            )

    async def get_scopes(
        self, user_info: TokenUserInfo
    ) -> Optional[List[str]]:
        """Get scopes from user information.

        Used to determine the scope claim of a token issued based on an OpenID
        Connect authentication.

        Parameters
        ----------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            User information for a user.

        Returns
        -------
        scopes : List[`str`] or `None`
            The scopes generated from the group membership based on the
            ``group_mapping`` configuration parameter, or `None` if the user
            was not a member of any known group.
        """
        if self._ldap:
            groups = await self._ldap.get_group_names(user_info.username)
        elif user_info.groups:
            groups = [g.name for g in user_info.groups]
        else:
            groups = []

        scopes = set(["user:token"])
        found = False
        for group in groups:
            if group in self._config.group_mapping:
                found = True
                scopes.update(self._config.group_mapping[group])

        return sorted(scopes) if found else None


class OIDCUserInfoService(UserInfoService):
    """Retrieve user metadata from external systems for OIDC authentication.

    This is a specialization of `UserInfoService` when the upstream
    authentication provider is OpenID Connect.  It adds additional methods to
    extract user information from the OpenID Connect ID token.

    Parameters
    ----------
    config : `gafaelfawr.config.Config`
        Gafaelfawr configuration.
    ldap : `gafaelfawr.services.ldap.LDAPService`, optional
        LDAP service for user metadata, if LDAP was configured.
    firestore : `gafaelfawr.services.firestore.FirestoreService`, optional
        Service for Firestore UID/GID lookups, if Firestore was configured.
    logger : `structlog.stdlib.BoundLogger`
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: Config,
        ldap: Optional[LDAPService],
        firestore: Optional[FirestoreService],
        logger: BoundLogger,
    ) -> None:
        super().__init__(
            config=config,
            ldap=ldap,
            firestore=firestore,
            logger=logger,
        )
        if not config.oidc:
            raise NotConfiguredError("OpenID Connect not configured")
        self._oidc_config = config.oidc

    async def get_user_info_from_oidc_token(
        self, token: OIDCVerifiedToken
    ) -> TokenUserInfo:
        """Return the metadata for a given user.

        Determine the user's username, numeric UID, and groups.  These may
        come from LDAP, from Firestore, or some combination, depending on
        configuration.  This is the data that we'll store with the token data
        in Redis.  It therefore only includes groups if we get them statically
        from the upstream authentication provider, not if they're read
        dynamically from LDAP.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The verified ID token from the OpenID Connect provider.

        Returns
        -------
        user_info : `gafaelfawr.models.token.TokenUserInfo`
            User information derived from external data sources and the
            provided token.

        Raises
        ------
        gafaelfawr.exceptions.FirestoreError
            UID/GID allocation using Firestore failed, probably because the UID
            or GID space has been exhausted.
        gafaelfawr.exceptions.LDAPError
            Gafaelfawr was configured to get user groups, username, or numeric
            UID from LDAP, but the attempt failed due to some error.
        gafaelfawr.exceptions.NoUsernameMappingError
            The opaque authentication identity could not be mapped to a
            username, probably because the user is not enrolled.
        gafaelfawr.exceptions.VerifyTokenError
            The token is missing required claims.
        """
        username = None
        groups = None
        uid = None
        ldap_data = LDAPUserData(uid=None, name=None, email=None)
        if self._ldap:
            if "sub" in token.claims:
                username = await self._ldap.get_username(token.claims["sub"])
            if username is None:
                username = self._get_username_from_oidc_token(token)
            ldap_data = await self._ldap.get_data(username)
        else:
            username = self._get_username_from_oidc_token(token)
            groups = await self._get_groups_from_oidc_token(token, username)
        if not self._firestore and not ldap_data.uid:
            uid = self._get_uid_from_oidc_token(token, username)

        # If LDAP is configured and provides a name or email, set those to
        # None to ensure that LDAP will be used for that data going forward.
        return TokenUserInfo(
            username=username,
            name=None if ldap_data.name else token.claims.get("name"),
            email=None if ldap_data.email else token.claims.get("email"),
            uid=uid,
            groups=groups,
        )

    async def _get_groups_from_oidc_token(
        self,
        token: OIDCVerifiedToken,
        username: str,
    ) -> List[TokenGroup]:
        """Determine the user's groups from token claims.

        Invalid groups are logged and ignored.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.
        username : `str`
            Authenticated username (for error reporting).

        Returns
        -------
        groups : List[`gafaelfawr.models.token.TokenGroup`]
            List of groups derived from the ``isMemberOf`` token claim.

        Raises
        ------
        gafaelfawr.exceptions.FirestoreError
            An error occured obtaining the GID from Firestore.
        gafaelfawr.exceptions.InvalidTokenClaimsError
            The ``isMemberOf`` claim has an invalid syntax.
        """
        groups = []
        invalid_groups = {}
        try:
            for oidc_group in token.claims.get("isMemberOf", []):
                if "name" not in oidc_group:
                    continue
                name = oidc_group["name"]
                try:
                    if self._firestore:
                        gid = await self._firestore.get_gid(name)
                    else:
                        if "id" not in oidc_group:
                            invalid_groups[name] = "missing id"
                            continue
                        gid = int(oidc_group["id"])
                    groups.append(TokenGroup(name=name, id=gid))
                except (TypeError, ValueError, ValidationError) as e:
                    invalid_groups[name] = str(e)
        except TypeError as e:
            msg = f"isMemberOf claim has invalid format: {str(e)}"
            self._logger.error(
                "Unable to get groups from token",
                error=msg,
                claim=token.claims.get("isMemberOf", []),
                user=username,
            )
            raise InvalidTokenClaimsError(msg)

        if invalid_groups:
            self._logger.warning(
                "Ignoring invalid groups in OIDC token",
                error="isMemberOf claim value could not be parsed",
                invalid_groups=invalid_groups,
                user=username,
            )

        return groups

    def _get_uid_from_oidc_token(
        self, token: OIDCVerifiedToken, username: str
    ) -> int:
        """Verify and return the numeric UID from the token.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.
        username : `str`
            Authenticated username (for error reporting).

        Returns
        -------
        uid : `int`
            The numeric UID of the user as obtained from the token.

        Raises
        ------
        gafaelfawr.exceptions.MissingClaimsError
            The token is missing the required numeric UID claim.
        gafaelfawr.exceptions.InvalidTokenClaimsError
            The numeric UID claim contains something that is not a number.
        """
        if self._oidc_config.uid_claim not in token.claims:
            msg = f"No {self._oidc_config.uid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise MissingClaimsError(msg)
        try:
            uid = int(token.claims[self._oidc_config.uid_claim])
        except Exception:
            msg = f"Invalid {self._oidc_config.uid_claim} claim in token"
            self._logger.warning(msg, claims=token.claims, user=username)
            raise InvalidTokenClaimsError(msg)
        return uid

    def _get_username_from_oidc_token(self, token: OIDCVerifiedToken) -> str:
        """Verify and return the username from the token.

        Parameters
        ----------
        token : `gafaelfawr.models.oidc.OIDCVerifiedToken`
            The previously verified token.

        Returns
        -------
        username : `str`
            The username of the user as obtained from the token.

        Raises
        ------
        gafaelfawr.exceptions.MissingClaimsError
            The token is missing the required username claim.
        """
        if self._oidc_config.username_claim not in token.claims:
            msg = f"No {self._oidc_config.username_claim} claim in token"
            self._logger.warning(msg, claims=token.claims)
            raise MissingClaimsError(msg)
        return token.claims[self._oidc_config.username_claim]
