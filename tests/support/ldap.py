"""Mock bonsai LDAP API for testing."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import Mock, patch

import bonsai
from bonsai.utils import escape_filter_exp

from gafaelfawr import factory
from gafaelfawr.constants import LDAP_TIMEOUT
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.userinfo import Group, UserInfo

_SearchResults = list[dict[str, list[str]]]
_MockData = dict[str, dict[tuple[str, str], _SearchResults]]

__all__ = ["MockLDAP", "patch_ldap"]


class MockLDAP(Mock):
    """Mock bonsai LDAP api for testing."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(spec=bonsai.LDAPConnection, **kwargs)
        self._entries: _MockData = defaultdict(dict)

    def add_entries_for_test(
        self, base_dn: str, attr: str, value: str, entries: _SearchResults
    ) -> None:
        """Add LDAP entries for testing.

        Parameters
        ----------
        base_dn
            The base DN of a search that should return this entry.
        attr
            The search attribute that will be used to retrieve this entry.
        value
            The value of that search attribute.
        entries
            The entries returned by that search, which will be filtered by the
            attribute list.
        """
        key = (attr, escape_filter_exp(value))
        self._entries[base_dn][key] = entries

    def add_test_group_membership(
        self, username: str, groups: list[Group], *, omit_gid: bool = False
    ) -> None:
        """Add group membership entries for a test user.

        Parameters
        ----------
        username
            Username of user
        groups
            Group memberships to add.
        omit_gid
            Whether to omit the GID from the record.
        """
        config = config_dependency.config()
        assert config.ldap
        if config.ldap.group_search_by_dn:
            base_dn = config.ldap.user_base_dn
            attr = config.ldap.user_search_attr
            search_value = f"{attr}={username},{base_dn}"
        else:
            search_value = username
        if omit_gid:
            entries = [{"cn": [g.name]} for g in groups]
        else:
            entries = [
                {"cn": [g.name], "gidNumber": [str(g.id)]} for g in groups
            ]
        self.add_entries_for_test(
            config.ldap.group_base_dn,
            config.ldap.group_member_attr,
            search_value,
            entries,
        )

    def add_test_user(self, userinfo: UserInfo) -> None:
        """Add a record for a test user.

        This only handles the cases that match the user information model.
        Malformed or weird entries must be added with `add_entries_for_test`.

        Parameters
        ----------
        userinfo
            Information for user whose entry should be added.
        """
        config = config_dependency.config()
        assert config.ldap
        entry = {}
        if userinfo.name:
            entry[config.ldap.name_attr or "displayName"] = [userinfo.name]
        if userinfo.email:
            entry[config.ldap.email_attr or "mail"] = [userinfo.email]
        if userinfo.uid:
            entry[config.ldap.uid_attr or "uidNumber"] = [str(userinfo.uid)]
        if userinfo.gid:
            entry[config.ldap.gid_attr or "gidNumber"] = [str(userinfo.gid)]
        self.add_entries_for_test(
            config.ldap.user_base_dn,
            config.ldap.user_search_attr,
            userinfo.username,
            [entry],
        )

    async def close(self) -> None:
        pass

    async def search(
        self,
        base: str,
        scope: bonsai.LDAPSearchScope,
        filter_exp: str,
        attrlist: list[str],
        timeout: float,
    ) -> list[dict[str, list[str]]]:
        assert scope in (
            bonsai.LDAPSearchScope.SUB,
            bonsai.LDAPSearchScope.ONELEVEL,
        )
        assert timeout == LDAP_TIMEOUT

        match = re.match(
            r"\((?:&\(objectClass=posixGroup\))?\(?([^=]+)=([^\)]+)\)?\)$",
            filter_exp,
        )
        assert match, f"{filter_exp} does not match regex of searches"
        key = (match.group(1), match.group(2))
        if key not in self._entries[base]:
            return []
        entries = self._entries[base][key]
        results = []
        for entry in entries:
            attributes = {a: entry[a] for a in attrlist if a in entry}
            results.append(attributes)
        return results

    @asynccontextmanager
    async def spawn(self) -> AsyncIterator[MockLDAP]:
        yield self


def patch_ldap() -> Iterator[MockLDAP]:
    """Mock the bonsai API for testing.

    Returns
    -------
    MockLDAP
        The mock LDAP API.
    """
    mock_ldap = MockLDAP()
    with patch.object(factory, "AIOConnectionPool") as mock_pool:
        mock_pool.return_value = mock_ldap
        yield mock_ldap
