"""Mock bonsai LDAP API for testing."""

import re
from collections import defaultdict
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import Mock, patch

import bonsai
from bonsai.utils import escape_filter_exp
from pydantic import BaseModel
from safir.testing.data import Data

from gafaelfawr import factory
from gafaelfawr.config import LDAPConfig
from gafaelfawr.constants import LDAP_TIMEOUT
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.userinfo import Group, UserInfo

_SearchResults = list[dict[str, list[str]]]
_MockData = dict[str, dict[tuple[str, str], _SearchResults]]

__all__ = ["MockLDAP", "patch_ldap"]


class _TestGroup(BaseModel):
    """Data for a single test group."""

    name: str
    gid: int | None = None
    members: list[str] = []


class _TestData(BaseModel):
    """Test LDAP data.

    This class is used to parse saved JSON data in the test data directory via
    the `MockLDAP.load_data_for_test` method. It can only be used for
    well-formed data. For malformed data, use `MockLDAP.add_entries_for_test`.
    """

    users: list[UserInfo]
    groups: list[_TestGroup]


class MockLDAP(Mock):
    """Mock bonsai LDAP api for testing."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(spec=bonsai.LDAPConnection, **kwargs)
        self._entries: _MockData = defaultdict(lambda: defaultdict(list))

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

    def add_test_group(self, group: _TestGroup) -> None:
        """Add a group with members to the test data.

        Do not call this method is called repeatedly with the same group name
        without resetting the test data (via `load_data_for_test`, for
        example). Doing so will will register duplicate groups in the search
        results and invalidate the tests.

        Parameters
        ----------
        group
            Test group information.
        """
        base_dn = self._config.group_base_dn
        group_key = (self._config.group_member_attr, "**")
        entry = {"cn": [group.name]}
        if group.gid:
            entry["gidNumber"] = [str(group.gid)]

        # Add the group to the list of all groups.
        self._entries[base_dn][group_key].append(entry)

        # For each member, add the group to the list of groups returned by a
        # search for their membership.
        user_base_dn = self._config.user_base_dn
        user_search_attr = self._config.user_search_attr
        group_member_attr = self._config.group_member_attr
        for member in group.members:
            if self._config.group_search_by_dn:
                search_value = f"{user_search_attr}={member},{user_base_dn}"
            else:
                search_value = member
            key = (group_member_attr, escape_filter_exp(search_value))
            self._entries[base_dn][key].append(entry)

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
        if self._config.group_search_by_dn:
            base_dn = self._config.user_base_dn
            attr = self._config.user_search_attr
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
            self._config.group_base_dn,
            self._config.group_member_attr,
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
        entry = {self._config.user_search_attr: [userinfo.username]}
        if userinfo.name:
            entry[self._config.name_attr or "displayName"] = [userinfo.name]
        if userinfo.email:
            entry[self._config.email_attr or "mail"] = [userinfo.email]
        if userinfo.uid:
            entry[self._config.uid_attr or "uidNumber"] = [str(userinfo.uid)]
        if userinfo.gid:
            entry[self._config.gid_attr or "gidNumber"] = [str(userinfo.gid)]
        self.add_entries_for_test(
            self._config.user_base_dn,
            self._config.user_search_attr,
            userinfo.username,
            [entry],
        )

    def load_data_for_test(self, data: Data, path: str) -> None:
        """Load test data for users and groups.

        This method replaces all existing test data with the new test data. To
        supplement this data after loading with invalid data, call
        `add_entries_for_test` after calling this method.

        Parameters
        ----------
        data
            Test data management object.
        path
            Path to the test data file containing user and group information.
        """
        self._entries = defaultdict(lambda: defaultdict(list))
        ldap_data = data.read_pydantic(_TestData, path)
        for user in ldap_data.users:
            self.add_test_user(user)
        for group in ldap_data.groups:
            self.add_test_group(group)

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
        results = []

        # Find the key for our internal mock storage.
        if filter_exp == "(objectClass=posixGroup)":
            key = (self._config.group_member_attr, "**")
        else:
            match = re.match(
                r"\((?:&\(objectClass=posixGroup\))?\(?([^=]+)=([^\)]+)\)?\)$",
                filter_exp,
            )
            assert match, f"{filter_exp} does not match regex of searches"
            key = (match.group(1), match.group(2))

        # Handle wildcard searches for users.
        if key[1] == "*":
            for entry_key, entries in self._entries[base].items():
                if entry_key[0] != key[0]:
                    continue
                for entry in entries:
                    attributes = {a: entry[a] for a in attrlist if a in entry}
                    results.append(attributes)
            return results

        # Otherwise, we're searching for a specific entry.
        if key not in self._entries[base]:
            return []
        entries = self._entries[base][key]
        for entry in entries:
            attributes = {a: entry[a] for a in attrlist if a in entry}
            results.append(attributes)
        return results

    @asynccontextmanager
    async def spawn(self) -> AsyncIterator[MockLDAP]:
        yield self

    @property
    def _config(self) -> LDAPConfig:
        """LDAP configuration for Gafaelafwr.

        This is deferred to a property so that it can be dynamically loaded on
        demand, allowing the LDAP mock to be installed unconditionally even if
        there is no LDAP configuration.
        """
        config = config_dependency.config()
        assert config.ldap
        return config.ldap


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
