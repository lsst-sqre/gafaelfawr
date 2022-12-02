"""Mock bonsai LDAP API for testing."""

from __future__ import annotations

import re
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Iterator, Tuple
from unittest.mock import Mock, patch

import bonsai
from bonsai.utils import escape_filter_exp

from gafaelfawr import factory
from gafaelfawr.constants import LDAP_TIMEOUT

_SearchResults = list[Dict[str, list[str]]]
_MockData = Dict[str, Dict[Tuple[str, str], _SearchResults]]

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

    async def close(self) -> None:
        pass

    async def search(
        self,
        base: str,
        scope: bonsai.LDAPSearchScope,
        filter_exp: str,
        attrlist: list[str],
        timeout: float,
    ) -> list[Dict[str, list[str]]]:
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
            results.append({a: entry[a] for a in attrlist if a in entry})
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
