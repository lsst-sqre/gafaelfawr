"""Mock bonsai LDAP API for testing."""

from __future__ import annotations

from types import TracebackType
from typing import Any, Dict, Iterator, List, Literal, Optional, Type
from unittest.mock import Mock, patch

import bonsai
from bonsai.utils import escape_filter_exp

from gafaelfawr import storage
from gafaelfawr.constants import LDAP_TIMEOUT
from gafaelfawr.dependencies import ldap
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.token import TokenGroup

__all__ = ["MockLDAP"]


class MockLDAP(Mock):
    """Mock bonsai LDAP api for testing."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(spec=bonsai.LDAPConnection, **kwargs)
        self.groups = [
            TokenGroup(name="foo", id=1222),
            TokenGroup(name="group-1", id=123123),
            TokenGroup(name="group-2", id=123442),
        ]
        self.source_id = "http://cilogon.org/serverA/users/1234"

    async def __aenter__(self) -> MockLDAP:
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[Exception]],
        exc: Optional[Exception],
        tb: Optional[TracebackType],
    ) -> Literal[False]:
        return False

    async def close(self) -> None:
        pass

    async def search(
        self,
        base: str,
        scope: bonsai.LDAPSearchScope,
        filter_exp: str,
        attrlist: List[str],
        timeout: float,
    ) -> List[Dict[str, List[str]]]:
        config = config_dependency.config()
        assert config.ldap
        assert base == config.ldap.base_dn
        assert scope in (
            bonsai.LDAPSearchScope.SUB,
            bonsai.LDAPSearchScope.ONELEVEL,
        )
        assert timeout == LDAP_TIMEOUT
        source_id_escaped = escape_filter_exp(self.source_id)
        if filter_exp == f"(voPersonSoRID={source_id_escaped})":
            assert attrlist == ["uid"]
            return [{"uid": ["ldap-user"]}]
        elif filter_exp == "(uid=ldap-user)":
            assert attrlist == ["uidNumber"]
            return [{"uidNumber": [str(2000)]}]
        elif filter_exp == "(&(objectClass=posixGroup)(member=ldap-user))":
            if attrlist == ["cn", "gidNumber"]:
                return [
                    {"cn": [g.name], "gidNumber": [str(g.id)]}
                    for g in self.groups
                ]
            elif attrlist == ["cn"]:
                return [{"cn": [g.name]} for g in self.groups]
            else:
                assert False, f"Invalid attribute list {attrlist}"
        else:
            return []


def patch_ldap() -> Iterator[MockLDAP]:
    """Mock the bonsai API for testing.

    Returns
    -------
    mock : `MockLDAP`
        The mock LDAP API.
    """
    mock_ldap = MockLDAP()
    with patch.object(storage.ldap, "AIOPoolContextManager") as mock_manager:
        mock_manager.return_value = mock_ldap
        with patch.object(ldap, "AIOConnectionPool") as mock_pool:
            mock_pool.return_value = mock_ldap
            yield mock_ldap
