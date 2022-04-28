"""Mock bonsai LDAP API for testing."""

from __future__ import annotations

from types import TracebackType
from typing import Dict, List, Literal, Optional, Type
from unittest.mock import Mock

import bonsai
from bonsai.utils import escape_filter_exp

from gafaelfawr.config import LDAPConfig
from gafaelfawr.models.token import TokenGroup

__all__ = ["MockLDAP"]


class MockLDAP(Mock):
    """Mock bonsai LDAP api for testing."""

    def __init__(self, config: LDAPConfig) -> None:
        super().__init__(spec=bonsai.LDAPClient)
        self.config = config
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

    def connect(self, is_async: bool) -> MockLDAP:
        assert is_async
        return self

    async def search(
        self,
        base_dn: str,
        scope: bonsai.LDAPSearchScope,
        query: str,
        attrlist: List[str],
    ) -> List[Dict[str, List[str]]]:
        assert base_dn == self.config.base_dn
        assert scope in (
            bonsai.LDAPSearchScope.SUB,
            bonsai.LDAPSearchScope.ONELEVEL,
        )
        source_id_escaped = escape_filter_exp(self.source_id)
        if query == f"(&(voPersonSoRID={source_id_escaped}))":
            assert attrlist == ["uid"]
            return [{"uid": ["ldap-user"]}]
        elif query == "(&(uid=ldap-user))":
            assert attrlist == ["uidNumber"]
            return [{"uidNumber": [str(2000)]}]
        elif query == "(&(objectClass=posixGroup)(member=ldap-user))":
            assert attrlist == ["cn", "gidNumber"]
            return [
                {"cn": [g.name], "gidNumber": [str(g.id)]} for g in self.groups
            ]
        else:
            return []
