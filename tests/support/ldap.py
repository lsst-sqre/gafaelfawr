"""Mock bonsai LDAP API for testing."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock

import bonsai

from gafaelfawr.models.token import TokenGroup

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Dict, List, Literal, Optional, Type

    from gafaelfawr.config import LDAPConfig

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
        self.query: Optional[str] = None

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
        assert scope == bonsai.LDAPSearchScope.SUB
        assert attrlist == ["cn", "gidNumber"]
        self.query = query
        return [
            {"cn": [g.name], "gidNumber": [str(g.id)]} for g in self.groups
        ]
