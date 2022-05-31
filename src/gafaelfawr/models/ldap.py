"""Data models for LDAP."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = ["LDAPUserData"]


@dataclass
class LDAPUserData:
    """Data for a user from LDAP.

    This represents the subset of `~gafaelfawr.models.token.TokenUserInfo`
    that comes from LDAP.  Which elements in particular are filled out varies
    based on configuration.
    """

    name: Optional[str]
    """Preferred full name."""

    email: Optional[str]
    """Preferred email address."""

    uid: Optional[int]
    """UID number."""
