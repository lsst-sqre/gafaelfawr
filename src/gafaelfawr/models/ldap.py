"""Data models for LDAP."""

from dataclasses import dataclass

__all__ = ["LDAPUserData"]


@dataclass
class LDAPUserData:
    """Data for a user from LDAP.

    This represents the subset of `~gafaelfawr.models.token.TokenUserInfo`
    that comes from LDAP.  Which elements in particular are filled out varies
    based on configuration.
    """

    name: str | None = None
    """Preferred full name."""

    email: str | None = None
    """Preferred email address."""

    uid: int | None = None
    """UID number."""

    gid: int | None = None
    """Primary GID."""

    def is_empty(self) -> bool:
        """Whether any information was found in LDAP for this user."""
        return (
            self.name is None
            and self.email is None
            and self.uid is None
            and self.gid is None
        )
