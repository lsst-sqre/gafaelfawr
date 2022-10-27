"""Models for the GitHub authentication provider.

Notes
-----
This is in a separate module primarily so that it can be used by the
configuration parsing code.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import List

__all__ = [
    "GitHubTeam",
    "GitHubUserInfo",
]


@dataclass(frozen=True)
class GitHubTeam:
    """An individual GitHub team."""

    slug: str
    """The slug of the team, taken from the slug attribute on GitHub."""

    organization: str
    """The organization (its login attribute) of which the team is a part."""

    gid: int
    """The GitHub ID of the team, used as a GID."""

    @property
    def group_name(self) -> str:
        """The group name corresponding to this GitHub team.

        Returns
        -------
        str
            The name of the group.

        Notes
        -----
        The default construction is the organization name (from the login
        field), a dash, and the team slug.  If this is over 32 characters, it
        will be truncated to 25 characters and the first six characters of a
        hash of the full name will be appended for uniqueness.
        """
        group_name = f"{self.organization.lower()}-{self.slug}"
        if len(group_name) > 32:
            name_hash = hashlib.sha256(group_name.encode()).digest()
            suffix = base64.urlsafe_b64encode(name_hash).decode()[:6]
            group_name = group_name[:25] + "-" + suffix
        return group_name


@dataclass(frozen=True)
class GitHubUserInfo:
    """Metadata about a user gathered from the GitHub API."""

    name: str
    """Full name of the user."""

    username: str
    """The GitHub login of the user."""

    uid: int
    """The GitHub ID of the user, used as the UID and primary GID."""

    email: str
    """The primary email address of the user."""

    teams: List[GitHubTeam]
    """The teams of which the user is a member."""
