"""Models for the GitHub authentication provider.

Notes
-----
This is in a separate module primarily so that it can be used by the
configuration parsing code.
"""

from dataclasses import dataclass

from ..util import group_name_for_github_team

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
        """
        return group_name_for_github_team(self.organization, self.slug)


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

    teams: list[GitHubTeam]
    """The teams of which the user is a member."""
