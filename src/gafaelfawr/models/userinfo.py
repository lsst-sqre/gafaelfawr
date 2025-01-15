"""Models for user metadata."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ..constants import GROUPNAME_REGEX
from ..pydantic import Timestamp

__all__ = [
    "CADCUserInfo",
    "Group",
    "NotebookQuota",
    "Quota",
    "RateLimitStatus",
    "UserInfo",
]


class CADCUserInfo(BaseModel):
    """User metadata required by the CADC authentication code.

    This model is hopefully temporary and will be retired by merging the CADC
    support with the OpenID Connect support.
    """

    exp: Timestamp | None = Field(
        None,
        title="Expiration time",
        description=(
            "Expiration timestamp of the token in seconds since epoch. If"
            " not present, the token never expires."
        ),
        examples=[1625986130],
    )

    preferred_username: str = Field(
        ...,
        title="Username",
        description="Username of user",
        examples=["someuser"],
    )

    sub: str = Field(
        ...,
        title="Unique identifier",
        description=(
            "For now, Gafaelfawr uses the username for this field as well,"
            " even though this is not entirely correct in the presence of"
            " username changes."
        ),
        examples=["someuser"],
    )


class Group(BaseModel):
    """Information about a single group."""

    name: str = Field(
        ...,
        title="Name of the group",
        examples=["g_special_users"],
        min_length=1,
        pattern=GROUPNAME_REGEX,
    )

    id: int = Field(
        ...,
        title="Numeric GID of the group",
        examples=[123181],
    )


class NotebookQuota(BaseModel):
    """Notebook Aspect quota information for a user."""

    model_config = ConfigDict(extra="forbid")

    cpu: float = Field(..., title="CPU equivalents", examples=[4.0])

    memory: float = Field(
        ..., title="Maximum memory use (GiB)", examples=[16.0]
    )

    spawn: bool = Field(
        True,
        title="Spawning allowed",
        description="Whether the user is allowed to spawn a notebook",
    )


class Quota(BaseModel):
    """Quota information for a user."""

    model_config = ConfigDict(extra="forbid")

    api: dict[str, int] = Field(
        {},
        title="API quotas",
        description=(
            "Mapping of service names to allowed requests per 15 minutes."
        ),
        examples=[
            {
                "datalinker": 500,
                "hips": 2000,
                "tap": 500,
                "vo-cutouts": 100,
            }
        ],
    )

    notebook: NotebookQuota | None = Field(
        None, title="Notebook Aspect quotas"
    )


class UserInfo(BaseModel):
    """Metadata about a user.

    All user metadata from whatever source (admin request, GitHub, LDAP,
    Firestore, etc.).
    """

    username: str = Field(
        ...,
        title="Username",
        description="User to whom the token was issued",
        examples=["someuser"],
        min_length=1,
        max_length=64,
    )

    name: str | None = Field(
        None,
        title="Preferred full name",
        examples=["Alice Example"],
        min_length=1,
    )

    email: str | None = Field(
        None,
        title="Email address",
        examples=["alice@example.com"],
        min_length=1,
    )

    uid: int | None = Field(None, title="UID number", examples=[4123], ge=1)

    gid: int | None = Field(
        None,
        title="Primary GID",
        description=(
            "GID of primary group. If set, this will also be the GID of one of"
            " the groups of which the user is a member."
        ),
        examples=[4123],
        ge=1,
    )

    groups: list[Group] = Field(
        [],
        title="Groups",
        description="Groups of which the user is a member",
    )

    quota: Quota | None = Field(None, title="Quota")


@dataclass
class RateLimitStatus:
    """Current status of rate limiting for a user for one API.

    This is an internal model used to hold rate limiting status information
    that will be returned to the user in HTTP headers. It represents a fixed
    window rate limit algorithm.
    """

    limit: int
    """Total number of API requests allowed to this service."""

    remaining: int
    """Number of API requests remaining in the rate limit period."""

    reset: datetime
    """Time at which the rate limit window will reset."""

    resource: str
    """Name of the resource being rate limited (the API service name)."""

    def to_http_headers(self) -> dict[str, str]:
        """Return the rate limit status as HTTP headers.

        The headers were chosen to match the `GitHub rate limit
        implementation`_.
        """
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Used": str(self.limit - self.remaining),
            "X-RateLimit-Reset": str(int(self.reset.timestamp())),
            "X-RateLimit-Resource": self.resource,
        }
