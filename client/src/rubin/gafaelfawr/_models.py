"""Models for the Gafaelawr API understood by the client.

These models are intentionally not shared with the server implementation since
they may have to handle multiple versions of the server.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, Field

__all__ = [
    "GafaelfawrGroup",
    "GafaelfawrNotebookQuota",
    "GafaelfawrQuota",
    "GafaelfawrTapQuota",
    "GafaelfawrTokenData",
    "GafaelfawrUserInfo",
]


class GafaelfawrGroup(BaseModel):
    """Information about a single group."""

    name: Annotated[
        str,
        Field(
            ...,
            title="Name of the group",
            examples=["g_special_users"],
        ),
    ]

    id: Annotated[
        int,
        Field(
            ...,
            title="Numeric GID of the group",
            examples=[123181],
        ),
    ]


class GafaelfawrTokenData(BaseModel):
    """Metadata about a token."""

    token: Annotated[str, Field(title="Associated token")]

    username: Annotated[
        str,
        Field(
            title="Username",
            description="User to whom the token was issued",
            examples=["someuser"],
        ),
    ]

    scopes: Annotated[
        set[str],
        Field(
            title="Token scopes",
            examples=[["read:all", "user:token"]],
        ),
    ] = set()


class GafaelfawrNotebookQuota(BaseModel):
    """Notebook Aspect quota information for a user."""

    cpu: Annotated[float, Field(title="CPU equivalents", examples=[4.0])]

    memory: Annotated[
        float, Field(title="Maximum memory use (GiB)", examples=[16.0])
    ]

    spawn: Annotated[
        bool,
        Field(
            title="Spawning allowed",
            description="Whether the user is allowed to spawn a notebook",
        ),
    ] = True

    def to_logging_context(self) -> dict[str, Any]:
        """Convert to variables for a structlog logging context."""
        result = {"cpu": self.cpu, "memory": f"{self.memory} GiB"}
        if not self.spawn:
            result["spawn"] = False
        return result


class GafaelfawrTapQuota(BaseModel):
    """TAP quota information for a user."""

    concurrent: Annotated[int, Field(title="Concurrent queries", examples=[5])]

    def to_logging_context(self) -> dict[str, Any]:
        """Convert to variables for a structlog logging context."""
        return {"concurrent": self.concurrent}


class GafaelfawrQuota(BaseModel):
    """Quota information for a user."""

    api: Annotated[
        dict[str, int],
        Field(
            title="API quotas",
            description=(
                "Mapping of service names to allowed requests per minute"
            ),
            examples=[{"datalinker": 500, "hips": 2000}],
        ),
    ] = {}

    notebook: Annotated[
        GafaelfawrNotebookQuota | None, Field(title="Notebook Aspect quotas")
    ] = None

    tap: Annotated[
        dict[str, GafaelfawrTapQuota],
        Field(title="TAP quotas", examples=[{"qserv": {"concurrent": 5}}]),
    ] = {}


class GafaelfawrUserInfo(BaseModel):
    """Information about a user."""

    username: Annotated[
        str, Field(..., title="Username", examples=["someuser"])
    ]

    name: Annotated[
        str | None,
        Field(title="Preferred full name", examples=["Alice Example"]),
    ] = None

    email: Annotated[
        str | None,
        Field(title="Email address", examples=["alice@example.com"]),
    ] = None

    uid: Annotated[int | None, Field(title="UID number", examples=[4123])] = (
        None
    )

    gid: Annotated[
        int | None,
        Field(
            title="Primary GID",
            description=(
                "GID of primary group. If set, this will also be the GID of"
                " one of the groups of which the user is a member."
            ),
            examples=[4123],
        ),
    ] = None

    groups: Annotated[
        list[GafaelfawrGroup],
        Field(
            title="Groups", description="Groups of which the user is a member"
        ),
    ] = []

    quota: Annotated[GafaelfawrQuota | None, Field(title="Quota")] = None

    @property
    def supplemental_groups(self) -> list[int]:
        """Supplemental GIDs."""
        return [g.id for g in self.groups]
