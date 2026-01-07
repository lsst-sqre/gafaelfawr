"""Models for the Gafaelawr API understood by the client.

These models are intentionally not shared with the server implementation since
they may have to handle multiple versions of the server. They are simplified
compared to the server models, and only the ones starting with ``Gafaelfawr``
are exposed to users of the module.
"""

from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, Field

__all__ = [
    "AdminTokenRequest",
    "GafaelfawrGroup",
    "GafaelfawrNotebookQuota",
    "GafaelfawrQuota",
    "GafaelfawrTapQuota",
    "GafaelfawrUserInfo",
    "NewToken",
    "TokenData",
    "TokenType",
]


class GafaelfawrGroup(BaseModel):
    """Information about a single group."""

    name: Annotated[str, Field(title="Name of the group")]

    id: Annotated[int, Field(title="Numeric GID of the group")]


class GafaelfawrNotebookQuota(BaseModel):
    """Notebook Aspect quota information for a user."""

    cpu: Annotated[float, Field(title="CPU equivalents", examples=[4.0])]

    memory: Annotated[float, Field(title="Maximum memory use (GiB)")]

    spawn: Annotated[
        bool,
        Field(title="Spawning allowed"),
    ] = True

    @property
    def memory_bytes(self) -> int:
        """Maximum memory use in bytes."""
        return int(self.memory * 1024 * 1024 * 1024)

    def to_logging_context(self) -> dict[str, Any]:
        """Convert to variables for a structlog logging context."""
        result = {"cpu": self.cpu, "memory": f"{self.memory} GiB"}
        if not self.spawn:
            result["spawn"] = False
        return result


class GafaelfawrTapQuota(BaseModel):
    """TAP quota information for a user."""

    concurrent: Annotated[int, Field(title="Concurrent queries")]

    def to_logging_context(self) -> dict[str, Any]:
        """Convert to variables for a structlog logging context."""
        return {"concurrent": self.concurrent}


class GafaelfawrQuota(BaseModel):
    """Quota information for a user."""

    api: Annotated[
        dict[str, int],
        Field(
            title="API quotas",
            description=("Mapping of service names to requests per minute"),
        ),
    ] = {}

    notebook: Annotated[
        GafaelfawrNotebookQuota | None, Field(title="Notebook Aspect quotas")
    ] = None

    tap: Annotated[
        dict[str, GafaelfawrTapQuota], Field(title="TAP quotas")
    ] = {}


class GafaelfawrUserInfo(BaseModel):
    """Information about a user."""

    username: Annotated[str, Field(..., title="Username")]

    name: Annotated[str | None, Field(title="Preferred full name")] = None

    email: Annotated[str | None, Field(title="Email address")] = None

    uid: Annotated[int | None, Field(title="UID number")] = None

    gid: Annotated[int | None, Field(title="Primary GID")] = None

    groups: Annotated[list[GafaelfawrGroup], Field(title="Groups")] = []

    quota: Annotated[GafaelfawrQuota | None, Field(title="Quota")] = None

    @property
    def supplemental_groups(self) -> list[int]:
        """Supplemental GIDs."""
        return [g.id for g in self.groups]


class TokenData(BaseModel):
    """Metadata about a token, used internally by the mock."""

    token: Annotated[str, Field(title="Associated token")]

    username: Annotated[str, Field(title="Username")]

    scopes: Annotated[set[str], Field(title="Token scopes")] = set()

    expires: Annotated[datetime | None, Field(title="Expiration time")] = None


class TokenType(Enum):
    """The class of token.

    This includes only the subset of token types used by the client.
    """

    service = "service"


class AdminTokenRequest(BaseModel):
    """A request to create a new token via the admin interface."""

    username: Annotated[str, Field(title="User for which to issue a token")]

    token_type: Annotated[TokenType, Field(title="Token type")]

    scopes: Annotated[list[str], Field(title="Token scopes")] = []

    expires: Annotated[datetime | None, Field(title="Token expiration")] = None

    name: Annotated[str | None, Field(title="Preferred full name")] = None

    email: Annotated[str | None, Field(title="Email address")] = None

    uid: Annotated[int | None, Field(title="UID number")] = None

    gid: Annotated[int | None, Field(title="Primary GID")] = None

    groups: Annotated[
        list[GafaelfawrGroup] | None,
        Field(title="Groups"),
    ] = None


class NewToken(BaseModel):
    """Response to a token creation request."""

    token: Annotated[str, Field(title="Newly-created token")]
