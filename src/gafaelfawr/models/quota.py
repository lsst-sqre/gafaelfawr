"""Models for user quotas."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "NotebookQuota",
    "Quota",
    "QuotaConfig",
    "TapQuota",
]


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

    def add(self, other: Self | None) -> Self:
        """Add an additional notebook quota to this one."""
        if not other:
            return self
        return type(self)(
            cpu=self.cpu + other.cpu,
            memory=self.memory + other.memory,
            spawn=self.spawn & other.spawn,
        )


class TapQuota(BaseModel):
    """TAP quota information for a user."""

    model_config = ConfigDict(extra="forbid")

    concurrent: int = Field(..., title="Concurrent queries", examples=[5])

    def add(self, other: Self | None) -> Self:
        """Add an additional TAP quota to this one."""
        if not other:
            return self
        return type(self)(concurrent=self.concurrent + other.concurrent)


class Quota(BaseModel):
    """Quota information for a user."""

    model_config = ConfigDict(extra="forbid")

    api: dict[str, int] = Field(
        {},
        title="API quotas",
        description=(
            "Mapping of service names to allowed requests per minute."
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

    tap: dict[str, TapQuota] = Field(
        {}, title="TAP quotas", examples=[{"qserv": {"concurrent": 5}}]
    )


class QuotaConfig(BaseModel):
    """Quota configuration."""

    model_config = ConfigDict(extra="forbid")

    default: Quota = Field(
        default_factory=Quota,
        title="Default quota",
        description="Default quotas for all users",
    )

    groups: dict[str, Quota] = Field(
        {},
        title="Quota grants by group",
        description="Additional quota grants by group name",
    )

    bypass: set[str] = Field(
        set(),
        title="Groups without quotas",
        description="Groups whose members bypass all quota restrictions",
    )

    def calculate_quota(self, groups: set[str]) -> Quota | None:
        """Calculate user's quota given their group membership.

        Parameters
        ----------
        groups
            Group membership of the user.

        Returns
        -------
        Quota or None
            Quota information for that user or `None` if no quotas apply. If
            the user bypasses quotas, a `~gafaelfawr.models.quota.Quota` model
            with quotas set to `None` or an empty dictionary is returned rather
            than `None`.
        """
        if groups & self.bypass:
            return Quota()

        # Start with the defaults.
        default = self.default
        api = dict(default.api)
        notebook = default.notebook.model_copy() if default.notebook else None
        tap = dict(default.tap)

        # Look for group-specific rules.
        for group in groups & set(self.groups.keys()):
            extra = self.groups[group]
            if notebook:
                notebook = notebook.add(extra.notebook)
            else:
                notebook = extra.notebook
            for service, rule in extra.tap.items():
                if service in tap:
                    tap[service] = tap[service].add(rule)
                else:
                    tap[service] = rule
            for service, quota in extra.api.items():
                if service in api:
                    api[service] += quota
                else:
                    api[service] = quota

        # Return the results.
        if not notebook and not api:
            return None
        else:
            return Quota(api=api, notebook=notebook, tap=tap)
