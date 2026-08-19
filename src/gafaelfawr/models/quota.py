"""Models for user quotas."""

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

    disk: dict[str, int] = Field(
        {},
        title="Disk quotas",
        description=(
            "Mapping of mount points to disk quota allocations in bytes"
        ),
        examples=[{"/home": 32212254720}],
    )

    notebook: NotebookQuota | None = Field(
        None, title="Notebook Aspect quotas"
    )

    tap: dict[str, TapQuota] = Field(
        {}, title="TAP quotas", examples=[{"qserv": {"concurrent": 5}}]
    )

    def is_empty(self) -> bool:
        """Whether this quota contains no rules."""
        return (
            not self.api
            and not self.disk
            and not self.notebook
            and not self.tap
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
        notebook = default.notebook.model_copy() if default.notebook else None
        quota = Quota(
            api=dict(default.api),
            disk=dict(default.disk),
            notebook=notebook,
            tap=dict(default.tap),
        )

        # Merge in group-specific rules.
        for group in groups & set(self.groups.keys()):
            self._merge_group_quota(quota, self.groups[group])

        # Return the results.
        if quota.is_empty():
            return None
        else:
            return quota

    def _merge_group_quota(self, base: Quota, extra: Quota) -> None:
        """Merge quota for a group into an existing quota.

        Parameters
        ----------
        base
            Quota being constructed.
        extra
            Additional quota allocated to a group.
        """
        if base.notebook:
            base.notebook = base.notebook.add(extra.notebook)
        else:
            base.notebook = extra.notebook
        for service, rule in extra.tap.items():
            if service in base.tap:
                base.tap[service] = base.tap[service].add(rule)
            else:
                base.tap[service] = rule
        for mount, quota in extra.disk.items():
            if mount in base.disk:
                base.disk[mount] += quota
            else:
                base.disk[mount] = quota
        for service, quota in extra.api.items():
            if service in base.api:
                base.api[service] += quota
            else:
                base.api[service] = quota
