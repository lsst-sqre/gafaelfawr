"""Storage layer for quota overrides."""

from __future__ import annotations

from safir.redis import DeserializeError, PydanticRedisStorage
from safir.slack.webhook import SlackWebhookClient
from structlog.stdlib import BoundLogger

from ..models.quota import QuotaConfig

__all__ = ["QuotaOverridesStore"]


class QuotaOverridesStore:
    """Stores and retrieves quota overrides in Redis.

    Parameters
    ----------
    storage
        Underlying storage for quota overrides.
    slack_client
        If provided, Slack webhook client to report deserialization errors of
        Redis data.
    logger
        Logger for diagnostics.
    """

    def __init__(
        self,
        storage: PydanticRedisStorage[QuotaConfig],
        slack_client: SlackWebhookClient | None,
        logger: BoundLogger,
    ) -> None:
        self._storage = storage
        self._slack = slack_client
        self._logger = logger

    async def delete(self) -> bool:
        """Delete any stored quota overrides.

        Returns
        -------
        bool
            `True` if there were quota overrides to delete, `False` otherwise.
        """
        return await self._storage.delete("quota-overrides")

    async def get(self) -> QuotaConfig | None:
        """Retrieve quota overrides from Redis, if any.

        Returns
        -------
        QuotaConfig or None
            Quota overrides if any are set, or `None` if there are none.
        """
        try:
            return await self._storage.get("quota-overrides")
        except DeserializeError as e:
            msg = "Cannot retrieve quota overrides"
            self._logger.exception(msg, error=str(e))
            if self._slack:
                await self._slack.post_exception(e)
            return None

    async def store(self, overrides: QuotaConfig) -> None:
        """Store quota overrides in Redis.

        Parameters
        ----------
        overrides
            Overrides to store, replacing any existing overrides.
        """
        await self._storage.store("quota-overrides", overrides)
