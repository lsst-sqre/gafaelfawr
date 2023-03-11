"""ForgeRock Identity Management storage layer for Gafaelfawr."""

from __future__ import annotations

from httpx import AsyncClient, BasicAuth, HTTPError
from structlog.stdlib import BoundLogger

from ..config import ForgeRockConfig
from ..exceptions import ForgeRockError, ForgeRockWebError

__all__ = ["ForgeRockStorage"]


class ForgeRockStorage:
    """Perform ForgeRock Identity Management lookups.

    Parameters
    ----------
    config
        ForgeRock Identity Management configuration.
    http_client
        HTTP client to use.
    logger
        Logger to use.
    """

    def __init__(
        self,
        *,
        config: ForgeRockConfig,
        http_client: AsyncClient,
        logger: BoundLogger,
    ) -> None:
        self._config = config
        self._logger = logger
        self._http_client = http_client

    async def get_gid(self, group_name: str) -> int | None:
        """Get the GID of a group from ForgeRock Identity Management.

        Parameters
        ----------
        group_name
            Name of the group.

        Returns
        -------
        int or None
            GID if found, else `None`.

        Raises
        ------
        ForgeRockError
            Raised if some error occured querying the ForgeRock server (other
            than that the group was not found).

        Notes
        -----
        This issues a :samp:`name eq {group_name}` query against the
        ``system/freeipa/group`` endpoint, which appears to be the correct
        place to find group information for at least one installation of the
        ForgeRock Identity Management server. This may or may not generalize
        to other installations.
        """
        url = self._config.url.rstrip("/") + "/system/freeipa/group"
        params = {
            "_queryFilter": f'name eq "{group_name}"',
            "_fields": "gid",
        }
        try:
            r = await self._http_client.get(
                url,
                params=params,
                auth=BasicAuth(self._config.username, self._config.password),
            )
            r.raise_for_status()
            result = r.json()
            self._logger.debug(
                f"ForgeRock data for group {group_name}",
                forgerock_url=url,
                forgerock_results=result,
                forgerock_query=params,
            )
            entries = result.get("result", [])
            if not entries:
                return None
            return int(entries[0].get("gid"))
        except (AttributeError, ValueError) as e:
            error = f"{type(e).__name__}: str(e)"
            msg = f"ForgeRock data for {group_name} invalid: {error}"
            raise ForgeRockError(msg) from e
        except HTTPError as e:
            raise ForgeRockWebError.from_exception(e) from e
